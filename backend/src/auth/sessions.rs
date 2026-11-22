//! 服务端会话：Cookie 只保存随机 token，数据库只保存其 SHA-256。
//!
//! 会话 Cookie 约定：
//! - token = 32 随机字节 → base64url 无填充（43 字符）；
//! - 库内 `sessions.token_hash` = `SHA-256(token)` 的 64 位小写十六进制；
//! - Cookie：`HttpOnly; SameSite=Lax; Path=/; Max-Age=ttl*3600`，
//!   `Secure` 当 `cookie_secure=true` 或 `public_base_url` 以 `https://` 开头；
//! - 撤销：`revoked_at` 非空或 `expires_at <= now` 即失效。

use actix_web::cookie::time::Duration as CookieDuration;
use actix_web::cookie::{Cookie, SameSite};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{Duration as ChronoDuration, NaiveDateTime, Utc};
use rand::Rng;
use sha2::{Digest, Sha256};
use sqlx::MySqlPool;

use crate::config::Config;
use crate::db::models::{Session, User};
use crate::error::AppError;
use crate::services::runtime_settings::RuntimeSettings;

/// token 的随机字节数。
pub const TOKEN_BYTES: usize = 32;
/// user_agent 入库前的最大长度。
pub const USER_AGENT_MAX: usize = 255;

/// 生成会话 token（base64url 无填充）。
pub fn new_session_token() -> String {
    let mut bytes = [0u8; TOKEN_BYTES];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// 计算入库用的 token 哈希（SHA-256 小写十六进制）。
pub fn hash_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// 会话是否仍然有效。
pub fn is_session_valid(session: &Session, now: NaiveDateTime) -> bool {
    session.revoked_at.is_none() && session.expires_at > now
}

/// 构造会话 Cookie。
pub fn session_cookie(
    config: &Config,
    settings: &RuntimeSettings,
    token: &str,
    ttl_hours: i64,
) -> Cookie<'static> {
    Cookie::build(config.cookie_name.clone(), token.to_string())
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(CookieDuration::seconds(ttl_hours.saturating_mul(3600)))
        .secure(settings.secure_cookies())
        .finish()
}

/// 构造删除会话 Cookie 的指令（过期时间设为 0）。
pub fn clear_session_cookie(config: &Config) -> Cookie<'static> {
    Cookie::build(config.cookie_name.clone(), String::new())
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(CookieDuration::seconds(0))
        .finish()
}

/// 创建会话并回写用户的最后登录时间；返回明文 token。
pub async fn create_session(
    pool: &MySqlPool,
    user: &User,
    ttl_hours: i64,
    ip: Option<&str>,
    user_agent: Option<&str>,
) -> Result<String, AppError> {
    let token = new_session_token();
    let now = Utc::now().naive_utc();
    let expires_at = now + ChronoDuration::hours(ttl_hours);
    // UA 按字符截断到 255，空串落库为 NULL。
    let user_agent = user_agent
        .map(|value| value.chars().take(USER_AGENT_MAX).collect::<String>())
        .filter(|value| !value.is_empty());
    let ip = ip.filter(|value| !value.is_empty());

    // 会话插入与最后登录时间必须同一事务提交。
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO sessions (token_hash, user_id, ip, user_agent, expires_at, created_at) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(hash_token(&token))
    .bind(user.id)
    .bind(ip)
    .bind(user_agent)
    .bind(expires_at)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE users SET last_login_at = ? WHERE id = ?")
        .bind(now)
        .bind(user.id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    Ok(token)
}

/// 用明文 token 解析出有效用户；无效/过期/撤销返回 `None`。
pub async fn resolve_session(pool: &MySqlPool, token: &str) -> Result<Option<User>, AppError> {
    if token.is_empty() {
        return Ok(None);
    }
    let session = sqlx::query_as::<_, Session>(
        "SELECT id, token_hash, user_id, ip, user_agent, expires_at, revoked_at, created_at \
         FROM sessions WHERE token_hash = ?",
    )
    .bind(hash_token(token))
    .fetch_optional(pool)
    .await?;
    let Some(session) = session else {
        return Ok(None);
    };
    if !is_session_valid(&session, Utc::now().naive_utc()) {
        return Ok(None);
    }
    let user = sqlx::query_as::<_, User>(
        "SELECT id, email, name, password_hash, role, status, last_login_at, created_at \
         FROM users WHERE id = ?",
    )
    .bind(session.user_id)
    .fetch_optional(pool)
    .await?;
    Ok(user)
}

/// 撤销单个会话。
pub async fn revoke_session(pool: &MySqlPool, token: &str) -> Result<(), AppError> {
    if token.is_empty() {
        return Ok(());
    }
    sqlx::query("UPDATE sessions SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL")
        .bind(Utc::now().naive_utc())
        .bind(hash_token(token))
        .execute(pool)
        .await?;
    Ok(())
}

/// 撤销该用户的全部会话（重置密码后调用）。
pub async fn revoke_user_sessions(pool: &MySqlPool, user_id: i64) -> Result<(), AppError> {
    sqlx::query("UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL")
        .bind(Utc::now().naive_utc())
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// 撤销该用户除当前会话外的其他登录设备（改密后调用）。
pub async fn revoke_other_sessions(
    pool: &MySqlPool,
    user_id: i64,
    keep_token: &str,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE sessions SET revoked_at = ? \
         WHERE user_id = ? AND token_hash <> ? AND revoked_at IS NULL",
    )
    .bind(Utc::now().naive_utc())
    .bind(user_id)
    .bind(hash_token(keep_token))
    .execute(pool)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_is_32_bytes_base64url_without_padding() {
        let token = new_session_token();
        assert_eq!(token.len(), 43);
        // 32 字节 = 256 位，base64url 无填充恰好 43 个字符。
        assert!(
            token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        );
        assert_ne!(token, new_session_token());
    }

    #[test]
    fn hash_token_matches_sha256_hex() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb924
        //              27ae41e4649b934ca495991b7852b855
        assert_eq!(
            hash_token(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(hash_token("abc").len(), 64);
    }

    #[test]
    fn session_validity_rejects_revoked_and_expired() {
        let now = Utc::now().naive_utc();
        let base = Session {
            id: 1,
            token_hash: String::new(),
            user_id: 1,
            ip: None,
            user_agent: None,
            expires_at: now + ChronoDuration::hours(1),
            revoked_at: None,
            created_at: now,
        };
        assert!(is_session_valid(&base, now));
        assert!(!is_session_valid(
            &Session {
                expires_at: now,
                ..base.clone()
            },
            now
        ));
        assert!(!is_session_valid(
            &Session {
                revoked_at: Some(now),
                ..base
            },
            now
        ));
    }
}
