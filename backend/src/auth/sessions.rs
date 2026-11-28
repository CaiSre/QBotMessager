//! 服务端会话：Cookie 只保存随机 token，数据库只保存其 SHA-256。
//!
//! 会话 Cookie 约定：
//! - token = 32 随机字节 → base64url 无填充（43 字符）；
//! - 库内 `sessions.token_hash` = `SHA-256(token)` 的 64 位小写十六进制；
//! - Cookie：`HttpOnly; SameSite=Lax; Path=/; Max-Age=ttl*3600`，
//!   `Secure` 当 `cookie_secure=true` 或 `public_base_url` 以 `https://` 开头；
//!   HTTPS 下名称加 `__Host-` 前缀，读取时兼容旧的无前缀 Cookie；
//! - 撤销：`revoked_at` 非空或 `expires_at <= now` 即失效。

use actix_web::HttpRequest;
use actix_web::cookie::time::Duration as CookieDuration;
use actix_web::cookie::{Cookie, SameSite};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{Duration as ChronoDuration, NaiveDateTime, Utc};
use rand::Rng;
use sqlx::MySqlPool;

use crate::config::Config;
use crate::db::models::{Session, User};
use crate::error::AppError;
use crate::services::runtime_settings::RuntimeSettings;

/// token 的随机字节数。
pub const TOKEN_BYTES: usize = 32;
/// user_agent 入库前的最大长度。
pub const USER_AGENT_MAX: usize = 255;
/// 敏感操作要求的最近验证窗口（分钟）。
pub const STEP_UP_WINDOW_MINUTES: i64 = 10;
/// 仅 HTTPS 可用的 Cookie 前缀。
pub const HOST_COOKIE_PREFIX: &str = "__Host-";

/// 生成会话 token（base64url 无填充）。
pub fn new_session_token() -> String {
    let mut bytes = [0u8; TOKEN_BYTES];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// 计算入库用的 token 哈希（SHA-256 小写十六进制）。
pub fn hash_token(token: &str) -> String {
    crate::crypto::hash_token(token)
}

/// 会话是否仍然有效。
pub fn is_session_valid(session: &Session, now: NaiveDateTime) -> bool {
    session.revoked_at.is_none() && session.expires_at > now
}

/// 最近验证是否仍在窗口内；`None`（旧会话或未验证）视为过期。
pub fn step_up_valid(verified_at: Option<NaiveDateTime>, now: NaiveDateTime) -> bool {
    verified_at.is_some_and(|value| value + ChronoDuration::minutes(STEP_UP_WINDOW_MINUTES) > now)
}

/// 当前设置下应写入的会话 Cookie 名。
///
/// HTTPS 使用 `__Host-` 前缀，浏览器会强制该 Cookie 必须 `Secure`、`Path=/`
/// 且不带 `Domain`，降低子域覆盖风险。
pub fn session_cookie_name(config: &Config, settings: &RuntimeSettings) -> String {
    if settings.secure_cookies() && !config.cookie_name.starts_with(HOST_COOKIE_PREFIX) {
        format!("{HOST_COOKIE_PREFIX}{}", config.cookie_name)
    } else {
        config.cookie_name.clone()
    }
}

/// 可能存在的会话 Cookie 名，按优先级排列。
///
/// 同时兼容开启/关闭 HTTPS 前后的旧 Cookie：读取时优先 `__Host-`，再退回原名。
pub fn session_cookie_names(config: &Config, settings: &RuntimeSettings) -> Vec<String> {
    let primary = session_cookie_name(config, settings);
    if primary == config.cookie_name {
        vec![primary]
    } else {
        vec![primary, config.cookie_name.clone()]
    }
}

/// 从请求中读取会话 token；没有 Cookie 时返回空串。
pub fn read_session_token(
    req: &HttpRequest,
    config: &Config,
    settings: &RuntimeSettings,
) -> String {
    session_cookie_names(config, settings)
        .into_iter()
        .find_map(|name| req.cookie(&name).map(|cookie| cookie.value().to_string()))
        .unwrap_or_default()
}

/// 构造会话 Cookie。
pub fn session_cookie(
    config: &Config,
    settings: &RuntimeSettings,
    token: &str,
    ttl_hours: i64,
) -> Cookie<'static> {
    Cookie::build(session_cookie_name(config, settings), token.to_string())
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(CookieDuration::seconds(ttl_hours.saturating_mul(3600)))
        .secure(settings.secure_cookies())
        .finish()
}

/// 构造删除当前会话 Cookie 的指令（过期时间设为 0，属性与签发时保持一致）。
pub fn clear_session_cookie(config: &Config, settings: &RuntimeSettings) -> Cookie<'static> {
    clear_cookie_named(session_cookie_name(config, settings), settings)
}

/// 删除当前与旧命名的会话 Cookie。
///
/// 从 HTTP 切到 HTTPS（或反向）后，浏览器里可能同时存在 `sid` 与 `__Host-sid`；
/// 退出登录必须都清掉，避免遗留 Cookie 继续被服务端接受。
pub fn clear_session_cookies(config: &Config, settings: &RuntimeSettings) -> Vec<Cookie<'static>> {
    session_cookie_names(config, settings)
        .into_iter()
        .map(|name| clear_cookie_named(name, settings))
        .collect()
}

fn clear_cookie_named(name: String, settings: &RuntimeSettings) -> Cookie<'static> {
    Cookie::build(name, String::new())
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(CookieDuration::seconds(0))
        .secure(settings.secure_cookies())
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
        "INSERT INTO sessions \
         (token_hash, user_id, ip, user_agent, verified_at, expires_at, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(hash_token(&token))
    .bind(user.id)
    .bind(ip)
    .bind(user_agent)
    .bind(now)
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
        "SELECT id, token_hash, user_id, ip, user_agent, verified_at, expires_at, revoked_at, created_at \
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

/// 读取会话最近验证时间；token 无效时返回 `None`。
pub async fn verified_at(pool: &MySqlPool, token: &str) -> Result<Option<NaiveDateTime>, AppError> {
    if token.is_empty() {
        return Ok(None);
    }
    let row: Option<(Option<NaiveDateTime>,)> =
        sqlx::query_as("SELECT verified_at FROM sessions WHERE token_hash = ?")
            .bind(hash_token(token))
            .fetch_optional(pool)
            .await?;
    Ok(row.and_then(|(value,)| value))
}

/// 标记当前会话刚刚完成身份验证。
pub async fn mark_verified(
    pool: &MySqlPool,
    token: &str,
    now: NaiveDateTime,
) -> Result<(), AppError> {
    if token.is_empty() {
        return Ok(());
    }
    sqlx::query("UPDATE sessions SET verified_at = ? WHERE token_hash = ? AND revoked_at IS NULL")
        .bind(now)
        .bind(hash_token(token))
        .execute(pool)
        .await?;
    Ok(())
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
            verified_at: Some(now),
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

    fn config() -> Config {
        Config {
            mysql_url: String::new(),
            app_secret_key: None,
            app_name: "test".to_string(),
            cookie_name: "sid".to_string(),
            bootstrap_admin_email: String::new(),
            bootstrap_admin_password: String::new(),
            qq_appid: String::new(),
            qq_app_secret: String::new(),
            openids: Vec::new(),
            qq_allowed_hosts: Vec::new(),
            db_pool_size: 1,
            db_max_overflow: 1,
            db_pool_timeout: 1,
            push_queue_max: 1,
            push_queue_max_per_user: 1,
            retention: Default::default(),
            trust_proxy: false,
            static_dir: std::path::PathBuf::new(),
        }
    }

    fn settings(values: serde_json::Value) -> RuntimeSettings {
        let mut settings = RuntimeSettings::new(None);
        let object = values.as_object().unwrap();
        let values = settings.validate(object).unwrap();
        settings.apply(&values);
        settings
    }

    #[test]
    fn secure_session_cookie_uses_host_prefix() {
        let config = config();
        let plain = settings(serde_json::json!({}));
        let secure = settings(serde_json::json!({"cookie_secure": true}));
        assert_eq!(session_cookie_name(&config, &plain), "sid");
        assert_eq!(session_cookie_name(&config, &secure), "__Host-sid");
        assert_eq!(
            session_cookie_names(&config, &secure),
            vec!["__Host-sid".to_string(), "sid".to_string()]
        );
        let cookie = session_cookie(&config, &secure, "token", 1);
        assert_eq!(cookie.name(), "__Host-sid");
        assert_eq!(cookie.path(), Some("/"));
        assert!(cookie.secure().unwrap_or(false));
        assert!(cookie.http_only().unwrap_or(false));
        assert_eq!(clear_session_cookie(&config, &secure).name(), "__Host-sid");
        let cleared: Vec<String> = clear_session_cookies(&config, &secure)
            .into_iter()
            .map(|cookie| cookie.name().to_string())
            .collect();
        assert_eq!(cleared, vec!["__Host-sid", "sid"]);
    }

    #[test]
    fn step_up_window_accepts_recent_and_rejects_stale_or_missing() {
        let now = Utc::now().naive_utc();
        assert!(step_up_valid(Some(now), now));
        assert!(step_up_valid(
            Some(now - ChronoDuration::minutes(STEP_UP_WINDOW_MINUTES - 1)),
            now
        ));
        assert!(!step_up_valid(
            Some(now - ChronoDuration::minutes(STEP_UP_WINDOW_MINUTES)),
            now
        ));
        assert!(!step_up_valid(None, now));
    }
}
