//! 邮箱验证码的签发与校验。
//!
//! 验证码只保存 PBKDF2 哈希；同一邮箱同一用途同时只有最新一条有效，
//! 过期、尝试次数用尽或校验成功后立即作废。
//!
//! 冷却与小时配额超限都映射为
//! 429（带 `Retry-After`），由 [`crate::error::AppError::rate_limited`] 统一表达。

use chrono::{Duration, NaiveDateTime, Utc};
use sqlx::MySqlPool;

use crate::auth::passwords::{hash_password_async, verify_password_async};
use crate::error::AppError;

/// 注册用途。
pub const PURPOSE_REGISTER: &str = "register";
/// 重置密码用途。
pub const PURPOSE_RESET_PASSWORD: &str = "reset_password";
/// 设置密码用途。
pub const PURPOSE_SET_PASSWORD: &str = "set_password";
/// 全部合法用途。
pub const PURPOSES: [&str; 3] = [
    PURPOSE_REGISTER,
    PURPOSE_RESET_PASSWORD,
    PURPOSE_SET_PASSWORD,
];

/// 单条验证码的最大失败次数。
pub const MAX_ATTEMPTS: i32 = 5;

/// 用途是否合法。
pub fn is_valid_purpose(purpose: &str) -> bool {
    PURPOSES.contains(&purpose)
}

/// 用途的展示名。
pub fn purpose_label(purpose: &str) -> &'static str {
    match purpose {
        PURPOSE_REGISTER => "注册账号",
        PURPOSE_RESET_PASSWORD => "重置密码",
        PURPOSE_SET_PASSWORD => "设置登录密码",
        _ => "验证身份",
    }
}

/// 生成 6 位数字验证码。
pub fn generate_code() -> String {
    format!("{:06}", rand::random::<u32>() % 1_000_000)
}

/// 签发验证码。
///
/// 冷却期（`resend_seconds`）内或小时配额（`hourly_limit`）用尽时返回 429；
/// 签发新码前把同 `(email, purpose)` 的未消费记录置为已消费。
pub async fn issue_code(
    pool: &MySqlPool,
    email: &str,
    purpose: &str,
    ttl_minutes: i64,
    resend_seconds: u64,
    hourly_limit: i64,
    ip: Option<&str>,
) -> Result<String, AppError> {
    let now = Utc::now().naive_utc();
    let mut tx = pool.begin().await?;

    let latest: Option<(NaiveDateTime,)> = sqlx::query_as(
        "SELECT created_at FROM email_verification_codes \
         WHERE email = ? AND purpose = ? AND consumed_at IS NULL \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(email)
    .bind(purpose)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some((created_at,)) = latest {
        let wait = too_frequent_wait(created_at, now, resend_seconds);
        if wait > 0 {
            return Err(AppError::rate_limited(
                format!("发送过于频繁，请 {wait} 秒后再试"),
                wait as u64,
            ));
        }
    }

    // COUNT(*) 在 MySQL 里是 BIGINT UNSIGNED；转成 SIGNED 以匹配 i64 解码。
    let sent: i64 = sqlx::query_scalar(
        "SELECT CAST(COUNT(*) AS SIGNED) FROM email_verification_codes \
         WHERE email = ? AND purpose = ? AND created_at >= ?",
    )
    .bind(email)
    .bind(purpose)
    .bind(now - Duration::hours(1))
    .fetch_one(&mut *tx)
    .await?;
    if sent >= hourly_limit.max(0) {
        return Err(AppError::rate_limited(
            "发送次数过多，请稍后再试",
            resend_seconds,
        ));
    }

    // 新码签发后旧码立即失效
    sqlx::query(
        "UPDATE email_verification_codes SET consumed_at = ? \
         WHERE email = ? AND purpose = ? AND consumed_at IS NULL",
    )
    .bind(now)
    .bind(email)
    .bind(purpose)
    .execute(&mut *tx)
    .await?;

    let code = generate_code();
    let code_hash = hash_password_async(&code).await?;
    let expires_at = now + Duration::minutes(ttl_minutes);

    sqlx::query(
        "INSERT INTO email_verification_codes \
         (email, purpose, code_hash, expires_at, attempts, ip, created_at) \
         VALUES (?, ?, ?, ?, 0, ?, ?)",
    )
    .bind(email)
    .bind(purpose)
    .bind(&code_hash)
    .bind(expires_at)
    .bind(ip)
    .bind(now)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(code)
}

/// 校验并一次性消费验证码；失败会累计尝试次数。
pub async fn verify_code(
    pool: &MySqlPool,
    email: &str,
    purpose: &str,
    code: &str,
) -> Result<bool, AppError> {
    let now = Utc::now().naive_utc();
    let row: Option<(i64, String, NaiveDateTime, i32)> = sqlx::query_as(
        "SELECT id, code_hash, expires_at, attempts FROM email_verification_codes \
         WHERE email = ? AND purpose = ? AND consumed_at IS NULL \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(email)
    .bind(purpose)
    .fetch_optional(pool)
    .await?;

    let Some((id, code_hash, expires_at, attempts)) = row else {
        return Ok(false);
    };

    if expires_at <= now || attempts >= MAX_ATTEMPTS {
        sqlx::query("UPDATE email_verification_codes SET consumed_at = ? WHERE id = ?")
            .bind(now)
            .bind(id)
            .execute(pool)
            .await?;
        return Ok(false);
    }

    if !verify_password_async(code.trim(), &code_hash).await {
        let attempts = attempts + 1;
        if attempts >= MAX_ATTEMPTS {
            sqlx::query(
                "UPDATE email_verification_codes SET attempts = ?, consumed_at = ? WHERE id = ?",
            )
            .bind(attempts)
            .bind(now)
            .bind(id)
            .execute(pool)
            .await?;
        } else {
            sqlx::query("UPDATE email_verification_codes SET attempts = ? WHERE id = ?")
                .bind(attempts)
                .bind(id)
                .execute(pool)
                .await?;
        }
        return Ok(false);
    }

    sqlx::query("UPDATE email_verification_codes SET consumed_at = ? WHERE id = ?")
        .bind(now)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(true)
}

/// 邮件发送失败时作废刚签发的验证码，允许用户立即重试。
pub async fn discard_latest(pool: &MySqlPool, email: &str, purpose: &str) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE email_verification_codes SET consumed_at = ? \
         WHERE email = ? AND purpose = ? AND consumed_at IS NULL",
    )
    .bind(Utc::now().naive_utc())
    .bind(email)
    .bind(purpose)
    .execute(pool)
    .await?;
    Ok(())
}

/// 距离可以再次发送还需等待的秒数；`<= 0` 表示已经可以发送。
///
/// 向零截断，不足 1 秒按 0 处理。
fn too_frequent_wait(created_at: NaiveDateTime, now: NaiveDateTime, resend_seconds: u64) -> i64 {
    let resend_seconds = i64::try_from(resend_seconds).unwrap_or(i64::MAX);
    (created_at + Duration::seconds(resend_seconds) - now).num_seconds()
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    #[test]
    fn code_is_six_digits() {
        for _ in 0..200 {
            let code = generate_code();
            assert_eq!(code.len(), 6, "{code}");
            assert!(code.chars().all(|ch| ch.is_ascii_digit()), "{code}");
        }
    }

    #[test]
    fn purposes_are_validated() {
        assert!(is_valid_purpose(PURPOSE_REGISTER));
        assert!(is_valid_purpose(PURPOSE_RESET_PASSWORD));
        assert!(is_valid_purpose(PURPOSE_SET_PASSWORD));
        assert!(!is_valid_purpose("login"));
        assert!(!is_valid_purpose(""));
    }

    #[test]
    fn purpose_labels_are_chinese() {
        assert_eq!(purpose_label(PURPOSE_REGISTER), "注册账号");
        assert_eq!(purpose_label(PURPOSE_RESET_PASSWORD), "重置密码");
        assert_eq!(purpose_label(PURPOSE_SET_PASSWORD), "设置登录密码");
        assert_eq!(purpose_label("other"), "验证身份");
    }

    #[test]
    fn resend_wait_counts_down_and_truncates() {
        let now = Utc
            .with_ymd_and_hms(2026, 1, 1, 12, 0, 0)
            .unwrap()
            .naive_utc();
        // 刚签发：完整等待 60 秒
        assert_eq!(too_frequent_wait(now, now, 60), 60);
        // 已过 30 秒：还需 30 秒
        assert_eq!(too_frequent_wait(now - Duration::seconds(30), now, 60), 30);
        // 已过 60 秒：可以再次发送
        assert_eq!(too_frequent_wait(now - Duration::seconds(60), now, 60), 0);
        // 不足 1 秒的剩余时间向零截断为 0
        assert_eq!(
            too_frequent_wait(now - Duration::milliseconds(59_500), now, 60),
            0
        );
        // 更早的记录不会产生负数
        assert!(too_frequent_wait(now - Duration::seconds(120), now, 60) < 0);
    }

    #[test]
    fn max_attempts_is_five() {
        assert_eq!(MAX_ATTEMPTS, 5);
    }
}
