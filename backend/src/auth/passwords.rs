//! 密码哈希：PBKDF2-HMAC-SHA256。
//!
//! 格式：`pbkdf2_sha256$<rounds>$<base64(salt)>$<base64(digest)>`
//! - 默认 600000 轮，salt 16 字节，digest 32 字节；
//! - **标准 base64**（带 `=` 填充），不是 base64url；
//! - 校验用常量时间比较，轮数从哈希串里读取（兼容历史低轮数）。
//!
//! 邮箱验证码复用同一套哈希。
//!
//! PBKDF2 是 CPU 密集型（600k 轮约 0.15s），必须放 `spawn_blocking`，
//! 不能阻塞 actix worker 线程。

use std::sync::OnceLock;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use pbkdf2::pbkdf2_hmac;
use rand::Rng;
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::error::AppError;

/// 哈希算法标识。
pub const ALGORITHM: &str = "pbkdf2_sha256";
/// 默认迭代轮数。
pub const DEFAULT_ROUNDS: u32 = 600_000;
/// salt 字节数。
pub const SALT_LEN: usize = 16;
/// digest 字节数。
pub const DIGEST_LEN: usize = 32;

/// 生成密码哈希。
pub fn hash_password(password: &str) -> Result<String, AppError> {
    let salt = random_salt();
    Ok(hash_password_with(password, &salt, DEFAULT_ROUNDS))
}

/// 用给定 salt 与轮数生成密码哈希。
///
/// 固定 salt 的变体只用于测试与迁移（需要复现历史哈希）。
pub fn hash_password_with(password: &str, salt: &[u8], rounds: u32) -> String {
    let mut digest = [0u8; DIGEST_LEN];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, rounds, &mut digest);
    format!(
        "{ALGORITHM}${rounds}${}${}",
        STANDARD.encode(salt),
        STANDARD.encode(digest)
    )
}

/// 校验密码。
///
/// 哈希串格式非法（段数不对、算法不符、轮数非法、base64 损坏）时返回 `false`。
pub fn verify_password(password: &str, stored: &str) -> bool {
    if stored.is_empty() {
        return false;
    }
    let parts: Vec<&str> = stored.split('$').collect();
    if parts.len() != 4 {
        return false;
    }
    if parts[0] != ALGORITHM {
        return false;
    }
    let Ok(rounds) = parts[1].parse::<u32>() else {
        return false;
    };
    if rounds == 0 {
        return false;
    }
    let (Ok(salt), Ok(expected)) = (STANDARD.decode(parts[2]), STANDARD.decode(parts[3])) else {
        return false;
    };

    let mut digest = [0u8; DIGEST_LEN];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, rounds, &mut digest);
    digest.ct_eq(expected.as_slice()).into()
}

/// 生成密码哈希（在线程池中执行，不阻塞 actix worker 线程）。
pub async fn hash_password_async(password: &str) -> Result<String, AppError> {
    let owned = password.to_string();
    tokio::task::spawn_blocking(move || hash_password(&owned))
        .await
        .map_err(|err| AppError::internal(format!("密码哈希任务失败：{err}")))?
}

/// 校验密码（在线程池中执行，不阻塞 actix worker 线程）。
pub async fn verify_password_async(password: &str, stored: &str) -> bool {
    let (owned_password, owned_stored) = (password.to_string(), stored.to_string());
    tokio::task::spawn_blocking(move || verify_password(&owned_password, &owned_stored))
        .await
        .unwrap_or(false)
}

/// 账号不存在时消耗一次等价 PBKDF2 计算。
///
/// 否则「邮箱未注册」会明显快于「密码错误」，攻击者可用响应时间枚举已注册邮箱。
pub fn burn_password(password: &str) {
    let dummy = dummy_hash();
    let _ = verify_password(password, dummy);
}

/// 账号不存在时消耗一次等价 PBKDF2 计算（在线程池中执行）。
pub async fn burn_password_async(password: &str) {
    let owned = password.to_string();
    let _ = tokio::task::spawn_blocking(move || burn_password(&owned)).await;
}

/// 计时均衡用的哑元哈希，首次用到时才生成。
fn dummy_hash() -> &'static str {
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| {
        hash_password_with(
            "qbotmessager-timing-equalizer",
            &random_salt(),
            DEFAULT_ROUNDS,
        )
    })
}

/// 随机 salt。
fn random_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    rand::rng().fill_bytes(&mut salt);
    salt
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::Regex;

    #[test]
    fn round_trip() {
        let stored = hash_password("s3cret").unwrap();
        assert!(verify_password("s3cret", &stored));
        assert!(!verify_password("wrong", &stored));
    }

    #[test]
    fn wrong_password_fails() {
        let stored = hash_password("s3cret").unwrap();
        assert!(!verify_password("s3crett", &stored));
        assert!(!verify_password("", &stored));
    }

    #[test]
    fn rounds_are_read_from_stored_hash() {
        // 兼容历史低轮数：轮数写在哈希串里，校验时按其取值。
        let stored = hash_password_with("s3cret", b"0123456789abcdef", 1_000);
        assert!(stored.starts_with("pbkdf2_sha256$1000$"));
        assert!(verify_password("s3cret", &stored));
    }

    #[test]
    fn malformed_hash_returns_false() {
        assert!(!verify_password("s3cret", ""));
        assert!(!verify_password("s3cret", "not-a-hash"));
        assert!(!verify_password("s3cret", "pbkdf2_sha256$600000$c2FsdA"));
        assert!(!verify_password("s3cret", "bcrypt$600000$c2FsdA$ZGlnZXN0"));
        assert!(!verify_password(
            "s3cret",
            "pbkdf2_sha256$abc$c2FsdA$ZGlnZXN0"
        ));
        assert!(!verify_password(
            "s3cret",
            "pbkdf2_sha256$0$c2FsdA$ZGlnZXN0"
        ));
        assert!(!verify_password(
            "s3cret",
            "pbkdf2_sha256$600000$!!!$ZGlnZXN0"
        ));
    }

    #[test]
    fn stored_format_matches_python() {
        let stored = hash_password_with("s3cret", b"0123456789abcdef", 600_000);
        let re = Regex::new(r"^pbkdf2_sha256\$\d+\$[A-Za-z0-9+/]+=*\$[A-Za-z0-9+/]+=*$").unwrap();
        assert!(re.is_match(&stored), "{stored}");
        // 标准 base64（带填充），不是 base64url
        let salt_b64 = stored.split('$').nth(2).unwrap();
        let digest_b64 = stored.split('$').nth(3).unwrap();
        assert!(!salt_b64.contains('-') && !salt_b64.contains('_'));
        assert!(!digest_b64.contains('-') && !digest_b64.contains('_'));
        // salt 16 字节 -> 24 字符 base64（含 2 个 '=' 填充）
        assert_eq!(salt_b64.len(), 24);
        // digest 32 字节 -> 44 字符 base64（含 1 个 '=' 填充）
        assert_eq!(digest_b64.len(), 44);
    }

    #[test]
    fn different_salts_produce_different_hashes() {
        let first = hash_password("s3cret").unwrap();
        let second = hash_password("s3cret").unwrap();
        assert_ne!(first, second);
        assert!(verify_password("s3cret", &first));
        assert!(verify_password("s3cret", &second));
    }

    #[tokio::test]
    async fn async_variants_match_sync() {
        let stored = hash_password_async("s3cret").await.unwrap();
        assert!(verify_password_async("s3cret", &stored).await);
        assert!(!verify_password_async("wrong", &stored).await);
    }

    #[test]
    fn burn_password_does_not_panic() {
        burn_password("s3cret");
    }
}
