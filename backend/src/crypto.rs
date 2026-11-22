//! 敏感字段的落库加密（Fernet）。
//!
//! 与 Python `server/db/crypto.py` 语义一致：
//! - `APP_SECRET_KEY` 缺失时降级为明文存储（带 `plain1:` 前缀）；
//! - 密文带 `enc1:` 前缀；
//! - 解密结果不得写回 ORM 实体，否则会把明文写回库。
//!
//! 密钥为 44 字符 urlsafe-base64 编码的 32 字节，**原样**使用，不做 KDF 派生。

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::Rng;
use thiserror::Error;

/// 生成 `secrets.token_urlsafe(n)` 等价 token（`n` 为随机字节数）。
pub fn random_token(bytes: usize) -> String {
    let mut buffer = vec![0u8; bytes];
    rand::rng().fill_bytes(&mut buffer);
    URL_SAFE_NO_PAD.encode(buffer)
}

/// 密文前缀。
pub const ENC_PREFIX: &str = "enc1:";
/// 明文降级前缀。
pub const PLAIN_PREFIX: &str = "plain1:";

/// 加解密失败。
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CryptoError {
    /// 密文存在但没有配置主密钥。
    #[error("密文存在但未配置 APP_SECRET_KEY，无法解密")]
    MissingKey,
    /// 密钥不匹配或密文损坏。
    #[error("解密失败：APP_SECRET_KEY 与密文不匹配")]
    DecryptFailed,
    /// 主密钥不是合法的 Fernet 密钥。
    #[error("APP_SECRET_KEY 不是合法的 Fernet 密钥（需 44 字符 urlsafe-base64 编码的 32 字节）")]
    InvalidKey,
}

/// 校验主密钥是否为合法的 Fernet 密钥。
pub fn validate_key(key: &str) -> Result<(), CryptoError> {
    if build_fernet(key).is_some() {
        Ok(())
    } else {
        Err(CryptoError::InvalidKey)
    }
}

/// 构造 Fernet 实例；密钥非法时返回 `None`。
fn build_fernet(key: &str) -> Option<fernet::Fernet> {
    fernet::Fernet::new(key)
}

/// 加密敏感字段。
///
/// `key` 为 `None`（未配置 `APP_SECRET_KEY`）时降级为带 `plain1:` 前缀的明文；
/// 空串保持为空（与 Python 实现一致，避免写入无意义的密文）。
///
/// 密钥格式非法时记录错误日志并同样降级为明文：正常流程下
/// [`crate::config::Config::from_env`] 已在启动时校验过密钥。
pub fn encrypt_secret(plain: &str, key: Option<&str>) -> String {
    match try_encrypt_secret(plain, key) {
        Ok(value) => value,
        Err(err) => {
            tracing::error!(error = %err, "敏感字段加密失败，降级为明文存储");
            format!("{PLAIN_PREFIX}{plain}")
        }
    }
}

/// 加密敏感字段，失败时返回错误（供需要显式失败的调用方使用）。
pub fn try_encrypt_secret(plain: &str, key: Option<&str>) -> Result<String, CryptoError> {
    if plain.is_empty() {
        return Ok(String::new());
    }
    let Some(key) = key else {
        return Ok(format!("{PLAIN_PREFIX}{plain}"));
    };
    let fernet = build_fernet(key).ok_or(CryptoError::InvalidKey)?;
    let token = fernet.encrypt(plain.as_bytes());
    Ok(format!("{ENC_PREFIX}{token}"))
}

/// 解密敏感字段。
///
/// - `enc1:` 前缀：必须有主密钥，否则报错；解密失败（密钥不匹配或密文损坏）报错；
/// - `plain1:` 前缀：去掉前缀返回明文；
/// - 其它：原样当作明文返回。
pub fn decrypt_secret(stored: &str, key: Option<&str>) -> Result<String, CryptoError> {
    if stored.is_empty() {
        return Ok(String::new());
    }
    if let Some(raw) = stored.strip_prefix(ENC_PREFIX) {
        let Some(key) = key else {
            return Err(CryptoError::MissingKey);
        };
        let fernet = build_fernet(key).ok_or(CryptoError::InvalidKey)?;
        let plain = fernet
            .decrypt(raw)
            .map_err(|_| CryptoError::DecryptFailed)?;
        String::from_utf8(plain).map_err(|_| CryptoError::DecryptFailed)
    } else if let Some(raw) = stored.strip_prefix(PLAIN_PREFIX) {
        Ok(raw.to_string())
    } else {
        Ok(stored.to_string())
    }
}

/// 是否为带 `enc1:` 前缀的密文。
pub fn is_encrypted(stored: &str) -> bool {
    stored.starts_with(ENC_PREFIX)
}

/// 界面回显用的掩码：保留首尾各 2 位。
pub fn mask_secret(value: &str) -> String {
    if value.is_empty() {
        return String::new();
    }
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= 8 {
        return "*".repeat(chars.len());
    }
    let head: String = chars[..2].iter().collect();
    let tail: String = chars[chars.len() - 2..].iter().collect();
    format!("{head}{}{tail}", "*".repeat(6))
}

#[cfg(test)]
mod tests {
    use super::*;

    // 由 Python `cryptography.fernet` 生成：Fernet(base64.urlsafe_b64encode(bytes(range(32))))
    const PY_KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    const PY_TOKEN: &str = "gAAAAABrAl8u3rbx89t5ksepnGbmqOyv4aIsVCeknGw1n4Hg8FZ2YUDrOCt-CJmdeQO4QuzpYPrgkiYkhBCL2wj626LmzA6CcCRqrb3XekMs_vYnGMJFW80=";
    const PY_PLAIN: &str = "qbotmessager-secret-probe";

    #[test]
    fn decrypts_python_generated_ciphertext() {
        // 跨语言互操作：Rust 必须能解开 Python cryptography.fernet 生成的密文。
        let stored = format!("{ENC_PREFIX}{PY_TOKEN}");
        assert_eq!(decrypt_secret(&stored, Some(PY_KEY)).unwrap(), PY_PLAIN);
    }

    #[test]
    fn round_trip_with_key() {
        let stored = encrypt_secret("s3cret", Some(PY_KEY));
        assert!(is_encrypted(&stored));
        assert_eq!(decrypt_secret(&stored, Some(PY_KEY)).unwrap(), "s3cret");
    }

    #[test]
    fn round_trip_without_key_is_plain_prefixed() {
        let stored = encrypt_secret("s3cret", None);
        assert_eq!(stored, format!("{PLAIN_PREFIX}s3cret"));
        assert!(!is_encrypted(&stored));
        assert_eq!(decrypt_secret(&stored, None).unwrap(), "s3cret");
    }

    #[test]
    fn empty_stays_empty() {
        assert_eq!(encrypt_secret("", Some(PY_KEY)), "");
        assert_eq!(decrypt_secret("", Some(PY_KEY)).unwrap(), "");
    }

    #[test]
    fn encrypted_without_key_is_an_error() {
        let stored = format!("{ENC_PREFIX}{PY_TOKEN}");
        assert_eq!(
            decrypt_secret(&stored, None).unwrap_err(),
            CryptoError::MissingKey
        );
    }

    #[test]
    fn wrong_key_is_an_error() {
        let stored = format!("{ENC_PREFIX}{PY_TOKEN}");
        let other_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        assert_eq!(
            decrypt_secret(&stored, Some(other_key)).unwrap_err(),
            CryptoError::DecryptFailed
        );
    }

    #[test]
    fn invalid_key_is_rejected() {
        assert_eq!(
            validate_key("not-a-key").unwrap_err(),
            CryptoError::InvalidKey
        );
        assert_eq!(
            try_encrypt_secret("x", Some("not-a-key")).unwrap_err(),
            CryptoError::InvalidKey
        );
    }

    #[test]
    fn plain_text_without_prefix_is_returned_as_is() {
        assert_eq!(
            decrypt_secret("legacy-plain", Some(PY_KEY)).unwrap(),
            "legacy-plain"
        );
    }

    #[test]
    fn mask_keeps_head_and_tail() {
        assert_eq!(mask_secret(""), "");
        assert_eq!(mask_secret("12345678"), "********");
        assert_eq!(mask_secret("123456789"), "12******89");
        assert_eq!(mask_secret("short"), "*****");
    }
}
