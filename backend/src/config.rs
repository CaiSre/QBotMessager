//! 运行配置：环境变量 + 可选 `.env`。
//!
//! 只包含「仅来自环境变量」的项；
//! 其余运行期配置放在数据库 `system_settings` 表里，由运行时设置服务读取。

use std::env;
use std::path::PathBuf;

use thiserror::Error;

/// 静态资源目录默认值。
pub const DEFAULT_STATIC_DIR: &str = "./web/out";
/// 默认应用名。
pub const DEFAULT_APP_NAME: &str = "QBotMessager";
/// 默认会话 Cookie 名。
pub const DEFAULT_COOKIE_NAME: &str = "sid";
/// 默认允许的 QQ 接口主机白名单。
pub const DEFAULT_QQ_ALLOWED_HOSTS: &str = "api.bot.qq.com";

/// 配置装载失败。
#[derive(Debug, Error)]
pub enum ConfigError {
    /// 缺少必需的环境变量。
    #[error("缺少必需的环境变量 {0}")]
    Missing(&'static str),
    /// 环境变量的值非法。
    #[error("环境变量 {0} 的值非法：{1}")]
    Invalid(&'static str, String),
    /// APP_SECRET_KEY 不是合法的 Fernet 密钥。
    #[error(transparent)]
    Crypto(#[from] crate::crypto::CryptoError),
}

/// 启动配置。
#[derive(Debug, Clone)]
pub struct Config {
    /// MySQL 连接串，必填。
    pub mysql_url: String,
    /// Fernet 主密钥；`None` 表示未配置（敏感字段降级为明文）。
    pub app_secret_key: Option<String>,
    /// 应用名。
    pub app_name: String,
    /// 会话 Cookie 名。
    pub cookie_name: String,
    /// 引导用的超管邮箱（与密码同时非空才创建）。
    pub bootstrap_admin_email: String,
    /// 引导用的超管密码。
    pub bootstrap_admin_password: String,
    /// QQ 机器人 AppID（首启导入用）。
    pub qq_appid: String,
    /// QQ 机器人 AppSecret（首启导入用）。
    pub qq_app_secret: String,
    /// 首启导入的默认推送目标 openid 列表。
    pub openids: Vec<String>,
    /// 允许的 QQ 接口主机白名单。
    pub qq_allowed_hosts: Vec<String>,
    /// 数据库连接池大小。
    pub db_pool_size: u32,
    /// 数据库连接池溢出上限。
    pub db_max_overflow: u32,
    /// 数据库连接池等待超时（秒）。
    pub db_pool_timeout: u32,
    /// 推送队列积压上限。
    pub push_queue_max: usize,
    /// 是否信任 `X-Forwarded-For` 最右一跳。
    pub trust_proxy: bool,
    /// 前端静态资源目录。
    pub static_dir: PathBuf,
}

impl Config {
    /// 从环境变量装载配置。
    ///
    /// `.env` 可选：存在则加载，读取失败不报错（缺少 `.env` 属于正常情况）。
    /// `MYSQL_URL` 缺失时返回错误；`APP_SECRET_KEY` 缺失时只告警，
    /// 敏感字段将降级为明文存储。
    pub fn from_env() -> Result<Self, ConfigError> {
        // .env 可选；读取失败（不存在或格式错误）都不阻断启动。
        let _ = dotenvy::dotenv();

        let mysql_url = match env::var("MYSQL_URL") {
            Ok(value) if !value.trim().is_empty() => value.trim().to_string(),
            _ => return Err(ConfigError::Missing("MYSQL_URL")),
        };

        let app_secret_key = match env::var("APP_SECRET_KEY") {
            Ok(value) if !value.trim().is_empty() => Some(value.trim().to_string()),
            _ => {
                tracing::warn!("未配置 APP_SECRET_KEY：敏感字段将降级为明文存储，生产环境务必设置");
                None
            }
        };
        if let Some(key) = app_secret_key.as_deref() {
            crate::crypto::validate_key(key)?;
        }

        Ok(Self {
            mysql_url,
            app_secret_key,
            app_name: env_or("APP_NAME", DEFAULT_APP_NAME),
            cookie_name: env_or("COOKIE_NAME", DEFAULT_COOKIE_NAME),
            bootstrap_admin_email: env_or("BOOTSTRAP_ADMIN_EMAIL", ""),
            bootstrap_admin_password: env_or("BOOTSTRAP_ADMIN_PASSWORD", ""),
            qq_appid: env_or("QQ_APPID", ""),
            qq_app_secret: env_or("QQ_APP_SECRET", ""),
            openids: load_openids(env::var("OPENID").ok().as_deref()),
            qq_allowed_hosts: split_list(&env_or("QQ_ALLOWED_HOSTS", DEFAULT_QQ_ALLOWED_HOSTS)),
            db_pool_size: parse_env("DB_POOL_SIZE", 10)?,
            db_max_overflow: parse_env("DB_MAX_OVERFLOW", 20)?,
            db_pool_timeout: parse_env("DB_POOL_TIMEOUT", 10)?,
            push_queue_max: parse_env("PUSH_QUEUE_MAX", 200)?,
            trust_proxy: parse_bool_env("TRUST_PROXY", false)?,
            static_dir: PathBuf::from(env_or("STATIC_DIR", DEFAULT_STATIC_DIR)),
        })
    }
}

/// 读取环境变量，缺失或为空时用默认值。
fn env_or(key: &str, default: &str) -> String {
    match env::var(key) {
        Ok(value) if !value.trim().is_empty() => value.trim().to_string(),
        _ => default.to_string(),
    }
}

/// 读取整数环境变量，缺失时用默认值；值非法时报错（不静默兜底）。
fn parse_env<T>(key: &'static str, default: T) -> Result<T, ConfigError>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    match env::var(key) {
        Ok(value) if !value.trim().is_empty() => value
            .trim()
            .parse::<T>()
            .map_err(|err| ConfigError::Invalid(key, format!("{value}（{err}）"))),
        _ => Ok(default),
    }
}

/// 读取布尔环境变量，缺失时用默认值。
///
/// 接受 `1/true/yes/on` 与 `0/false/no/off`（大小写不敏感），其余取值报错。
fn parse_bool_env(key: &'static str, default: bool) -> Result<bool, ConfigError> {
    match env::var(key) {
        Ok(value) => match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            other => Err(ConfigError::Invalid(
                key,
                format!("{other}（只接受 1/0、true/false、yes/no、on/off）"),
            )),
        },
        Err(_) => Ok(default),
    }
}

/// 按逗号分隔并去掉空白项。
fn split_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect()
}

/// 从 `OPENID` 读取 openid 列表：JSON 数组（字符串元素）或逗号分隔单值。
pub fn load_openids(raw: Option<&str>) -> Vec<String> {
    let Some(raw) = raw else {
        return Vec::new();
    };
    let raw = raw.trim();
    if raw.is_empty() {
        return Vec::new();
    }

    if raw.starts_with('[') && raw.ends_with(']') {
        if let Ok(serde_json::Value::Array(items)) = serde_json::from_str::<serde_json::Value>(raw)
        {
            return items
                .into_iter()
                .filter_map(|item| match item {
                    serde_json::Value::String(text) if !text.is_empty() => Some(text),
                    _ => None,
                })
                .collect();
        }
        // 形如数组的输入解析失败时按逗号分隔处理，保留原始文本提示用户纠正格式。
        return split_list(raw);
    }

    if raw.contains(',') {
        return split_list(raw);
    }
    vec![raw.to_string()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openids_accept_json_array() {
        assert_eq!(
            load_openids(Some(r#"["openid1", "openid2"]"#)),
            vec!["openid1", "openid2"]
        );
    }

    #[test]
    fn openids_accept_comma_separated() {
        assert_eq!(
            load_openids(Some("openid1, openid2")),
            vec!["openid1", "openid2"]
        );
    }

    #[test]
    fn openids_invalid_array_falls_back_to_split() {
        assert_eq!(
            load_openids(Some("openid1, openid2]")),
            vec!["openid1", "openid2]"]
        );
    }

    #[test]
    fn openids_accept_single_value() {
        assert_eq!(load_openids(Some("openid1")), vec!["openid1"]);
    }

    #[test]
    fn openids_empty_variants() {
        assert!(load_openids(None).is_empty());
        assert!(load_openids(Some("")).is_empty());
        assert!(load_openids(Some("   ")).is_empty());
        assert!(load_openids(Some("[]")).is_empty());
    }

    #[test]
    fn openids_drop_empty_items() {
        assert_eq!(load_openids(Some(r#"["a", "", "b"]"#)), vec!["a", "b"]);
    }
}
