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
    /// 缺少加密主密钥，且未显式允许明文存储。
    #[error(
        "缺少 APP_SECRET_KEY：敏感字段无法加密。请设置 APP_SECRET_KEY；仅本地调试可显式设置 ALLOW_PLAINTEXT_SECRETS=true"
    )]
    MissingSecretKey,
}

/// 过期数据保留策略；天数为 0 表示关闭该表的清理。
#[derive(Debug, Clone, Copy)]
pub struct RetentionPolicy {
    /// 已过期会话保留天数。
    pub sessions_days: u32,
    /// 邮箱验证码保留天数。
    pub email_codes_days: u32,
    /// 发码守卫行保留天数。
    pub email_guards_days: u32,
    /// 管理审计日志保留天数。
    pub audit_days: u32,
    /// 推送日志保留天数。
    pub push_logs_days: u32,
    /// 推送日志内容预览保留天数。
    pub push_preview_days: u32,
    /// 清理任务执行间隔（小时）。
    pub interval_hours: u32,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            sessions_days: 30,
            email_codes_days: 7,
            email_guards_days: 7,
            audit_days: 180,
            push_logs_days: 90,
            push_preview_days: 7,
            interval_hours: 24,
        }
    }
}

impl RetentionPolicy {
    /// 从环境变量装载；缺省值见 [`Default`]。
    fn from_env() -> Result<Self, ConfigError> {
        let defaults = Self::default();
        Ok(Self {
            sessions_days: parse_retention_days("RETENTION_SESSIONS_DAYS", defaults.sessions_days)?,
            email_codes_days: parse_retention_days(
                "RETENTION_EMAIL_CODES_DAYS",
                defaults.email_codes_days,
            )?,
            email_guards_days: parse_retention_days(
                "RETENTION_EMAIL_GUARDS_DAYS",
                defaults.email_guards_days,
            )?,
            audit_days: parse_retention_days("RETENTION_AUDIT_DAYS", defaults.audit_days)?,
            push_logs_days: parse_retention_days(
                "RETENTION_PUSH_LOGS_DAYS",
                defaults.push_logs_days,
            )?,
            push_preview_days: parse_retention_days(
                "RETENTION_PUSH_PREVIEW_DAYS",
                defaults.push_preview_days,
            )?,
            interval_hours: parse_retention_hours(
                "RETENTION_INTERVAL_HOURS",
                defaults.interval_hours,
            )?,
        })
    }

    /// 是否有任何清理项开启。
    pub fn enabled(&self) -> bool {
        self.sessions_days > 0
            || self.email_codes_days > 0
            || self.email_guards_days > 0
            || self.audit_days > 0
            || self.push_logs_days > 0
            || self.push_preview_days > 0
    }
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
    /// 推送队列总积压上限。
    pub push_queue_max: usize,
    /// 单个用户可占用的推送队列积压上限。
    pub push_queue_max_per_user: usize,
    /// 过期数据保留策略。
    pub retention: RetentionPolicy,
    /// 是否信任 `X-Forwarded-For` 最右一跳。
    pub trust_proxy: bool,
    /// 前端静态资源目录。
    pub static_dir: PathBuf,
}

impl Config {
    /// 从环境变量装载配置。
    ///
    /// `.env` 可选：存在则加载，读取失败不报错（缺少 `.env` 属于正常情况）。
    /// `MYSQL_URL` 与 `APP_SECRET_KEY` 均缺失时报错；仅当显式设置
    /// `ALLOW_PLAINTEXT_SECRETS=true` 时才允许不带主密钥启动（敏感字段降级明文）。
    pub fn from_env() -> Result<Self, ConfigError> {
        // .env 可选；读取失败（不存在或格式错误）都不阻断启动。
        let _ = dotenvy::dotenv();

        let mysql_url = match env::var("MYSQL_URL") {
            Ok(value) if !value.trim().is_empty() => value.trim().to_string(),
            _ => return Err(ConfigError::Missing("MYSQL_URL")),
        };

        let allow_plaintext = parse_bool_env("ALLOW_PLAINTEXT_SECRETS", false)?;
        let app_secret_key =
            resolve_app_secret_key(env::var("APP_SECRET_KEY").ok().as_deref(), allow_plaintext)?;

        Ok(Self {
            mysql_url,
            app_secret_key,
            app_name: env_or("APP_NAME", DEFAULT_APP_NAME),
            cookie_name: env_or("COOKIE_NAME", DEFAULT_COOKIE_NAME),
            bootstrap_admin_email: env_or("BOOTSTRAP_ADMIN_EMAIL", ""),
            bootstrap_admin_password: env_or("BOOTSTRAP_ADMIN_PASSWORD", ""),
            qq_appid: env_or("QQ_APPID", ""),
            qq_app_secret: env_or("QQ_APP_SECRET", ""),
            openids: {
                let openids = load_openids(env::var("OPENID").ok().as_deref());
                if let Some(invalid) = openids
                    .iter()
                    .find(|openid| !crate::services::qq::is_valid_target(openid))
                {
                    return Err(ConfigError::Invalid(
                        "OPENID",
                        format!("推送目标只能包含字母、数字、下划线和连字符：{invalid}"),
                    ));
                }
                openids
            },
            qq_allowed_hosts: split_list(&env_or("QQ_ALLOWED_HOSTS", DEFAULT_QQ_ALLOWED_HOSTS)),
            db_pool_size: parse_env("DB_POOL_SIZE", 10)?,
            db_max_overflow: parse_env("DB_MAX_OVERFLOW", 20)?,
            db_pool_timeout: parse_env("DB_POOL_TIMEOUT", 10)?,
            push_queue_max: parse_env("PUSH_QUEUE_MAX", 200)?,
            push_queue_max_per_user: parse_env(
                "PUSH_QUEUE_MAX_PER_USER",
                crate::services::queue::DEFAULT_MAX_PENDING_PER_USER,
            )?,
            retention: RetentionPolicy::from_env()?,
            trust_proxy: parse_bool_env("TRUST_PROXY", false)?,
            static_dir: PathBuf::from(env_or("STATIC_DIR", DEFAULT_STATIC_DIR)),
        })
    }
}

/// 解析主密钥：缺省时默认拒绝启动，只有显式允许才降级明文。
fn resolve_app_secret_key(
    raw: Option<&str>,
    allow_plaintext: bool,
) -> Result<Option<String>, ConfigError> {
    match raw.map(str::trim).filter(|value| !value.is_empty()) {
        Some(key) => {
            crate::crypto::validate_key(key)?;
            Ok(Some(key.to_string()))
        }
        None if allow_plaintext => {
            tracing::warn!(
                "ALLOW_PLAINTEXT_SECRETS=true：未配置 APP_SECRET_KEY，敏感字段将降级为明文存储"
            );
            Ok(None)
        }
        None => Err(ConfigError::MissingSecretKey),
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

/// 读取保留天数：最多 100 年，避免极端值在日期运算中溢出。
fn parse_retention_days(key: &'static str, default: u32) -> Result<u32, ConfigError> {
    let value = parse_env(key, default)?;
    if value > 36_500 {
        return Err(ConfigError::Invalid(key, "最多 36500 天".to_string()));
    }
    Ok(value)
}

/// 读取清理间隔小时数：最多一年。
fn parse_retention_hours(key: &'static str, default: u32) -> Result<u32, ConfigError> {
    let value = parse_env(key, default)?;
    if value == 0 || value > 8_760 {
        return Err(ConfigError::Invalid(
            key,
            "取值范围 1~8760 小时".to_string(),
        ));
    }
    Ok(value)
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

    fn fernet_key(seed: u8) -> String {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE.encode([seed; 32])
    }

    #[test]
    fn missing_secret_key_fails_closed_by_default() {
        assert!(matches!(
            resolve_app_secret_key(None, false),
            Err(ConfigError::MissingSecretKey)
        ));
        assert!(matches!(
            resolve_app_secret_key(Some("   "), false),
            Err(ConfigError::MissingSecretKey)
        ));
    }

    #[test]
    fn missing_secret_key_allowed_only_when_opted_in() {
        assert_eq!(resolve_app_secret_key(None, true).unwrap(), None);
        assert_eq!(resolve_app_secret_key(Some(""), true).unwrap(), None);
    }

    #[test]
    fn secret_key_is_trimmed_and_validated() {
        let key = fernet_key(0x11);
        assert_eq!(
            resolve_app_secret_key(Some(&format!("  {key}  ")), false).unwrap(),
            Some(key)
        );
        assert!(matches!(
            resolve_app_secret_key(Some("not-a-key"), false),
            Err(ConfigError::Crypto(crate::crypto::CryptoError::InvalidKey))
        ));
    }
}
