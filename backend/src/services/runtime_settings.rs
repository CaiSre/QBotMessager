//! 系统设置：非敏感运行配置持久化到数据库，并通过内存缓存即时生效。
//!
//! 运行期系统设置（库表持久化 + 环境变量首启导入）：
//! - 30 项设置以 `system_settings` 表为准；
//! - 启动时若库中缺少某项，而同名环境变量的值与默认值不同，则**一次性**写入库
//!   （来源标记 `environment`），此后运行期只读数据库；
//! - 敏感项（`smtp_password`）用 Fernet 密文入库，缓存里保留明文供服务使用；
//! - 管理端修改后调用 [`RuntimeSettings::validate`] → [`RuntimeSettings::persist`] →
//!   [`RuntimeSettings::apply`]，再调用 [`RuntimeSettings::apply_side_effects`]
//!   让频控参数立即采用新值。

use std::collections::BTreeMap;
use std::env;
use std::time::Duration;

use chrono::Utc;
use serde::Serialize;
use serde_json::Value;
use sqlx::MySqlPool;

use crate::crypto::{decrypt_secret, encrypt_secret};
use crate::error::AppError;
use crate::services::throttle::{AttemptLimiter, LimiterRegistry};

/// 站点与访问。
pub const GROUP_SITE: &str = "站点与访问";
/// 注册与会话。
pub const GROUP_ACCOUNT: &str = "注册与会话";
/// 登录保护。
pub const GROUP_LOGIN: &str = "登录保护";
/// 邮件服务。
pub const GROUP_MAIL: &str = "邮件服务";
/// QQ 推送。
pub const GROUP_QQ: &str = "QQ 推送";

/// 设置值类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SettingKind {
    /// 布尔。
    Bool,
    /// 整数。
    Int,
    /// 浮点数。
    Float,
    /// 文本。
    Str,
    /// 枚举文本。
    Select,
}

/// 设置项默认值（可直接放进静态目录）。
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SettingDefault {
    /// 布尔默认值。
    Bool(bool),
    /// 整数默认值。
    Int(i64),
    /// 浮点数默认值。
    Float(f64),
    /// 文本默认值。
    Str(&'static str),
}

impl SettingDefault {
    /// 转成运行期值。
    pub fn to_value(self) -> SettingValue {
        match self {
            Self::Bool(value) => SettingValue::Bool(value),
            Self::Int(value) => SettingValue::Int(value),
            Self::Float(value) => SettingValue::Float(value),
            Self::Str(value) => SettingValue::Str(value.to_string()),
        }
    }

    /// 转成 JSON 表示。
    pub fn to_json(self) -> Value {
        self.to_value().to_json()
    }
}

/// 运行期设置值。
#[derive(Debug, Clone, PartialEq)]
pub enum SettingValue {
    /// 布尔。
    Bool(bool),
    /// 整数。
    Int(i64),
    /// 浮点数。
    Float(f64),
    /// 文本。
    Str(String),
}

impl SettingValue {
    /// 取布尔值；非布尔返回 `false`。
    pub fn as_bool(&self) -> bool {
        matches!(self, Self::Bool(value) if *value)
    }

    /// 取整数；非整数返回 0。
    pub fn as_i64(&self) -> i64 {
        match self {
            Self::Bool(value) => i64::from(*value),
            Self::Int(value) => *value,
            Self::Float(value) => *value as i64,
            Self::Str(_) => 0,
        }
    }

    /// 取浮点数；非数字返回 0.0。
    pub fn as_f64(&self) -> f64 {
        match self {
            Self::Bool(value) => {
                if *value {
                    1.0
                } else {
                    0.0
                }
            }
            Self::Int(value) => *value as f64,
            Self::Float(value) => *value,
            Self::Str(_) => 0.0,
        }
    }

    /// 取文本；非文本返回空串。
    pub fn as_str(&self) -> &str {
        match self {
            Self::Str(value) => value,
            _ => "",
        }
    }

    /// 转成 JSON 表示。
    pub fn to_json(&self) -> Value {
        match self {
            Self::Bool(value) => Value::Bool(*value),
            Self::Int(value) => Value::Number((*value).into()),
            Self::Float(value) => serde_json::Number::from_f64(*value)
                .map(Value::Number)
                .unwrap_or(Value::Null),
            Self::Str(value) => Value::String(value.clone()),
        }
    }
}

/// 设置项来源。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SettingSource {
    /// 使用内置默认值。
    Default,
    /// 由环境变量一次性导入。
    Environment,
    /// 来自数据库。
    Database,
}

impl SettingSource {
    /// 来源标识字符串。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Environment => "environment",
            Self::Database => "database",
        }
    }
}

/// 单个设置项的声明。
#[derive(Debug, Clone, Copy)]
pub struct SettingSpec {
    /// 设置键（也是环境变量名的大写形式）。
    pub key: &'static str,
    /// 展示名。
    pub label: &'static str,
    /// 分组。
    pub group: &'static str,
    /// 类型。
    pub kind: SettingKind,
    /// 默认值。
    pub default: SettingDefault,
    /// 说明。
    pub description: &'static str,
    /// 数值下限。
    pub minimum: Option<f64>,
    /// 数值上限。
    pub maximum: Option<f64>,
    /// 枚举取值。
    pub options: &'static [&'static str],
    /// 文本最大长度。
    pub max_length: usize,
    /// 是否敏感项（以密文入库）。
    pub secret: bool,
}

/// 全部设置项，顺序即管理页展示顺序。
pub static CATALOG: [SettingSpec; 30] = [
    SettingSpec {
        key: "public_base_url",
        label: "对外访问地址",
        group: GROUP_SITE,
        kind: SettingKind::Str,
        default: SettingDefault::Str(""),
        description: "用于生成 Webhook 地址与 OAuth 回调；留空时按请求头推导",
        minimum: None,
        maximum: None,
        options: &[],
        max_length: 512,
        secret: false,
    },
    SettingSpec {
        key: "timezone",
        label: "统计时区",
        group: GROUP_SITE,
        kind: SettingKind::Str,
        default: SettingDefault::Str(""),
        description: "统计按该时区切分日期，例如 Asia/Shanghai；留空取容器 TZ 或本机时区",
        minimum: None,
        maximum: None,
        options: &[],
        max_length: 64,
        secret: false,
    },
    SettingSpec {
        key: "log_level",
        label: "日志级别",
        group: GROUP_SITE,
        kind: SettingKind::Select,
        default: SettingDefault::Str("INFO"),
        description: "保存后立即调整后端日志输出",
        minimum: None,
        maximum: None,
        options: &["DEBUG", "INFO", "WARNING", "ERROR"],
        max_length: 512,
        secret: false,
    },
    SettingSpec {
        key: "max_body_bytes",
        label: "请求体上限",
        group: GROUP_SITE,
        kind: SettingKind::Int,
        default: SettingDefault::Int(65536),
        description: "Webhook 单次请求体上限（字节）",
        minimum: Some(1024.0),
        maximum: Some(10_485_760.0),
        options: &[],
        max_length: 512,
        secret: false,
    },
    SettingSpec {
        key: "github_max_body_bytes",
        label: "GitHub 请求体上限",
        group: GROUP_SITE,
        kind: SettingKind::Int,
        default: SettingDefault::Int(2_097_152),
        description: "GitHub Webhook 单次请求体上限（字节）；GitHub 自身的负载上限为 25MB",
        minimum: Some(1024.0),
        maximum: Some(26_214_400.0),
        options: &[],
        max_length: 512,
        secret: false,
    },
    SettingSpec {
        key: "webhook_allow_query_token",
        label: "允许 URL 传凭据",
        group: GROUP_SITE,
        kind: SettingKind::Bool,
        default: SettingDefault::Bool(false),
        description: "允许用 ?token= 传 Webhook 凭据；查询参数会落入访问日志，默认关闭",
        minimum: None,
        maximum: None,
        options: &[],
        max_length: 512,
        secret: false,
    },
    SettingSpec {
        key: "register_enabled",
        label: "允许邀请注册",
        group: GROUP_ACCOUNT,
        kind: SettingKind::Bool,
        default: SettingDefault::Bool(false),
        description: "开启后持有邀请码的用户才能注册",
        minimum: None,
        maximum: None,
        options: &[],
        max_length: 512,
        secret: false,
    },
    SettingSpec {
        key: "session_ttl_hours",
        label: "会话有效期",
        group: GROUP_ACCOUNT,
        kind: SettingKind::Int,
        default: SettingDefault::Int(72),
        description: "登录会话有效小时数，对新登录生效",
        minimum: Some(1.0),
        maximum: Some(8760.0),
        options: &[],
        max_length: 512,
        secret: false,
    },
    SettingSpec {
        key: "cookie_secure",
        label: "Cookie 仅限 HTTPS",
        group: GROUP_ACCOUNT,
        kind: SettingKind::Bool,
        default: SettingDefault::Bool(false),
        description: "对外访问地址为 https 时会自动开启",
        minimum: None,
        maximum: None,
        options: &[],
        max_length: 512,
        secret: false,
    },
    SettingSpec {
        key: "rp_id",
        label: "通行密钥 RP ID",
        group: GROUP_ACCOUNT,
        kind: SettingKind::Str,
        default: SettingDefault::Str(""),
        description: "WebAuthn 依赖方标识；留空时取对外地址的主机名",
        minimum: None,
        maximum: None,
        options: &[],
        max_length: 255,
        secret: false,
    },
    SettingSpec {
        key: "rp_name",
        label: "通行密钥显示名称",
        group: GROUP_ACCOUNT,
        kind: SettingKind::Str,
        default: SettingDefault::Str("QBotMessager"),
        description: "创建通行密钥时展示给用户的名称",
        minimum: None,
        maximum: None,
        options: &[],
        max_length: 128,
        secret: false,
    },
    SettingSpec {
        key: "login_max_failures",
        label: "单账号失败上限",
        group: GROUP_LOGIN,
        kind: SettingKind::Int,
        default: SettingDefault::Int(5),
        description: "同一（IP, 账号）在统计窗口内的失败次数上限",
        minimum: Some(1.0),
        maximum: Some(1000.0),
        options: &[],
        max_length: 512,
        secret: false,
    },
    SettingSpec {
        key: "login_ip_max_failures",
        label: "单 IP 失败上限",
        group: GROUP_LOGIN,
        kind: SettingKind::Int,
        default: SettingDefault::Int(30),
        description: "同一 IP 在统计窗口内的失败次数上限",
        minimum: Some(1.0),
        maximum: Some(10_000.0),
        options: &[],
        max_length: 512,
        secret: false,
    },
    SettingSpec {
        key: "login_window_seconds",
        label: "统计窗口",
        group: GROUP_LOGIN,
        kind: SettingKind::Int,
        default: SettingDefault::Int(900),
        description: "登录失败计数的统计窗口（秒）",
        minimum: Some(60.0),
        maximum: Some(86_400.0),
        options: &[],
        max_length: 512,
        secret: false,
    },
    SettingSpec {
        key: "smtp_host",
        label: "SMTP 服务器",
        group: GROUP_MAIL,
        kind: SettingKind::Str,
        default: SettingDefault::Str(""),
        description: "邮件服务器地址，例如 smtp.example.com；留空则停用邮件验证码",
        minimum: None,
        maximum: None,
        options: &[],
        max_length: 255,
        secret: false,
    },
    SettingSpec {
        key: "smtp_port",
        label: "SMTP 端口",
        group: GROUP_MAIL,
        kind: SettingKind::Int,
        default: SettingDefault::Int(587),
        description: "常用端口：587（STARTTLS）、465（SSL）、25（不加密）",
        minimum: Some(1.0),
        maximum: Some(65_535.0),
        options: &[],
        max_length: 512,
        secret: false,
    },
    SettingSpec {
        key: "smtp_security",
        label: "连接方式",
        group: GROUP_MAIL,
        kind: SettingKind::Select,
        default: SettingDefault::Str("starttls"),
        description: "starttls 为 STARTTLS 升级，ssl 为直接 TLS，none 为明文（不推荐）",
        minimum: None,
        maximum: None,
        options: &["starttls", "ssl", "none"],
        max_length: 512,
        secret: false,
    },
    SettingSpec {
        key: "smtp_username",
        label: "SMTP 用户名",
        group: GROUP_MAIL,
        kind: SettingKind::Str,
        default: SettingDefault::Str(""),
        description: "登录邮件服务器的账号；留空则不登录",
        minimum: None,
        maximum: None,
        options: &[],
        max_length: 255,
        secret: false,
    },
    SettingSpec {
        key: "smtp_password",
        label: "SMTP 密码",
        group: GROUP_MAIL,
        kind: SettingKind::Str,
        default: SettingDefault::Str(""),
        description: "登录邮件服务器的密码或授权码；加密入库，留空保持不变",
        minimum: None,
        maximum: None,
        options: &[],
        max_length: 512,
        secret: true,
    },
    SettingSpec {
        key: "smtp_from",
        label: "发件人地址",
        group: GROUP_MAIL,
        kind: SettingKind::Str,
        default: SettingDefault::Str(""),
        description: "验证码邮件的发件人；留空时使用 SMTP 用户名",
        minimum: None,
        maximum: None,
        options: &[],
        max_length: 255,
        secret: false,
    },
    SettingSpec {
        key: "smtp_timeout",
        label: "SMTP 超时",
        group: GROUP_MAIL,
        kind: SettingKind::Int,
        default: SettingDefault::Int(15),
        description: "连接与发送的超时秒数",
        minimum: Some(1.0),
        maximum: Some(120.0),
        options: &[],
        max_length: 512,
        secret: false,
    },
    SettingSpec {
        key: "email_code_ttl_minutes",
        label: "验证码有效期",
        group: GROUP_MAIL,
        kind: SettingKind::Int,
        default: SettingDefault::Int(10),
        description: "邮箱验证码的有效分钟数",
        minimum: Some(1.0),
        maximum: Some(60.0),
        options: &[],
        max_length: 512,
        secret: false,
    },
    SettingSpec {
        key: "email_code_resend_seconds",
        label: "重发间隔",
        group: GROUP_MAIL,
        kind: SettingKind::Int,
        default: SettingDefault::Int(60),
        description: "同一邮箱同一用途两次发码的最短间隔（秒）",
        minimum: Some(30.0),
        maximum: Some(600.0),
        options: &[],
        max_length: 512,
        secret: false,
    },
    SettingSpec {
        key: "email_code_hourly_limit",
        label: "每小时发码上限",
        group: GROUP_MAIL,
        kind: SettingKind::Int,
        default: SettingDefault::Int(5),
        description: "同一邮箱同一用途每小时最多发送次数",
        minimum: Some(1.0),
        maximum: Some(50.0),
        options: &[],
        max_length: 512,
        secret: false,
    },
    SettingSpec {
        key: "qq_host",
        label: "QQ API 域名",
        group: GROUP_QQ,
        kind: SettingKind::Str,
        default: SettingDefault::Str("https://api.bot.qq.com"),
        description: "机器人未单独配置域名时使用的默认地址",
        minimum: None,
        maximum: None,
        options: &[],
        max_length: 255,
        secret: false,
    },
    SettingSpec {
        key: "qq_qps",
        label: "每秒上限",
        group: GROUP_QQ,
        kind: SettingKind::Int,
        default: SettingDefault::Int(5),
        description: "单个机器人每秒最多发送数",
        minimum: Some(1.0),
        maximum: Some(1000.0),
        options: &[],
        max_length: 512,
        secret: false,
    },
    SettingSpec {
        key: "qq_qpm",
        label: "每分钟上限",
        group: GROUP_QQ,
        kind: SettingKind::Int,
        default: SettingDefault::Int(30),
        description: "单个机器人每分钟最多发送数",
        minimum: Some(1.0),
        maximum: Some(100_000.0),
        options: &[],
        max_length: 512,
        secret: false,
    },
    SettingSpec {
        key: "qq_min_interval",
        label: "最小发送间隔",
        group: GROUP_QQ,
        kind: SettingKind::Float,
        default: SettingDefault::Float(0.21),
        description: "两次发送之间的最小间隔（秒）",
        minimum: Some(0.0),
        maximum: Some(60.0),
        options: &[],
        max_length: 512,
        secret: false,
    },
    SettingSpec {
        key: "markdown_max_len",
        label: "Markdown 长度上限",
        group: GROUP_QQ,
        kind: SettingKind::Int,
        default: SettingDefault::Int(4000),
        description: "Markdown 类型消息的长度上限",
        minimum: Some(1.0),
        maximum: Some(100_000.0),
        options: &[],
        max_length: 512,
        secret: false,
    },
    SettingSpec {
        key: "text_max_len",
        label: "文本长度上限",
        group: GROUP_QQ,
        kind: SettingKind::Int,
        default: SettingDefault::Int(2000),
        description: "纯文本类型消息的长度上限",
        minimum: Some(1.0),
        maximum: Some(100_000.0),
        options: &[],
        max_length: 512,
        secret: false,
    },
];

/// 按 key 查找设置声明。
pub fn spec(key: &str) -> Option<&'static SettingSpec> {
    CATALOG.iter().find(|item| item.key == key)
}

/// 全部设置 key（顺序与 [`CATALOG`] 一致）。
pub fn keys() -> impl Iterator<Item = &'static str> {
    CATALOG.iter().map(|item| item.key)
}

/// 管理端设置项视图。
#[derive(Debug, Clone, Serialize)]
pub struct SettingItem {
    /// 键。
    pub key: String,
    /// 展示名。
    pub label: String,
    /// 说明。
    pub description: String,
    /// 类型。
    pub kind: SettingKind,
    /// 当前值（敏感项固定为空串）。
    pub value: Value,
    /// 默认值。
    pub default: Value,
    /// 数值下限。
    pub minimum: Option<f64>,
    /// 数值上限。
    pub maximum: Option<f64>,
    /// 枚举取值。
    pub options: Vec<String>,
    /// 来源。
    pub source: SettingSource,
    /// 是否敏感项。
    pub secret: bool,
    /// 敏感项是否已设置；非敏感项为 `None`。
    pub has_value: Option<bool>,
}

/// 管理端设置分组。
#[derive(Debug, Clone, Serialize)]
pub struct SettingGroup {
    /// 分组名。
    pub name: String,
    /// 组内设置项。
    pub items: Vec<SettingItem>,
}

/// 运行期系统设置缓存。
#[derive(Debug, Clone)]
pub struct RuntimeSettings {
    secret_key: Option<String>,
    values: BTreeMap<String, SettingValue>,
    sources: BTreeMap<String, SettingSource>,
}

impl RuntimeSettings {
    /// 以默认值初始化缓存；`secret_key` 用于敏感项加解密。
    pub fn new(secret_key: Option<String>) -> Self {
        let mut values = BTreeMap::new();
        let mut sources = BTreeMap::new();
        for item in CATALOG.iter() {
            values.insert(item.key.to_string(), item.default.to_value());
            sources.insert(item.key.to_string(), SettingSource::Default);
        }
        Self {
            secret_key,
            values,
            sources,
        }
    }

    /// Fernet 主密钥；供推送任务解密队列里的 `app_secret_cipher` 使用。
    pub(crate) fn secret_key(&self) -> Option<&str> {
        self.secret_key.as_deref()
    }

    /// 读取库内设置；缺失项把环境变量中的非默认值一次性落库。
    ///
    /// 数据库读取或落库失败时返回错误；单个值非法或密文损坏只告警并退回默认值，
    /// 单项坏数据只告警并回退默认值，避免拖垮整个服务。
    pub async fn load(&mut self, pool: &MySqlPool) -> Result<(), AppError> {
        self.reset_to_defaults();

        let rows: Vec<(String, String)> =
            sqlx::query_as("SELECT `key`, `value` FROM system_settings")
                .fetch_all(pool)
                .await?;
        let rows: BTreeMap<String, String> = rows.into_iter().collect();

        for item in CATALOG.iter() {
            if rows.contains_key(item.key) {
                continue;
            }
            let Ok(raw) = env::var(item.key.to_ascii_uppercase()) else {
                continue;
            };
            let raw = raw.trim();
            if raw.is_empty() {
                continue;
            }
            let value = match coerce_text(item, raw) {
                Ok(value) => value,
                Err(message) => {
                    tracing::warn!(
                        "环境变量 {} 的值非法，忽略：{message}",
                        item.key.to_uppercase()
                    );
                    continue;
                }
            };
            if value == item.default.to_value() {
                continue;
            }
            let stored = serialize_value(item, &value, self.secret_key.as_deref());
            sqlx::query(
                "INSERT IGNORE INTO system_settings (`key`, `value`, `created_at`, `updated_at`) \
                 VALUES (?, ?, ?, ?)",
            )
            .bind(item.key)
            .bind(stored)
            .bind(Utc::now().naive_utc())
            .bind(Utc::now().naive_utc())
            .execute(pool)
            .await?;
            self.values.insert(item.key.to_string(), value);
            self.sources
                .insert(item.key.to_string(), SettingSource::Environment);
        }

        for item in CATALOG.iter() {
            let Some(raw) = rows.get(item.key) else {
                continue;
            };
            let raw = if item.secret {
                match decrypt_secret(raw, self.secret_key.as_deref()) {
                    Ok(value) => value,
                    Err(err) => {
                        tracing::warn!("系统设置 {} 解密失败：{err}", item.key);
                        String::new()
                    }
                }
            } else {
                raw.clone()
            };
            match coerce_text(item, &raw) {
                Ok(value) => {
                    self.values.insert(item.key.to_string(), value);
                    self.sources
                        .insert(item.key.to_string(), SettingSource::Database);
                }
                Err(message) => {
                    tracing::warn!("系统设置 {} 的值非法，改用默认值：{message}", item.key);
                }
            }
        }

        if self
            .sources
            .values()
            .any(|source| *source == SettingSource::Environment)
        {
            tracing::info!("已将环境变量中的非默认系统设置导入数据库");
        }
        Ok(())
    }

    /// 校验管理端提交的改动，返回可写入数据库的值。
    pub fn validate(
        &self,
        changes: &serde_json::Map<String, Value>,
    ) -> Result<BTreeMap<String, SettingValue>, AppError> {
        let unknown: Vec<&str> = changes
            .keys()
            .filter(|key| spec(key).is_none())
            .map(String::as_str)
            .collect();
        if !unknown.is_empty() {
            return Err(AppError::bad_request(format!(
                "未知设置项：{}",
                unknown.join(", ")
            )));
        }

        let mut values = BTreeMap::new();
        for (key, raw) in changes {
            let Some(item) = spec(key) else {
                continue;
            };
            let value = coerce_json(item, raw).map_err(AppError::bad_request)?;
            // 敏感项留空表示保持原值，避免页面回显导致误清空
            if item.secret && value.as_str().is_empty() {
                continue;
            }
            values.insert(key.clone(), value);
        }
        Ok(values)
    }

    /// 把校验过的值写入待提交事务之外（每项独立 upsert，调用方负责错误处理）。
    pub async fn persist(
        &self,
        pool: &MySqlPool,
        values: &BTreeMap<String, SettingValue>,
    ) -> Result<(), AppError> {
        let now = Utc::now().naive_utc();
        for (key, value) in values {
            let Some(item) = spec(key) else {
                continue;
            };
            let stored = serialize_value(item, value, self.secret_key.as_deref());
            sqlx::query(
                "INSERT INTO system_settings (`key`, `value`, `created_at`, `updated_at`) \
                 VALUES (?, ?, ?, ?) \
                 ON DUPLICATE KEY UPDATE `value` = VALUES(`value`), \
                 `updated_at` = VALUES(`updated_at`)",
            )
            .bind(key)
            .bind(stored)
            .bind(now)
            .bind(now)
            .execute(pool)
            .await?;
        }
        Ok(())
    }

    /// 把已持久化的值写入内存缓存。
    pub fn apply(&mut self, values: &BTreeMap<String, SettingValue>) {
        for (key, value) in values {
            self.values.insert(key.clone(), value.clone());
            self.sources.insert(key.clone(), SettingSource::Database);
        }
    }

    /// 让日志级别与进程内限速器立即采用新值。
    ///
    /// 日志级别由 `main` 的 tracing 订阅器在启动时读取 `RUST_LOG`；运行期调整日志级别
    /// 需要 `tracing-subscriber` 的 registry 特性，本 crate 未启用，故此处只更新频控。
    pub fn apply_side_effects(&self, limiters: &LimiterRegistry, login_limiter: &AttemptLimiter) {
        limiters.configure(
            self.qq_qps(),
            self.qq_qpm(),
            self.qq_min_interval_duration(),
        );
        login_limiter.configure(
            self.login_max_failures(),
            self.login_ip_max_failures(),
            self.login_window_seconds(),
        );
    }

    /// 某个设置项的来源。
    pub fn source_of(&self, key: &str) -> SettingSource {
        self.sources
            .get(key)
            .copied()
            .unwrap_or(SettingSource::Default)
    }

    /// 当前全部设置值（只读）。
    pub fn values(&self) -> &BTreeMap<String, SettingValue> {
        &self.values
    }

    /// 取某个设置项的值。
    pub fn get(&self, key: &str) -> Option<&SettingValue> {
        self.values.get(key)
    }

    /// 管理端分组视图。
    pub fn describe_groups(&self) -> Vec<SettingGroup> {
        let mut groups: Vec<SettingGroup> = Vec::new();
        for item in CATALOG.iter() {
            let value = self.value_of(item.key);
            let entry = SettingItem {
                key: item.key.to_string(),
                label: item.label.to_string(),
                description: item.description.to_string(),
                kind: item.kind,
                value: if item.secret {
                    Value::String(String::new())
                } else {
                    value.to_json()
                },
                default: item.default.to_json(),
                minimum: item.minimum,
                maximum: item.maximum,
                options: item
                    .options
                    .iter()
                    .map(|option| option.to_string())
                    .collect(),
                source: self.source_of(item.key),
                secret: item.secret,
                has_value: if item.secret {
                    Some(!value.as_str().is_empty())
                } else {
                    None
                },
            };
            if let Some(group) = groups.iter_mut().find(|group| group.name == item.group) {
                group.items.push(entry);
            } else {
                groups.push(SettingGroup {
                    name: item.group.to_string(),
                    items: vec![entry],
                });
            }
        }
        groups
    }

    /// 对外访问地址。
    pub fn public_base_url(&self) -> &str {
        self.str_value("public_base_url")
    }

    /// 统计时区。
    pub fn timezone(&self) -> &str {
        self.str_value("timezone")
    }

    /// 日志级别。
    pub fn log_level(&self) -> &str {
        self.str_value("log_level")
    }

    /// 普通请求体上限。
    pub fn max_body_bytes(&self) -> usize {
        self.int_value("max_body_bytes").max(0) as usize
    }

    /// GitHub 请求体上限。
    pub fn github_max_body_bytes(&self) -> usize {
        self.int_value("github_max_body_bytes").max(0) as usize
    }

    /// 是否允许 `?token=`。
    pub fn webhook_allow_query_token(&self) -> bool {
        self.bool_value("webhook_allow_query_token")
    }

    /// 是否允许邀请注册。
    pub fn register_enabled(&self) -> bool {
        self.bool_value("register_enabled")
    }

    /// 会话有效期（小时）。
    pub fn session_ttl_hours(&self) -> i64 {
        self.int_value("session_ttl_hours")
    }

    /// 是否强制 Cookie 仅限 HTTPS。
    pub fn cookie_secure(&self) -> bool {
        self.bool_value("cookie_secure")
    }

    /// 会话 Cookie 实际是否带 `Secure`：显式开启或对外地址为 https。
    pub fn secure_cookies(&self) -> bool {
        self.cookie_secure()
            || self
                .public_base_url()
                .to_ascii_lowercase()
                .starts_with("https://")
    }

    /// WebAuthn RP ID。
    pub fn rp_id(&self) -> &str {
        self.str_value("rp_id")
    }

    /// WebAuthn 显示名。
    pub fn rp_name(&self) -> &str {
        self.str_value("rp_name")
    }

    /// 单账号失败上限。
    pub fn login_max_failures(&self) -> u32 {
        self.int_value("login_max_failures").max(1) as u32
    }

    /// 单 IP 失败上限。
    pub fn login_ip_max_failures(&self) -> u32 {
        self.int_value("login_ip_max_failures").max(1) as u32
    }

    /// 登录失败统计窗口（秒）。
    pub fn login_window_seconds(&self) -> u64 {
        self.int_value("login_window_seconds").max(1) as u64
    }

    /// SMTP 服务器。
    pub fn smtp_host(&self) -> &str {
        self.str_value("smtp_host")
    }

    /// SMTP 端口。
    pub fn smtp_port(&self) -> u16 {
        self.int_value("smtp_port").clamp(1, 65_535) as u16
    }

    /// SMTP 连接方式：`starttls` / `ssl` / `none`。
    pub fn smtp_security(&self) -> &str {
        self.str_value("smtp_security")
    }

    /// SMTP 用户名。
    pub fn smtp_username(&self) -> &str {
        self.str_value("smtp_username")
    }

    /// SMTP 密码（缓存内为明文）。
    pub fn smtp_password(&self) -> &str {
        self.str_value("smtp_password")
    }

    /// 发件人地址。
    pub fn smtp_from(&self) -> &str {
        self.str_value("smtp_from")
    }

    /// SMTP 超时（秒）。
    pub fn smtp_timeout(&self) -> u64 {
        self.int_value("smtp_timeout").max(1) as u64
    }

    /// 邮件是否已配置：需要服务器地址与发件人（或用户名）。
    pub fn smtp_configured(&self) -> bool {
        let sender = if !self.smtp_from().trim().is_empty() {
            self.smtp_from()
        } else {
            self.smtp_username()
        };
        !self.smtp_host().trim().is_empty() && !sender.trim().is_empty()
    }

    /// 验证码有效期（分钟）。
    pub fn email_code_ttl_minutes(&self) -> i64 {
        self.int_value("email_code_ttl_minutes")
    }

    /// 验证码重发间隔（秒）。
    pub fn email_code_resend_seconds(&self) -> u64 {
        self.int_value("email_code_resend_seconds").max(1) as u64
    }

    /// 每小时发码上限。
    pub fn email_code_hourly_limit(&self) -> i64 {
        self.int_value("email_code_hourly_limit")
    }

    /// 默认 QQ API 域名。
    pub fn qq_host(&self) -> &str {
        self.str_value("qq_host")
    }

    /// 单机器人 QPS。
    pub fn qq_qps(&self) -> u32 {
        self.int_value("qq_qps").max(1) as u32
    }

    /// 单机器人 QPM。
    pub fn qq_qpm(&self) -> u32 {
        self.int_value("qq_qpm").max(1) as u32
    }

    /// 最小发送间隔（秒）。
    pub fn qq_min_interval(&self) -> f64 {
        let value = self.float_value("qq_min_interval");
        if value.is_finite() && value > 0.0 {
            value
        } else {
            0.0
        }
    }

    /// 最小发送间隔。
    pub fn qq_min_interval_duration(&self) -> Duration {
        Duration::from_secs_f64(self.qq_min_interval())
    }

    /// Markdown 长度上限。
    pub fn markdown_max_len(&self) -> usize {
        self.int_value("markdown_max_len").max(1) as usize
    }

    /// 纯文本长度上限。
    pub fn text_max_len(&self) -> usize {
        self.int_value("text_max_len").max(1) as usize
    }

    /// 重置为默认值（`load` 的第一步）。
    fn reset_to_defaults(&mut self) {
        for item in CATALOG.iter() {
            self.values
                .insert(item.key.to_string(), item.default.to_value());
            self.sources
                .insert(item.key.to_string(), SettingSource::Default);
        }
    }

    fn value_of(&self, key: &str) -> SettingValue {
        self.values
            .get(key)
            .cloned()
            .or_else(|| spec(key).map(|item| item.default.to_value()))
            .unwrap_or_else(|| SettingValue::Str(String::new()))
    }

    fn bool_value(&self, key: &str) -> bool {
        self.values
            .get(key)
            .map(SettingValue::as_bool)
            .unwrap_or(false)
    }

    fn int_value(&self, key: &str) -> i64 {
        self.values.get(key).map(SettingValue::as_i64).unwrap_or(0)
    }

    fn float_value(&self, key: &str) -> f64 {
        self.values
            .get(key)
            .map(SettingValue::as_f64)
            .unwrap_or(0.0)
    }

    fn str_value(&self, key: &str) -> &str {
        match self.values.get(key) {
            Some(SettingValue::Str(value)) => value,
            _ => "",
        }
    }
}

/// 判断文本是否表示真。
fn truthy(raw: &str) -> bool {
    matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// 把库内/环境变量字符串转换为声明类型。
fn coerce_text(item: &SettingSpec, raw: &str) -> Result<SettingValue, String> {
    match item.kind {
        SettingKind::Bool => Ok(SettingValue::Bool(truthy(raw))),
        SettingKind::Int => {
            let value = raw
                .trim()
                .parse::<i64>()
                .map_err(|_| format!("「{}」必须是整数", item.label))?;
            check_number_bounds(item, value as f64)?;
            Ok(SettingValue::Int(value))
        }
        SettingKind::Float => {
            let value = raw
                .trim()
                .parse::<f64>()
                .map_err(|_| format!("「{}」必须是数字", item.label))?;
            check_number_bounds(item, value)?;
            Ok(SettingValue::Float(value))
        }
        SettingKind::Str | SettingKind::Select => coerce_string(item, raw),
    }
}

/// 把管理端 JSON 值转换为声明类型。
fn coerce_json(item: &SettingSpec, raw: &Value) -> Result<SettingValue, String> {
    match item.kind {
        SettingKind::Bool => match raw {
            Value::Bool(value) => Ok(SettingValue::Bool(*value)),
            Value::String(value) => Ok(SettingValue::Bool(truthy(value))),
            _ => Err(format!("「{}」必须是布尔值", item.label)),
        },
        SettingKind::Int => {
            let value = match raw {
                Value::Number(number) => number
                    .as_i64()
                    .or_else(|| {
                        let value = number.as_f64()?;
                        (value.is_finite() && value.fract() == 0.0).then_some(value as i64)
                    })
                    .ok_or_else(|| format!("「{}」必须是整数", item.label))?,
                Value::String(text) => text
                    .trim()
                    .parse::<i64>()
                    .map_err(|_| format!("「{}」必须是整数", item.label))?,
                _ => return Err(format!("「{}」必须是数字", item.label)),
            };
            check_number_bounds(item, value as f64)?;
            Ok(SettingValue::Int(value))
        }
        SettingKind::Float => {
            let value = match raw {
                Value::Number(number) => number
                    .as_f64()
                    .ok_or_else(|| format!("「{}」必须是数字", item.label))?,
                Value::String(text) => text
                    .trim()
                    .parse::<f64>()
                    .map_err(|_| format!("「{}」必须是数字", item.label))?,
                _ => return Err(format!("「{}」必须是数字", item.label)),
            };
            check_number_bounds(item, value)?;
            Ok(SettingValue::Float(value))
        }
        SettingKind::Str | SettingKind::Select => match raw {
            Value::String(value) => coerce_string(item, value),
            _ => Err(format!("「{}」必须是文本", item.label)),
        },
    }
}

/// 文本/枚举校验。
fn coerce_string(item: &SettingSpec, raw: &str) -> Result<SettingValue, String> {
    let value = raw.trim();
    if value.chars().count() > item.max_length {
        return Err(format!(
            "「{}」不能超过 {} 个字符",
            item.label, item.max_length
        ));
    }
    if item.kind == SettingKind::Select && !item.options.contains(&value) {
        return Err(format!("「{}」取值非法", item.label));
    }
    Ok(SettingValue::Str(value.to_string()))
}

/// 数值上下限校验。
fn check_number_bounds(item: &SettingSpec, value: f64) -> Result<(), String> {
    if value.is_nan() {
        return Err(format!("「{}」必须是数字", item.label));
    }
    if let Some(minimum) = item.minimum
        && value < minimum
    {
        return Err(format!("「{}」不能小于 {minimum}", item.label));
    }
    if let Some(maximum) = item.maximum
        && value > maximum
    {
        return Err(format!("「{}」不能大于 {maximum}", item.label));
    }
    Ok(())
}

/// 把值序列化为库内字符串（敏感项加密）。
fn serialize_value(item: &SettingSpec, value: &SettingValue, secret_key: Option<&str>) -> String {
    if item.secret {
        return encrypt_secret(value.as_str(), secret_key);
    }
    match value {
        SettingValue::Bool(value) => {
            if *value {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        SettingValue::Int(value) => value.to_string(),
        SettingValue::Float(value) => value.to_string(),
        SettingValue::Str(value) => value.clone(),
    }
}
