//! 数据库行结构体（`sqlx::FromRow`）。
//!
//! 时间列统一用 `chrono::NaiveDateTime`：MySQL `DATETIME` 无时区，按 UTC 解释。

use chrono::NaiveDateTime;
use serde_json::Value;

/// 角色与状态取值（数据库枚举字符串）。
pub const ROLE_SUPER_ADMIN: &str = "super_admin";
pub const ROLE_USER: &str = "user";
/// 全部合法角色。
pub const ROLES: [&str; 2] = [ROLE_SUPER_ADMIN, ROLE_USER];

pub const STATUS_ACTIVE: &str = "active";
pub const STATUS_DISABLED: &str = "disabled";

pub const PLATFORM_DINGTALK: &str = "dingtalk";
pub const PLATFORM_WECOM: &str = "wecom";
pub const PLATFORM_FEISHU: &str = "feishu";
pub const PLATFORM_GITHUB: &str = "github";
/// 全部合法平台。
pub const PLATFORMS: [&str; 4] = [
    PLATFORM_DINGTALK,
    PLATFORM_WECOM,
    PLATFORM_FEISHU,
    PLATFORM_GITHUB,
];

/// 账号。
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct User {
    /// 主键。
    pub id: i64,
    /// 邮箱（唯一）。
    pub email: String,
    /// 用户名（忽略大小写唯一）。
    pub name: String,
    /// 密码哈希。
    pub password_hash: Option<String>,
    /// 角色。
    pub role: String,
    /// 状态。
    pub status: String,
    /// 最后登录时间。
    pub last_login_at: Option<NaiveDateTime>,
    /// 创建时间。
    pub created_at: NaiveDateTime,
}

/// OAuth2 提供方与用户的绑定关系。
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuthIdentity {
    /// 主键。
    pub id: i64,
    /// 所属用户。
    pub user_id: i64,
    /// 提供方标识。
    pub provider: String,
    /// 提供方侧的用户 ID。
    pub provider_user_id: String,
    /// 提供方侧的登录名。
    pub provider_login: Option<String>,
    /// 创建时间。
    pub created_at: NaiveDateTime,
}

/// Passkey（WebAuthn）凭据。
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct WebauthnCredential {
    /// 主键。
    pub id: i64,
    /// 所属用户。
    pub user_id: i64,
    /// 凭据 ID（`VARBINARY(255)`）。
    pub credential_id: Vec<u8>,
    /// COSE 公钥原始字节。
    pub public_key: Vec<u8>,
    /// 签名计数。
    pub sign_count: i64,
    /// AAGUID。
    pub aaguid: Option<String>,
    /// 传输方式（JSON）。
    pub transports: Option<Value>,
    /// 设备类型。
    pub device_type: Option<String>,
    /// 是否已备份。
    pub backed_up: bool,
    /// 标签。
    pub label: String,
    /// 最后使用时间。
    pub last_used_at: Option<NaiveDateTime>,
    /// 创建时间。
    pub created_at: NaiveDateTime,
}

/// 服务端会话；Cookie 只保存 token，库里只存哈希。
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Session {
    /// 主键。
    pub id: i64,
    /// token 的 SHA-256 十六进制（唯一）。
    pub token_hash: String,
    /// 所属用户。
    pub user_id: i64,
    /// 客户端 IP。
    pub ip: Option<String>,
    /// 客户端 UA（截断 255 字符）。
    pub user_agent: Option<String>,
    /// 过期时间。
    pub expires_at: NaiveDateTime,
    /// 撤销时间。
    pub revoked_at: Option<NaiveDateTime>,
    /// 创建时间。
    pub created_at: NaiveDateTime,
}

/// 超级管理员邀请码；注册用户一律为普通用户。
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct InviteCode {
    /// 主键。
    pub id: i64,
    /// 邀请码（唯一）。
    pub code: String,
    /// 限定邮箱。
    pub email: Option<String>,
    /// 最大可用次数。
    pub max_uses: i32,
    /// 已用次数。
    pub used_count: i32,
    /// 过期时间。
    pub expires_at: Option<NaiveDateTime>,
    /// 撤销时间。
    pub revoked_at: Option<NaiveDateTime>,
    /// 创建者。
    pub created_by: Option<i64>,
    /// 创建时间。
    pub created_at: NaiveDateTime,
}

/// 用户的 QQ 机器人配置。
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct BotProfile {
    /// 主键。
    pub id: i64,
    /// 所属用户。
    pub owner_user_id: i64,
    /// 名称。
    pub name: String,
    /// QQ AppID。
    pub qq_appid: String,
    /// QQ AppSecret（密文，可能带 `enc1:` 前缀）。
    pub qq_app_secret: String,
    /// QQ 接口主机。
    pub qq_host: String,
    /// 默认推送目标 openid 列表（JSON）。
    pub default_openids: Value,
    /// 默认群 openid。
    pub default_group_openid: Option<String>,
    /// 是否启用。
    pub enabled: bool,
    /// 创建时间。
    pub created_at: NaiveDateTime,
}

/// 平台接入通道；webhook_token 用于反查所属机器人。
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Channel {
    /// 主键。
    pub id: i64,
    /// 所属机器人。
    pub bot_profile_id: i64,
    /// 平台标识。
    pub platform: String,
    /// Webhook 凭据（唯一）。
    pub webhook_token: String,
    /// 是否启用。
    pub enabled: bool,
    /// 平台附加配置（JSON）。
    pub extra: Option<Value>,
    /// 创建时间。
    pub created_at: NaiveDateTime,
}

/// 推送日志（审计）。
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PushLog {
    /// 主键。
    pub id: i64,
    /// 归属用户。
    pub owner_user_id: i64,
    /// 通道（删除通道后置空）。
    pub channel_id: Option<i64>,
    /// 机器人（删除机器人后置空）。
    pub bot_profile_id: Option<i64>,
    /// 平台标识。
    pub platform: String,
    /// 平台原始消息类型。
    pub source_msgtype: String,
    /// 推送目标。
    pub target: String,
    /// QQ 消息类型。
    pub qq_msg_type: Option<i32>,
    /// 内容预览。
    pub content_preview: String,
    /// 内容长度。
    pub content_len: i32,
    /// 推送状态。
    pub status: String,
    /// 错误码。
    pub error_code: Option<String>,
    /// 错误信息。
    pub error_message: Option<String>,
    /// 耗时（毫秒）。
    pub duration_ms: f32,
    /// 请求 ID。
    pub request_id: String,
    /// 创建时间。
    pub created_at: NaiveDateTime,
}

/// 邮箱验证码：只保存哈希，按用途与邮箱匹配，一次性消费。
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct EmailVerificationCode {
    /// 主键。
    pub id: i64,
    /// 邮箱。
    pub email: String,
    /// 用途：register / reset_password / set_password。
    pub purpose: String,
    /// 验证码哈希。
    pub code_hash: String,
    /// 过期时间。
    pub expires_at: NaiveDateTime,
    /// 消费时间。
    pub consumed_at: Option<NaiveDateTime>,
    /// 校验失败次数。
    pub attempts: i32,
    /// 签发时的客户端 IP。
    pub ip: Option<String>,
    /// 创建时间。
    pub created_at: NaiveDateTime,
}

/// 后台写操作审计。
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AdminAuditLog {
    /// 主键。
    pub id: i64,
    /// 操作者。
    pub actor_user_id: Option<i64>,
    /// 动作。
    pub action: String,
    /// 目标类型。
    pub target_type: Option<String>,
    /// 目标 ID。
    pub target_id: Option<String>,
    /// 详情（JSON）。
    pub detail: Option<Value>,
    /// 客户端 IP。
    pub ip: Option<String>,
    /// 创建时间。
    pub created_at: NaiveDateTime,
}

/// 通用 OAuth2 提供方配置；client_secret 加密入库。
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct OAuthProvider {
    /// 主键。
    pub id: i64,
    /// 提供方标识（唯一）。
    pub key: String,
    /// 展示名。
    pub display_name: String,
    /// 客户端 ID。
    pub client_id: String,
    /// 客户端密钥（密文，可能带 `enc1:` 前缀）。
    pub client_secret: String,
    /// 授权地址。
    pub authorization_url: String,
    /// 令牌地址。
    pub token_url: String,
    /// 用户信息地址。
    pub userinfo_url: String,
    /// 授权范围。
    pub scopes: String,
    /// 邮箱字段名。
    pub email_field: String,
    /// ID 字段名。
    pub id_field: String,
    /// 昵称字段名。
    pub name_field: String,
    /// 是否启用。
    pub enabled: bool,
    /// 提供方是否已验证邮箱所有权。
    pub email_verified: bool,
    /// 创建时间。
    pub created_at: NaiveDateTime,
}

/// 全局开关（注册开关等）。
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SystemSetting {
    /// 键（主键）。
    pub key: String,
    /// 值。
    pub value: String,
    /// 更新时间。
    pub updated_at: NaiveDateTime,
    /// 创建时间。
    pub created_at: NaiveDateTime,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_are_stable() {
        assert_eq!(ROLE_SUPER_ADMIN, "super_admin");
        assert_eq!(ROLE_USER, "user");
        assert_eq!(STATUS_ACTIVE, "active");
        assert_eq!(STATUS_DISABLED, "disabled");
        assert_eq!(PLATFORM_DINGTALK, "dingtalk");
        assert_eq!(PLATFORM_WECOM, "wecom");
        assert_eq!(PLATFORM_FEISHU, "feishu");
        assert_eq!(PLATFORM_GITHUB, "github");
        assert_eq!(ROLES.len(), 2);
        assert_eq!(PLATFORMS.len(), 4);
    }
}
