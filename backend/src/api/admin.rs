//! 管理端端点（`/api/admin`）。
//!
//! 端点清单：
//! - `GET/POST   /api/admin/bot-profiles`；`PATCH/DELETE /api/admin/bot-profiles/{id}`
//! - `GET/POST   /api/admin/channels`；`PATCH/DELETE /api/admin/channels/{id}`；
//!   `POST /api/admin/channels/{id}/rotate`
//! - `GET  /api/admin/logs?page=&page_size=&platform=&status=&keyword=`；
//!   `GET /api/admin/logs/{log_id}`
//! - `GET  /api/admin/users`；`PATCH /api/admin/users/{id}`
//! - `GET/POST   /api/admin/invites`；`DELETE /api/admin/invites/{id}`
//! - `GET/POST   /api/admin/oauth-providers`；
//!   `PATCH/DELETE /api/admin/oauth-providers/{id}`
//! - `GET/PATCH  /api/admin/settings`
//! - `GET  /api/admin/stats`
//!
//! 权限边界：普通登录用户只能管理
//! 自己的机器人与通道、查看自己的日志与统计；用户、邀请码、OAuth 提供方与系统
//! 设置仅超级管理员可用。

use std::collections::HashMap;

use actix_web::web;
use actix_web::{HttpRequest, HttpResponse};
use chrono::{Duration as ChronoDuration, Local, NaiveDate, NaiveDateTime, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::{MySql, QueryBuilder};

use crate::auth::sessions;
use crate::crypto::{encrypt_secret, mask_secret, random_token};
use crate::db::models::{
    BotProfile, Channel, PLATFORM_GITHUB, PLATFORMS, PushLog, STATUS_ACTIVE, User,
};
use crate::db::queries;
use crate::db::queries::bots::NewBotProfile;
use crate::db::queries::channels::NewChannel;
use crate::db::queries::invites::NewInviteCode;
use crate::error::AppError;
use crate::services::audit::{self, AuditEntry};
use crate::services::runtime_settings::{
    self, RuntimeSettings, SettingKind, SettingSource, SettingValue,
};
use crate::services::users::{self, AdminUserPatch};
use crate::state::AppState;

/// 默认目标数量上限。
const MAX_DEFAULT_TARGETS: usize = 50;
/// 单个目标 openid 长度上限。
const MAX_TARGET_LEN: usize = 128;
/// 机器人名称 / AppID 上限。
const BOT_TEXT_MAX: usize = 128;
/// AppSecret 上限。
const BOT_SECRET_MAX: usize = 512;
/// 用户名上限。
const USER_NAME_MAX: usize = 128;

/// GitHub OAuth 预设值。
const GITHUB_PRESET_AUTHORIZATION_URL: &str = "https://github.com/login/oauth/authorize";
const GITHUB_PRESET_TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
const GITHUB_PRESET_USERINFO_URL: &str = "https://api.github.com/user";
const GITHUB_PRESET_SCOPES: &str = "read:user user:email";
const GITHUB_PRESET_EMAIL_FIELD: &str = "email";
const GITHUB_PRESET_ID_FIELD: &str = "id";
const GITHUB_PRESET_NAME_FIELD: &str = "login";

/// 注册管理端路由。
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/admin")
            .app_data(json_config())
            .service(
                web::resource("/bot-profiles")
                    .route(web::get().to(list_bots))
                    .route(web::post().to(create_bot)),
            )
            .service(
                web::resource("/bot-profiles/{bot_id}")
                    .route(web::patch().to(patch_bot))
                    .route(web::delete().to(delete_bot)),
            )
            .service(
                web::resource("/channels")
                    .route(web::get().to(list_channels))
                    .route(web::post().to(create_channel)),
            )
            .service(
                web::resource("/channels/{channel_id}")
                    .route(web::patch().to(patch_channel))
                    .route(web::delete().to(delete_channel)),
            )
            .route(
                "/channels/{channel_id}/rotate",
                web::post().to(rotate_channel),
            )
            .route("/logs", web::get().to(list_logs))
            .route("/logs/{log_id}", web::get().to(get_log))
            .route("/users", web::get().to(list_users))
            .route("/users/{user_id}", web::patch().to(patch_user))
            .service(
                web::resource("/invites")
                    .route(web::get().to(list_invites))
                    .route(web::post().to(create_invite)),
            )
            .route("/invites/{invite_id}", web::delete().to(revoke_invite))
            .service(
                web::resource("/oauth-providers")
                    .route(web::get().to(list_oauth_providers))
                    .route(web::post().to(create_oauth_provider)),
            )
            .service(
                web::resource("/oauth-providers/{provider_id}")
                    .route(web::patch().to(patch_oauth_provider))
                    .route(web::delete().to(delete_oauth_provider)),
            )
            .service(
                web::resource("/settings")
                    .route(web::get().to(get_settings))
                    .route(web::patch().to(patch_settings)),
            )
            .route("/stats", web::get().to(get_stats)),
    );
}

// --------------------------------------------------------------------- 请求体

/// 新建机器人配置。
#[derive(Debug, Deserialize)]
struct BotIn {
    name: String,
    qq_appid: String,
    qq_app_secret: String,
    #[serde(default = "default_qq_host")]
    qq_host: String,
    #[serde(default)]
    default_openids: Vec<String>,
    #[serde(default)]
    default_group_openid: Option<String>,
    #[serde(default = "default_true")]
    enabled: bool,
}

/// 修改机器人配置；缺失字段保持不变。
#[derive(Debug, Deserialize)]
struct BotPatch {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    qq_appid: Option<String>,
    #[serde(default)]
    qq_app_secret: Option<String>,
    #[serde(default)]
    qq_host: Option<String>,
    #[serde(default)]
    default_openids: Option<Vec<String>>,
    #[serde(default)]
    default_group_openid: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
}

/// 新建通道。
#[derive(Debug, Deserialize)]
struct ChannelIn {
    platform: String,
    bot_profile_id: i64,
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default)]
    secret: Option<String>,
}

/// 修改通道。
#[derive(Debug, Deserialize)]
struct ChannelPatch {
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    bot_profile_id: Option<i64>,
}

/// 修改账号。
#[derive(Debug, Deserialize)]
struct UserPatch {
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

/// 新建邀请码。
#[derive(Debug, Deserialize)]
struct InviteIn {
    #[serde(default)]
    email: Option<String>,
    #[serde(default = "default_one")]
    max_uses: i64,
    #[serde(default = "default_seven")]
    expires_in_days: i64,
}

/// 新建 OAuth 提供方。
#[derive(Debug, Deserialize)]
struct OAuthIn {
    key: String,
    display_name: String,
    client_id: String,
    client_secret: String,
    #[serde(default)]
    authorization_url: String,
    #[serde(default)]
    token_url: String,
    #[serde(default)]
    userinfo_url: String,
    #[serde(default)]
    scopes: String,
    #[serde(default = "default_email_field")]
    email_field: String,
    #[serde(default = "default_id_field")]
    id_field: String,
    #[serde(default = "default_name_field")]
    name_field: String,
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default)]
    email_verified: Option<bool>,
    #[serde(default)]
    use_github_preset: bool,
}

/// 修改 OAuth 提供方；缺失字段保持不变。
#[derive(Debug, Deserialize)]
struct OAuthPatch {
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    client_secret: Option<String>,
    #[serde(default)]
    authorization_url: Option<String>,
    #[serde(default)]
    token_url: Option<String>,
    #[serde(default)]
    userinfo_url: Option<String>,
    #[serde(default)]
    scopes: Option<String>,
    #[serde(default)]
    email_field: Option<String>,
    #[serde(default)]
    id_field: Option<String>,
    #[serde(default)]
    name_field: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    email_verified: Option<bool>,
}

fn default_qq_host() -> String {
    "https://api.bot.qq.com".to_string()
}

fn default_true() -> bool {
    true
}

fn default_one() -> i64 {
    1
}

fn default_seven() -> i64 {
    7
}

fn default_email_field() -> String {
    "email".to_string()
}

fn default_id_field() -> String {
    "id".to_string()
}

fn default_name_field() -> String {
    "name".to_string()
}

// ------------------------------------------------------------------ 请求解析

/// JSON 解析错误映射：422 字段错误，400 请求体过大。
fn json_config() -> web::JsonConfig {
    web::JsonConfig::default().error_handler(|err, _req| json_payload_error(err).into())
}

fn json_payload_error(err: actix_web::error::JsonPayloadError) -> AppError {
    use actix_web::error::JsonPayloadError;

    match err {
        JsonPayloadError::ContentType => AppError::validation("请求体必须是 application/json"),
        JsonPayloadError::Deserialize(_) => AppError::validation("请求体字段缺失或格式非法"),
        JsonPayloadError::Overflow { .. } | JsonPayloadError::OverflowKnownLength { .. } => {
            AppError::bad_request("请求体过大")
        }
        _ => AppError::validation("请求体格式非法"),
    }
}

// ----------------------------------------------------------------------- 通用

/// 读取当前请求的会话用户；未登录 401，停用 403。
async fn require_user(state: &AppState, req: &HttpRequest) -> Result<User, AppError> {
    let token = req
        .cookie(state.config.cookie_name.as_str())
        .map(|cookie| cookie.value().to_string())
        .unwrap_or_default();
    match sessions::resolve_session(&state.pool, &token).await? {
        None => Err(AppError::unauthorized("未登录")),
        Some(user) if user.status != STATUS_ACTIVE => Err(AppError::forbidden("账号已停用")),
        Some(user) => Ok(user),
    }
}

/// 按字符数校验长度上限。
fn ensure_max_length(label: &str, value: &str, max: usize) -> Result<(), AppError> {
    if value.chars().count() > max {
        return Err(AppError::validation(format!("{label}最长 {max} 个字符")));
    }
    Ok(())
}

/// 必填字段的最小长度。
fn ensure_min_length(label: &str, value: &str, min: usize) -> Result<(), AppError> {
    if value.chars().count() < min {
        return Err(AppError::validation(format!("{label}至少 {min} 个字符")));
    }
    Ok(())
}

/// 校验并规范化 QQ 接口地址。
fn validate_qq_host(value: &str, allowed_hosts: &[String]) -> Result<String, AppError> {
    let value = value.trim().trim_end_matches('/');
    if value.is_empty() {
        return Ok("https://api.bot.qq.com".to_string());
    }
    let parsed = url::Url::parse(value)
        .map_err(|_| AppError::validation("QQ 接口地址必须是以 https:// 开头的完整地址"))?;
    if parsed.scheme() != "https" || parsed.host().is_none() {
        return Err(AppError::validation(
            "QQ 接口地址必须是以 https:// 开头的完整地址",
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(AppError::validation("QQ 接口地址不能包含用户信息"));
    }
    if parsed.query().is_some_and(|value| !value.is_empty())
        || parsed.fragment().is_some_and(|value| !value.is_empty())
    {
        return Err(AppError::validation("QQ 接口地址不能包含查询参数或锚点"));
    }
    let Some(hostname) = parsed.host_str() else {
        return Err(AppError::validation(
            "QQ 接口地址必须是以 https:// 开头的完整地址",
        ));
    };
    let allowed = allowed_hosts
        .iter()
        .any(|item| item.trim().eq_ignore_ascii_case(hostname));
    if !allowed {
        return Err(AppError::validation("QQ 接口地址不在允许的主机列表中"));
    }
    Ok(value.to_string())
}

/// 校验默认目标列表。
fn validate_openids(values: &[String]) -> Result<Vec<String>, AppError> {
    if values.len() > MAX_DEFAULT_TARGETS {
        return Err(AppError::validation(format!(
            "默认目标最多 {MAX_DEFAULT_TARGETS} 个"
        )));
    }
    let mut out = Vec::with_capacity(values.len());
    for item in values {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        if item.chars().count() > MAX_TARGET_LEN {
            return Err(AppError::validation(format!(
                "单个 openid 最长 {MAX_TARGET_LEN} 个字符"
            )));
        }
        out.push(item.to_string());
    }
    Ok(out)
}

/// 读取机器人配置并校验归属；超级管理员可操作全部。
async fn owned_bot(state: &AppState, actor: &User, bot_id: i64) -> Result<BotProfile, AppError> {
    let Some(bot) = queries::bots::find_by_id(&state.pool, bot_id).await? else {
        return Err(AppError::not_found("机器人配置不存在"));
    };
    if bot.owner_user_id != actor.id && !users::is_super_admin(actor) {
        return Err(AppError::not_found("机器人配置不存在"));
    }
    Ok(bot)
}

/// 读取通道并校验其机器人归属。
async fn owned_channel(
    state: &AppState,
    actor: &User,
    channel_id: i64,
) -> Result<Channel, AppError> {
    let Some(channel) = queries::channels::find_by_id(&state.pool, channel_id).await? else {
        return Err(AppError::not_found("通道不存在"));
    };
    let Some(bot) = queries::bots::find_by_id(&state.pool, channel.bot_profile_id).await? else {
        return Err(AppError::not_found("通道不存在"));
    };
    if bot.owner_user_id != actor.id && !users::is_super_admin(actor) {
        return Err(AppError::not_found("通道不存在"));
    }
    Ok(channel)
}

/// 写入审计记录（同事务）。
async fn audit_tx(
    tx: &mut sqlx::Transaction<'_, MySql>,
    actor: &User,
    action: &str,
    target_type: &str,
    target_id: Option<String>,
    detail: Option<Value>,
    ip: Option<&str>,
) -> Result<(), AppError> {
    audit::record_audit_on(
        &mut **tx,
        AuditEntry {
            actor_user_id: Some(actor.id),
            action,
            target_type: Some(target_type),
            target_id,
            detail,
            ip,
        },
    )
    .await
}

/// RFC 3339 时间戳（整秒省略小数部分）。
fn isoformat(value: NaiveDateTime) -> String {
    if value.and_utc().timestamp_subsec_micros() == 0 {
        value.format("%Y-%m-%dT%H:%M:%S").to_string()
    } else {
        value.format("%Y-%m-%dT%H:%M:%S%.6f").to_string()
    }
}

fn isoformat_opt(value: Option<NaiveDateTime>) -> Value {
    value.map_or(Value::Null, |value| Value::String(isoformat(value)))
}

/// `default_openids` 字段：`null` 视为空数组。
fn json_openids(value: &Value) -> Value {
    if value.is_null() {
        json!([])
    } else {
        value.clone()
    }
}

/// JSON 值是否视为配置了密钥（用于 `has_secret`）。
fn json_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64().is_some_and(|value| value != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
    }
}

/// 通道 `extra.secret_cipher` 是否存在。
fn channel_has_secret(channel: &Channel) -> bool {
    channel
        .extra
        .as_ref()
        .and_then(|extra| extra.get("secret_cipher"))
        .is_some_and(json_truthy)
}

/// 生成 Webhook 地址前缀：优先运行期 `public_base_url`，否则按请求头推导。
fn webhook_base(req: &HttpRequest, settings: &RuntimeSettings) -> String {
    let configured = settings.public_base_url().trim();
    if !configured.is_empty() {
        return configured.trim_end_matches('/').to_string();
    }
    let info = req.connection_info();
    format!("{}://{}", info.scheme(), info.host())
}

/// 通道的对外 Webhook 地址。
fn webhook_url(base: &str, platform: &str, token: &str) -> String {
    if platform == PLATFORM_GITHUB {
        format!("{base}/webhook/github/{token}")
    } else {
        format!("{base}/webhook/{platform}")
    }
}

/// 解析查询参数；同名参数取最后一个（与 Starlette 的 `.get` 一致）。
fn query_params(req: &HttpRequest) -> HashMap<String, String> {
    let mut params = HashMap::new();
    for (key, value) in url::form_urlencoded::parse(req.query_string().as_bytes()) {
        params.insert(key.into_owned(), value.into_owned());
    }
    params
}

// ------------------------------------------------------------------- 机器人配置

/// `GET /api/admin/bot-profiles`
async fn list_bots(req: HttpRequest, state: web::Data<AppState>) -> Result<HttpResponse, AppError> {
    let actor = require_user(&state, &req).await?;
    let owner = if users::is_super_admin(&actor) {
        None
    } else {
        Some(actor.id)
    };
    let rows = queries::bots::list_with_owner(&state.pool, owner).await?;
    let items: Vec<Value> = rows
        .into_iter()
        .map(|(bot, owner_email)| {
            json!({
                "id": bot.id,
                "owner_user_id": bot.owner_user_id,
                "owner_email": owner_email,
                "name": bot.name,
                "qq_appid": bot.qq_appid,
                "qq_app_secret_masked": mask_secret(&bot.qq_app_secret),
                "has_secret": !bot.qq_app_secret.is_empty(),
                "qq_host": bot.qq_host,
                "default_openids": json_openids(&bot.default_openids),
                "default_group_openid": bot.default_group_openid,
                "enabled": bot.enabled,
            })
        })
        .collect();
    Ok(HttpResponse::Ok().json(items))
}

/// `POST /api/admin/bot-profiles`
async fn create_bot(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<BotIn>,
) -> Result<HttpResponse, AppError> {
    let actor = require_user(&state, &req).await?;
    let data = body.into_inner();
    ensure_min_length("名称", &data.name, 1)?;
    ensure_max_length("名称", &data.name, BOT_TEXT_MAX)?;
    ensure_min_length("AppID", &data.qq_appid, 1)?;
    ensure_max_length("AppID", &data.qq_appid, BOT_TEXT_MAX)?;
    ensure_min_length("AppSecret", &data.qq_app_secret, 1)?;
    ensure_max_length("AppSecret", &data.qq_app_secret, BOT_SECRET_MAX)?;
    let qq_host = validate_qq_host(&data.qq_host, &state.config.qq_allowed_hosts)?;
    let openids = validate_openids(&data.default_openids)?;
    let group_openid = data.default_group_openid.filter(|value| !value.is_empty());
    if let Some(group) = group_openid.as_deref() {
        ensure_max_length("默认群 openid", group, MAX_TARGET_LEN)?;
    }

    let encrypted = encrypt_secret(&data.qq_app_secret, state.config.app_secret_key.as_deref());
    let openids_value = Value::Array(openids.into_iter().map(Value::String).collect());
    let now = Utc::now().naive_utc();
    let ip = state.client_ip(&req);

    let mut tx = state.pool.begin().await?;
    let bot_id = queries::bots::insert(
        &mut *tx,
        &NewBotProfile {
            owner_user_id: actor.id,
            name: &data.name,
            qq_appid: &data.qq_appid,
            qq_app_secret: &encrypted,
            qq_host: &qq_host,
            default_openids: &openids_value,
            default_group_openid: group_openid.as_deref(),
            enabled: data.enabled,
            created_at: now,
        },
    )
    .await?;
    audit_tx(
        &mut tx,
        &actor,
        "bot.create",
        "bot_profile",
        Some(bot_id.to_string()),
        Some(json!({"name": data.name, "appid": data.qq_appid})),
        ip.as_deref(),
    )
    .await?;
    tx.commit().await?;

    Ok(HttpResponse::Created().json(json!({"id": bot_id})))
}

/// `PATCH /api/admin/bot-profiles/{bot_id}`
async fn patch_bot(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<i64>,
    body: web::Json<BotPatch>,
) -> Result<HttpResponse, AppError> {
    let actor = require_user(&state, &req).await?;
    let bot = owned_bot(&state, &actor, path.into_inner()).await?;
    let data = body.into_inner();
    let ip = state.client_ip(&req);

    // 先校验全部字段，再在同一事务里更新并写审计。
    if let Some(name) = data.name.as_deref() {
        ensure_max_length("名称", name, BOT_TEXT_MAX)?;
    }
    if let Some(appid) = data.qq_appid.as_deref() {
        ensure_max_length("AppID", appid, BOT_TEXT_MAX)?;
    }
    if let Some(secret) = data.qq_app_secret.as_deref() {
        ensure_max_length("AppSecret", secret, BOT_SECRET_MAX)?;
    }
    let qq_host = match data.qq_host.as_deref() {
        Some(value) => Some(validate_qq_host(value, &state.config.qq_allowed_hosts)?),
        None => None,
    };
    let openids = match data.default_openids.as_deref() {
        Some(values) => Some(validate_openids(values)?),
        None => None,
    };
    if let Some(group) = data.default_group_openid.as_deref() {
        ensure_max_length("默认群 openid", group, MAX_TARGET_LEN)?;
    }

    let mut fields: Vec<&'static str> = Vec::new();
    let mut has_updates = false;
    let mut update = QueryBuilder::<MySql>::new("UPDATE bot_profiles SET ");
    let mut separator = "";

    if let Some(name) = data.name {
        update.push(separator).push("name = ").push_bind(name);
        separator = ", ";
        has_updates = true;
        fields.push("name");
    }
    if let Some(appid) = data.qq_appid {
        update.push(separator).push("qq_appid = ").push_bind(appid);
        separator = ", ";
        has_updates = true;
        fields.push("qq_appid");
    }
    if let Some(secret) = data.qq_app_secret {
        // 空串表示清空；非空值加密后入库。
        let stored = if secret.is_empty() {
            secret
        } else {
            encrypt_secret(&secret, state.config.app_secret_key.as_deref())
        };
        update
            .push(separator)
            .push("qq_app_secret = ")
            .push_bind(stored);
        separator = ", ";
        has_updates = true;
    }
    if let Some(host) = qq_host {
        update.push(separator).push("qq_host = ").push_bind(host);
        separator = ", ";
        has_updates = true;
        fields.push("qq_host");
    }
    if let Some(values) = openids {
        let value = Value::Array(values.into_iter().map(Value::String).collect());
        update
            .push(separator)
            .push("default_openids = ")
            .push_bind(value);
        separator = ", ";
        has_updates = true;
        fields.push("default_openids");
    }
    if let Some(group) = data.default_group_openid {
        let value = if group.is_empty() { None } else { Some(group) };
        update
            .push(separator)
            .push("default_group_openid = ")
            .push_bind(value);
        separator = ", ";
        has_updates = true;
        fields.push("default_group_openid");
    }
    if let Some(enabled) = data.enabled {
        update.push(separator).push("enabled = ").push_bind(enabled);
        has_updates = true;
        fields.push("enabled");
    }

    fields.sort_unstable();

    let mut tx = state.pool.begin().await?;
    if has_updates {
        update.push(" WHERE id = ").push_bind(bot.id);
        update.build().execute(&mut *tx).await?;
    }
    audit_tx(
        &mut tx,
        &actor,
        "bot.update",
        "bot_profile",
        Some(bot.id.to_string()),
        Some(json!({"fields": fields})),
        ip.as_deref(),
    )
    .await?;
    tx.commit().await?;

    Ok(HttpResponse::Ok().json(json!({"id": bot.id})))
}

/// `DELETE /api/admin/bot-profiles/{bot_id}`
async fn delete_bot(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<i64>,
) -> Result<HttpResponse, AppError> {
    let actor = require_user(&state, &req).await?;
    let bot = owned_bot(&state, &actor, path.into_inner()).await?;
    let ip = state.client_ip(&req);

    let mut tx = state.pool.begin().await?;
    // 与旧实现一致：先删通道，再删机器人（push_logs 的外键会置空）。
    sqlx::query("DELETE FROM channels WHERE bot_profile_id = ?")
        .bind(bot.id)
        .execute(&mut *tx)
        .await?;
    queries::bots::delete(&mut *tx, bot.id).await?;
    audit_tx(
        &mut tx,
        &actor,
        "bot.delete",
        "bot_profile",
        Some(bot.id.to_string()),
        None,
        ip.as_deref(),
    )
    .await?;
    tx.commit().await?;

    Ok(HttpResponse::Ok().json(json!({"ok": true})))
}

// ------------------------------------------------------------------------- 通道

/// `GET /api/admin/channels`
async fn list_channels(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> Result<HttpResponse, AppError> {
    let actor = require_user(&state, &req).await?;
    let settings = state.settings().clone();
    let base = webhook_base(&req, &settings);
    let owner = if users::is_super_admin(&actor) {
        None
    } else {
        Some(actor.id)
    };
    let rows = queries::channels::list_with_bot(&state.pool, owner).await?;

    let mut emails: HashMap<i64, String> = HashMap::new();
    let mut items = Vec::with_capacity(rows.len());
    for (channel, bot) in rows {
        let owner_email = match emails.get(&bot.owner_user_id) {
            Some(email) => email.clone(),
            None => {
                let email = queries::users::find_by_id(&state.pool, bot.owner_user_id)
                    .await?
                    .map(|user| user.email)
                    .unwrap_or_default();
                emails.insert(bot.owner_user_id, email.clone());
                email
            }
        };
        items.push(json!({
            "id": channel.id,
            "owner_user_id": bot.owner_user_id,
            "owner_email": owner_email,
            "platform": channel.platform,
            "bot_profile_id": channel.bot_profile_id,
            "webhook_token": channel.webhook_token,
            "webhook_url": webhook_url(&base, &channel.platform, &channel.webhook_token),
            "has_secret": channel_has_secret(&channel),
            "enabled": channel.enabled,
        }));
    }
    Ok(HttpResponse::Ok().json(items))
}

/// `POST /api/admin/channels`
async fn create_channel(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<ChannelIn>,
) -> Result<HttpResponse, AppError> {
    let actor = require_user(&state, &req).await?;
    let data = body.into_inner();
    if !PLATFORMS.contains(&data.platform.as_str()) {
        return Err(AppError::bad_request("平台不受支持"));
    }
    owned_bot(&state, &actor, data.bot_profile_id).await?;

    let mut secret_plain: Option<String> = None;
    let mut extra: Option<Value> = None;
    if data.platform == PLATFORM_GITHUB {
        let secret = data.secret.as_deref().unwrap_or("").trim().to_string();
        let secret = if secret.is_empty() {
            random_token(32)
        } else {
            secret
        };
        extra = Some(json!({
            "secret_cipher": encrypt_secret(&secret, state.config.app_secret_key.as_deref()),
        }));
        secret_plain = Some(secret);
    }

    let token = random_token(24);
    let now = Utc::now().naive_utc();
    let ip = state.client_ip(&req);

    let mut tx = state.pool.begin().await?;
    let channel_id = queries::channels::insert(
        &mut *tx,
        &NewChannel {
            bot_profile_id: data.bot_profile_id,
            platform: &data.platform,
            webhook_token: &token,
            enabled: data.enabled,
            extra: extra.as_ref(),
            created_at: now,
        },
    )
    .await?;
    audit_tx(
        &mut tx,
        &actor,
        "channel.create",
        "channel",
        Some(channel_id.to_string()),
        Some(json!({"platform": data.platform})),
        ip.as_deref(),
    )
    .await?;
    tx.commit().await?;

    let mut result = json!({"id": channel_id, "webhook_token": token.clone()});
    if let Some(secret) = secret_plain {
        let settings = state.settings().clone();
        let base = webhook_base(&req, &settings);
        result["webhook_url"] = Value::String(webhook_url(&base, PLATFORM_GITHUB, &token));
        result["secret"] = Value::String(secret);
    }
    Ok(HttpResponse::Created().json(result))
}

/// `PATCH /api/admin/channels/{channel_id}`
async fn patch_channel(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<i64>,
    body: web::Json<ChannelPatch>,
) -> Result<HttpResponse, AppError> {
    let actor = require_user(&state, &req).await?;
    let channel = owned_channel(&state, &actor, path.into_inner()).await?;
    let data = body.into_inner();

    let mut bot_profile_id = None;
    if let Some(value) = data.bot_profile_id {
        let bot = owned_bot(&state, &actor, value).await?;
        bot_profile_id = Some(bot.id);
    }
    let enabled = data.enabled;

    let ip = state.client_ip(&req);
    let mut tx = state.pool.begin().await?;
    if bot_profile_id.is_some() || enabled.is_some() {
        let mut update = QueryBuilder::<MySql>::new("UPDATE channels SET ");
        let mut separator = "";
        if let Some(value) = bot_profile_id {
            update
                .push(separator)
                .push("bot_profile_id = ")
                .push_bind(value);
            separator = ", ";
        }
        if let Some(value) = enabled {
            update.push(separator).push("enabled = ").push_bind(value);
        }
        update.push(" WHERE id = ").push_bind(channel.id);
        update.build().execute(&mut *tx).await?;
    }
    audit_tx(
        &mut tx,
        &actor,
        "channel.update",
        "channel",
        Some(channel.id.to_string()),
        None,
        ip.as_deref(),
    )
    .await?;
    tx.commit().await?;

    Ok(HttpResponse::Ok().json(json!({
        "id": channel.id,
        "enabled": enabled.unwrap_or(channel.enabled),
    })))
}

/// `POST /api/admin/channels/{channel_id}/rotate`
async fn rotate_channel(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<i64>,
) -> Result<HttpResponse, AppError> {
    let actor = require_user(&state, &req).await?;
    let channel = owned_channel(&state, &actor, path.into_inner()).await?;
    let token = random_token(24);

    let mut secret_plain: Option<String> = None;
    let mut extra: Option<Value> = channel.extra.clone();
    if channel.platform == PLATFORM_GITHUB {
        // GitHub 不支持自定义请求头，URL token 与签名密钥需同时轮换。
        let secret = random_token(32);
        let mut object = match extra.take() {
            Some(Value::Object(object)) => object,
            _ => serde_json::Map::new(),
        };
        object.insert(
            "secret_cipher".to_string(),
            Value::String(encrypt_secret(
                &secret,
                state.config.app_secret_key.as_deref(),
            )),
        );
        extra = Some(Value::Object(object));
        secret_plain = Some(secret);
    }

    let ip = state.client_ip(&req);
    let mut tx = state.pool.begin().await?;
    if channel.platform == PLATFORM_GITHUB {
        sqlx::query("UPDATE channels SET webhook_token = ?, extra = ? WHERE id = ?")
            .bind(&token)
            .bind(extra.as_ref())
            .bind(channel.id)
            .execute(&mut *tx)
            .await?;
    } else {
        queries::channels::update_webhook_token(&mut *tx, channel.id, &token).await?;
    }
    audit_tx(
        &mut tx,
        &actor,
        "channel.rotate_token",
        "channel",
        Some(channel.id.to_string()),
        None,
        ip.as_deref(),
    )
    .await?;
    tx.commit().await?;

    let mut result = json!({"id": channel.id, "webhook_token": token.clone()});
    if let Some(secret) = secret_plain {
        let settings = state.settings().clone();
        let base = webhook_base(&req, &settings);
        result["webhook_url"] = Value::String(webhook_url(&base, PLATFORM_GITHUB, &token));
        result["secret"] = Value::String(secret);
    }
    Ok(HttpResponse::Ok().json(result))
}

/// `DELETE /api/admin/channels/{channel_id}`
async fn delete_channel(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<i64>,
) -> Result<HttpResponse, AppError> {
    let actor = require_user(&state, &req).await?;
    let channel = owned_channel(&state, &actor, path.into_inner()).await?;
    let ip = state.client_ip(&req);

    let mut tx = state.pool.begin().await?;
    queries::channels::delete(&mut *tx, channel.id).await?;
    audit_tx(
        &mut tx,
        &actor,
        "channel.delete",
        "channel",
        Some(channel.id.to_string()),
        None,
        ip.as_deref(),
    )
    .await?;
    tx.commit().await?;

    Ok(HttpResponse::Ok().json(json!({"ok": true})))
}

// ------------------------------------------------------------------------- 日志

/// `GET /api/admin/logs`
async fn list_logs(req: HttpRequest, state: web::Data<AppState>) -> Result<HttpResponse, AppError> {
    let actor = require_user(&state, &req).await?;
    let params = query_params(&req);

    let page = parse_query_int(&params, "page", 1)?;
    let page_size = parse_query_int(&params, "page_size", 20)?;
    if page < 1 {
        return Err(AppError::validation("page 必须大于等于 1"));
    }
    if !(1..=200).contains(&page_size) {
        return Err(AppError::validation("page_size 需在 1 到 200 之间"));
    }
    let (page_size, offset) = queries::normalize_pagination(page, page_size);

    let platform = params.get("platform").filter(|value| !value.is_empty());
    let status = params.get("status").filter(|value| !value.is_empty());
    let keyword = params.get("keyword").filter(|value| !value.is_empty());
    let owner_user_id = if users::is_super_admin(&actor) {
        None
    } else {
        Some(actor.id)
    };

    let filter = queries::push_logs::PushLogFilter {
        owner_user_id,
        platform: platform.map(String::as_str),
        status: status.map(String::as_str),
        keyword: keyword.map(String::as_str),
        since: None,
        until: None,
    };
    let total = queries::push_logs::count(&state.pool, &filter).await?;
    let rows = queries::push_logs::list(&state.pool, &filter, page_size, offset).await?;

    let items: Vec<Value> = rows
        .into_iter()
        .map(|(row, owner_email)| log_json(&row, Some(owner_email)))
        .collect();
    Ok(HttpResponse::Ok().json(json!({
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": items,
    })))
}

/// `GET /api/admin/logs/{log_id}`
async fn get_log(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<i64>,
) -> Result<HttpResponse, AppError> {
    let actor = require_user(&state, &req).await?;
    let Some(row) = queries::push_logs::find_by_id(&state.pool, path.into_inner()).await? else {
        return Err(AppError::not_found("日志不存在"));
    };
    if row.owner_user_id != actor.id && !users::is_super_admin(&actor) {
        return Err(AppError::not_found("日志不存在"));
    }
    let owner_email = queries::users::find_by_id(&state.pool, row.owner_user_id)
        .await?
        .map(|user| user.email);
    Ok(HttpResponse::Ok().json(log_json(&row, owner_email)))
}

/// 日志响应体。
fn log_json(row: &PushLog, owner_email: Option<String>) -> Value {
    json!({
        "id": row.id,
        "owner_user_id": row.owner_user_id,
        "owner_email": owner_email,
        "platform": row.platform,
        "source_msgtype": row.source_msgtype,
        "target": row.target,
        "qq_msg_type": row.qq_msg_type,
        "content_preview": row.content_preview,
        "content_len": row.content_len,
        "status": row.status,
        "error_code": row.error_code,
        "error_message": row.error_message,
        "duration_ms": row.duration_ms,
        "request_id": row.request_id,
        "created_at": isoformat(row.created_at),
    })
}

/// 读取查询参数中的整数；缺失时使用默认值。
fn parse_query_int(
    params: &HashMap<String, String>,
    key: &str,
    default: i64,
) -> Result<i64, AppError> {
    match params.get(key) {
        None => Ok(default),
        Some(raw) => raw
            .parse::<i64>()
            .map_err(|_| AppError::validation(format!("{key} 必须为整数"))),
    }
}

// ------------------------------------------------------------------------- 用户

/// `GET /api/admin/users`
async fn list_users(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> Result<HttpResponse, AppError> {
    let actor = require_user(&state, &req).await?;
    let rows = users::list_users(&state.pool, &actor).await?;
    let items: Vec<Value> = rows
        .into_iter()
        .map(|row| {
            json!({
                "id": row.id,
                "email": row.email,
                "name": row.name,
                "role": row.role,
                "status": row.status,
                "last_login_at": isoformat_opt(row.last_login_at),
            })
        })
        .collect();
    Ok(HttpResponse::Ok().json(items))
}

/// `PATCH /api/admin/users/{user_id}`
async fn patch_user(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<i64>,
    body: web::Json<UserPatch>,
) -> Result<HttpResponse, AppError> {
    let actor = require_user(&state, &req).await?;
    let data = body.into_inner();
    if let Some(name) = data.name.as_deref() {
        ensure_max_length("用户名", name, USER_NAME_MAX)?;
    }
    let ip = state.client_ip(&req);
    let target = users::admin_update_user(
        &state.pool,
        &actor,
        path.into_inner(),
        AdminUserPatch {
            role: data.role.as_deref(),
            status: data.status.as_deref(),
            name: data.name.as_deref(),
        },
        ip.as_deref(),
    )
    .await?;
    Ok(HttpResponse::Ok().json(json!({"id": target.id})))
}

// ----------------------------------------------------------------------- 邀请码

/// `GET /api/admin/invites`
async fn list_invites(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> Result<HttpResponse, AppError> {
    let actor = require_user(&state, &req).await?;
    users::require_super_admin(&actor)?;
    let rows = queries::invites::list_desc(&state.pool).await?;
    let items: Vec<Value> = rows
        .into_iter()
        .map(|row| {
            json!({
                "id": row.id,
                "code": row.code,
                "email": row.email,
                "max_uses": row.max_uses,
                "used_count": row.used_count,
                "expires_at": isoformat_opt(row.expires_at),
                "revoked": row.revoked_at.is_some(),
                "created_at": isoformat(row.created_at),
            })
        })
        .collect();
    Ok(HttpResponse::Ok().json(items))
}

/// `POST /api/admin/invites`
async fn create_invite(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<InviteIn>,
) -> Result<HttpResponse, AppError> {
    let actor = require_user(&state, &req).await?;
    users::require_super_admin(&actor)?;
    let data = body.into_inner();
    if !(1..=100).contains(&data.max_uses) {
        return Err(AppError::validation("max_uses 需在 1 到 100 之间"));
    }
    if !(1..=365).contains(&data.expires_in_days) {
        return Err(AppError::validation("expires_in_days 需在 1 到 365 之间"));
    }

    let now = Utc::now().naive_utc();
    let code = random_token(16);
    let expires_at = now + ChronoDuration::days(data.expires_in_days);
    let email = data
        .email
        .filter(|value| !value.is_empty())
        .map(|value| value.to_lowercase());
    let ip = state.client_ip(&req);

    let mut tx = state.pool.begin().await?;
    let invite_id = queries::invites::insert(
        &mut *tx,
        &NewInviteCode {
            code: &code,
            email: email.as_deref(),
            max_uses: data.max_uses as i32,
            expires_at: Some(expires_at),
            created_by: Some(actor.id),
            created_at: now,
        },
    )
    .await?;
    audit_tx(
        &mut tx,
        &actor,
        "invite.create",
        "invite",
        Some(code.clone()),
        Some(json!({"max_uses": data.max_uses})),
        ip.as_deref(),
    )
    .await?;
    tx.commit().await?;

    Ok(HttpResponse::Created().json(json!({
        "id": invite_id,
        "code": code,
        // 旧实现返回的是刚构造的 aware UTC 时间，isoformat() 带 `+00:00`。
        "expires_at": format!("{}+00:00", isoformat(expires_at)),
    })))
}

/// `DELETE /api/admin/invites/{invite_id}`
async fn revoke_invite(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<i64>,
) -> Result<HttpResponse, AppError> {
    let actor = require_user(&state, &req).await?;
    users::require_super_admin(&actor)?;
    let invite_id = path.into_inner();
    let now = Utc::now().naive_utc();
    let ip = state.client_ip(&req);

    let mut tx = state.pool.begin().await?;
    let exists: Option<i64> = sqlx::query_scalar("SELECT id FROM invite_codes WHERE id = ?")
        .bind(invite_id)
        .fetch_optional(&mut *tx)
        .await?;
    if exists.is_none() {
        return Err(AppError::not_found("邀请码不存在"));
    }
    queries::invites::revoke(&mut *tx, invite_id, now).await?;
    audit_tx(
        &mut tx,
        &actor,
        "invite.revoke",
        "invite",
        Some(invite_id.to_string()),
        None,
        ip.as_deref(),
    )
    .await?;
    tx.commit().await?;

    Ok(HttpResponse::Ok().json(json!({"ok": true})))
}

// --------------------------------------------------------------------- 安全设置

/// `GET /api/admin/oauth-providers`
async fn list_oauth_providers(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> Result<HttpResponse, AppError> {
    let actor = require_user(&state, &req).await?;
    users::require_super_admin(&actor)?;
    let rows = queries::oauth::list_all(&state.pool).await?;
    let items: Vec<Value> = rows
        .into_iter()
        .map(|row| {
            json!({
                "id": row.id,
                "key": row.key,
                "display_name": row.display_name,
                "client_id": row.client_id,
                "client_secret_masked": mask_secret(&row.client_secret),
                "authorization_url": row.authorization_url,
                "token_url": row.token_url,
                "userinfo_url": row.userinfo_url,
                "scopes": row.scopes,
                "email_field": row.email_field,
                "id_field": row.id_field,
                "name_field": row.name_field,
                "enabled": row.enabled,
                "email_verified": row.email_verified,
            })
        })
        .collect();
    Ok(HttpResponse::Ok().json(items))
}

/// `POST /api/admin/oauth-providers`
async fn create_oauth_provider(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<OAuthIn>,
) -> Result<HttpResponse, AppError> {
    let actor = require_user(&state, &req).await?;
    users::require_super_admin(&actor)?;
    let data = body.into_inner();

    ensure_min_length("key", &data.key, 1)?;
    ensure_max_length("key", &data.key, 64)?;
    ensure_min_length("display_name", &data.display_name, 1)?;
    ensure_max_length("display_name", &data.display_name, 128)?;
    ensure_min_length("client_id", &data.client_id, 1)?;
    ensure_max_length("client_id", &data.client_id, 255)?;
    ensure_min_length("client_secret", &data.client_secret, 1)?;
    ensure_max_length("client_secret", &data.client_secret, 512)?;

    let mut authorization_url = data.authorization_url;
    let mut token_url = data.token_url;
    let mut userinfo_url = data.userinfo_url;
    let mut scopes = data.scopes.clone();
    let mut email_field = data.email_field.clone();
    let mut id_field = data.id_field.clone();
    let mut name_field = data.name_field.clone();
    let preset = data.use_github_preset && data.key == "github";
    if preset {
        if authorization_url.is_empty() {
            authorization_url = GITHUB_PRESET_AUTHORIZATION_URL.to_string();
        }
        if token_url.is_empty() {
            token_url = GITHUB_PRESET_TOKEN_URL.to_string();
        }
        if userinfo_url.is_empty() {
            userinfo_url = GITHUB_PRESET_USERINFO_URL.to_string();
        }
        if scopes.is_empty() {
            scopes = GITHUB_PRESET_SCOPES.to_string();
        }
        if email_field.is_empty() {
            email_field = GITHUB_PRESET_EMAIL_FIELD.to_string();
        }
        if id_field.is_empty() {
            id_field = GITHUB_PRESET_ID_FIELD.to_string();
        }
        if name_field.is_empty() {
            name_field = GITHUB_PRESET_NAME_FIELD.to_string();
        }
    }

    for (field, value) in [
        ("authorization_url", authorization_url.as_str()),
        ("token_url", token_url.as_str()),
        ("userinfo_url", userinfo_url.as_str()),
    ] {
        if value.is_empty() {
            return Err(AppError::bad_request(format!("{field} 不能为空")));
        }
        require_https(value)?;
    }

    if queries::oauth::find_by_key(&state.pool, &data.key)
        .await?
        .is_some()
    {
        return Err(AppError::conflict("提供方已存在"));
    }

    let email_verified = if preset {
        data.email_verified.unwrap_or(true)
    } else {
        data.email_verified.unwrap_or(false)
    };
    let encrypted = encrypt_secret(&data.client_secret, state.config.app_secret_key.as_deref());
    let now = Utc::now().naive_utc();
    let ip = state.client_ip(&req);

    let mut tx = state.pool.begin().await?;
    let result = sqlx::query(
        "INSERT INTO oauth_providers (`key`, display_name, client_id, client_secret, \
         authorization_url, token_url, userinfo_url, scopes, email_field, id_field, name_field, \
         enabled, email_verified, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&data.key)
    .bind(&data.display_name)
    .bind(&data.client_id)
    .bind(&encrypted)
    .bind(&authorization_url)
    .bind(&token_url)
    .bind(&userinfo_url)
    .bind(&scopes)
    .bind(&email_field)
    .bind(&id_field)
    .bind(&name_field)
    .bind(data.enabled)
    .bind(email_verified)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    let provider_id = result.last_insert_id() as i64;
    audit_tx(
        &mut tx,
        &actor,
        "oauth.create",
        "oauth_provider",
        Some(data.key.clone()),
        None,
        ip.as_deref(),
    )
    .await?;
    tx.commit().await?;

    Ok(HttpResponse::Created().json(json!({"id": provider_id, "key": data.key})))
}

/// `PATCH /api/admin/oauth-providers/{provider_id}`
async fn patch_oauth_provider(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<i64>,
    body: web::Json<OAuthPatch>,
) -> Result<HttpResponse, AppError> {
    let actor = require_user(&state, &req).await?;
    users::require_super_admin(&actor)?;
    let provider_id = path.into_inner();
    let Some(row) = queries::oauth::list_all(&state.pool)
        .await?
        .into_iter()
        .find(|row| row.id == provider_id)
    else {
        return Err(AppError::not_found("提供方不存在"));
    };
    let data = body.into_inner();

    for value in [
        data.authorization_url.as_deref(),
        data.token_url.as_deref(),
        data.userinfo_url.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if !value.is_empty() {
            require_https(value)?;
        }
    }

    let mut fields: Vec<&'static str> = Vec::new();
    let mut has_updates = false;
    let mut update = QueryBuilder::<MySql>::new("UPDATE oauth_providers SET ");
    let mut separator = "";

    if let Some(value) = data.display_name {
        update
            .push(separator)
            .push("display_name = ")
            .push_bind(value);
        separator = ", ";
        has_updates = true;
        fields.push("display_name");
    }
    if let Some(value) = data.client_id {
        update.push(separator).push("client_id = ").push_bind(value);
        separator = ", ";
        has_updates = true;
        fields.push("client_id");
    }
    if let Some(value) = data.client_secret {
        let stored = if value.is_empty() {
            value
        } else {
            encrypt_secret(&value, state.config.app_secret_key.as_deref())
        };
        update
            .push(separator)
            .push("client_secret = ")
            .push_bind(stored);
        separator = ", ";
        has_updates = true;
    }
    if let Some(value) = data.authorization_url {
        update
            .push(separator)
            .push("authorization_url = ")
            .push_bind(value);
        separator = ", ";
        has_updates = true;
        fields.push("authorization_url");
    }
    if let Some(value) = data.token_url {
        update.push(separator).push("token_url = ").push_bind(value);
        separator = ", ";
        has_updates = true;
        fields.push("token_url");
    }
    if let Some(value) = data.userinfo_url {
        update
            .push(separator)
            .push("userinfo_url = ")
            .push_bind(value);
        separator = ", ";
        has_updates = true;
        fields.push("userinfo_url");
    }
    if let Some(value) = data.scopes {
        update.push(separator).push("scopes = ").push_bind(value);
        separator = ", ";
        has_updates = true;
        fields.push("scopes");
    }
    if let Some(value) = data.email_field {
        update
            .push(separator)
            .push("email_field = ")
            .push_bind(value);
        separator = ", ";
        has_updates = true;
        fields.push("email_field");
    }
    if let Some(value) = data.id_field {
        update.push(separator).push("id_field = ").push_bind(value);
        separator = ", ";
        has_updates = true;
        fields.push("id_field");
    }
    if let Some(value) = data.name_field {
        update
            .push(separator)
            .push("name_field = ")
            .push_bind(value);
        separator = ", ";
        has_updates = true;
        fields.push("name_field");
    }
    if let Some(value) = data.enabled {
        update.push(separator).push("enabled = ").push_bind(value);
        separator = ", ";
        has_updates = true;
        fields.push("enabled");
    }
    if let Some(value) = data.email_verified {
        update
            .push(separator)
            .push("email_verified = ")
            .push_bind(value);
        has_updates = true;
        fields.push("email_verified");
    }

    fields.sort_unstable();
    let ip = state.client_ip(&req);

    let mut tx = state.pool.begin().await?;
    if has_updates {
        update.push(" WHERE id = ").push_bind(row.id);
        update.build().execute(&mut *tx).await?;
    }
    audit_tx(
        &mut tx,
        &actor,
        "oauth.update",
        "oauth_provider",
        Some(row.key.clone()),
        Some(json!({"fields": fields})),
        ip.as_deref(),
    )
    .await?;
    tx.commit().await?;

    Ok(HttpResponse::Ok().json(json!({"id": row.id})))
}

/// `DELETE /api/admin/oauth-providers/{provider_id}`
async fn delete_oauth_provider(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<i64>,
) -> Result<HttpResponse, AppError> {
    let actor = require_user(&state, &req).await?;
    users::require_super_admin(&actor)?;
    let provider_id = path.into_inner();
    let Some(row) = queries::oauth::list_all(&state.pool)
        .await?
        .into_iter()
        .find(|row| row.id == provider_id)
    else {
        return Err(AppError::not_found("提供方不存在"));
    };
    let ip = state.client_ip(&req);

    let mut tx = state.pool.begin().await?;
    sqlx::query("DELETE FROM oauth_providers WHERE id = ?")
        .bind(row.id)
        .execute(&mut *tx)
        .await?;
    audit_tx(
        &mut tx,
        &actor,
        "oauth.delete",
        "oauth_provider",
        Some(row.key.clone()),
        None,
        ip.as_deref(),
    )
    .await?;
    tx.commit().await?;

    Ok(HttpResponse::Ok().json(json!({"ok": true})))
}

/// 提供方 URL 必须是 https（本地开发允许 localhost）。
fn require_https(value: &str) -> Result<(), AppError> {
    if value.starts_with("https://")
        || value.starts_with("http://localhost")
        || value.starts_with("http://127.0.0.1")
    {
        Ok(())
    } else {
        Err(AppError::bad_request(
            "提供方 URL 必须为 https（本地开发可用 localhost）",
        ))
    }
}

// --------------------------------------------------------------------- 系统设置

/// `GET /api/admin/settings`
async fn get_settings(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> Result<HttpResponse, AppError> {
    let actor = require_user(&state, &req).await?;
    users::require_super_admin(&actor)?;
    let runtime = state.settings();
    Ok(HttpResponse::Ok().json(settings_payload(&runtime)))
}

/// `PATCH /api/admin/settings`
async fn patch_settings(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<Value>,
) -> Result<HttpResponse, AppError> {
    let actor = require_user(&state, &req).await?;
    users::require_super_admin(&actor)?;
    let Value::Object(changes) = body.into_inner() else {
        return Err(AppError::validation("请求体必须是 JSON 对象"));
    };

    let values = {
        let runtime = state.settings();
        runtime.validate(&changes)?
    };
    if values.is_empty() {
        let runtime = state.settings();
        return Ok(HttpResponse::Ok().json(settings_payload(&runtime)));
    }

    {
        let runtime = state.settings().clone();
        runtime.persist(&state.pool, &values).await?;
    }

    let mut detail = serde_json::Map::new();
    for (key, value) in &values {
        let rendered = if runtime_settings::spec(key).is_some_and(|item| item.secret) {
            "******".to_string()
        } else {
            setting_display(value)
        };
        detail.insert(key.clone(), Value::String(rendered));
    }
    let ip = state.client_ip(&req);
    audit::record_audit(
        &state.pool,
        AuditEntry {
            actor_user_id: Some(actor.id),
            action: "settings.update",
            target_type: Some("system_setting"),
            target_id: None,
            detail: Some(json!({"values": Value::Object(detail)})),
            ip: ip.as_deref(),
        },
    )
    .await?;

    {
        let mut runtime = state
            .runtime
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        runtime.apply(&values);
        runtime.apply_side_effects(&state.limiters, &state.login_limiter);
    }

    let runtime = state.settings();
    Ok(HttpResponse::Ok().json(settings_payload(&runtime)))
}

/// 管理端设置视图（`kind` 沿用前端契约的 `"string"` 拼写）。
fn settings_payload(runtime: &RuntimeSettings) -> Value {
    let groups: Vec<Value> = runtime
        .describe_groups()
        .into_iter()
        .map(|group| {
            let items: Vec<Value> = group
                .items
                .into_iter()
                .map(|item| {
                    json!({
                        "key": item.key,
                        "label": item.label,
                        "description": item.description,
                        "kind": kind_name(item.kind),
                        "value": item.value,
                        "default": item.default,
                        "minimum": item.minimum,
                        "maximum": item.maximum,
                        "options": item.options,
                        "source": item.source,
                        "secret": item.secret,
                        "has_value": item.has_value,
                    })
                })
                .collect();
            json!({"name": group.name, "items": items})
        })
        .collect();
    json!({
        "register_enabled": runtime.register_enabled(),
        "register_enabled_source": match runtime.source_of("register_enabled") {
            SettingSource::Database => "database",
            _ => "env",
        },
        "env_default": register_env_default(),
        "groups": groups,
    })
}

/// 未显式设置时关闭注册，与系统设置目录的默认值一致。
fn register_env_default() -> bool {
    std::env::var("REGISTER_ENABLED")
        .map(|raw| {
            matches!(
                raw.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on" | "y" | "t"
            )
        })
        .unwrap_or(false)
}

fn kind_name(kind: SettingKind) -> &'static str {
    match kind {
        SettingKind::Bool => "bool",
        SettingKind::Int => "int",
        SettingKind::Float => "float",
        SettingKind::Str => "string",
        SettingKind::Select => "select",
    }
}

fn setting_display(value: &SettingValue) -> String {
    match value {
        SettingValue::Bool(value) => {
            if *value {
                "True".to_string()
            } else {
                "False".to_string()
            }
        }
        SettingValue::Int(value) => value.to_string(),
        SettingValue::Float(value) => value.to_string(),
        SettingValue::Str(value) => value.clone(),
    }
}

// ------------------------------------------------------------------------- 统计

/// `GET /api/admin/stats`
async fn get_stats(req: HttpRequest, state: web::Data<AppState>) -> Result<HttpResponse, AppError> {
    let actor = require_user(&state, &req).await?;
    let super_admin = users::is_super_admin(&actor);
    let owner_user_id = if super_admin { None } else { Some(actor.id) };
    let timezone = state.settings().timezone().to_string();

    let now = Utc::now().naive_utc();
    let today = local_date(&timezone, now);
    let start = local_midnight_utc(today, &timezone);
    let end = local_midnight_utc(today + ChronoDuration::days(1), &timezone);

    let total_today =
        queries::push_logs::count_between(&state.pool, owner_user_id, start, end, None).await?;
    let success_today =
        queries::push_logs::count_between(&state.pool, owner_user_id, start, end, Some("success"))
            .await?;
    let recent_failures =
        queries::push_logs::recent_failures(&state.pool, owner_user_id, 5).await?;
    let by_platform =
        queries::push_logs::platform_counts_between(&state.pool, owner_user_id, start, end).await?;

    let mut trend = Vec::with_capacity(7);
    for offset in (0..7).rev() {
        let day = today - ChronoDuration::days(offset);
        let day_start = local_midnight_utc(day, &timezone);
        let day_end = local_midnight_utc(day + ChronoDuration::days(1), &timezone);
        let count =
            queries::push_logs::count_between(&state.pool, owner_user_id, day_start, day_end, None)
                .await?;
        trend.push(json!({
            "date": day.format("%Y-%m-%d").to_string(),
            "count": count,
        }));
    }

    let success_rate = if total_today > 0 {
        (success_today as f64 / total_today as f64 * 10_000.0).round() / 10_000.0
    } else {
        0.0
    };
    let platforms: Vec<Value> = by_platform
        .into_iter()
        .map(|(platform, count)| json!({"platform": platform, "count": count}))
        .collect();
    let failures: Vec<Value> = recent_failures
        .into_iter()
        .map(|row| {
            json!({
                "id": row.id,
                "platform": row.platform,
                "target": row.target,
                "error_code": row.error_code,
                "error_message": row.error_message,
                "created_at": isoformat(row.created_at),
            })
        })
        .collect();

    Ok(HttpResponse::Ok().json(json!({
        "scope": if super_admin { "all" } else { "mine" },
        "today": {"total": total_today, "success": success_today},
        "success_rate": success_rate,
        "by_platform": platforms,
        "trend": trend,
        "recent_failures": failures,
    })))
}

// --------------------------------------------------------------------- 时区

/// 业务时区在某一 UTC 时间戳的偏移（秒，东为正）。
///
/// 优先读取系统 tzdata（容器内已安装）；Windows 开发环境没有 zoneinfo，
/// 退回进程本地时区（`TZ` 环境变量或系统设置）。
fn timezone_offset(zone: &str, at: i64) -> i32 {
    let name = zone.trim();
    if name.is_empty() {
        return local_offset();
    }
    if name.eq_ignore_ascii_case("UTC")
        || name.eq_ignore_ascii_case("Etc/UTC")
        || name.eq_ignore_ascii_case("GMT")
        || name == "Z"
    {
        return 0;
    }
    if valid_zone_name(name) {
        for root in ["/usr/share/zoneinfo", "/usr/lib/zoneinfo", "/etc/zoneinfo"] {
            if let Ok(data) = std::fs::read(format!("{root}/{name}"))
                && let Some(offset) = parse_tzif(&data, at)
            {
                return offset;
            }
        }
    }
    local_offset()
}

fn local_offset() -> i32 {
    Local::now().offset().local_minus_utc()
}

/// 只允许安全的相对路径，避免 `..` 穿越。
fn valid_zone_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('/')
        && !name.contains("..")
        && name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '/' | '_' | '-' | '+' | '.'))
}

/// 当前业务日期。
fn local_date(zone: &str, now_utc: NaiveDateTime) -> NaiveDate {
    let offset = timezone_offset(zone, now_utc.and_utc().timestamp());
    (now_utc + ChronoDuration::seconds(offset as i64)).date()
}

/// 业务时区某一天零点对应的 UTC 时刻（naive UTC）。
fn local_midnight_utc(day: NaiveDate, zone: &str) -> NaiveDateTime {
    let naive = day.and_hms_opt(0, 0, 0).expect("日期零点始终是合法时间");
    let guess = naive.and_utc().timestamp();
    let first = timezone_offset(zone, guess);
    let offset = timezone_offset(zone, guess - first as i64);
    naive - ChronoDuration::seconds(offset as i64)
}

/// 读取 TZif 文件，返回指定时刻适用的 UTC 偏移（秒）。
fn parse_tzif(data: &[u8], at: i64) -> Option<i32> {
    fn read_header(data: &[u8], position: usize) -> Option<(u8, [usize; 6], usize)> {
        if position + 44 > data.len() || &data[position..position + 4] != b"TZif" {
            return None;
        }
        let version = data[position + 4];
        let mut counts = [0usize; 6];
        for (index, slot) in counts.iter_mut().enumerate() {
            let start = position + 20 + index * 4;
            *slot = u32::from_be_bytes(data[start..start + 4].try_into().ok()?) as usize;
        }
        Some((version, counts, position + 44))
    }

    fn block_size(counts: [usize; 6], time_size: usize) -> Option<usize> {
        let [isut, isstd, leap, timecnt, typecnt, charcnt] = counts;
        let mut total = 0usize;
        total = total.checked_add(timecnt.checked_mul(time_size)?)?;
        total = total.checked_add(timecnt)?;
        total = total.checked_add(typecnt.checked_mul(6)?)?;
        total = total.checked_add(charcnt)?;
        total = total.checked_add(leap.checked_mul(time_size + 4)?)?;
        total = total.checked_add(isstd)?;
        total = total.checked_add(isut)?;
        Some(total)
    }

    let (version, counts, start) = read_header(data, 0)?;
    let (counts, start, time_size) = if version >= b'2' {
        let next = start + block_size(counts, 4)?;
        let (_, counts, start) = read_header(data, next)?;
        (counts, start, 8usize)
    } else {
        (counts, start, 4usize)
    };

    let [_, _, _, timecnt, typecnt, _] = counts;
    if typecnt == 0 {
        return None;
    }
    let transitions_end = start.checked_add(timecnt.checked_mul(time_size)?)?;
    let indices_start = transitions_end;
    let info_start = indices_start.checked_add(timecnt)?;
    if info_start.checked_add(typecnt.checked_mul(6)?)? > data.len() {
        return None;
    }

    let read_time = |index: usize| -> Option<i64> {
        let position = start + index * time_size;
        if time_size == 4 {
            Some(i32::from_be_bytes(data[position..position + 4].try_into().ok()?) as i64)
        } else {
            Some(i64::from_be_bytes(
                data[position..position + 8].try_into().ok()?,
            ))
        }
    };

    let type_index = if timecnt == 0 {
        // 没有转换记录时使用第一个标准时间类型（规范建议）。
        (0..typecnt)
            .find(|&index| data[info_start + index * 6 + 4] == 0)
            .unwrap_or(0)
    } else if at < read_time(0)? {
        (0..typecnt)
            .find(|&index| data[info_start + index * 6 + 4] == 0)
            .unwrap_or(0)
    } else {
        // 找到最后一个 <= at 的转换。
        let mut low = 0usize;
        let mut high = timecnt;
        while low < high {
            let middle = (low + high) / 2;
            if read_time(middle)? <= at {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        let index = data[indices_start + low - 1] as usize;
        if index < typecnt { index } else { 0 }
    };

    let position = info_start + type_index * 6;
    Some(i32::from_be_bytes(
        data[position..position + 4].try_into().ok()?,
    ))
}
