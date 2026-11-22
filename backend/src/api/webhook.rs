//! Webhook 接收端点（`/webhook`）。
//!
//! 端点清单：
//! - `POST /webhook/{hook_type}` —— `hook_type ∈ {dingtalk,wecom,feishu,github}`
//! - `POST /webhook/github/{token}` —— GitHub 专用（token 在路径）
//!
//! 行为要点：请求体上限、token 提取顺序、
//! GitHub 签名校验、钩子响应体形状、队列优先与同步降级。

use std::sync::OnceLock;
use std::time::{Duration, Instant};

use actix_web::http::StatusCode;
use actix_web::http::header::{AUTHORIZATION, CONTENT_LENGTH};
use actix_web::{HttpRequest, HttpResponse, web};
use dashmap::DashMap;
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::adapters::{
    Adapter, AdapterError, DingTalkAdapter, FeishuAdapter, GitHubAdapter, UnifiedMessage,
    WeComAdapter,
};
use crate::crypto::decrypt_secret;
use crate::db::models::{BotProfile, Channel, HOOK_TYPE_GITHUB, HOOK_TYPES};
use crate::db::queries;
use crate::error::AppError;
use crate::markdown::truncate;
use crate::renderer::{MSG_TYPE_MARKDOWN, QqPayload, render_qq_with_limits};
use crate::services::push::{PushJob, execute_push};
use crate::services::qq::QqTarget;
use crate::services::queue::{QueueError, dedupe_key};
use crate::state::AppState;

/// 默认目标数量上限。
const MAX_FANOUT: usize = 50;
/// 单个目标 openid 长度上限。
const MAX_TARGET_LEN: usize = 128;
/// 钩子事件头。
const GITHUB_EVENT_HEADER: &str = "X-GitHub-Event";
/// 钩子投递 ID 头。
const GITHUB_DELIVERY_HEADER: &str = "X-GitHub-Delivery";
/// GitHub 签名头。
const GITHUB_SIGNATURE_HEADER: &str = "X-Hub-Signature-256";
/// Webhook 凭据头。
const WEBHOOK_TOKEN_HEADER: &str = "X-Webhook-Token";
/// 推送调试标记头：存在时来源标注固定为「推送调试」。
const DEBUG_PUSH_HEADER: &str = "X-QBot-Debug";
/// 推送调试的来源标注。
const DEBUG_PUSH_SOURCE: &str = "推送调试";

/// 注册 Webhook 路由。
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/webhook")
            .route("/github/{token}", web::post().to(github_webhook))
            .route("/{hook_type}", web::post().to(receive_webhook)),
    );
}

// --------------------------------------------------------------------- 处理器

/// `POST /webhook/{hook_type}`
async fn receive_webhook(
    path: web::Path<String>,
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Payload,
) -> Result<HttpResponse, AppError> {
    let hook_type = path.into_inner();
    if !HOOK_TYPES.contains(&hook_type.as_str()) {
        // 路径段来自外部输入，不回显以避免反射型注入。
        return Ok(hook_type_response(
            &hook_type,
            StatusCode::NOT_FOUND,
            404,
            "未知钩子类型",
        ));
    }
    if hook_type == HOOK_TYPE_GITHUB {
        return Ok(hook_type_response(
            &hook_type,
            StatusCode::NOT_FOUND,
            404,
            "GitHub 通道请使用 /webhook/github/{token}",
        ));
    }
    receive(&req, &state, body, &hook_type, None).await
}

/// `POST /webhook/github/{token}`
async fn github_webhook(
    path: web::Path<String>,
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Payload,
) -> Result<HttpResponse, AppError> {
    let token = path.into_inner();
    receive(&req, &state, body, HOOK_TYPE_GITHUB, Some(&token)).await
}

// ------------------------------------------------------------------ 核心流程

/// Webhook 主流程；`path_token` 仅 GitHub 路径路由提供。
async fn receive(
    req: &HttpRequest,
    state: &AppState,
    body: web::Payload,
    hook_type: &str,
    path_token: Option<&str>,
) -> Result<HttpResponse, AppError> {
    let settings = state.settings().clone();
    let limit = if hook_type == HOOK_TYPE_GITHUB {
        settings.github_max_body_bytes()
    } else {
        settings.max_body_bytes()
    };

    // 鉴权先于读体：缺乏凭据的请求在消耗内存读体之前就被拒绝；
    // GitHub 的签名校验依赖原始请求体，仍保持在读体之后。
    let token = extract_token(req, path_token, settings.webhook_allow_query_token());
    if token.is_empty() {
        return Ok(hook_type_response(
            hook_type,
            StatusCode::UNAUTHORIZED,
            401,
            "缺少 webhook token",
        ));
    }

    let Some(channel) =
        queries::channels::find_enabled_for_hook_type(&state.pool, hook_type, &token).await?
    else {
        return Ok(hook_type_response(
            hook_type,
            StatusCode::UNAUTHORIZED,
            401,
            "token 无效或通道已停用",
        ));
    };

    // 先看 Content-Length，避免把明显超限的请求体读进内存。
    if let Some(declared) = req
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        && declared.bytes().all(|byte| byte.is_ascii_digit())
        && declared
            .parse::<u64>()
            .is_ok_and(|length| length > limit as u64)
    {
        return Ok(hook_type_response(
            hook_type,
            StatusCode::PAYLOAD_TOO_LARGE,
            413,
            "请求体过大",
        ));
    }

    let raw = match body.to_bytes_limited(limit).await {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(_)) => {
            return Ok(hook_type_response(
                hook_type,
                StatusCode::BAD_REQUEST,
                400,
                "请求体读取失败",
            ));
        }
        Err(_) => {
            return Ok(hook_type_response(
                hook_type,
                StatusCode::PAYLOAD_TOO_LARGE,
                413,
                "请求体过大",
            ));
        }
    };

    if hook_type == HOOK_TYPE_GITHUB
        && let Some((status, message)) =
            verify_github_signature(&channel, req, &raw, state.config.app_secret_key.as_deref())
    {
        return Ok(hook_type_response(
            hook_type,
            status,
            status.as_u16(),
            message,
        ));
    }

    if hook_type == HOOK_TYPE_GITHUB
        && let Some((status, message)) = reject_replayed_delivery(&channel, req)
    {
        return Ok(hook_type_response(
            hook_type,
            status,
            status.as_u16(),
            message,
        ));
    }

    let payload: Value = if raw.is_empty() {
        json!({})
    } else {
        match serde_json::from_slice(&raw) {
            Ok(payload) => payload,
            Err(_) => {
                return Ok(hook_type_response(
                    hook_type,
                    StatusCode::BAD_REQUEST,
                    400,
                    "请求体不是合法 JSON",
                ));
            }
        }
    };

    let Some(bot) = queries::bots::find_enabled_by_id(&state.pool, channel.bot_profile_id).await?
    else {
        return Ok(hook_type_response(
            hook_type,
            StatusCode::BAD_GATEWAY,
            502,
            "机器人配置不可用",
        ));
    };

    let event = if hook_type == HOOK_TYPE_GITHUB {
        req.headers()
            .get(GITHUB_EVENT_HEADER)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
    } else {
        ""
    };
    let message = match parse_message(hook_type, &payload, event) {
        Ok(message) => message,
        Err(AdapterError::Ignored(reason)) => {
            // 未订阅的事件按成功确认，避免钩子判定投递失败并重试。
            return Ok(hook_type_response(
                hook_type,
                StatusCode::OK,
                0,
                reason.0.as_str(),
            ));
        }
        Err(AdapterError::Payload(reason)) => {
            return Ok(hook_type_response(
                hook_type,
                StatusCode::BAD_REQUEST,
                400,
                reason.0.as_str(),
            ));
        }
    };

    let targets = resolve_targets(&payload, &bot);
    if targets.is_empty() {
        return Ok(hook_type_response(
            hook_type,
            StatusCode::BAD_REQUEST,
            400,
            "未指定推送目标且机器人未配置默认目标",
        ));
    }

    if decrypt_secret(&bot.qq_app_secret, state.config.app_secret_key.as_deref()).is_err() {
        return Ok(hook_type_response(
            hook_type,
            StatusCode::BAD_GATEWAY,
            502,
            "机器人密钥无法解密，请检查 APP_SECRET_KEY",
        ));
    }

    let request_id = Uuid::new_v4().simple().to_string();
    let push_source = if req.headers().contains_key(DEBUG_PUSH_HEADER) {
        DEBUG_PUSH_SOURCE.to_string()
    } else {
        channel.push_source.clone()
    };
    let markdown_max_len = settings.markdown_max_len();
    let text_max_len = settings.text_max_len();
    let qq_payload = render_qq_with_limits(&message, markdown_max_len, text_max_len);
    let qq_payload = with_push_source(qq_payload, &push_source, markdown_max_len, text_max_len);
    let source_msgtype = if message.source_msgtype.is_empty() {
        "unknown".to_string()
    } else {
        message.source_msgtype.clone()
    };
    let job = PushJob {
        request_id: request_id.clone(),
        hook_type: channel.hook_type.clone(),
        push_source,
        channel_id: Some(channel.id),
        bot_id: bot.id,
        owner_user_id: bot.owner_user_id,
        bot_host: bot.qq_host.clone(),
        bot_appid: bot.qq_appid.clone(),
        app_secret_cipher: bot.qq_app_secret.clone(),
        source_msgtype,
        msg_type: qq_payload.msg_type,
        content: qq_payload.content,
        markdown: qq_payload.markdown,
        targets,
    };

    if let Some(queue) = state.queue.as_ref() {
        let delivery = delivery_id(hook_type, req, &payload);
        // 通道并入去重键：同一条钩子投递可配置到多个通道，各通道独立计数。
        let job_id = dedupe_key(hook_type, channel.id, delivery.as_deref(), &request_id);
        match queue.enqueue(job.clone(), &job_id).await {
            Ok(false) => {
                return Ok(hook_type_response(
                    hook_type,
                    StatusCode::OK,
                    0,
                    "重复投递，已忽略",
                ));
            }
            Ok(true) => return Ok(hook_type_response(hook_type, StatusCode::OK, 0, "ok")),
            Err(QueueError::Full(_)) => {
                tracing::warn!(
                    hook_type,
                    request_id = %request_id,
                    "推送队列积压，拒绝入队"
                );
                // 其他钩子类型会重试失败投递；GitHub 不会，改走同步发送避免事件丢失。
                if hook_type != HOOK_TYPE_GITHUB {
                    return Ok(hook_type_response(
                        hook_type,
                        StatusCode::SERVICE_UNAVAILABLE,
                        503,
                        "推送队列繁忙，请稍后重试",
                    ));
                }
            }
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    hook_type,
                    request_id = %request_id,
                    "推送队列不可用，改为同步发送"
                );
            }
        }
    }

    // 未配置队列（或队列不可用）时同步发送；同样启用幂等守卫，
    // 队列重投与同步回退共用同一套 `request_id:target` 完成标记。
    let limiter = state.limiters.get(&format!("bot:{}", job.bot_id));
    let outcome = execute_push(
        &state.pool,
        &job,
        &settings,
        &state.qq,
        &limiter,
        Some(&state.sent_guard),
    )
    .await;
    let failures = outcome.failed();
    if failures.is_empty() {
        return Ok(hook_type_response(hook_type, StatusCode::OK, 0, "ok"));
    }
    // 具体失败原因只进日志与 push_logs（execute_push 已落库），对外固定文案。
    tracing::warn!(failures = ?failures, request_id = %request_id, "同步推送存在失败");
    let message = if failures.len() == outcome.errors.len() {
        "推送失败，请稍后重试"
    } else {
        "部分目标推送失败"
    };
    Ok(hook_type_response(
        hook_type,
        StatusCode::BAD_GATEWAY,
        502,
        message,
    ))
}

// ------------------------------------------------------------------ 辅助函数

/// 在转换后的消息头部标注推送来源：Markdown 用一级标题，纯文本用普通一行。
fn with_push_source(
    payload: QqPayload,
    push_source: &str,
    markdown_max_len: usize,
    text_max_len: usize,
) -> QqPayload {
    // 来源为用户自填，压平换行避免破坏头部结构。
    let source = push_source.replace(['\r', '\n'], " ");
    let source = source.trim();
    if source.is_empty() {
        return payload;
    }
    if payload.msg_type == MSG_TYPE_MARKDOWN {
        let body = payload.markdown.as_deref().unwrap_or_default();
        let markdown = truncate(
            &format!("# 「消息来源」{source}\n\n{body}"),
            Some(markdown_max_len),
        );
        return QqPayload {
            markdown: Some(markdown),
            ..payload
        };
    }
    QqPayload {
        content: truncate(
            &format!("「消息来源」{source}\n{}", payload.content),
            Some(text_max_len),
        ),
        ..payload
    }
}

/// 钩子类型响应体。
fn hook_type_response(
    hook_type: &str,
    status: StatusCode,
    errcode: u16,
    errmsg: &str,
) -> HttpResponse {
    let body = if hook_type == HOOK_TYPE_GITHUB {
        if errcode == 0 {
            json!({"ok": true})
        } else {
            json!({"ok": false, "error": errmsg})
        }
    } else if hook_type == "feishu" {
        if errcode == 0 {
            json!({"code": 0, "msg": "success", "data": {}})
        } else {
            json!({"code": errcode, "msg": errmsg, "data": {"error": errmsg}})
        }
    } else {
        json!({"errcode": errcode, "errmsg": errmsg})
    };
    HttpResponse::build(status).json(body)
}

/// 提取 webhook token：路径 > `X-Webhook-Token` > Bearer > （可选）查询参数。
fn extract_token(req: &HttpRequest, path_token: Option<&str>, allow_query: bool) -> String {
    let token = path_token.unwrap_or("").trim();
    if !token.is_empty() {
        return token.to_string();
    }

    let header_token = req
        .headers()
        .get(WEBHOOK_TOKEN_HEADER)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if !header_token.is_empty() {
        return header_token.to_string();
    }

    let authorization = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let (scheme, credentials) = authorization.split_once(' ').unwrap_or((authorization, ""));
    if scheme.eq_ignore_ascii_case("bearer") {
        let bearer = credentials.trim();
        if !bearer.is_empty() {
            return bearer.to_string();
        }
    }

    if allow_query
        && let Some((_, value)) = url::form_urlencoded::parse(req.query_string().as_bytes())
            .find(|(key, _)| key == "token")
    {
        return value.into_owned();
    }
    String::new()
}

/// 校验 GitHub `X-Hub-Signature-256`；通过时返回 `None`。
fn verify_github_signature(
    channel: &Channel,
    req: &HttpRequest,
    raw: &[u8],
    key: Option<&str>,
) -> Option<(StatusCode, &'static str)> {
    let stored = channel
        .extra
        .as_ref()
        .and_then(|extra| extra.get("secret_cipher"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if stored.is_empty() {
        return Some((StatusCode::UNAUTHORIZED, "通道未配置签名密钥"));
    }
    let secret = match decrypt_secret(stored, key) {
        Ok(secret) => secret,
        Err(_) => {
            return Some((
                StatusCode::BAD_GATEWAY,
                "签名密钥无法解密，请检查 APP_SECRET_KEY",
            ));
        }
    };

    let header = req
        .headers()
        .get(GITHUB_SIGNATURE_HEADER)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .trim();
    if !header.starts_with("sha256=") {
        return Some((StatusCode::UNAUTHORIZED, "缺少 X-Hub-Signature-256 签名"));
    }

    let mut mac = match Hmac::<Sha256>::new_from_slice(secret.as_bytes()) {
        Ok(mac) => mac,
        Err(_) => {
            return Some((
                StatusCode::BAD_GATEWAY,
                "签名密钥无法解密，请检查 APP_SECRET_KEY",
            ));
        }
    };
    mac.update(raw);
    let expected = format!("sha256={}", hex_lower(&mac.finalize().into_bytes()));
    if expected.as_bytes().ct_eq(header.as_bytes()).unwrap_u8() != 1 {
        return Some((StatusCode::UNAUTHORIZED, "签名不匹配"));
    }
    None
}

/// 小写十六进制编码。
fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// 按钩子类型构造适配器并解析负载。
fn parse_message(
    hook_type: &str,
    payload: &Value,
    event: &str,
) -> Result<UnifiedMessage, AdapterError> {
    match hook_type {
        "dingtalk" => DingTalkAdapter::new().parse(payload, event),
        "wecom" => WeComAdapter::new().parse(payload, event),
        "feishu" => FeishuAdapter::new().parse(payload, event),
        HOOK_TYPE_GITHUB => GitHubAdapter::new().parse(payload, event),
        _ => Err(AdapterError::payload(format!("未知钩子类型：{hook_type}"))),
    }
}

/// 请求体优先，缺省使用机器人的默认目标。
fn resolve_targets(payload: &Value, bot: &BotProfile) -> Vec<QqTarget> {
    if let Some(object) = payload.as_object() {
        let group_openid = object
            .get("group_openid")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim();
        if !group_openid.is_empty() {
            return if group_openid.chars().count() <= MAX_TARGET_LEN {
                vec![QqTarget::group(group_openid)]
            } else {
                Vec::new()
            };
        }
        let openid = object
            .get("openid")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim();
        if !openid.is_empty() {
            return if openid.chars().count() <= MAX_TARGET_LEN {
                vec![QqTarget::user(openid)]
            } else {
                Vec::new()
            };
        }
    }

    let group_default = bot.default_group_openid.as_deref().unwrap_or("").trim();
    if !group_default.is_empty() {
        return vec![QqTarget::group(group_default)];
    }
    bot.default_openids
        .as_array()
        .map(|items| {
            items
                .iter()
                .take(MAX_FANOUT)
                .filter_map(Value::as_str)
                .filter(|openid| !openid.is_empty())
                .map(QqTarget::user)
                .collect()
        })
        .unwrap_or_default()
}

/// 钩子投递 ID，用于队列去重与防重放。
fn delivery_id(hook_type: &str, req: &HttpRequest, payload: &Value) -> Option<String> {
    if hook_type == HOOK_TYPE_GITHUB {
        return req
            .headers()
            .get(GITHUB_DELIVERY_HEADER)
            .and_then(|value| value.to_str().ok())
            .filter(|value| !value.is_empty())
            .map(str::to_string);
    }
    if hook_type == "feishu" {
        return payload
            .get("header")
            .and_then(|header| header.get("event_id"))
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
    }
    for key in ["msgid", "msg_id"] {
        if let Some(value) = payload.get(key).and_then(Value::as_str)
            && !value.is_empty()
        {
            return Some(value.to_string());
        }
    }
    None
}

/// GitHub 防重放窗口；窗口内同一条投递只会被处理一次。
const REPLAY_WINDOW: Duration = Duration::from_secs(3600);
/// 防重放表的容量上限，超过后批量清理过期项（参照 AttemptLimiter 的 MAX_KEYS）。
const MAX_DELIVERIES: usize = 4096;

/// GitHub 投递 GUID 的进程内防重放记录。
///
/// 记录仅存在于进程内存：重启后失效，是可接受的折衷——GitHub 官方确认
/// redeliver 才会复用 GUID，重放攻击不得不用同签名重发旧 GUID，
/// 签名校验已通过后的窗口内拒绝足够拦截绝大多数回放。
/// key 为（通道, delivery GUID）二元组：同一事件配置到多个通道时，
/// 每个通道各自独立处理，不能被第一个通道的记录误伤。
fn deliveries() -> &'static DashMap<(i64, String), Instant> {
    static DELIVERIES: OnceLock<DashMap<(i64, String), Instant>> = OnceLock::new();
    DELIVERIES.get_or_init(DashMap::new)
}

/// 记录并判断该投递是否在窗口内重复；重复时返回拒绝响应。
fn reject_replayed_delivery(
    channel: &Channel,
    req: &HttpRequest,
) -> Option<(StatusCode, &'static str)> {
    let delivery = req
        .headers()
        .get(GITHUB_DELIVERY_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .unwrap_or("");
    if delivery.is_empty() {
        return None;
    }
    let now = Instant::now();
    let key = (channel.id, delivery.to_string());
    if let Some(seen_at) = deliveries().get(&key)
        && now.duration_since(*seen_at) < REPLAY_WINDOW
    {
        // GitHub 对非 2xx 会重投；用 400 让其 webhook 配置页显示失败但不触发重试风暴。
        return Some((StatusCode::BAD_REQUEST, "重复投递，已拒绝"));
    }
    let map = deliveries();
    map.insert(key, now);
    if map.len() > MAX_DELIVERIES {
        let expired: Vec<(i64, String)> = map
            .iter()
            .filter(|entry| now.duration_since(*entry.value()) >= REPLAY_WINDOW)
            .map(|entry| entry.key().clone())
            .collect();
        for key in expired {
            map.remove(&key);
        }
    }
    None
}
