//! QQ 机器人 HTTP 客户端：token 缓存、消息发送、错误分类与重试。
//!
//! QQ 机器人 API 客户端：
//! - token 与频控按 `app:<host>:<appid>` 缓存，提前 60 秒刷新，每个 key 独立锁 + 双检；
//! - HTTP 401 清缓存并重试一次；
//! - 错误码提取顺序 `code` → `err_code` → `errcode`，都没有时用 `http_{status}`；
//! - `40054005`（去重）视为成功，`40034100`（超频）与 5xx 可重试；
//! - 频控许可在**取 token 之前**获取（含重试）。

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::Mutex;

use crate::renderer::QqPayload;
use crate::services::throttle::RateLimiter;

/// 默认 QQ API 域名。
pub const DEFAULT_HOST: &str = "https://api.bot.qq.com";
/// 单个推送目标的最大字符数。
pub const MAX_TARGET_LEN: usize = 128;
/// 主动消息超频错误码。
pub const ERR_RATE_LIMIT: i64 = 40034100;
/// 消息去重错误码（视为成功）。
pub const ERR_DUPLICATE: i64 = 40054005;
/// 默认最大尝试次数。
pub const DEFAULT_MAX_ATTEMPTS: usize = 3;
/// token 提前刷新秒数。
const TOKEN_REFRESH_AHEAD: i64 = 60;
/// 首次重试退避（秒）。
const INITIAL_BACKOFF: f64 = 0.5;
/// 退避上限（秒）。
const MAX_BACKOFF: f64 = 8.0;

/// 推送目标是否安全：仅允许字母、数字、下划线与连字符，且不超长。
///
/// openid 会直接拼进 QQ API 路径；允许 `/`、`?`、`#` 或 `..`
/// 会改变请求路径或查询串。
pub fn is_valid_target(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty()
        && value.chars().count() <= MAX_TARGET_LEN
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
}

/// 校验 QQ API 域名格式：必须为 https、默认端口、根路径，且无用户信息/查询/锚点。
///
/// 主机是否在允许列表由调用方另行判断；此函数只做与配置位置无关的语法校验。
pub fn validate_host(value: &str) -> Result<(), String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("QQ 接口地址不能为空".to_string());
    }
    let parsed = url::Url::parse(value)
        .map_err(|_| "QQ 接口地址必须是以 https:// 开头的完整地址".to_string())?;
    if parsed.scheme() != "https" || parsed.host().is_none() {
        return Err("QQ 接口地址必须是以 https:// 开头的完整地址".to_string());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("QQ 接口地址不能包含用户信息".to_string());
    }
    if parsed.port().is_some_and(|port| port != 443) {
        return Err("QQ 接口地址只能使用默认端口 443".to_string());
    }
    if !matches!(parsed.path(), "" | "/") {
        return Err("QQ 接口地址不能包含路径".to_string());
    }
    if parsed.query().is_some_and(|value| !value.is_empty())
        || parsed.fragment().is_some_and(|value| !value.is_empty())
    {
        return Err("QQ 接口地址不能包含查询参数或锚点".to_string());
    }
    Ok(())
}

/// 一次推送的目标：群或用户。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct QqTarget {
    /// 用户 openid。
    pub openid: Option<String>,
    /// 群 openid。
    pub group_openid: Option<String>,
}

impl QqTarget {
    /// 推送群消息。
    pub fn group(group_openid: impl Into<String>) -> Self {
        Self {
            openid: None,
            group_openid: Some(group_openid.into()),
        }
    }

    /// 推送用户消息。
    pub fn user(openid: impl Into<String>) -> Self {
        Self {
            openid: Some(openid.into()),
            group_openid: None,
        }
    }

    /// 目标是否为空。
    pub fn is_empty(&self) -> bool {
        self.group_openid
            .as_deref()
            .map(str::trim)
            .unwrap_or_default()
            .is_empty()
            && self
                .openid
                .as_deref()
                .map(str::trim)
                .unwrap_or_default()
                .is_empty()
    }

    /// QQ 接口路径。
    pub fn path(&self) -> Result<String, QqError> {
        if let Some(group_openid) = self
            .group_openid
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            if !is_valid_target(group_openid) {
                return Err(QqError::new(
                    "invalid_target",
                    "群 openid 只能包含字母、数字、下划线和连字符",
                    false,
                ));
            }
            return Ok(format!("/v2/groups/{group_openid}/messages"));
        }
        if let Some(openid) = self
            .openid
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            if !is_valid_target(openid) {
                return Err(QqError::new(
                    "invalid_target",
                    "用户 openid 只能包含字母、数字、下划线和连字符",
                    false,
                ));
            }
            return Ok(format!("/v2/users/{openid}/messages"));
        }
        Err(QqError::new("invalid_target", "推送目标为空", false))
    }

    /// 推送目标的审计标签：`group:{group_openid}` / `user:{openid}`。
    pub fn label(&self) -> String {
        if let Some(group_openid) = self
            .group_openid
            .as_deref()
            .filter(|value| !value.is_empty())
        {
            format!("group:{group_openid}")
        } else {
            format!("user:{}", self.openid.as_deref().unwrap_or_default())
        }
    }

    /// 写入推送日志的目标表示。
    pub fn to_db_value(&self) -> String {
        self.label()
    }
}

/// QQ 推送失败。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct QqError {
    /// 平台错误码或内部错误码。
    pub code: String,
    /// 可展示的错误信息。
    pub message: String,
    /// 是否允许重试。
    pub retryable: bool,
}

impl QqError {
    /// 构造错误。
    pub fn new(code: impl Into<String>, message: impl Into<String>, retryable: bool) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            retryable,
        }
    }
}

/// QQ 凭据缓存与频控共用的键。
///
/// QQ access_token 与调用额度都归属于 AppID，而不是本地机器人行；同一 AppID
/// 被多个机器人复用时必须共享缓存与限流，否则会各自放大平台调用量。
pub fn account_key(host: &str, app_id: &str) -> String {
    format!(
        "app:{}:{}",
        host.trim().trim_end_matches('/').to_ascii_lowercase(),
        app_id.trim()
    )
}

/// 已缓存的 access_token。
#[derive(Debug, Clone)]
struct CachedToken {
    token: String,
    expires_at: Instant,
}

/// 按 `app:<host>:<appid>` 缓存 access_token 的异步客户端。
pub struct QqClient {
    client: reqwest::Client,
    tokens: DashMap<String, CachedToken>,
    locks: DashMap<String, Arc<tokio::sync::Mutex<()>>>,
}

impl QqClient {
    /// 用共享的 HTTP 客户端创建。
    pub fn new(client: reqwest::Client) -> Self {
        Self {
            client,
            tokens: DashMap::new(),
            locks: DashMap::new(),
        }
    }

    /// 共享的 HTTP 客户端。
    pub fn http(&self) -> &reqwest::Client {
        &self.client
    }

    /// 取 access_token；`force` 为 true 时忽略缓存。
    pub async fn get_access_token(
        &self,
        key: &str,
        host: &str,
        app_id: &str,
        app_secret: &str,
        force: bool,
    ) -> Result<String, QqError> {
        if !force && let Some(token) = self.cached_token(key) {
            return Ok(token);
        }

        // 每个 key 独立锁 + 双检：并发请求同一机器人时只刷新一次 token。
        let lock = self
            .locks
            .entry(key.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone();
        let _guard = lock.lock().await;

        if !force && let Some(token) = self.cached_token(key) {
            return Ok(token);
        }

        let response = self
            .client
            .post(format!("{host}/app/getAppAccessToken"))
            .json(&serde_json::json!({
                "appId": app_id,
                "clientSecret": app_secret,
            }))
            .send()
            .await
            .map_err(|err| {
                QqError::new(
                    "token_network",
                    format!("获取 access_token 网络错误：{err}"),
                    true,
                )
            })?;

        let status = response.status();
        if status.as_u16() != 200 {
            return Err(QqError::new(
                format!("token_http_{}", status.as_u16()),
                format!("获取 access_token 失败：HTTP {}", status.as_u16()),
                status.is_server_error(),
            ));
        }

        let data = response.json::<Value>().await.map_err(|err| {
            QqError::new(
                "token_invalid_json",
                format!("获取 access_token 失败：响应不是合法 JSON（{err}）"),
                false,
            )
        })?;

        let token = data
            .get("access_token")
            .and_then(Value::as_str)
            .filter(|token| !token.is_empty())
            .ok_or_else(|| {
                QqError::new(
                    "token_missing",
                    format!("获取 access_token 失败：{data}"),
                    false,
                )
            })?
            .to_string();

        let ttl = (token_ttl(&data) - TOKEN_REFRESH_AHEAD).max(1);
        self.tokens.insert(
            key.to_string(),
            CachedToken {
                token: token.clone(),
                expires_at: expires_at_from_now(Duration::from_secs(ttl as u64)),
            },
        );
        Ok(token)
    }

    /// 读取仍然有效的缓存 token。
    fn cached_token(&self, key: &str) -> Option<String> {
        let cached = self.tokens.get(key)?;
        (cached.expires_at > Instant::now()).then(|| cached.token.clone())
    }

    /// 清除某个机器人的 token 缓存。
    pub fn invalidate(&self, key: &str) {
        self.tokens.remove(key);
    }

    /// 发送消息；`limiter` 在每次实际请求（含重试）前获取频控许可。
    #[allow(clippy::too_many_arguments)]
    pub async fn send(
        &self,
        key: &str,
        host: &str,
        app_id: &str,
        app_secret: &str,
        target: &QqTarget,
        payload: &QqPayload,
        limiter: &RateLimiter,
        max_attempts: usize,
    ) -> Result<serde_json::Value, QqError> {
        let path = target.path()?;
        let body = payload.to_dict();
        // max_attempts 是总尝试次数（含首次请求）。
        let max_retries = max_attempts.saturating_sub(1);
        let mut attempt = 0usize;
        let mut token_refreshed = false;
        let mut backoff = INITIAL_BACKOFF;

        loop {
            // 频控许可在取 token 之前获取（含 401 刷新与退避重试）。
            limiter.acquire().await;
            let token = self
                .get_access_token(key, host, app_id, app_secret, false)
                .await?;

            let response = self
                .client
                .post(format!("{host}{path}"))
                .header(reqwest::header::AUTHORIZATION, format!("QQBot {token}"))
                .json(&body)
                .send()
                .await;

            let response = match response {
                Ok(response) => response,
                Err(err) => {
                    attempt += 1;
                    if attempt > max_retries {
                        return Err(QqError::new(
                            "network",
                            format!("推送网络错误：{err}"),
                            true,
                        ));
                    }
                    tokio::time::sleep(backoff_duration(backoff)).await;
                    backoff = next_backoff(backoff);
                    continue;
                }
            };

            let status = response.status();
            if status.as_u16() == 200 {
                return Ok(safe_json(response).await);
            }

            if status.as_u16() == 401 && !token_refreshed {
                token_refreshed = true;
                self.invalidate(key);
                continue;
            }

            let retry_after = retry_after_value(
                response
                    .headers()
                    .get("retry-after")
                    .and_then(|value| value.to_str().ok()),
            );
            let body = safe_json(response).await;
            let code = extract_code(&body).unwrap_or_else(|| format!("http_{}", status.as_u16()));
            let message =
                extract_message(&body).unwrap_or_else(|| format!("HTTP {}", status.as_u16()));

            if code == ERR_DUPLICATE.to_string() {
                tracing::info!(code = %code, "QQ 返回消息去重（视为成功）");
                return Ok(body);
            }

            let rate_limited = code == ERR_RATE_LIMIT.to_string();
            let retryable = status.is_server_error() || rate_limited;
            if retryable && attempt < max_retries {
                attempt += 1;
                let mut delay = retry_after.unwrap_or(backoff);
                if rate_limited {
                    delay = delay.max(2.0);
                }
                tokio::time::sleep(backoff_duration(delay)).await;
                backoff = next_backoff(backoff);
                continue;
            }

            return Err(QqError::new(code, message, retryable));
        }
    }
}

/// `expires_in` 秒数；缺失、为零或非法时回退 7200，超过一天时按一天封顶。
fn token_ttl(data: &Value) -> i64 {
    let seconds = match data.get("expires_in") {
        Some(Value::Number(number)) => number
            .as_i64()
            .or_else(|| number.as_f64().map(|value| value as i64)),
        Some(Value::String(text)) => text.trim().parse::<i64>().ok(),
        _ => None,
    }
    .unwrap_or(7200);
    if seconds == 0 {
        7200
    } else {
        seconds.min(86_400)
    }
}

/// 相对当前的过期时刻；`Instant` 加法溢出时按立即过期处理，下轮刷新重建。
fn expires_at_from_now(ttl: Duration) -> Instant {
    Instant::now().checked_add(ttl).unwrap_or_else(Instant::now)
}

/// 退避时长；负值按 0 处理，避免 `Duration` 构造 panic。
fn backoff_duration(seconds: f64) -> Duration {
    if seconds.is_finite() && seconds > 0.0 {
        Duration::from_secs_f64(seconds)
    } else {
        Duration::ZERO
    }
}

/// 下一次退避时长（×2，上限 8 秒）。
fn next_backoff(backoff: f64) -> f64 {
    (backoff * 2.0).min(MAX_BACKOFF)
}

/// 读取 `Retry-After`（秒）；无法解析或过长时忽略，clamp 到 [0, 30]。
fn retry_after_value(raw: Option<&str>) -> Option<f64> {
    let raw = raw?.trim();
    if raw.is_empty() {
        return None;
    }
    let seconds = raw.parse::<f64>().ok()?;
    if !seconds.is_finite() {
        return None;
    }
    Some(seconds.clamp(0.0, 30.0))
}

/// 提取平台错误码；顺序 `code` → `err_code` → `errcode`。
///
/// 接口返回非字符串消息时回退到 `http_{status}`：
/// `null`、`0`、空串与空容器都视为没有错误码。
/// 首键为假值时继续尝试后续键，避免吞掉有序在后面的真实错误码。
fn extract_code(body: &Value) -> Option<String> {
    ["code", "err_code", "errcode"]
        .iter()
        .filter_map(|key| body.get(key))
        .find_map(truthy_code)
}

/// 把 JSON 值转成错误码字符串；假值返回 `None`。
fn truthy_code(value: &Value) -> Option<String> {
    match value {
        Value::Null => None,
        Value::Bool(flag) => flag.then(|| "true".to_string()),
        Value::Number(number) => {
            let zero = number.as_i64() == Some(0) || number.as_f64() == Some(0.0);
            (!zero).then(|| number.to_string())
        }
        Value::String(text) => (!text.is_empty()).then(|| text.clone()),
        Value::Array(items) => (!items.is_empty()).then(|| value.to_string()),
        Value::Object(map) => (!map.is_empty()).then(|| value.to_string()),
    }
}

/// 提取错误信息；顺序 `message` → `msg` → `errmsg`。
fn extract_message(body: &Value) -> Option<String> {
    for key in ["message", "msg", "errmsg"] {
        if let Some(text) = body.get(key).and_then(Value::as_str)
            && !text.is_empty()
        {
            return Some(text.to_string());
        }
    }
    None
}

/// 尽量把响应体解析成 JSON 对象；失败时保留前 500 个字符。
async fn safe_json(response: reqwest::Response) -> Value {
    let text = response.text().await.unwrap_or_default();
    match serde_json::from_str::<Value>(&text) {
        Ok(Value::Object(map)) => Value::Object(map),
        Ok(other) => serde_json::json!({ "data": other }),
        Err(_) => serde_json::json!({ "raw": text.chars().take(500).collect::<String>() }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_key_is_scoped_by_host_and_appid() {
        assert_eq!(
            account_key("https://API.BOT.QQ.COM/", "123"),
            "app:https://api.bot.qq.com:123"
        );
        // 同一 AppID 的不同域名不能共用 token；不同 AppID 也不能共用限流。
        assert_ne!(
            account_key("https://api.bot.qq.com", "123"),
            account_key("https://sandbox.bot.qq.com", "123")
        );
        assert_ne!(
            account_key("https://api.bot.qq.com", "123"),
            account_key("https://api.bot.qq.com", "456")
        );
    }

    #[test]
    fn target_path_prefers_group() {
        assert_eq!(
            QqTarget::group("g1").path().unwrap(),
            "/v2/groups/g1/messages"
        );
        assert_eq!(
            QqTarget::user("u1").path().unwrap(),
            "/v2/users/u1/messages"
        );
        assert!(QqTarget::default().path().is_err());
    }

    #[test]
    fn targets_are_limited_to_safe_path_characters() {
        for valid in ["u1", "A-Z_09", "group-123"] {
            assert!(is_valid_target(valid), "{valid}");
            assert!(QqTarget::user(valid).path().is_ok(), "{valid}");
        }
        for invalid in [
            "",
            " ",
            "a/b",
            "a?b",
            "a#b",
            "../x",
            "a b",
            "用户",
            &"a".repeat(MAX_TARGET_LEN + 1),
        ] {
            assert!(!is_valid_target(invalid), "{invalid}");
            assert!(QqTarget::user(invalid).path().is_err(), "{invalid}");
        }
    }

    #[test]
    fn host_validation_rejects_ports_paths_and_userinfo() {
        assert!(validate_host("https://api.bot.qq.com").is_ok());
        assert!(validate_host("https://api.bot.qq.com/").is_ok());
        assert!(validate_host("https://api.bot.qq.com:443").is_ok());
        for invalid in [
            "",
            "http://api.bot.qq.com",
            "https://api.bot.qq.com:8443",
            "https://api.bot.qq.com/v2",
            "https://api.bot.qq.com/?token=1",
            "https://user:pass@api.bot.qq.com",
        ] {
            assert!(validate_host(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn target_label_and_db_value() {
        assert_eq!(QqTarget::group("g1").label(), "group:g1");
        assert_eq!(QqTarget::group("g1").to_db_value(), "group:g1");
        assert_eq!(QqTarget::user("u1").label(), "user:u1");
        assert_eq!(QqTarget::user("u1").to_db_value(), "user:u1");
    }

    #[test]
    fn token_ttl_defaults_and_floor() {
        assert_eq!(token_ttl(&serde_json::json!({})), 7200);
        assert_eq!(token_ttl(&serde_json::json!({ "expires_in": 0 })), 7200);
        assert_eq!(token_ttl(&serde_json::json!({ "expires_in": null })), 7200);
        assert_eq!(token_ttl(&serde_json::json!({ "expires_in": 3600 })), 3600);
        assert_eq!(
            token_ttl(&serde_json::json!({ "expires_in": "1800" })),
            1800
        );
        // 小于刷新提前量时至少缓存 1 秒
        assert_eq!(
            (token_ttl(&serde_json::json!({ "expires_in": 30 })) - TOKEN_REFRESH_AHEAD).max(1),
            1
        );
        // 超过一天时按一天封顶，避免异常响应把缓存期限拉得过长。
        assert_eq!(
            token_ttl(&serde_json::json!({ "expires_in": 999_999 })),
            86_400
        );
        assert_eq!(token_ttl(&serde_json::json!({ "expires_in": -5 })), -5);
    }

    #[test]
    fn retry_after_is_clamped() {
        assert_eq!(retry_after_value(None), None);
        assert_eq!(retry_after_value(Some("")), None);
        assert_eq!(retry_after_value(Some("abc")), None);
        assert_eq!(retry_after_value(Some("-1")), Some(0.0));
        assert_eq!(retry_after_value(Some("2.5")), Some(2.5));
        assert_eq!(retry_after_value(Some("120")), Some(30.0));
    }

    #[test]
    fn code_extraction_order_and_fallbacks() {
        assert_eq!(
            extract_code(&serde_json::json!({ "code": 40054005 })),
            Some("40054005".to_string())
        );
        assert_eq!(
            extract_code(&serde_json::json!({ "err_code": 100, "code": 200 })),
            Some("200".to_string())
        );
        assert_eq!(
            extract_code(&serde_json::json!({ "errcode": "x" })),
            Some("x".to_string())
        );
        assert_eq!(
            extract_code(&serde_json::json!({ "code": 0, "err_code": 40034100 })),
            Some("40034100".to_string())
        );
        assert_eq!(extract_code(&serde_json::json!({ "code": 0 })), None);
        assert_eq!(extract_code(&serde_json::json!({ "code": null })), None);
        assert_eq!(extract_code(&serde_json::json!({})), None);
    }

    #[test]
    fn message_extraction_order() {
        assert_eq!(
            extract_message(&serde_json::json!({ "message": "a", "msg": "b" })),
            Some("a".to_string())
        );
        assert_eq!(
            extract_message(&serde_json::json!({ "msg": "", "errmsg": "c" })),
            Some("c".to_string())
        );
        assert_eq!(extract_message(&serde_json::json!({})), None);
    }

    #[test]
    fn backoff_doubles_and_caps() {
        assert_eq!(next_backoff(0.5), 1.0);
        assert_eq!(next_backoff(5.0), 8.0);
        assert_eq!(next_backoff(8.0), 8.0);
        assert_eq!(backoff_duration(-1.0), Duration::ZERO);
        assert_eq!(backoff_duration(0.5), Duration::from_millis(500));
    }

    #[test]
    fn duplicate_and_rate_limit_constants() {
        assert_eq!(ERR_DUPLICATE, 40054005);
        assert_eq!(ERR_RATE_LIMIT, 40034100);
        // 去重视为成功、超频可重试的错误码字符串与平台返回一致
        assert_eq!(ERR_DUPLICATE.to_string(), "40054005");
        assert_eq!(ERR_RATE_LIMIT.to_string(), "40034100");
    }
}
