//! 通用 OAuth2 授权码流程（GitHub 等）。
//!
//! OAuth2 授权码流程（提供方走 system 欢迎/管理端配置）：
//! - state 参数为 "{flow16}.{state32}"：flow 是流程临时标识（8 随机字节 hex），
//!   '.' 不在 base64url 字母表内可无歧义切分，主体仍为 24 随机字节 →
//!   base64url 无填充（32 字符）、纯随机；
//! - 双提交 Cookie：`oauth_state_{flow}` 与 `oauth_provider_{flow}`（绑定流程另有
//!   `oauth_link_{flow}`），名带 flow 后缀，同一浏览器并行流程互不覆盖，`Max-Age=600`；
//! - 回调常量时间比对 state，并要求提供方 Cookie 与路径上的 key 一致；
//! - token / userinfo 请求的参数名、请求头与 GitHub 主邮箱兜底逻辑逐项复刻；
//! - `client_secret` 由调用方解密后显式传入，绝不写回实体（否则会把明文写进库）。

use actix_web::cookie::time::Duration as CookieDuration;
use actix_web::cookie::{Cookie, SameSite};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::Rng;
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, USER_AGENT};
use serde_json::Value;
use subtle::ConstantTimeEq;
use url::form_urlencoded;

use crate::crypto::decrypt_secret;
use crate::db::models::OAuthProvider;
use crate::error::AppError;
use crate::services::runtime_settings::RuntimeSettings;

/// state Cookie 名。
pub const STATE_COOKIE: &str = "oauth_state";
/// 提供方 Cookie 名。
pub const PROVIDER_COOKIE: &str = "oauth_provider";
/// 绑定用途 Cookie 名；存在表示本次流程用于给已登录用户绑定账号。
pub const LINK_COOKIE: &str = "oauth_link";
/// 两个临时 Cookie 的有效期（秒）。
pub const COOKIE_MAX_AGE_SECONDS: i64 = 600;
/// state 的随机字节数（24 字节 → 32 字符 base64url）。
pub const STATE_BYTES: usize = 24;
/// 流程标识的随机字节数（8 字节 → 16 个小写 hex 字符）。
pub const FLOW_BYTES: usize = 8;
/// GitHub 主邮箱兜底地址。
pub const GITHUB_EMAILS_URL: &str = "https://api.github.com/user/emails";
/// OAuth 回调路径前缀。
pub const CALLBACK_PATH_PREFIX: &str = "/api/auth/oauth/";

/// OAuth 提供方返回的用户信息（已按配置字段名抽取）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthProfile {
    /// 提供方侧的用户 ID。
    pub provider_user_id: String,
    /// 提供方侧的登录名。
    pub login: String,
    /// 邮箱。
    pub email: Option<String>,
    /// 昵称。
    pub name: Option<String>,
    /// 提供方是否验证过该邮箱。
    pub email_verified: bool,
}

/// 生成 OAuth state 主体（24 随机字节 → base64url 无填充，32 字符）。
pub fn new_state() -> String {
    let mut bytes = [0u8; STATE_BYTES];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// 生成流程标识（8 随机字节 → 16 个小写 hex 字符）。
///
/// 并行流程以 flow 后缀区分 Cookie 名，互不覆盖。
pub fn new_flow() -> String {
    let mut bytes = [0u8; FLOW_BYTES];
    rand::rng().fill_bytes(&mut bytes);
    // 手写 hex 编码避免新增依赖；小写与 hex 惯例一致。
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// 拼接带 flow 后缀的 Cookie 名：`{base}_{flow}`。
///
/// flow 为空时退回不带后缀的回退名，保证校验自然失败而非 panic。
pub fn flow_cookie_name(base: &str, flow: &str) -> String {
    if flow.is_empty() {
        base.to_string()
    } else {
        format!("{base}_{flow}")
    }
}

/// 从回调 state 参数解析 (flow, state 主体)。
///
/// state 为 "{flow16}.{state32}"；缺失 '.' 时 flow 为空，校验自然失败。
pub fn split_state_param(state_param: &str) -> (String, &str) {
    match state_param.split_once('.') {
        Some((flow, body)) => (flow.to_string(), body),
        None => (String::new(), state_param),
    }
}

/// 回调路径：`/api/auth/oauth/{key}/callback`。
pub fn callback_path(provider_key: &str) -> String {
    format!("{CALLBACK_PATH_PREFIX}{provider_key}/callback")
}

/// 构造完整 `redirect_uri`：`{origin}/api/auth/oauth/{key}/callback`。
pub fn redirect_uri(origin: &str, provider_key: &str) -> String {
    format!(
        "{}{}",
        origin.trim_end_matches('/'),
        callback_path(provider_key)
    )
}

/// 构造授权跳转地址。
///
/// 参数顺序：client_id、redirect_uri、response_type、
/// state，最后才是可选的 scope。
pub fn build_authorize_url(provider: &OAuthProvider, redirect_uri: &str, state: &str) -> String {
    let mut query = form_urlencoded::Serializer::new(String::new());
    query.append_pair("client_id", &provider.client_id);
    query.append_pair("redirect_uri", redirect_uri);
    query.append_pair("response_type", "code");
    query.append_pair("state", state);
    if !provider.scopes.is_empty() {
        query.append_pair("scope", &provider.scopes);
    }
    format!("{}?{}", provider.authorization_url, query.finish())
}

/// 常量时间比对 state，并校验提供方 Cookie 与路径 key 一致。
///
/// 返回 `400 OAuth state 校验失败`。
pub fn validate_state(
    state_param: &str,
    cookie_state: &str,
    cookie_provider: &str,
    provider_key: &str,
) -> Result<(), AppError> {
    let state_ok = !state_param.is_empty()
        && constant_time_eq(state_param.as_bytes(), cookie_state.as_bytes());
    if !state_ok || cookie_provider != provider_key {
        return Err(AppError::bad_request("OAuth state 校验失败"));
    }
    Ok(())
}

/// 解密提供方 client_secret；解密失败统一按 500 处理。
pub fn client_secret(
    provider: &OAuthProvider,
    app_secret_key: Option<&str>,
) -> Result<String, AppError> {
    decrypt_secret(&provider.client_secret, app_secret_key).map_err(|err| {
        tracing::error!(provider = %provider.key, error = %err, "OAuth 提供方密钥无法解密");
        AppError::internal("提供方密钥无法解密")
    })
}

/// 用授权码换取 token。
///
/// `client_secret` 由调用方解密后传入：`provider.client_secret` 是库内密文，
/// 写回实体会把明文提交进数据库。
pub async fn exchange_code(
    client: &reqwest::Client,
    provider: &OAuthProvider,
    code: &str,
    redirect_uri: &str,
    client_secret: &str,
) -> Result<Value, AppError> {
    let mut form = form_urlencoded::Serializer::new(String::new());
    form.append_pair("client_id", &provider.client_id);
    form.append_pair("client_secret", client_secret);
    form.append_pair("code", code);
    form.append_pair("redirect_uri", redirect_uri);
    form.append_pair("grant_type", "authorization_code");

    let response = client
        .post(&provider.token_url)
        .header(ACCEPT, "application/json")
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(form.finish())
        .send()
        .await
        .map_err(|err| AppError::external_service(format!("OAuth 登录失败：{err}")))?;

    if !response.status().is_success() {
        return Err(AppError::external_service(format!(
            "OAuth 登录失败：HTTP {}",
            response.status()
        )));
    }

    let data: Value = response
        .json()
        .await
        .map_err(|err| AppError::external_service(format!("OAuth 登录失败：{err}")))?;
    if !data.is_object() {
        return Err(AppError::external_service(
            "OAuth 登录失败：token 响应格式非法",
        ));
    }
    match data.get("access_token").and_then(Value::as_str) {
        Some(token) if !token.is_empty() => Ok(data),
        _ => {
            let detail = data
                .get("error_description")
                .and_then(Value::as_str)
                .unwrap_or("token 响应缺少 access_token");
            Err(AppError::external_service(format!(
                "OAuth 登录失败：{detail}"
            )))
        }
    }
}

/// 拉取提供方用户信息；GitHub 在 email 为空时额外拉取主邮箱。
pub async fn fetch_profile(
    client: &reqwest::Client,
    provider: &OAuthProvider,
    access_token: &str,
) -> Result<OAuthProfile, AppError> {
    let response = client
        .get(&provider.userinfo_url)
        .header(AUTHORIZATION, format!("Bearer {access_token}"))
        .header(ACCEPT, "application/json")
        .header(USER_AGENT, "qbotmessager")
        .send()
        .await
        .map_err(|err| AppError::external_service(format!("OAuth 登录失败：{err}")))?;

    if !response.status().is_success() {
        return Err(AppError::external_service(format!(
            "OAuth 登录失败：HTTP {}",
            response.status()
        )));
    }

    let data: Value = response
        .json()
        .await
        .map_err(|err| AppError::external_service(format!("OAuth 登录失败：{err}")))?;
    if !data.is_object() {
        return Err(AppError::external_service(
            "OAuth 登录失败：userinfo 响应格式非法",
        ));
    }

    let raw_id = data.get(&provider.id_field).ok_or_else(|| {
        AppError::external_service(format!(
            "OAuth 登录失败：userinfo 缺少字段 {}",
            provider.id_field
        ))
    })?;
    let provider_user_id = match raw_id {
        Value::String(value) => value.clone(),
        other => other.to_string(),
    };

    let mut email = data
        .get(&provider.email_field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let mut email_verified = data
        .get("email_verified")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || data
            .get("verified")
            .and_then(Value::as_bool)
            .unwrap_or(false);

    if provider.key == "github" {
        // GitHub 的 /user 不返回邮箱验证标记，且 email 可能是私有的：
        // 总是请求 /user/emails 取 primary 且 verified 的邮箱；失败不阻断登录，
        // 此时 email_verified 保持 /user 响应解析出的值（GitHub 下为 false）。
        if let Ok(response) = client
            .get(GITHUB_EMAILS_URL)
            .header(AUTHORIZATION, format!("Bearer {access_token}"))
            .header(ACCEPT, "application/json")
            .header(USER_AGENT, "qbotmessager")
            .send()
            .await
            && response.status().is_success()
            && let Ok(Value::Array(items)) = response.json::<Value>().await
            && let Some(verified_primary) = items.iter().find(|item| {
                item.as_object()
                    .map(|object| {
                        object.get("primary").and_then(Value::as_bool) == Some(true)
                            && object.get("verified").and_then(Value::as_bool) == Some(true)
                    })
                    .unwrap_or(false)
            })
            && let Some(verified_email) = verified_primary
                .get("email")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
        {
            email = Some(verified_email.to_string());
            email_verified = true;
        }
    }

    let login = data
        .get("login")
        .and_then(Value::as_str)
        .or_else(|| data.get(&provider.name_field).and_then(Value::as_str))
        .map(str::to_string)
        .unwrap_or_else(|| provider_user_id.clone());
    let name = data
        .get(&provider.name_field)
        .and_then(Value::as_str)
        .or_else(|| data.get("name").and_then(Value::as_str))
        .map(str::to_string);

    Ok(OAuthProfile {
        provider_user_id,
        login,
        email,
        name,
        email_verified,
    })
}

/// 构造 state Cookie（HttpOnly、SameSite=Lax、Path=/、Max-Age=600）。
///
/// Cookie 名带 flow 后缀隔离并行流程；值仍为 state 主体（不含 flow 前缀）。
pub fn state_cookie(settings: &RuntimeSettings, flow: &str, state: &str) -> Cookie<'static> {
    oauth_cookie(
        flow_cookie_name(STATE_COOKIE, flow),
        state.to_string(),
        settings,
    )
}

/// 构造提供方 Cookie。Cookie 名带 flow 后缀隔离并行流程。
pub fn provider_cookie(
    settings: &RuntimeSettings,
    flow: &str,
    provider_key: &str,
) -> Cookie<'static> {
    oauth_cookie(
        flow_cookie_name(PROVIDER_COOKIE, flow),
        provider_key.to_string(),
        settings,
    )
}

/// 构造绑定用途 Cookie；值只是意图标记，回调以解析出的会话为准。
pub fn link_cookie(settings: &RuntimeSettings, flow: &str) -> Cookie<'static> {
    oauth_cookie(
        flow_cookie_name(LINK_COOKIE, flow),
        "1".to_string(),
        settings,
    )
}

/// 构造删除 OAuth 临时 Cookie 的指令（属性与签发时保持一致）。
///
/// name 接受运行期拼接的带 flow 后缀名，因此放宽为 `&str`。
pub fn clear_cookie(name: &str, settings: &RuntimeSettings) -> Cookie<'static> {
    Cookie::build(name.to_string(), String::new())
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(CookieDuration::seconds(0))
        .secure(settings.secure_cookies())
        .finish()
}

fn oauth_cookie(name: String, value: String, settings: &RuntimeSettings) -> Cookie<'static> {
    Cookie::build(name, value)
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(CookieDuration::seconds(COOKIE_MAX_AGE_SECONDS))
        .secure(settings.secure_cookies())
        .finish()
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && bool::from(left.ct_eq(right))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider() -> OAuthProvider {
        OAuthProvider {
            id: 1,
            key: "github".to_string(),
            display_name: "GitHub".to_string(),
            client_id: "client".to_string(),
            client_secret: String::new(),
            authorization_url: "https://github.com/login/oauth/authorize".to_string(),
            token_url: "https://github.com/login/oauth/access_token".to_string(),
            userinfo_url: "https://api.github.com/user".to_string(),
            scopes: "read:user user:email".to_string(),
            email_field: "email".to_string(),
            id_field: "id".to_string(),
            name_field: "login".to_string(),
            enabled: true,
            email_verified: true,
            created_at: chrono::Utc::now().naive_utc(),
        }
    }

    #[test]
    fn state_is_32_url_safe_chars() {
        let state = new_state();
        assert_eq!(state.len(), 32);
        assert!(
            state
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        );
        assert_ne!(state, new_state());
    }

    #[test]
    fn flow_is_16_lowercase_hex_chars() {
        let flow = new_flow();
        assert_eq!(flow.len(), 16);
        assert!(
            flow.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
        assert_ne!(flow, new_flow());
    }

    #[test]
    fn cookie_names_carry_flow_suffix() {
        let settings = RuntimeSettings::new(None);
        let flow = new_flow();
        assert_eq!(
            flow_cookie_name(STATE_COOKIE, &flow),
            format!("oauth_state_{flow}")
        );
        // flow 为空时退回回退名，回调解析失败也能拿到默认名查询。
        assert_eq!(flow_cookie_name(STATE_COOKIE, ""), "oauth_state");

        let cookie = state_cookie(&settings, &flow, "state-body");
        assert_eq!(cookie.name(), format!("oauth_state_{flow}"));
        assert_eq!(cookie.value(), "state-body");
        let cookie = provider_cookie(&settings, &flow, "github");
        assert_eq!(cookie.name(), format!("oauth_provider_{flow}"));
        assert_eq!(cookie.value(), "github");
        let cookie = link_cookie(&settings, &flow);
        assert_eq!(cookie.name(), format!("oauth_link_{flow}"));
        assert_eq!(cookie.value(), "1");
        // 清除指令同样落在带后缀的名上。
        let cookie = clear_cookie(&format!("oauth_state_{flow}"), &settings);
        assert_eq!(cookie.name(), format!("oauth_state_{flow}"));
    }

    #[test]
    fn state_param_splits_into_flow_and_body() {
        let flow = new_flow();
        let state = new_state();
        let param = format!("{flow}.{state}");
        let (parsed_flow, body) = split_state_param(&param);
        assert_eq!(parsed_flow, flow);
        assert_eq!(body, state);
        // 缺失分隔符：flow 为空，主体保持原值（校验随后自然失败）。
        let (parsed_flow, body) = split_state_param(&state);
        assert_eq!(parsed_flow, "");
        assert_eq!(body, state);
    }

    #[test]
    fn state_validation_accepts_matching_pair() {
        let state = new_state();
        assert!(validate_state(&state, &state, "github", "github").is_ok());
    }

    #[test]
    fn state_validation_rejects_mismatch() {
        let state = new_state();
        assert!(validate_state(&state, "another-state", "github", "github").is_err());
        // 空参数与空 Cookie 都必须拒绝。
        assert!(validate_state("", "", "github", "github").is_err());
        assert!(validate_state(&state, "", "github", "github").is_err());
        assert!(validate_state("", &state, "github", "github").is_err());
    }

    #[test]
    fn state_validation_rejects_provider_mismatch() {
        let state = new_state();
        let error = validate_state(&state, &state, "gitlab", "github").unwrap_err();
        assert_eq!(error.detail(), "OAuth state 校验失败");
    }

    #[test]
    fn callback_path_and_redirect_uri_follow_contract() {
        assert_eq!(callback_path("github"), "/api/auth/oauth/github/callback");
        assert_eq!(
            redirect_uri("https://example.com/", "github"),
            "https://example.com/api/auth/oauth/github/callback"
        );
    }

    #[test]
    fn authorize_url_keeps_parameter_order() {
        let url = build_authorize_url(&provider(), "https://example.com/cb", "st ate");
        assert!(url.starts_with("https://github.com/login/oauth/authorize?"));
        let query = url.split_once('?').unwrap().1;
        let keys: Vec<&str> = query
            .split('&')
            .map(|pair| pair.split_once('=').unwrap().0)
            .collect();
        assert_eq!(
            keys,
            vec![
                "client_id",
                "redirect_uri",
                "response_type",
                "state",
                "scope"
            ]
        );
        // form 编码：空格编码为 `+`。
        assert!(query.contains("state=st+ate"));
    }
}
