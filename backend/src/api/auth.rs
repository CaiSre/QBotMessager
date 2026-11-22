//! 认证相关端点（`/api/auth`）。
//!
//! 约定：
//! - 响应体字段、状态码与中文错误信息；
//! - 会话 / OAuth / Passkey 的 Cookie 全部通过 [`crate::auth`] 下的子模块构造；
//! - 登录失败限速复用 [`crate::services::throttle::AttemptLimiter`]；
//! - 请求体解析失败统一返回 422（400 用于请求体过大），`detail` 为中文。
//!
//! 端点清单：
//! - `GET  /api/auth/providers`
//! - `GET  /api/auth/me`
//! - `PATCH /api/auth/me/name`、`PATCH /api/auth/me/email`、
//!   `PATCH /api/auth/me/password`、`POST /api/auth/me/password-code`
//! - `POST /api/auth/email-code`
//! - `POST /api/auth/password/reset`
//! - `POST /api/auth/login`、`POST /api/auth/logout`、`POST /api/auth/register`
//! - `GET  /api/auth/oauth/{key}/start`、`GET /api/auth/oauth/{key}/callback`
//! - `GET  /api/auth/oauth/identities`、`DELETE /api/auth/oauth/identities/{id}`
//! - `GET  /api/auth/passkey`、`DELETE /api/auth/passkey/{id}`
//! - `POST /api/auth/passkey/register/begin`、`POST /api/auth/passkey/register/finish`
//! - `POST /api/auth/passkey/login/begin`、`POST /api/auth/passkey/login/finish`

use actix_web::http::header::{HOST, LOCATION, USER_AGENT};
use actix_web::web;
use actix_web::{HttpRequest, HttpResponse};
use chrono::{NaiveDateTime, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::MySqlPool;
use webauthn_rs_core::proto::{PublicKeyCredential, RegisterPublicKeyCredential};

use crate::auth::{oauth, passkey, sessions};
use crate::db::models::{ROLE_USER, STATUS_ACTIVE, User, WebauthnCredential};
use crate::db::queries;
use crate::error::AppError;
use crate::services::runtime_settings::RuntimeSettings;
use crate::services::{email_codes, mail, users};
use crate::state::AppState;

/// 注册认证路由。
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/auth")
            .app_data(json_config())
            .route("/providers", web::get().to(list_providers))
            .route("/me", web::get().to(me))
            .route("/me/name", web::patch().to(update_name))
            .route("/me/email", web::patch().to(update_email))
            .route("/me/password", web::patch().to(update_password))
            .route("/me/password-code", web::post().to(request_password_code))
            .route("/email-code", web::post().to(request_email_code))
            .route("/password/reset", web::post().to(reset_password))
            .route("/login", web::post().to(login))
            .route("/logout", web::post().to(logout))
            .route("/register", web::post().to(register))
            .route("/oauth/{provider_key}/start", web::get().to(oauth_start))
            .route(
                "/oauth/{provider_key}/callback",
                web::get().to(oauth_callback),
            )
            .route("/oauth/identities", web::get().to(list_oauth_identities))
            .route("/oauth/identities/{id}", web::delete().to(unlink_oauth))
            .route("/passkey", web::get().to(list_passkeys))
            .route("/passkey/{credential_id}", web::delete().to(delete_passkey))
            .route(
                "/passkey/register/begin",
                web::post().to(passkey_register_begin),
            )
            .route(
                "/passkey/register/finish",
                web::post().to(passkey_register_finish),
            )
            .route("/passkey/login/begin", web::post().to(passkey_login_begin))
            .route(
                "/passkey/login/finish",
                web::post().to(passkey_login_finish),
            ),
    );
}

// --------------------------------------------------------------------------- 请求体
//
// 请求体只负责反序列化；业务校验在各自的辅助函数或 services 中完成
// （失败返回 422，信息为中文）。

/// 登录：账号（用户名或邮箱）与密码。
#[derive(Debug, Deserialize)]
struct LoginIn {
    account: String,
    password: String,
}

/// 注册：邀请码、邮箱、密码，可选用户名与邮箱验证码。
#[derive(Debug, Deserialize)]
struct RegisterIn {
    invite_code: String,
    email: String,
    password: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    email_code: String,
}

/// 发送邮箱验证码。
#[derive(Debug, Deserialize)]
struct EmailCodeIn {
    email: String,
    purpose: String,
}

/// 通过邮箱验证码重置密码。
#[derive(Debug, Deserialize)]
struct PasswordResetIn {
    email: String,
    code: String,
    new_password: String,
}

/// 修改用户名。
#[derive(Debug, Deserialize)]
struct NameIn {
    name: String,
}

/// 修改邮箱；已有密码的账号必须提供当前密码。
#[derive(Debug, Deserialize)]
struct EmailChangeIn {
    email: String,
    #[serde(default)]
    current_password: String,
}

/// 修改密码；无密码账号可改用邮箱验证码。
#[derive(Debug, Deserialize)]
struct PasswordChangeIn {
    #[serde(default)]
    current_password: String,
    new_password: String,
    #[serde(default)]
    email_code: String,
}

/// Passkey 注册 / 登录完成：浏览器返回的凭据对象与本次流程的 flow。
///
/// `flow` 必填（缺失由 serde 拒绝），值来自 begin 响应外层的 `flow` 键，
/// 用于定位 `webauthn_*_{flow}` 临时 Cookie，隔离同浏览器并行的流程。
#[derive(Debug, Deserialize)]
struct PasskeyFinishIn {
    credential: Value,
    flow: String,
}

/// OAuth 回调查询参数；缺失时按空串处理。
#[derive(Debug, Deserialize)]
struct OAuthCallbackQuery {
    #[serde(default)]
    code: String,
    #[serde(default)]
    state: String,
}

/// 请求体解析错误的统一映射。
///
/// 校验失败返回 422；请求体过大映射为 400；`detail` 一律使用中文，
/// 前端 `detailOf()` 只取字符串分支。
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

// --------------------------------------------------------------------- 元信息 / 会话

/// `GET /api/auth/providers`
async fn list_providers(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> Result<HttpResponse, AppError> {
    let settings = (*state.settings()).clone();
    let providers = queries::oauth::list_enabled(&state.pool).await?;
    let oauth_providers: Vec<Value> = providers
        .iter()
        .map(|provider| {
            json!({
                "key": &provider.key,
                "display_name": &provider.display_name,
            })
        })
        .collect();
    let rp_id = request_rp_id(&settings, &req);

    Ok(HttpResponse::Ok().json(json!({
        "registration_enabled": settings.register_enabled(),
        "password_enabled": true,
        "passkey_enabled": true,
        "email_code_enabled": mail::is_configured(&settings),
        "rp_id": rp_id,
        "oauth_providers": oauth_providers,
    })))
}

/// `GET /api/auth/me`
async fn me(req: HttpRequest, state: web::Data<AppState>) -> Result<HttpResponse, AppError> {
    let user = require_user(&state, &req).await?;
    let passkey_count = passkey_store::count_for_user(&state.pool, user.id).await?;

    let mut payload = user_payload(&user);
    if let Value::Object(map) = &mut payload {
        map.insert("passkey_count".to_string(), json!(passkey_count));
    }
    Ok(HttpResponse::Ok().json(payload))
}

// ---------------------------------------------------------------------- 个人资料

/// `PATCH /api/auth/me/name`
async fn update_name(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<NameIn>,
) -> Result<HttpResponse, AppError> {
    let user = require_user(&state, &req).await?;
    let updated = users::update_profile_name(&state.pool, &user, &body.name).await?;
    Ok(HttpResponse::Ok().json(user_payload(&updated)))
}

/// `PATCH /api/auth/me/email`
async fn update_email(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<EmailChangeIn>,
) -> Result<HttpResponse, AppError> {
    let user = require_user(&state, &req).await?;
    validate_optional_password(&body.current_password)?;
    let email = validate_email_input(&body.email)?;
    let token = session_token(&state, &req);
    let updated =
        users::update_profile_email(&state.pool, &user, &email, &body.current_password, &token)
            .await?;
    Ok(HttpResponse::Ok().json(user_payload(&updated)))
}

/// `PATCH /api/auth/me/password`
async fn update_password(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<PasswordChangeIn>,
) -> Result<HttpResponse, AppError> {
    let user = require_user(&state, &req).await?;
    let settings = (*state.settings()).clone();
    validate_optional_password(&body.current_password)?;
    validate_email_code_field(&body.email_code)?;
    let token = session_token(&state, &req);

    users::change_password(
        &state.pool,
        &settings,
        &user,
        &body.current_password,
        &body.new_password,
        &body.email_code,
        &token,
    )
    .await?;
    Ok(HttpResponse::Ok().json(json!({ "ok": true })))
}

/// `POST /api/auth/me/password-code`
async fn request_password_code(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> Result<HttpResponse, AppError> {
    let user = require_user(&state, &req).await?;
    let settings = (*state.settings()).clone();
    if !mail::is_configured(&settings) {
        return Err(AppError::database_busy("邮件服务未配置"));
    }
    if user.password_hash.is_some() {
        return Err(AppError::bad_request("账号已有密码，请直接修改密码"));
    }
    let ip = state.client_ip(&req);
    let response = send_code(
        &state,
        &settings,
        &user.email,
        email_codes::PURPOSE_SET_PASSWORD,
        ip.as_deref(),
    )
    .await?;
    Ok(HttpResponse::Ok().json(response))
}

/// `POST /api/auth/email-code`
async fn request_email_code(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<EmailCodeIn>,
) -> Result<HttpResponse, AppError> {
    // 请求体校验先于业务开关与邮件配置检查。
    let email = validate_email_input(&body.email)?;
    validate_email_code_purpose(&body.purpose)?;

    let settings = (*state.settings()).clone();
    if !mail::is_configured(&settings) {
        return Err(AppError::database_busy("邮件服务未配置"));
    }

    if body.purpose == email_codes::PURPOSE_REGISTER {
        if !settings.register_enabled() {
            return Err(AppError::forbidden("注册入口已关闭"));
        }
        if queries::users::find_by_email(&state.pool, &email)
            .await?
            .is_some()
        {
            // 邮箱已注册时不发信，但返回相同结果，避免枚举账号。
            return Ok(HttpResponse::Ok().json(code_response(&settings)));
        }
    } else {
        let existing = queries::users::find_by_email(&state.pool, &email).await?;
        if !existing.is_some_and(|user| user.status == STATUS_ACTIVE) {
            // 用户不存在或已停用时同样静默返回，避免枚举账号。
            return Ok(HttpResponse::Ok().json(code_response(&settings)));
        }
    }

    let ip = state.client_ip(&req);
    let response = send_code(&state, &settings, &email, &body.purpose, ip.as_deref()).await?;
    Ok(HttpResponse::Ok().json(response))
}

/// `POST /api/auth/password/reset`
async fn reset_password(
    state: web::Data<AppState>,
    body: web::Json<PasswordResetIn>,
) -> Result<HttpResponse, AppError> {
    let settings = (*state.settings()).clone();
    let email = validate_email_input(&body.email)?;
    validate_code_field(&body.code)?;

    users::reset_password(
        &state.pool,
        &settings,
        &email,
        &body.code,
        &body.new_password,
    )
    .await?;
    Ok(HttpResponse::Ok().json(json!({ "ok": true })))
}

/// `POST /api/auth/login`
async fn login(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<LoginIn>,
) -> Result<HttpResponse, AppError> {
    let settings = (*state.settings()).clone();
    let ip = state.client_ip(&req);
    let user_agent = user_agent(&req);

    let session = users::login(
        &state.pool,
        &state.login_limiter,
        &settings,
        &body.account,
        &body.password,
        ip.as_deref(),
        user_agent,
    )
    .await?;

    let cookie = sessions::session_cookie(
        &state.config,
        &settings,
        &session.token,
        settings.session_ttl_hours(),
    );
    Ok(HttpResponse::Ok()
        .cookie(cookie)
        .json(user_payload(&session.user)))
}

/// `POST /api/auth/logout`
async fn logout(req: HttpRequest, state: web::Data<AppState>) -> Result<HttpResponse, AppError> {
    let settings = (*state.settings()).clone();
    let token = session_token(&state, &req);
    sessions::revoke_session(&state.pool, &token).await?;
    Ok(HttpResponse::Ok()
        .cookie(sessions::clear_session_cookie(&state.config, &settings))
        .json(json!({ "ok": true })))
}

/// `POST /api/auth/register`
async fn register(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<RegisterIn>,
) -> Result<HttpResponse, AppError> {
    let settings = (*state.settings()).clone();
    validate_email_code_field(&body.email_code)?;
    let email = validate_email_input(&body.email)?;
    let ip = state.client_ip(&req);
    let user_agent = user_agent(&req);

    let session = users::register(
        &state.pool,
        &settings,
        users::RegisterInput {
            email: &email,
            password: &body.password,
            name: &body.name,
            invite_code: &body.invite_code,
            email_code: Some(body.email_code.as_str()),
        },
        ip.as_deref(),
        user_agent,
    )
    .await?;

    let cookie = sessions::session_cookie(
        &state.config,
        &settings,
        &session.token,
        settings.session_ttl_hours(),
    );
    Ok(HttpResponse::Ok()
        .cookie(cookie)
        .json(user_payload(&session.user)))
}

// ----------------------------------------------------------------------- OAuth2

/// `GET /api/auth/oauth/{key}/start`
async fn oauth_start(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let provider_key = path.into_inner();
    let provider = queries::oauth::find_enabled_by_key(&state.pool, &provider_key)
        .await?
        .ok_or_else(|| AppError::not_found("提供方不存在或未启用"))?;

    // 只做一次可解密性校验：结果不写回实体。
    let _client_secret = oauth::client_secret(&provider, state.config.app_secret_key.as_deref())?;

    let settings = (*state.settings()).clone();
    let origin = request_origin(&state, &settings, &req);
    let redirect_uri = oauth::redirect_uri(&origin, &provider.key);
    // flow 编码进 state 参数与 Cookie 名后缀，同一浏览器的并行流程互不覆盖。
    let flow = oauth::new_flow();
    let state_value = oauth::new_state();
    let url =
        oauth::build_authorize_url(&provider, &redirect_uri, &format!("{flow}.{state_value}"));

    // 已登录用户发起的流程按「绑定」处理：回调据此把第三方账号挂到当前用户，
    // 而不是走登录/自动注册分支。
    let session_user = sessions::resolve_session(&state.pool, &session_token(&state, &req)).await?;
    let mut response = HttpResponse::Found()
        .append_header((LOCATION, url))
        .finish();
    let cookie_result = response
        .add_cookie(&oauth::state_cookie(&settings, &flow, &state_value))
        .and_then(|()| {
            response.add_cookie(&oauth::provider_cookie(&settings, &flow, &provider.key))
        })
        .and_then(|()| {
            if session_user.is_some() {
                response.add_cookie(&oauth::link_cookie(&settings, &flow))
            } else {
                Ok(())
            }
        });
    cookie_result.map_err(|_| AppError::internal("响应构造失败"))?;
    Ok(response)
}

/// `GET /api/auth/oauth/{key}/callback`
///
/// 浏览器直达端点：任何流程错误都不再返回 JSON，而是 302 到前端提示页
/// `/oauth/failure`，由页面渲染中文提示与后续操作。
async fn oauth_callback(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    query: web::Query<OAuthCallbackQuery>,
) -> HttpResponse {
    let settings = (*state.settings()).clone();
    let provider_key_path = path.into_inner();
    // 失败路径的 Cookie 清理以 query.state 解析出的 flow 为准；
    // 能解析则清对应流程的三个 Cookie，解析不出则不清。
    let (failure_flow, _) = oauth::split_state_param(&query.state);
    let result = oauth_callback_inner(&req, &state, &provider_key_path, &query).await;
    match result {
        Ok(response) => response,
        Err(err) => oauth_failure_redirect(&settings, &failure_flow, &err),
    }
}

/// 回调主逻辑；错误统一交给外层转提示页。
async fn oauth_callback_inner(
    req: &HttpRequest,
    state: &web::Data<AppState>,
    path: &str,
    query: &OAuthCallbackQuery,
) -> Result<HttpResponse, AppError> {
    let provider_key = path.to_string();
    // state 参数格式为 "{flow16}.{state32}"：flow 决定读哪组 Cookie；
    // 缺 '.' 时 flow 为空，回退到不带后缀的名，校验自然失败而非 panic。
    let (flow, state_body) = oauth::split_state_param(&query.state);
    let cookie_state = req
        .cookie(&oauth::flow_cookie_name(oauth::STATE_COOKIE, &flow))
        .map(|cookie| cookie.value().to_string())
        .unwrap_or_default();
    let cookie_provider = req
        .cookie(&oauth::flow_cookie_name(oauth::PROVIDER_COOKIE, &flow))
        .map(|cookie| cookie.value().to_string())
        .unwrap_or_default();
    oauth::validate_state(state_body, &cookie_state, &cookie_provider, &provider_key)?;
    if query.code.is_empty() {
        return Err(AppError::bad_request("缺少授权码"));
    }

    let provider = queries::oauth::find_enabled_by_key(&state.pool, &provider_key)
        .await?
        .ok_or_else(|| AppError::not_found("提供方不存在或未启用"))?;
    let client_secret = oauth::client_secret(&provider, state.config.app_secret_key.as_deref())?;

    let settings = (*state.settings()).clone();
    let origin = request_origin(state, &settings, req);
    let redirect_uri = oauth::redirect_uri(&origin, &provider.key);

    let token_data = oauth::exchange_code(
        &state.http,
        &provider,
        &query.code,
        &redirect_uri,
        &client_secret,
    )
    .await?;
    let access_token = token_data
        .get("access_token")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let profile = oauth::fetch_profile(&state.http, &provider, &access_token).await?;

    let now = Utc::now().naive_utc();
    let identity =
        queries::oauth::find_identity(&state.pool, &provider.key, &profile.provider_user_id)
            .await?;

    // 绑定分支：start 时带会话、且回调时仍能解析出有效会话。
    let link_cookie_name = oauth::flow_cookie_name(oauth::LINK_COOKIE, &flow);
    let link_user = match req.cookie(&link_cookie_name) {
        Some(_) => sessions::resolve_session(&state.pool, &session_token(state, req)).await?,
        None => None,
    };
    if let Some(current) = link_user {
        if current.status != STATUS_ACTIVE {
            return Err(AppError::forbidden("账号不可用"));
        }
        return match identity {
            // 已绑定在当前用户名下：视为成功，直接回用户中心。
            Some(found) if found.user_id == current.id => Ok(oauth_done_redirect(
                &settings,
                &flow,
                false,
                "该账号已绑定，无需重复操作",
            )),
            // 被其他用户绑定：不允许接管。
            Some(_) => Err(AppError::conflict(
                "该第三方账号已绑定到其他用户，无法重复绑定",
            )),
            None => {
                queries::oauth::insert_identity(
                    &state.pool,
                    &queries::oauth::NewAuthIdentity {
                        user_id: current.id,
                        provider: &provider.key,
                        provider_user_id: &profile.provider_user_id,
                        provider_login: Some(&profile.login),
                        created_at: now,
                    },
                )
                .await?;
                Ok(oauth_done_redirect(&settings, &flow, true, "绑定成功"))
            }
        };
    }

    let identity_exists = identity.is_some();
    // 自动注册分支会在建号事务内一并绑定身份；外层兜底插入须跳过该路径，
    // 否则同一身份会被插入两次并撞唯一索引。
    let mut identity_created_in_tx = false;

    let user = if let Some(identity) = identity {
        queries::users::find_by_id(&state.pool, identity.user_id).await?
    } else {
        let existing = match profile.email.as_deref() {
            Some(email) => {
                queries::users::find_by_email(&state.pool, &email.to_lowercase()).await?
            }
            None => None,
        };
        match existing {
            Some(found) => {
                // 自动关联要求提供方在本次响应中确认邮箱已验证；
                // 管理端的静态开关不参与该判定，避免逐响应标记被整体覆盖。
                if !profile.email_verified {
                    return Err(AppError::conflict(
                        "该邮箱已存在本地账号，但提供方未验证邮箱，无法自动关联；请改用密码登录",
                    ));
                }
                Some(found)
            }
            None => {
                if !settings.register_enabled() {
                    return Err(AppError::forbidden(
                        "未找到关联账号，且注册入口已关闭，请联系管理员邀请",
                    ));
                }
                let Some(email) = profile.email.as_deref() else {
                    return Err(AppError::bad_request("提供方未返回邮箱，无法创建账号"));
                };
                let email_lower = email.to_lowercase();
                let preferred = profile
                    .name
                    .as_deref()
                    .filter(|value| !value.is_empty())
                    .unwrap_or(profile.login.as_str());
                let name = users::unique_name(&state.pool, preferred).await?;
                let new_user = queries::users::NewUser {
                    email: &email_lower,
                    name: &name,
                    password_hash: None,
                    role: ROLE_USER,
                    status: STATUS_ACTIVE,
                    created_at: now,
                };
                // 建号与身份绑定同一事务提交，任一步失败整体回滚，避免产生
                // 没有任何登录凭据的孤儿账号。
                let mut tx = state.pool.begin().await?;
                let user_id = queries::users::insert(&mut *tx, &new_user).await?;
                queries::oauth::insert_identity(
                    &mut *tx,
                    &queries::oauth::NewAuthIdentity {
                        user_id,
                        provider: &provider.key,
                        provider_user_id: &profile.provider_user_id,
                        provider_login: Some(&profile.login),
                        created_at: now,
                    },
                )
                .await?;
                tx.commit().await?;
                identity_created_in_tx = true;
                Some(User {
                    id: user_id,
                    email: email_lower,
                    name,
                    password_hash: None,
                    role: ROLE_USER.to_string(),
                    status: STATUS_ACTIVE.to_string(),
                    last_login_at: None,
                    created_at: now,
                })
            }
        }
    };

    let Some(user) = user else {
        return Err(AppError::forbidden("账号不可用"));
    };
    if user.status != STATUS_ACTIVE {
        return Err(AppError::forbidden("账号不可用"));
    }

    // 已有账号但尚未绑定身份：绑定动作在账号确认可用之后单独提交。
    // 注册事务里已绑定的不算，避免重复插入撞唯一索引。
    if !identity_exists && !identity_created_in_tx {
        queries::oauth::insert_identity(
            &state.pool,
            &queries::oauth::NewAuthIdentity {
                user_id: user.id,
                provider: &provider.key,
                provider_user_id: &profile.provider_user_id,
                provider_login: Some(&profile.login),
                created_at: now,
            },
        )
        .await?;
    }

    let ip = state.client_ip(req);
    let token = sessions::create_session(
        &state.pool,
        &user,
        settings.session_ttl_hours(),
        ip.as_deref(),
        user_agent(req),
    )
    .await?;
    let cookie = sessions::session_cookie(
        &state.config,
        &settings,
        &token,
        settings.session_ttl_hours(),
    );

    Ok(HttpResponse::Found()
        .append_header((LOCATION, "/"))
        .cookie(cookie)
        .cookie(oauth::clear_cookie(
            &oauth::flow_cookie_name(oauth::STATE_COOKIE, &flow),
            &settings,
        ))
        .cookie(oauth::clear_cookie(
            &oauth::flow_cookie_name(oauth::PROVIDER_COOKIE, &flow),
            &settings,
        ))
        .cookie(oauth::clear_cookie(
            &oauth::flow_cookie_name(oauth::LINK_COOKIE, &flow),
            &settings,
        ))
        .finish())
}

/// 绑定流程结束后的跳转：带结果参数跳回安全设置页。
///
/// 只清除当前 flow 对应的临时 Cookie；其它并行流程的残留按 Max-Age 自然过期。
fn oauth_done_redirect(
    settings: &RuntimeSettings,
    flow: &str,
    ok: bool,
    message: &str,
) -> HttpResponse {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("oauth", if ok { "ok" } else { "fail" })
        .append_pair("message", message)
        .finish();
    HttpResponse::Found()
        .append_header((LOCATION, format!("/security?{query}")))
        .cookie(oauth::clear_cookie(
            &oauth::flow_cookie_name(oauth::STATE_COOKIE, flow),
            settings,
        ))
        .cookie(oauth::clear_cookie(
            &oauth::flow_cookie_name(oauth::PROVIDER_COOKIE, flow),
            settings,
        ))
        .cookie(oauth::clear_cookie(
            &oauth::flow_cookie_name(oauth::LINK_COOKIE, flow),
            settings,
        ))
        .finish()
}

/// 回调失败后的跳转：中文提示交给前端提示页展示。
///
/// flow 为空（state 无法解析出 flow）时不下发任何清除指令，
/// 避免误清其它并行流程仍在使用的 Cookie。
fn oauth_failure_redirect(settings: &RuntimeSettings, flow: &str, err: &AppError) -> HttpResponse {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("message", err.detail())
        .append_pair("detail", &err.to_string())
        .finish();
    let location = format!("/oauth/failure?{query}");
    tracing::warn!(error = %err, "OAuth 回调失败，重定向到提示页");
    // 无法解析 flow 时不下发任何清除指令，避免误删其它并行流程仍在使用的 Cookie。
    let mut builder = HttpResponse::Found();
    let mut response = builder.append_header((LOCATION, location));
    if !flow.is_empty() {
        response = response
            .cookie(oauth::clear_cookie(
                &oauth::flow_cookie_name(oauth::STATE_COOKIE, flow),
                settings,
            ))
            .cookie(oauth::clear_cookie(
                &oauth::flow_cookie_name(oauth::PROVIDER_COOKIE, flow),
                settings,
            ))
            .cookie(oauth::clear_cookie(
                &oauth::flow_cookie_name(oauth::LINK_COOKIE, flow),
                settings,
            ));
    }
    response.finish()
}

/// `GET /api/auth/oauth/identities`
async fn list_oauth_identities(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> Result<HttpResponse, AppError> {
    let user = require_user(&state, &req).await?;
    let rows = queries::oauth::list_identities_for_user(&state.pool, user.id).await?;
    let items: Vec<Value> = rows
        .iter()
        .map(|row| {
            json!({
                "id": row.id,
                "provider": &row.provider,
                "provider_login": &row.provider_login,
                "created_at": &row.created_at,
            })
        })
        .collect();
    Ok(HttpResponse::Ok().json(items))
}

/// `DELETE /api/auth/oauth/identities/{id}`
///
/// 解绑前确保账号仍保有至少一种登录方式：密码、通行密钥或其他第三方绑定；
/// 否则仅剩这一条绑定会被删光，账号将无法登录。
async fn unlink_oauth(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let user = require_user(&state, &req).await?;
    let identity_id = path
        .into_inner()
        .parse::<i64>()
        .map_err(|_| AppError::validation("绑定 ID 非法"))?;

    let record = queries::oauth::find_identity_by_id(&state.pool, identity_id).await?;
    if record.as_ref().map(|row| row.user_id) != Some(user.id) {
        return Err(AppError::not_found("绑定不存在"));
    }

    let has_password = user.password_hash.is_some();
    let passkey_count = passkey_store::count_for_user(&state.pool, user.id).await?;
    let identity_count = queries::oauth::count_identities_for_user(&state.pool, user.id).await?;
    if !has_password && passkey_count == 0 && identity_count <= 1 {
        return Err(AppError::conflict(
            "解绑后账号将没有任何登录方式，请先设置密码或通行密钥",
        ));
    }

    queries::oauth::delete_identity(&state.pool, identity_id).await?;
    Ok(HttpResponse::Ok().json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------- Passkey

/// `GET /api/auth/passkey`
async fn list_passkeys(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> Result<HttpResponse, AppError> {
    let user = require_user(&state, &req).await?;
    let rows = passkey_store::list_for_user(&state.pool, user.id).await?;
    let items: Vec<Value> = rows
        .iter()
        .map(|row| {
            json!({
                "id": row.id,
                "label": &row.label,
                "device_type": row.device_type.as_deref(),
                "backed_up": row.backed_up,
                "created_at": &row.created_at,
                "last_used_at": row.last_used_at.as_ref(),
            })
        })
        .collect();
    Ok(HttpResponse::Ok().json(items))
}

/// `POST /api/auth/passkey/register/begin`
async fn passkey_register_begin(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> Result<HttpResponse, AppError> {
    let user = require_user(&state, &req).await?;
    let settings = (*state.settings()).clone();
    let rp_id = request_rp_id(&settings, &req);
    let origin = request_origin(&state, &settings, &req);
    let begin =
        passkey::registration_options(&rp_id, settings.rp_name(), &origin, user.id, &user.email)?;
    let flow = passkey::new_flow();
    let mut body = begin.options;
    // flow 并入 options JSON 外层（前端 unwrap 只取 publicKey，外层多键安全）。
    if let Some(obj) = body.as_object_mut() {
        obj.insert("flow".into(), json!(flow));
    }

    Ok(HttpResponse::Ok()
        .cookie(passkey::challenge_cookie(
            &settings,
            &flow,
            &begin.challenge,
        ))
        .cookie(passkey::user_cookie(&settings, &flow, user.id))
        .cookie(passkey::state_cookie(&settings, &flow, &begin.state))
        .json(body))
}

/// `POST /api/auth/passkey/register/finish`
async fn passkey_register_finish(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<PasskeyFinishIn>,
) -> Result<HttpResponse, AppError> {
    let user = require_user(&state, &req).await?;
    let settings = (*state.settings()).clone();
    let flow = finish_flow(&body.flow)?;
    let raw_challenge = cookie_value(
        &req,
        &passkey::cookie_name(passkey::CHALLENGE_COOKIE, &flow),
    );
    let cookie_user = cookie_value(&req, &passkey::cookie_name(passkey::USER_COOKIE, &flow));
    if raw_challenge.is_empty() || cookie_user != user.id.to_string() {
        return Err(AppError::bad_request("注册会话已过期，请重试"));
    }
    let state_cookie = cookie_value(&req, &passkey::cookie_name(passkey::STATE_COOKIE, &flow));
    if state_cookie.is_empty() {
        return Err(AppError::bad_request("注册会话已过期，请重试"));
    }
    if !body.credential.is_object() {
        return Err(AppError::validation("credential 必须是 JSON 对象"));
    }

    let challenge = passkey::b64url_decode(&raw_challenge)
        .map_err(|_| AppError::bad_request("注册会话已过期，请重试"))?;
    let credential: RegisterPublicKeyCredential =
        serde_json::from_value(body.credential.clone())
            .map_err(|err| AppError::bad_request(format!("Passkey 校验失败：{err}")))?;

    let rp_id = request_rp_id(&settings, &req);
    let origin = request_origin(&state, &settings, &req);
    let result = passkey::verify_registration(
        &credential,
        &challenge,
        &rp_id,
        settings.rp_name(),
        &origin,
        &state_cookie,
    )?;

    if passkey_store::find_by_credential_id(&state.pool, &result.credential_id)
        .await?
        .is_some()
    {
        return Err(AppError::conflict("该 Passkey 已绑定"));
    }

    let transports = passkey_transports(&body.credential);
    let label = passkey_label(&body.credential);
    passkey_store::insert(
        &state.pool,
        passkey_store::NewPasskey {
            user_id: user.id,
            credential_id: &result.credential_id,
            public_key: &result.public_key,
            sign_count: result.sign_count,
            aaguid: &result.aaguid,
            transports: transports.as_ref(),
            device_type: &result.device_type,
            backed_up: result.backed_up,
            label: &label,
            created_at: Utc::now().naive_utc(),
        },
    )
    .await?;

    let mut response = HttpResponse::Ok();
    for cookie in passkey::clear_passkey_cookies(&settings, &flow) {
        response.cookie(cookie);
    }
    Ok(response.json(json!({ "ok": true })))
}

/// `DELETE /api/auth/passkey/{id}`
async fn delete_passkey(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let user = require_user(&state, &req).await?;
    let credential_id = path
        .into_inner()
        .parse::<i64>()
        .map_err(|_| AppError::validation("凭证 ID 非法"))?;

    let record = passkey_store::find_by_id(&state.pool, credential_id).await?;
    if record.as_ref().map(|row| row.user_id) != Some(user.id) {
        return Err(AppError::not_found("凭证不存在"));
    }
    passkey_store::delete(&state.pool, credential_id).await?;
    Ok(HttpResponse::Ok().json(json!({ "ok": true })))
}

/// `POST /api/auth/passkey/login/begin`
async fn passkey_login_begin(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> Result<HttpResponse, AppError> {
    let settings = (*state.settings()).clone();
    let rp_id = request_rp_id(&settings, &req);
    let origin = request_origin(&state, &settings, &req);
    let begin = passkey::authentication_options(&rp_id, settings.rp_name(), &origin)?;
    let flow = passkey::new_flow();
    let mut body = begin.options;
    // flow 并入 options JSON 外层（前端 unwrap 只取 publicKey，外层多键安全）。
    if let Some(obj) = body.as_object_mut() {
        obj.insert("flow".into(), json!(flow));
    }

    Ok(HttpResponse::Ok()
        .cookie(passkey::challenge_cookie(
            &settings,
            &flow,
            &begin.challenge,
        ))
        .cookie(passkey::state_cookie(&settings, &flow, &begin.state))
        .json(body))
}

/// `POST /api/auth/passkey/login/finish`
async fn passkey_login_finish(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<PasskeyFinishIn>,
) -> Result<HttpResponse, AppError> {
    let settings = (*state.settings()).clone();
    let flow = finish_flow(&body.flow)?;
    let raw_challenge = cookie_value(
        &req,
        &passkey::cookie_name(passkey::CHALLENGE_COOKIE, &flow),
    );
    if raw_challenge.is_empty() {
        return Err(AppError::bad_request("登录会话已过期，请重试"));
    }
    let state_cookie = cookie_value(&req, &passkey::cookie_name(passkey::STATE_COOKIE, &flow));
    if state_cookie.is_empty() {
        return Err(AppError::bad_request("登录会话已过期，请重试"));
    }
    if !body.credential.is_object() {
        return Err(AppError::validation("credential 必须是 JSON 对象"));
    }

    let raw_id = body
        .credential
        .get("id")
        .or_else(|| body.credential.get("rawId"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let credential_id =
        passkey::b64url_decode(raw_id).map_err(|_| AppError::bad_request("凭证格式非法"))?;
    let record = passkey_store::find_by_credential_id(&state.pool, &credential_id)
        .await?
        .ok_or_else(|| AppError::unauthorized("该 Passkey 未绑定"))?;

    let challenge = passkey::b64url_decode(&raw_challenge)
        .map_err(|_| AppError::bad_request("登录会话已过期，请重试"))?;
    let credential: PublicKeyCredential = serde_json::from_value(body.credential.clone())
        .map_err(|err| AppError::unauthorized(format!("Passkey 校验失败：{err}")))?;

    let rp_id = request_rp_id(&settings, &req);
    let origin = request_origin(&state, &settings, &req);
    let result = passkey::verify_authentication(
        &credential,
        &challenge,
        &rp_id,
        settings.rp_name(),
        &origin,
        &state_cookie,
        passkey::StoredCredential {
            credential_id: &record.credential_id,
            public_key: &record.public_key,
            sign_count: record.sign_count,
            device_type: record.device_type.as_deref(),
            backed_up: record.backed_up,
        },
    )?;

    let Some(user) = queries::users::find_by_id(&state.pool, record.user_id).await? else {
        return Err(AppError::forbidden("账号不可用"));
    };
    if user.status != STATUS_ACTIVE {
        return Err(AppError::forbidden("账号不可用"));
    }

    passkey_store::update_usage(
        &state.pool,
        record.id,
        i64::from(result.new_sign_count),
        Utc::now().naive_utc(),
        &result.device_type,
        result.backed_up,
    )
    .await?;

    let ip = state.client_ip(&req);
    let token = sessions::create_session(
        &state.pool,
        &user,
        settings.session_ttl_hours(),
        ip.as_deref(),
        user_agent(&req),
    )
    .await?;
    let cookie = sessions::session_cookie(
        &state.config,
        &settings,
        &token,
        settings.session_ttl_hours(),
    );

    let mut response = HttpResponse::Ok();
    response.cookie(cookie);
    for cookie in passkey::clear_passkey_cookies(&settings, &flow) {
        response.cookie(cookie);
    }
    Ok(response.json(json!({ "ok": true })))
}

/// 校验 finish 请求体里的 flow，通过则原样返回。
///
/// flow 会被拼进 Cookie 名，必须先收紧为 `new_flow` 的输出格式，
/// 防止任意字符串进入 Set-Cookie 头。
fn finish_flow(flow: &str) -> Result<&str, AppError> {
    if passkey::is_valid_flow(flow) {
        Ok(flow)
    } else {
        Err(AppError::validation("flow 格式非法"))
    }
}

// ----------------------------------------------------------------------- 辅助

/// 读取当前请求的会话用户；未登录 401，停用 403。
async fn require_user(state: &AppState, req: &HttpRequest) -> Result<User, AppError> {
    let token = session_token(state, req);
    match sessions::resolve_session(&state.pool, &token).await? {
        None => Err(AppError::unauthorized("未登录")),
        Some(user) if user.status != STATUS_ACTIVE => Err(AppError::forbidden("账号已停用")),
        Some(user) => Ok(user),
    }
}

/// 从请求中读取会话 token（Cookie 名来自环境变量配置）。
fn session_token(state: &AppState, req: &HttpRequest) -> String {
    req.cookie(state.config.cookie_name.as_str())
        .map(|cookie| cookie.value().to_string())
        .unwrap_or_default()
}

/// 读取指定 Cookie 的值。
fn cookie_value(req: &HttpRequest, name: &str) -> String {
    req.cookie(name)
        .map(|cookie| cookie.value().to_string())
        .unwrap_or_default()
}

/// 请求头中的 User-Agent。
fn user_agent(req: &HttpRequest) -> Option<&str> {
    req.headers()
        .get(USER_AGENT)
        .and_then(|value| value.to_str().ok())
}

/// 用户公开字段（`_user_payload`）。
fn user_payload(user: &User) -> Value {
    json!({
        "id": user.id,
        "email": &user.email,
        "name": &user.name,
        "role": &user.role,
        "status": &user.status,
        "has_password": user.password_hash.is_some(),
    })
}

/// 验证码响应体（`_code_response`）。
fn code_response(settings: &RuntimeSettings) -> Value {
    json!({
        "ok": true,
        "expires_in": settings.email_code_ttl_minutes().saturating_mul(60),
        "resend_after": settings.email_code_resend_seconds(),
    })
}

/// 签发并发送验证码；邮件失败时作废刚签发的验证码，允许立即重试。
async fn send_code(
    state: &AppState,
    settings: &RuntimeSettings,
    email: &str,
    purpose: &str,
    ip: Option<&str>,
) -> Result<Value, AppError> {
    let code = email_codes::issue_code(
        &state.pool,
        email,
        purpose,
        settings.email_code_ttl_minutes(),
        settings.email_code_resend_seconds(),
        settings.email_code_hourly_limit(),
        ip,
    )
    .await?;

    let (subject, text, html) = mail::render_code_email(
        &code,
        email_codes::purpose_label(purpose),
        settings.email_code_ttl_minutes(),
    );
    if let Err(err) = mail::send_mail(settings, email, &subject, &text, Some(&html)).await {
        tracing::warn!(error = %err, purpose, "验证码邮件发送失败");
        if let Err(discard_err) = email_codes::discard_latest(&state.pool, email, purpose).await {
            // 作废失败不阻断报错返回；残留记录由冷却期抑制下次签发。
            tracing::warn!(error = %discard_err, "作废验证码失败");
        }
        return Err(match err {
            mail::MailError::NotConfigured => AppError::database_busy("邮件服务未配置"),
            mail::MailError::SendFailed => {
                AppError::external_service("验证码邮件发送失败，请稍后重试")
            }
        });
    }
    Ok(code_response(settings))
}

/// 邮箱格式与长度校验，返回规范化后的邮箱。
fn validate_email_input(raw: &str) -> Result<String, AppError> {
    let length = raw.chars().count();
    if length < 3 {
        return Err(AppError::validation("邮箱最短 3 个字符"));
    }
    if length > users::EMAIL_MAX {
        return Err(AppError::validation(format!(
            "邮箱最长 {} 个字符",
            users::EMAIL_MAX
        )));
    }
    let email = users::normalize_email(raw);
    users::validate_email(&email)?;
    Ok(email)
}

/// 邮箱验证码用途（`register` 或 `reset_password`）。
fn validate_email_code_purpose(purpose: &str) -> Result<(), AppError> {
    match purpose {
        email_codes::PURPOSE_REGISTER | email_codes::PURPOSE_RESET_PASSWORD => Ok(()),
        _ => Err(AppError::validation(
            "用途必须是 register 或 reset_password",
        )),
    }
}

/// 重置密码验证码长度（4 到 12 字符）。
fn validate_code_field(code: &str) -> Result<(), AppError> {
    let length = code.chars().count();
    if !(4..=12).contains(&length) {
        return Err(AppError::validation("验证码长度需在 4 到 12 位之间"));
    }
    Ok(())
}

/// 邮箱验证码字段长度（最长 12 字符）。
fn validate_email_code_field(code: &str) -> Result<(), AppError> {
    if code.chars().count() > 12 {
        return Err(AppError::validation("邮箱验证码最长 12 个字符"));
    }
    Ok(())
}

/// 可选当前密码字段长度（最长 256 字符）。
fn validate_optional_password(password: &str) -> Result<(), AppError> {
    if password.chars().count() > users::PASSWORD_MAX {
        return Err(AppError::validation(format!(
            "密码最长 {} 个字符",
            users::PASSWORD_MAX
        )));
    }
    Ok(())
}

/// Passkey 标签：凭据里的 `label`，缺省「通行密钥」，按字符截断 64。
fn passkey_label(credential: &Value) -> String {
    credential
        .get("label")
        .and_then(Value::as_str)
        .filter(|label| !label.is_empty())
        .unwrap_or("通行密钥")
        .chars()
        .take(64)
        .collect()
}

/// Passkey 传输方式：`credential.response.transports`，空值按未提供处理。
fn passkey_transports(credential: &Value) -> Option<Value> {
    let value = credential
        .get("response")
        .and_then(|response| response.get("transports"))?;
    let empty = match value {
        Value::Null => true,
        Value::Array(items) => items.is_empty(),
        Value::Object(map) => map.is_empty(),
        Value::String(text) => text.is_empty(),
        _ => false,
    };
    if empty { None } else { Some(value.clone()) }
}

/// 请求 Host（不含转发头）。
fn request_host(req: &HttpRequest) -> Option<String> {
    if let Some(value) = req
        .headers()
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Some(value.to_string());
    }
    let connection = req.connection_info();
    let host = connection.host().trim();
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// 取最后一个转发头值（`TRUST_PROXY=true` 时使用）。
fn last_forwarded(req: &HttpRequest, name: &str) -> Option<String> {
    req.headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(|raw| raw.rsplit(',').next())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// 站点 origin：`public_base_url` 优先，否则按请求推导。
///
/// `public_base_url` 为空时 origin 取自请求 Host（或 `TRUST_PROXY` 下的转发头），
/// 仅适用于反向代理已强制校验 Host 的部署；转发 proto 只认 http/https，
/// 其它值按 http 回退。
fn request_origin(state: &AppState, settings: &RuntimeSettings, req: &HttpRequest) -> String {
    if !settings.public_base_url().is_empty() {
        return settings.public_base_url().trim_end_matches('/').to_string();
    }
    let mut scheme = "http".to_string();
    let mut host = request_host(req).unwrap_or_else(|| "localhost".to_string());
    if state.config.trust_proxy {
        if let Some(value) = last_forwarded(req, "x-forwarded-proto")
            && matches!(value.to_ascii_lowercase().as_str(), "http" | "https")
        {
            scheme = value;
        }
        if let Some(value) = last_forwarded(req, "x-forwarded-host") {
            host = value;
        }
    }
    passkey::resolve_origin("", &scheme, Some(&host))
}

/// WebAuthn RP ID：`settings.rp_id` → `public_base_url` hostname → 请求 Host → localhost。
fn request_rp_id(settings: &RuntimeSettings, req: &HttpRequest) -> String {
    let host = request_host(req);
    passkey::resolve_rp_id(
        settings.rp_id(),
        settings.public_base_url(),
        host.as_deref(),
    )
}

// --------------------------------------------------------------- Passkey 持久化

/// `webauthn_credentials` 的读写。
mod passkey_store {
    use super::*;

    /// 新凭据的插入参数。
    pub struct NewPasskey<'a> {
        pub user_id: i64,
        pub credential_id: &'a [u8],
        pub public_key: &'a [u8],
        pub sign_count: i64,
        pub aaguid: &'a str,
        pub transports: Option<&'a Value>,
        pub device_type: &'a str,
        pub backed_up: bool,
        pub label: &'a str,
        pub created_at: NaiveDateTime,
    }

    /// 该用户的全部凭据（按 id 升序）。
    pub async fn list_for_user(
        pool: &MySqlPool,
        user_id: i64,
    ) -> Result<Vec<WebauthnCredential>, sqlx::Error> {
        sqlx::query_as::<_, WebauthnCredential>(
            "SELECT id, user_id, credential_id, public_key, sign_count, aaguid, transports, \
             device_type, backed_up, label, last_used_at, created_at \
             FROM webauthn_credentials WHERE user_id = ? ORDER BY id",
        )
        .bind(user_id)
        .fetch_all(pool)
        .await
    }

    /// 凭据数量。
    pub async fn count_for_user(pool: &MySqlPool, user_id: i64) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            "SELECT CAST(COUNT(*) AS SIGNED) FROM webauthn_credentials WHERE user_id = ?",
        )
        .bind(user_id)
        .fetch_one(pool)
        .await
    }

    /// 按主键查询。
    pub async fn find_by_id(
        pool: &MySqlPool,
        id: i64,
    ) -> Result<Option<WebauthnCredential>, sqlx::Error> {
        sqlx::query_as::<_, WebauthnCredential>(
            "SELECT id, user_id, credential_id, public_key, sign_count, aaguid, transports, \
             device_type, backed_up, label, last_used_at, created_at \
             FROM webauthn_credentials WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(pool)
        .await
    }

    /// 按凭据 ID 查询。
    pub async fn find_by_credential_id(
        pool: &MySqlPool,
        credential_id: &[u8],
    ) -> Result<Option<WebauthnCredential>, sqlx::Error> {
        sqlx::query_as::<_, WebauthnCredential>(
            "SELECT id, user_id, credential_id, public_key, sign_count, aaguid, transports, \
             device_type, backed_up, label, last_used_at, created_at \
             FROM webauthn_credentials WHERE credential_id = ? LIMIT 1",
        )
        .bind(credential_id)
        .fetch_optional(pool)
        .await
    }

    /// 插入凭据。
    pub async fn insert(pool: &MySqlPool, new: NewPasskey<'_>) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO webauthn_credentials \
             (user_id, credential_id, public_key, sign_count, aaguid, transports, \
              device_type, backed_up, label, last_used_at, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)",
        )
        .bind(new.user_id)
        .bind(new.credential_id)
        .bind(new.public_key)
        .bind(new.sign_count)
        .bind(new.aaguid)
        .bind(new.transports)
        .bind(new.device_type)
        .bind(new.backed_up)
        .bind(new.label)
        .bind(new.created_at)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// 认证成功后回写签名计数、使用时间与设备信息。
    ///
    /// 并发断言取较大计数回写，避免双写时互相回退。
    pub async fn update_usage(
        pool: &MySqlPool,
        id: i64,
        sign_count: i64,
        last_used_at: NaiveDateTime,
        device_type: &str,
        backed_up: bool,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE webauthn_credentials \
             SET sign_count = GREATEST(sign_count, ?), last_used_at = ?, device_type = ?, \
             backed_up = ? WHERE id = ?",
        )
        .bind(sign_count)
        .bind(last_used_at)
        .bind(device_type)
        .bind(backed_up)
        .bind(id)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// 删除凭据。
    pub async fn delete(pool: &MySqlPool, id: i64) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM webauthn_credentials WHERE id = ?")
            .bind(id)
            .execute(pool)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use actix_web::ResponseError;

    use super::*;

    #[test]
    fn email_code_purpose_accepts_only_known_purposes() {
        assert!(validate_email_code_purpose("register").is_ok());
        assert!(validate_email_code_purpose("reset_password").is_ok());
        // set_password 只能通过 `/me/password-code` 触发。
        assert_eq!(
            validate_email_code_purpose("set_password")
                .unwrap_err()
                .status_code(),
            actix_web::http::StatusCode::UNPROCESSABLE_ENTITY
        );
        assert!(validate_email_code_purpose("login").is_err());
    }

    #[test]
    fn reset_code_length_bounds() {
        assert!(validate_code_field("1234").is_ok());
        assert!(validate_code_field("123456789012").is_ok());
        assert!(validate_code_field("123").is_err());
        assert!(validate_code_field("1234567890123").is_err());
        // 按字符计数：3 个汉字不足 4 位，4 个汉字刚好合法。
        assert!(validate_code_field("验证码").is_err());
        assert!(validate_code_field("验证码四").is_ok());
    }

    #[test]
    fn email_code_field_caps_at_twelve() {
        assert!(validate_email_code_field("").is_ok());
        assert!(validate_email_code_field("123456789012").is_ok());
        assert!(validate_email_code_field("1234567890123").is_err());
    }

    #[test]
    fn optional_password_caps_at_256() {
        assert!(validate_optional_password("").is_ok());
        assert!(validate_optional_password(&"x".repeat(users::PASSWORD_MAX)).is_ok());
        assert!(validate_optional_password(&"x".repeat(users::PASSWORD_MAX + 1)).is_err());
    }

    #[test]
    fn email_input_is_trimmed_lowercased_and_validated() {
        assert_eq!(
            validate_email_input("  Alice@Example.COM ").unwrap(),
            "alice@example.com"
        );
        assert_eq!(
            validate_email_input("ab").unwrap_err().detail(),
            "邮箱最短 3 个字符"
        );
        assert_eq!(
            validate_email_input("not-an-email").unwrap_err().detail(),
            "邮箱格式非法"
        );
    }

    #[test]
    fn passkey_label_defaults_and_truncates() {
        assert_eq!(passkey_label(&json!({})), "通行密钥");
        assert_eq!(passkey_label(&json!({"label": ""})), "通行密钥");
        assert_eq!(passkey_label(&json!({"label": "我的手机"})), "我的手机");
        let long = "长".repeat(80);
        let label = passkey_label(&json!({ "label": long }));
        assert_eq!(label.chars().count(), 64);
    }

    #[test]
    fn passkey_transports_drop_empty_values() {
        assert_eq!(passkey_transports(&json!({})), None);
        assert_eq!(
            passkey_transports(&json!({"response": {"transports": []}})),
            None
        );
        assert_eq!(
            passkey_transports(&json!({"response": {"transports": ["internal", "hybrid"]}})),
            Some(json!(["internal", "hybrid"]))
        );
    }

    #[test]
    fn code_response_matches_api_contract() {
        let settings = RuntimeSettings::new(None);
        let payload = code_response(&settings);
        assert_eq!(payload["ok"], json!(true));
        assert_eq!(
            payload["expires_in"],
            json!(settings.email_code_ttl_minutes() * 60)
        );
        assert_eq!(
            payload["resend_after"],
            json!(settings.email_code_resend_seconds())
        );
    }

    #[test]
    fn user_payload_reports_password_presence() {
        let user = User {
            id: 7,
            email: "alice@example.com".to_string(),
            name: "alice".to_string(),
            password_hash: Some("hash".to_string()),
            role: ROLE_USER.to_string(),
            status: STATUS_ACTIVE.to_string(),
            last_login_at: None,
            created_at: Utc::now().naive_utc(),
        };
        let payload = user_payload(&user);
        assert_eq!(payload["id"], json!(7));
        assert_eq!(payload["email"], json!("alice@example.com"));
        assert_eq!(payload["role"], json!("user"));
        assert_eq!(payload["status"], json!("active"));
        assert_eq!(payload["has_password"], json!(true));
    }
}
