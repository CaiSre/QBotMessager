//! 认证相关集成测试。
//!
//! 覆盖范围：登录 / 注册 / 邀请码 / 限速 / 会话管理、个人中心（改名、改邮箱、
//! 改密）、邮箱验证码与密码重置（SMTP 密文）、OAuth state 流转与邮箱可信度、
//! Passkey 注册与断言。
//!
//! 驱动方式：`actix_web::test::init_service` + `TestRequest`，数据库为真实 MySQL。
//! 进程内只执行一次 `sqlx::migrate!`，用全局互斥锁串行化测试：`system_settings`
//! 与登录失败计数是进程级/全局状态，测试之间不能并行改写；测试数据全部带
//! 随机前缀，避免互相干扰。
//!
//! Passkey 登录用 p256 产生真实 ES256 签名（`passkey_login_succeeds_with_real_signature`），
//! 注册走测试构造的 attestation 对象。

mod common;

use std::collections::HashMap;
use std::fmt::Debug;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration as StdDuration;

use actix_web::body::MessageBody;
use actix_web::dev::{Service, ServiceResponse};
use actix_web::http::header::{self, HeaderMap};
use actix_web::http::{Method, StatusCode};
use actix_web::test::{self, TestRequest};
use actix_web::{App, HttpResponse, HttpServer, web};
use base64::Engine;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use chrono::{Duration, NaiveDateTime, Utc};
use qbotmessager::auth::passkey;
use qbotmessager::auth::{passwords, sessions};
use qbotmessager::config::Config;
use qbotmessager::crypto;
use qbotmessager::db::models::{ROLE_SUPER_ADMIN, ROLE_USER, STATUS_ACTIVE, STATUS_DISABLED};
use qbotmessager::db::queries;
use qbotmessager::services::email_codes;
use qbotmessager::services::runtime_settings::RuntimeSettings;
use qbotmessager::state::AppState;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::Row;
use sqlx::mysql::{MySqlPool, MySqlPoolOptions};

/// 测试账号统一密码（长度满足 8..=256）。
const PASSWORD: &str = "TestPassw0rd!";
/// 另一个合法密码。
const OTHER_PASSWORD: &str = "OtherPassw0rd!";

/// 进程内串行化：运行期设置与登录限速器都是全局可变状态。
static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
/// 进程内只执行一次迁移，避免并发 DDL 冲突。
///
/// 连接池按测试新建：`#[actix_web::test]` 每个用例都有独立的 Actix System /
/// Tokio 运行时，跨运行时复用连接池会让连接绑定的 IO 驱动随首个运行时销毁。
static MIGRATED: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();

fn database_url() -> String {
    let url = std::env::var("MYSQL_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| {
            "mysql://qbotmessager:testpw@127.0.0.1:13306/qbot_test_auth".to_string()
        });
    // 库名固定为本套件的库：与其它套件隔离，避免并跑时互相清库。
    common::with_database(&url, "qbot_test_auth")
}

async fn test_pool() -> MySqlPool {
    MIGRATED
        .get_or_init(|| async {
            let pool = MySqlPoolOptions::new()
                .max_connections(1)
                .acquire_timeout(StdDuration::from_secs(15))
                .connect(&database_url())
                .await
                .expect("连接测试 MySQL 失败（请设置 MYSQL_URL）");
            qbotmessager::db::migrator()
                .run(&pool)
                .await
                .expect("执行数据库迁移失败");
        })
        .await;
    MySqlPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(StdDuration::from_secs(15))
        .connect(&database_url())
        .await
        .expect("连接测试 MySQL 失败（请设置 MYSQL_URL）")
}

// --------------------------------------------------------------------------- 夹具

struct Fixture {
    pool: MySqlPool,
    state: Arc<AppState>,
    prefix: String,
    fernet_key: String,
}

impl Fixture {
    /// 直接改写内存中的运行期设置（不落库，只影响本测试的 AppState）。
    fn apply_settings(&self, changes: Value) {
        let mut runtime = self.state.runtime.write().unwrap();
        let object = changes.as_object().expect("设置必须是 JSON 对象");
        let values = runtime.validate(object).expect("设置校验失败");
        runtime.apply(&values);
        // 与管理端一致：设置生效后立即让进程内限速器采用新值。
        runtime.apply_side_effects(
            &self.state.limiters,
            &self.state.login_limiter,
            &self.state.issue_limiter,
        );
    }

    fn enable_register(&self) {
        self.apply_settings(json!({"register_enabled": true}));
    }

    fn configure_mail(&self) {
        self.apply_settings(json!({
            "smtp_host": "smtp.example.com",
            "smtp_from": "noreply@example.com",
        }));
    }

    fn configure_webauthn(&self) {
        self.apply_settings(json!({
            "public_base_url": "https://passkey.example",
            "rp_id": "passkey.example",
        }));
    }
}

async fn setup() -> Fixture {
    // reqwest（rustls-no-provider）需要进程级 CryptoProvider。
    let _ = rustls::crypto::ring::default_provider().install_default();
    let pool = test_pool().await;
    let fernet_key = URL_SAFE.encode([9u8; 32]);
    let config = Config {
        mysql_url: database_url(),
        app_secret_key: Some(fernet_key.clone()),
        app_name: "QBotMessager".to_string(),
        cookie_name: "sid".to_string(),
        bootstrap_admin_email: String::new(),
        bootstrap_admin_password: String::new(),
        qq_appid: String::new(),
        qq_app_secret: String::new(),
        openids: Vec::new(),
        qq_allowed_hosts: vec!["api.bot.qq.com".to_string()],
        db_pool_size: 10,
        db_max_overflow: 20,
        db_pool_timeout: 10,
        push_queue_max: 20,
        push_queue_max_per_user: 20,
        retention: Default::default(),
        trust_proxy: false,
        static_dir: PathBuf::from("./web/out"),
    };
    let runtime = RuntimeSettings::new(Some(fernet_key.clone()));
    let http = reqwest::Client::builder()
        .timeout(StdDuration::from_secs(10))
        .build()
        .expect("构造 HTTP 客户端失败");
    let state = Arc::new(AppState::new(
        pool.clone(),
        Arc::new(config),
        runtime,
        http,
        None,
    ));
    Fixture {
        pool,
        state,
        prefix: format!("t{}", uuid::Uuid::new_v4().simple()),
        fernet_key,
    }
}

macro_rules! app {
    ($state:expr) => {
        actix_web::test::init_service(
            actix_web::App::new()
                .app_data(actix_web::web::Data::from($state))
                .configure(qbotmessager::api::configure),
        )
        .await
    };
}

// --------------------------------------------------------------------------- 请求

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl Reply {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|err| {
            panic!("响应不是 JSON（{}）：{err}\n{}", self.status, self.text())
        })
    }

    fn detail(&self) -> String {
        self.json()
            .get("detail")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    }

    fn raw_cookie(&self, name: &str) -> Option<String> {
        self.headers
            .get_all(header::SET_COOKIE)
            .filter_map(|value| value.to_str().ok())
            .find(|line| {
                line.split(';')
                    .next()
                    .and_then(|pair| pair.split_once('='))
                    .is_some_and(|(key, _)| key == name)
            })
            .map(str::to_string)
    }

    fn cookie(&self, name: &str) -> Option<String> {
        let line = self.raw_cookie(name)?;
        let pair = line.split(';').next()?;
        let (_, value) = pair.split_once('=')?;
        Some(value.to_string())
    }
}

fn request(
    method: Method,
    uri: &str,
    body: Option<&Value>,
    cookies: &[(&str, &str)],
) -> TestRequest {
    let mut request = TestRequest::default().method(method).uri(uri);
    if let Some(body) = body {
        request = request
            .insert_header((header::CONTENT_TYPE, "application/json"))
            .set_payload(body.to_string());
    }
    if !cookies.is_empty() {
        let joined = cookies
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join("; ");
        request = request.insert_header((header::COOKIE, joined));
    }
    request
}

async fn call<S, R, B, E>(app: &S, request: R) -> Reply
where
    S: Service<R, Response = ServiceResponse<B>, Error = E>,
    B: MessageBody,
    E: Debug,
{
    let response = test::call_service(app, request).await;
    let status = response.status();
    let headers = response.headers().clone();
    let body = test::read_body(response).await.to_vec();
    Reply {
        status,
        headers,
        body,
    }
}

macro_rules! send {
    ($app:expr, $req:expr) => {
        call(&$app, $req.to_request()).await
    };
}

fn get(uri: &str) -> TestRequest {
    request(Method::GET, uri, None, &[])
}

fn get_with(uri: &str, cookies: &[(&str, &str)]) -> TestRequest {
    request(Method::GET, uri, None, cookies)
}

fn post_json(uri: &str, body: &Value) -> TestRequest {
    request(Method::POST, uri, Some(body), &[])
}

/// 指定来源地址的 POST 请求（模拟不同客户端 IP）。
fn post_json_from(ip: &str, uri: &str, body: &Value) -> TestRequest {
    let addr: SocketAddr = format!("{ip}:12345")
        .parse()
        .expect("测试来源地址必须是合法 IP");
    request(Method::POST, uri, Some(body), &[]).peer_addr(addr)
}

fn post_json_with(uri: &str, body: &Value, cookies: &[(&str, &str)]) -> TestRequest {
    request(Method::POST, uri, Some(body), cookies)
}

fn patch_json_with(uri: &str, body: &Value, cookies: &[(&str, &str)]) -> TestRequest {
    request(Method::PATCH, uri, Some(body), cookies)
}

fn delete_with(uri: &str, cookies: &[(&str, &str)]) -> TestRequest {
    request(Method::DELETE, uri, None, cookies)
}

macro_rules! assert_status {
    ($reply:expr, $expected:expr) => {{
        let reply = $reply;
        assert_eq!(
            reply.status,
            $expected,
            "期望 {}，实际 {}：{}",
            $expected,
            reply.status,
            reply.text()
        );
        reply
    }};
}

// --------------------------------------------------------------------------- 账号

struct Account {
    id: i64,
    email: String,
    name: String,
}

async fn make_account(
    fixture: &Fixture,
    label: &str,
    password: Option<&str>,
    role: &str,
    status: &str,
) -> Account {
    let email = format!("{}-{label}@example.com", fixture.prefix);
    let name = format!("{}-{label}", fixture.prefix);
    let password_hash =
        password.map(|value| passwords::hash_password_with(value, b"test-salt-16byte", 1_000));
    let id = sqlx::query(
        "INSERT INTO users (email, name, password_hash, role, status, created_at) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&email)
    .bind(&name)
    .bind(password_hash.as_deref())
    .bind(role)
    .bind(status)
    .bind(Utc::now().naive_utc())
    .execute(&fixture.pool)
    .await
    .expect("插入测试账号失败")
    .last_insert_id() as i64;
    Account { id, email, name }
}

async fn token_for(fixture: &Fixture, user_id: i64) -> String {
    let user = queries::users::find_by_id(&fixture.pool, user_id)
        .await
        .expect("查询账号失败")
        .expect("账号不存在");
    sessions::create_session(&fixture.pool, &user, 72, None, None)
        .await
        .expect("创建会话失败")
}

/// 把会话的最近验证时间拨到窗口外，模拟长时间未验证的会话。
async fn expire_step_up(fixture: &Fixture, token: &str) {
    sqlx::query("UPDATE sessions SET verified_at = ? WHERE token_hash = ?")
        .bind(Utc::now().naive_utc() - Duration::minutes(11))
        .bind(sessions::hash_token(token))
        .execute(&fixture.pool)
        .await
        .expect("过期会话验证时间失败");
}

async fn make_admin(fixture: &Fixture, label: &str) -> (Account, String) {
    let account = make_account(
        fixture,
        label,
        Some(PASSWORD),
        ROLE_SUPER_ADMIN,
        STATUS_ACTIVE,
    )
    .await;
    let token = token_for(fixture, account.id).await;
    (account, token)
}

async fn create_invite(
    fixture: &Fixture,
    tag: &str,
    max_uses: i32,
    email: Option<&str>,
    expires_at: Option<NaiveDateTime>,
    revoked_at: Option<NaiveDateTime>,
) -> String {
    let code = format!("{}-{tag}", fixture.prefix);
    sqlx::query(
        "INSERT INTO invite_codes \
         (code, email, max_uses, used_count, expires_at, revoked_at, created_by, created_at) \
         VALUES (?, ?, ?, 0, ?, ?, NULL, ?)",
    )
    .bind(&code)
    .bind(email)
    .bind(max_uses)
    .bind(expires_at)
    .bind(revoked_at)
    .bind(Utc::now().naive_utc())
    .execute(&fixture.pool)
    .await
    .expect("插入邀请码失败");
    code
}

async fn invite_used_count(fixture: &Fixture, code: &str) -> i32 {
    sqlx::query_scalar("SELECT used_count FROM invite_codes WHERE code = ?")
        .bind(code)
        .fetch_one(&fixture.pool)
        .await
        .expect("查询邀请码失败")
}

async fn insert_email_code(
    fixture: &Fixture,
    email: &str,
    purpose: &str,
    code: &str,
    created_at: NaiveDateTime,
    consumed: bool,
) {
    let code_hash = passwords::hash_password_with(code, b"code-salt-16byte", 1_000);
    sqlx::query(
        "INSERT INTO email_verification_codes \
         (email, purpose, code_hash, expires_at, consumed_at, attempts, ip, created_at) \
         VALUES (?, ?, ?, ?, ?, 0, NULL, ?)",
    )
    .bind(email)
    .bind(purpose)
    .bind(&code_hash)
    .bind(created_at + Duration::minutes(10))
    .bind(consumed.then(Utc::now).map(|value| value.naive_utc()))
    .bind(created_at)
    .execute(&fixture.pool)
    .await
    .expect("插入邮箱验证码失败");
}

fn find_setting<'a>(payload: &'a Value, key: &str) -> &'a Value {
    payload["groups"]
        .as_array()
        .expect("设置响应缺少 groups")
        .iter()
        .flat_map(|group| group["items"].as_array().expect("分组缺少 items"))
        .find(|item| item["key"].as_str() == Some(key))
        .unwrap_or_else(|| panic!("设置中缺少 {key}"))
}

// --------------------------------------------------------------------------- 会话

#[actix_web::test]
async fn requires_login() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());

    let reply = send!(app, get("/api/auth/me"));
    let reply = assert_status!(reply, StatusCode::UNAUTHORIZED);
    assert_eq!(reply.detail(), "未登录");

    let reply = send!(
        app,
        get_with("/api/auth/me", &[("sid", "not-a-real-token")])
    );
    let reply = assert_status!(reply, StatusCode::UNAUTHORIZED);
    assert_eq!(reply.detail(), "未登录");
}

#[actix_web::test]
async fn login_and_logout() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let account = make_account(&fixture, "login", Some(PASSWORD), ROLE_USER, STATUS_ACTIVE).await;

    let reply = send!(
        app,
        post_json(
            "/api/auth/login",
            &json!({"account": account.email, "password": PASSWORD})
        )
    );
    let reply = assert_status!(reply, StatusCode::OK);
    let body = reply.json();
    assert_eq!(body["id"], json!(account.id));
    assert_eq!(body["email"], json!(account.email));
    assert_eq!(body["name"], json!(account.name));
    assert_eq!(body["role"], json!("user"));
    assert_eq!(body["status"], json!("active"));
    assert_eq!(body["has_password"], json!(true));

    let sid = reply.cookie("sid").expect("登录必须下发 sid Cookie");
    let raw = reply.raw_cookie("sid").unwrap();
    assert!(raw.contains("HttpOnly"), "{raw}");
    assert!(raw.contains("SameSite=Lax"), "{raw}");
    assert!(raw.contains("Path=/"), "{raw}");
    assert!(raw.contains("Max-Age=259200"), "{raw}");
    assert!(!raw.contains("Secure"), "http 下不应带 Secure：{raw}");

    let me = send!(app, get_with("/api/auth/me", &[("sid", sid.as_str())]));
    let me = assert_status!(me, StatusCode::OK);
    let me_body = me.json();
    assert_eq!(me_body["id"], json!(account.id));
    assert_eq!(me_body["passkey_count"], json!(0));
    assert_eq!(me_body["step_up_valid"], json!(true));

    let logout = send!(
        app,
        post_json_with("/api/auth/logout", &json!({}), &[("sid", sid.as_str())])
    );
    let logout = assert_status!(logout, StatusCode::OK);
    assert_eq!(logout.json(), json!({"ok": true}));
    let cleared = logout.raw_cookie("sid").expect("登出必须清理 Cookie");
    assert!(cleared.contains("Max-Age=0"), "{cleared}");

    let after = send!(app, get_with("/api/auth/me", &[("sid", sid.as_str())]));
    let after = assert_status!(after, StatusCode::UNAUTHORIZED);
    assert_eq!(after.detail(), "未登录");
}

#[actix_web::test]
async fn login_by_username_and_rejects_bad_credentials() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let account = make_account(&fixture, "byname", Some(PASSWORD), ROLE_USER, STATUS_ACTIVE).await;

    let reply = send!(
        app,
        post_json(
            "/api/auth/login",
            &json!({"account": account.name.to_uppercase(), "password": PASSWORD})
        )
    );
    let reply = assert_status!(reply, StatusCode::OK);
    assert_eq!(reply.json()["id"], json!(account.id));

    let wrong = send!(
        app,
        post_json(
            "/api/auth/login",
            &json!({"account": account.email, "password": "WrongPassw0rd!"})
        )
    );
    let wrong = assert_status!(wrong, StatusCode::UNAUTHORIZED);
    assert_eq!(wrong.detail(), "用户名或密码错误");

    let unknown = send!(
        app,
        post_json(
            "/api/auth/login",
            &json!({"account": format!("{}-ghost@example.com", fixture.prefix), "password": PASSWORD})
        )
    );
    let unknown = assert_status!(unknown, StatusCode::UNAUTHORIZED);
    assert_eq!(unknown.detail(), "用户名或密码错误");

    let empty = send!(
        app,
        post_json(
            "/api/auth/login",
            &json!({"account": "   ", "password": PASSWORD})
        )
    );
    let empty = assert_status!(empty, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(empty.detail(), "请填写用户名或邮箱");

    let no_password = send!(
        app,
        post_json(
            "/api/auth/login",
            &json!({"account": account.email, "password": ""})
        )
    );
    let no_password = assert_status!(no_password, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(no_password.detail(), "请填写密码");
}

#[actix_web::test]
async fn login_rate_limit_and_reset_after_success() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let account = make_account(&fixture, "limit", Some(PASSWORD), ROLE_USER, STATUS_ACTIVE).await;
    let wrong = json!({"account": account.email, "password": "WrongPassw0rd!"});

    for _ in 0..4 {
        let reply = send!(app, post_json("/api/auth/login", &wrong));
        assert_status!(reply, StatusCode::UNAUTHORIZED);
    }

    // 登录成功会清空 (IP, 账号) 维度的失败计数。
    let ok = send!(
        app,
        post_json(
            "/api/auth/login",
            &json!({"account": account.email, "password": PASSWORD})
        )
    );
    assert_status!(ok, StatusCode::OK);

    for _ in 0..5 {
        let reply = send!(app, post_json("/api/auth/login", &wrong));
        assert_status!(reply, StatusCode::UNAUTHORIZED);
    }

    let limited = send!(app, post_json("/api/auth/login", &wrong));
    let limited = assert_status!(limited, StatusCode::TOO_MANY_REQUESTS);
    assert!(
        limited.detail().contains("尝试过于频繁"),
        "{}",
        limited.detail()
    );
    let retry_after = limited
        .headers
        .get(header::RETRY_AFTER)
        .expect("429 必须带 Retry-After")
        .to_str()
        .unwrap()
        .parse::<u64>()
        .expect("Retry-After 必须是数字");
    assert!(retry_after > 0, "Retry-After 应为正数");
}

#[actix_web::test]
async fn secure_cookie_on_https() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    fixture.apply_settings(json!({"public_base_url": "https://app.example.com"}));
    let account = make_account(&fixture, "secure", Some(PASSWORD), ROLE_USER, STATUS_ACTIVE).await;

    let reply = send!(
        app,
        post_json(
            "/api/auth/login",
            &json!({"account": account.email, "password": PASSWORD})
        )
    );
    let reply = assert_status!(reply, StatusCode::OK);
    let raw = reply
        .raw_cookie("__Host-sid")
        .expect("https 下登录必须下发 __Host-sid");
    assert!(
        raw.contains("Secure"),
        "https 下 Cookie 必须带 Secure：{raw}"
    );
    assert!(raw.contains("Path=/"), "Cookie 必须限定 Path=/：{raw}");
    assert!(!raw.contains("Domain="), "Cookie 不得带 Domain：{raw}");
    let sid = reply.cookie("__Host-sid").unwrap();
    let me = send!(
        app,
        get_with("/api/auth/me", &[("__Host-sid", sid.as_str())])
    );
    assert_status!(me, StatusCode::OK);
}

#[actix_web::test]
async fn session_expiry_and_revocation() {
    // 会话过期与撤销（规格书 6.3）
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let account = make_account(
        &fixture,
        "session",
        Some(PASSWORD),
        ROLE_USER,
        STATUS_ACTIVE,
    )
    .await;

    let token = token_for(&fixture, account.id).await;
    assert_status!(
        send!(app, get_with("/api/auth/me", &[("sid", token.as_str())])),
        StatusCode::OK
    );

    // 过期：expires_at <= now 即失效。
    sqlx::query("UPDATE sessions SET expires_at = ? WHERE token_hash = ?")
        .bind(Utc::now().naive_utc() - Duration::minutes(1))
        .bind(sessions::hash_token(&token))
        .execute(&fixture.pool)
        .await
        .unwrap();
    let expired = send!(app, get_with("/api/auth/me", &[("sid", token.as_str())]));
    let expired = assert_status!(expired, StatusCode::UNAUTHORIZED);
    assert_eq!(expired.detail(), "未登录");

    // 撤销：revoked_at 非空即失效。
    let revoked_token = token_for(&fixture, account.id).await;
    sqlx::query("UPDATE sessions SET revoked_at = ? WHERE token_hash = ?")
        .bind(Utc::now().naive_utc())
        .bind(sessions::hash_token(&revoked_token))
        .execute(&fixture.pool)
        .await
        .unwrap();
    let revoked = send!(
        app,
        get_with("/api/auth/me", &[("sid", revoked_token.as_str())])
    );
    let revoked = assert_status!(revoked, StatusCode::UNAUTHORIZED);
    assert_eq!(revoked.detail(), "未登录");

    // 有效会话但账号已停用：403。
    let disabled_token = token_for(&fixture, account.id).await;
    sqlx::query("UPDATE users SET status = ? WHERE id = ?")
        .bind(STATUS_DISABLED)
        .bind(account.id)
        .execute(&fixture.pool)
        .await
        .unwrap();
    let disabled = send!(
        app,
        get_with("/api/auth/me", &[("sid", disabled_token.as_str())])
    );
    let disabled = assert_status!(disabled, StatusCode::FORBIDDEN);
    assert_eq!(disabled.detail(), "账号已停用");
}

// --------------------------------------------------------------------------- 注册

#[actix_web::test]
async fn register_disabled_by_default() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let code = create_invite(
        &fixture,
        "disabled",
        1,
        None,
        Some(Utc::now().naive_utc() + Duration::days(1)),
        None,
    )
    .await;

    let providers = send!(app, get("/api/auth/providers"));
    let providers = assert_status!(providers, StatusCode::OK);
    let body = providers.json();
    assert_eq!(body["registration_enabled"], json!(false));
    assert_eq!(body["password_enabled"], json!(true));
    assert_eq!(body["passkey_enabled"], json!(true));
    assert_eq!(body["email_code_enabled"], json!(false));
    assert!(body["rp_id"].is_string());

    let reply = send!(
        app,
        post_json(
            "/api/auth/register",
            &json!({
                "invite_code": code,
                "email": format!("{}-closed@example.com", fixture.prefix),
                "password": PASSWORD,
                "name": format!("{}-closed", fixture.prefix),
            })
        )
    );
    let reply = assert_status!(reply, StatusCode::FORBIDDEN);
    assert_eq!(reply.detail(), "注册入口已关闭");
    assert_eq!(invite_used_count(&fixture, &code).await, 0);
}

#[actix_web::test]
async fn register_with_invite_creates_user_scope_session() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    fixture.enable_register();
    let code = create_invite(
        &fixture,
        "invite",
        1,
        None,
        Some(Utc::now().naive_utc() + Duration::days(1)),
        None,
    )
    .await;
    let email = format!("{}-new@example.com", fixture.prefix);
    let name = format!("{}-new", fixture.prefix);

    let reply = send!(
        app,
        post_json(
            "/api/auth/register",
            &json!({
                "invite_code": code,
                "email": email,
                "password": PASSWORD,
                "name": name,
            })
        )
    );
    let reply = assert_status!(reply, StatusCode::OK);
    let body = reply.json();
    assert_eq!(body["email"], json!(email));
    assert_eq!(body["name"], json!(name));
    assert_eq!(body["role"], json!("user"));
    assert_eq!(body["status"], json!("active"));
    assert_eq!(body["has_password"], json!(true));
    let sid = reply.cookie("sid").expect("注册成功必须下发会话");
    assert_eq!(invite_used_count(&fixture, &code).await, 1);

    let me = send!(app, get_with("/api/auth/me", &[("sid", sid.as_str())]));
    let me = assert_status!(me, StatusCode::OK);
    assert_eq!(me.json()["email"], json!(email));
}

#[actix_web::test]
async fn register_duplicate_username_case_insensitive() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    fixture.enable_register();
    let existing = make_account(&fixture, "taken", Some(PASSWORD), ROLE_USER, STATUS_ACTIVE).await;
    let code = create_invite(
        &fixture,
        "dupname",
        2,
        None,
        Some(Utc::now().naive_utc() + Duration::days(1)),
        None,
    )
    .await;

    let reply = send!(
        app,
        post_json(
            "/api/auth/register",
            &json!({
                "invite_code": code,
                "email": format!("{}-dupname@example.com", fixture.prefix),
                "password": PASSWORD,
                "name": existing.name.to_uppercase(),
            })
        )
    );
    let reply = assert_status!(reply, StatusCode::CONFLICT);
    assert_eq!(reply.detail(), "该用户名已被使用");
    // 冲突发生在占用名额之前，邀请码不能被消耗。
    assert_eq!(invite_used_count(&fixture, &code).await, 0);
}

#[actix_web::test]
async fn register_generates_unique_default_name() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    fixture.enable_register();
    // 先占用同名用户（名字来自邮箱前缀）。
    let taken_name = format!("{}-dup", fixture.prefix);
    sqlx::query(
        "INSERT INTO users (email, name, password_hash, role, status, created_at) \
         VALUES (?, ?, NULL, ?, ?, ?)",
    )
    .bind(format!("{}-other@example.com", fixture.prefix))
    .bind(&taken_name)
    .bind(ROLE_USER)
    .bind(STATUS_ACTIVE)
    .bind(Utc::now().naive_utc())
    .execute(&fixture.pool)
    .await
    .unwrap();
    let code = create_invite(
        &fixture,
        "dup",
        1,
        None,
        Some(Utc::now().naive_utc() + Duration::days(1)),
        None,
    )
    .await;

    let reply = send!(
        app,
        post_json(
            "/api/auth/register",
            &json!({
                "invite_code": code,
                "email": format!("{}-dup@example.com", fixture.prefix),
                "password": PASSWORD,
                "name": "",
            })
        )
    );
    let reply = assert_status!(reply, StatusCode::OK);
    assert_eq!(reply.json()["name"], json!(format!("{taken_name}-2")));
}

#[actix_web::test]
async fn invite_edge_cases() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    fixture.enable_register();

    let register = |code: String, tag: &str| {
        post_json(
            "/api/auth/register",
            &json!({
                "invite_code": code,
                "email": format!("{}-{tag}@example.com", fixture.prefix),
                "password": PASSWORD,
                "name": format!("{}-{tag}", fixture.prefix),
            }),
        )
    };

    let invalid = send!(app, register("no-such-code".to_string(), "invalid"));
    let invalid = assert_status!(invalid, StatusCode::BAD_REQUEST);
    assert_eq!(invalid.detail(), "邀请码无效");

    let expired_code = create_invite(
        &fixture,
        "expired",
        1,
        None,
        Some(Utc::now().naive_utc() - Duration::minutes(1)),
        None,
    )
    .await;
    let expired = send!(app, register(expired_code, "expired"));
    let expired = assert_status!(expired, StatusCode::BAD_REQUEST);
    assert_eq!(expired.detail(), "邀请码已过期");

    let revoked_code = create_invite(
        &fixture,
        "revoked",
        1,
        None,
        Some(Utc::now().naive_utc() + Duration::days(1)),
        Some(Utc::now().naive_utc()),
    )
    .await;
    let revoked = send!(app, register(revoked_code, "revoked"));
    let revoked = assert_status!(revoked, StatusCode::BAD_REQUEST);
    assert_eq!(revoked.detail(), "邀请码已作废");

    let exhausted_code = create_invite(
        &fixture,
        "exhausted",
        0,
        None,
        Some(Utc::now().naive_utc() + Duration::days(1)),
        None,
    )
    .await;
    let exhausted = send!(app, register(exhausted_code, "exhausted"));
    let exhausted = assert_status!(exhausted, StatusCode::BAD_REQUEST);
    assert_eq!(exhausted.detail(), "邀请码已用尽");

    let restricted = create_invite(
        &fixture,
        "restricted",
        1,
        Some("allowed@example.com"),
        Some(Utc::now().naive_utc() + Duration::days(1)),
        None,
    )
    .await;
    let mismatch = send!(app, register(restricted, "mismatch"));
    let mismatch = assert_status!(mismatch, StatusCode::BAD_REQUEST);
    assert_eq!(mismatch.detail(), "邀请码不适用于该邮箱");
}

#[actix_web::test]
async fn invite_max_uses_is_atomic_under_concurrency() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    fixture.enable_register();
    let code = create_invite(
        &fixture,
        "race",
        1,
        None,
        Some(Utc::now().naive_utc() + Duration::days(1)),
        None,
    )
    .await;

    let build = |index: u32| {
        let body = json!({
            "invite_code": code,
            "email": format!("{}-race{index}@example.com", fixture.prefix),
            "password": PASSWORD,
            "name": format!("{}-race{index}", fixture.prefix),
        });
        post_json("/api/auth/register", &body).to_request()
    };
    let (first, second, third, fourth) = tokio::join!(
        test::call_service(&app, build(0)),
        test::call_service(&app, build(1)),
        test::call_service(&app, build(2)),
        test::call_service(&app, build(3)),
    );
    let mut statuses = vec![
        first.status(),
        second.status(),
        third.status(),
        fourth.status(),
    ];
    statuses.sort();
    assert_eq!(
        statuses,
        vec![
            StatusCode::OK,
            StatusCode::BAD_REQUEST,
            StatusCode::BAD_REQUEST,
            StatusCode::BAD_REQUEST,
        ],
        "并发注册必须只有一个成功"
    );

    let bodies = [first, second, third, fourth];
    let failures = bodies
        .iter()
        .filter(|response| response.status() == StatusCode::BAD_REQUEST)
        .count();
    assert_eq!(failures, 3);

    assert_eq!(invite_used_count(&fixture, &code).await, 1);
    let users: i64 =
        sqlx::query_scalar("SELECT CAST(COUNT(*) AS SIGNED) FROM users WHERE email LIKE ?")
            .bind(format!("{}-race%@example.com", fixture.prefix))
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
    assert_eq!(users, 1);
}

#[actix_web::test]
async fn database_unique_username_index() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let name = format!("{}-Uniq", fixture.prefix);
    sqlx::query(
        "INSERT INTO users (email, name, password_hash, role, status, created_at) \
         VALUES (?, ?, NULL, ?, ?, ?)",
    )
    .bind(format!("{}-uniq-a@example.com", fixture.prefix))
    .bind(&name)
    .bind(ROLE_USER)
    .bind(STATUS_ACTIVE)
    .bind(Utc::now().naive_utc())
    .execute(&fixture.pool)
    .await
    .unwrap();

    let error = sqlx::query(
        "INSERT INTO users (email, name, password_hash, role, status, created_at) \
         VALUES (?, ?, NULL, ?, ?, ?)",
    )
    .bind(format!("{}-uniq-b@example.com", fixture.prefix))
    .bind(name.to_uppercase())
    .bind(ROLE_USER)
    .bind(STATUS_ACTIVE)
    .bind(Utc::now().naive_utc())
    .execute(&fixture.pool)
    .await
    .expect_err("用户名忽略大小写必须唯一");
    let sqlx::Error::Database(db_error) = error else {
        panic!("期望数据库错误：{error:?}");
    };
    // sqlx 的 MySQL 错误 `code()` 返回 SQLSTATE，唯一键冲突即 23000。
    assert_eq!(db_error.code().as_deref(), Some("23000"));
    assert!(
        db_error.message().to_ascii_lowercase().contains("name"),
        "{}",
        db_error.message()
    );
}

// --------------------------------------------------------------------------- 权限

#[actix_web::test]
async fn cross_user_resource_isolation() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let alice = make_account(&fixture, "alice", Some(PASSWORD), ROLE_USER, STATUS_ACTIVE).await;
    let bob = make_account(&fixture, "bob", Some(PASSWORD), ROLE_USER, STATUS_ACTIVE).await;
    let alice_token = token_for(&fixture, alice.id).await;
    let bob_token = token_for(&fixture, bob.id).await;

    let created = send!(
        app,
        post_json_with(
            "/api/admin/bot-profiles",
            &json!({
                "name": "Alice Bot",
                "qq_appid": "123456",
                "qq_app_secret": "super-secret-value",
                "qq_host": "https://api.bot.qq.com",
            }),
            &[("sid", alice_token.as_str())]
        )
    );
    let created = assert_status!(created, StatusCode::CREATED);
    let bot_id = created.json()["id"].as_i64().expect("缺少机器人 id");

    let bob_list = send!(
        app,
        get_with("/api/admin/bot-profiles", &[("sid", bob_token.as_str())])
    );
    let bob_list = assert_status!(bob_list, StatusCode::OK);
    assert_eq!(bob_list.json(), json!([]));

    let hijack = send!(
        app,
        patch_json_with(
            &format!("/api/admin/bot-profiles/{bot_id}"),
            &json!({"name": "hijacked"}),
            &[("sid", bob_token.as_str())]
        )
    );
    assert_status!(hijack, StatusCode::NOT_FOUND);

    let alice_list = send!(
        app,
        get_with("/api/admin/bot-profiles", &[("sid", alice_token.as_str())])
    );
    let alice_list = assert_status!(alice_list, StatusCode::OK);
    let items = alice_list.json();
    assert_eq!(items.as_array().unwrap().len(), 1);
    assert_eq!(items[0]["owner_email"], json!(alice.email));
    assert_eq!(items[0]["has_secret"], json!(true));
    assert_ne!(
        items[0]["qq_app_secret_masked"],
        json!("super-secret-value")
    );
}

#[actix_web::test]
async fn admin_rename_conflict_and_self_protection() {
    // test_super_admin_cannot_change_own_role_or_status
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let (admin, admin_token) = make_admin(&fixture, "admin").await;
    let alice = make_account(&fixture, "alice2", Some(PASSWORD), ROLE_USER, STATUS_ACTIVE).await;
    let bob = make_account(&fixture, "bob2", Some(PASSWORD), ROLE_USER, STATUS_ACTIVE).await;

    let rename = send!(
        app,
        patch_json_with(
            &format!("/api/admin/users/{}", bob.id),
            &json!({"name": alice.name.to_uppercase()}),
            &[("sid", admin_token.as_str())]
        )
    );
    let rename = assert_status!(rename, StatusCode::CONFLICT);
    assert_eq!(rename.detail(), "该用户名已被使用");

    let own_role = send!(
        app,
        patch_json_with(
            &format!("/api/admin/users/{}", admin.id),
            &json!({"role": "user"}),
            &[("sid", admin_token.as_str())]
        )
    );
    let own_role = assert_status!(own_role, StatusCode::BAD_REQUEST);
    assert_eq!(own_role.detail(), "不能修改自己的角色");

    let own_status = send!(
        app,
        patch_json_with(
            &format!("/api/admin/users/{}", admin.id),
            &json!({"status": "disabled"}),
            &[("sid", admin_token.as_str())]
        )
    );
    let own_status = assert_status!(own_status, StatusCode::BAD_REQUEST);
    assert_eq!(own_status.detail(), "不能修改自己的账号状态");
}

// --------------------------------------------------------------------------- 个人中心

#[actix_web::test]
async fn profile_name_update() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let account = make_account(&fixture, "rename", Some(PASSWORD), ROLE_USER, STATUS_ACTIVE).await;
    let token = token_for(&fixture, account.id).await;

    let desired = format!("{}-Alice Smith", fixture.prefix);
    let renamed = send!(
        app,
        patch_json_with(
            "/api/auth/me/name",
            &json!({"name": format!("  {desired}  ")}),
            &[("sid", token.as_str())]
        )
    );
    let renamed = assert_status!(renamed, StatusCode::OK);
    assert_eq!(renamed.json()["name"], json!(desired));

    let blank = send!(
        app,
        patch_json_with(
            "/api/auth/me/name",
            &json!({"name": "   "}),
            &[("sid", token.as_str())]
        )
    );
    let blank = assert_status!(blank, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(blank.detail(), "用户名不能为空");

    let too_long = send!(
        app,
        patch_json_with(
            "/api/auth/me/name",
            &json!({"name": "a".repeat(129)}),
            &[("sid", token.as_str())]
        )
    );
    assert_status!(too_long, StatusCode::UNPROCESSABLE_ENTITY);
}

#[actix_web::test]
async fn profile_name_conflict_case_insensitive() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let alice = make_account(&fixture, "alice3", Some(PASSWORD), ROLE_USER, STATUS_ACTIVE).await;
    let bob = make_account(&fixture, "bob3", Some(PASSWORD), ROLE_USER, STATUS_ACTIVE).await;
    let bob_token = token_for(&fixture, bob.id).await;

    let conflict = send!(
        app,
        patch_json_with(
            "/api/auth/me/name",
            &json!({"name": alice.name.to_uppercase()}),
            &[("sid", bob_token.as_str())]
        )
    );
    let conflict = assert_status!(conflict, StatusCode::CONFLICT);
    assert_eq!(conflict.detail(), "该用户名已被使用");

    // 自己的名字只改大小写应当允许（排除自身后再判定唯一性）。
    let own = send!(
        app,
        patch_json_with(
            "/api/auth/me/name",
            &json!({"name": bob.name.to_uppercase()}),
            &[("sid", bob_token.as_str())]
        )
    );
    let own = assert_status!(own, StatusCode::OK);
    assert_eq!(own.json()["name"], json!(bob.name.to_uppercase()));
}

#[actix_web::test]
async fn profile_email_update_requires_password() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let account = make_account(&fixture, "mail", Some(PASSWORD), ROLE_USER, STATUS_ACTIVE).await;
    let other = make_account(
        &fixture,
        "othermail",
        Some(PASSWORD),
        ROLE_USER,
        STATUS_ACTIVE,
    )
    .await;
    let token = token_for(&fixture, account.id).await;
    let new_email = format!("{}-CHANGED@Example.COM", fixture.prefix);

    let missing = send!(
        app,
        patch_json_with(
            "/api/auth/me/email",
            &json!({"email": new_email}),
            &[("sid", token.as_str())]
        )
    );
    let missing = assert_status!(missing, StatusCode::BAD_REQUEST);
    assert_eq!(missing.detail(), "当前密码错误");

    let wrong = send!(
        app,
        patch_json_with(
            "/api/auth/me/email",
            &json!({"email": new_email, "current_password": "WrongPassw0rd!"}),
            &[("sid", token.as_str())]
        )
    );
    let wrong = assert_status!(wrong, StatusCode::BAD_REQUEST);
    assert_eq!(wrong.detail(), "当前密码错误");

    let conflict = send!(
        app,
        patch_json_with(
            "/api/auth/me/email",
            &json!({"email": other.email, "current_password": PASSWORD}),
            &[("sid", token.as_str())]
        )
    );
    let conflict = assert_status!(conflict, StatusCode::CONFLICT);
    assert_eq!(conflict.detail(), "该邮箱已被使用");

    let updated = send!(
        app,
        patch_json_with(
            "/api/auth/me/email",
            &json!({"email": new_email, "current_password": PASSWORD}),
            &[("sid", token.as_str())]
        )
    );
    let updated = assert_status!(updated, StatusCode::OK);
    let normalized = new_email.to_lowercase();
    assert_eq!(updated.json()["email"], json!(normalized));

    let old_login = send!(
        app,
        post_json(
            "/api/auth/login",
            &json!({"account": account.email, "password": PASSWORD})
        )
    );
    assert_status!(old_login, StatusCode::UNAUTHORIZED);

    let new_login = send!(
        app,
        post_json(
            "/api/auth/login",
            &json!({"account": normalized, "password": PASSWORD})
        )
    );
    assert_status!(new_login, StatusCode::OK);

    let invalid = send!(
        app,
        patch_json_with(
            "/api/auth/me/email",
            &json!({"email": "not-an-email", "current_password": PASSWORD}),
            &[("sid", token.as_str())]
        )
    );
    let invalid = assert_status!(invalid, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(invalid.detail(), "邮箱格式非法");
}

#[actix_web::test]
async fn profile_password_change_revokes_other_sessions() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let account = make_account(
        &fixture,
        "pwchange",
        Some(PASSWORD),
        ROLE_USER,
        STATUS_ACTIVE,
    )
    .await;
    let current = token_for(&fixture, account.id).await;
    let other = token_for(&fixture, account.id).await;
    let new_password = "BrandNewPassw0rd!";

    let wrong = send!(
        app,
        patch_json_with(
            "/api/auth/me/password",
            &json!({"current_password": "WrongPassw0rd!", "new_password": new_password}),
            &[("sid", current.as_str())]
        )
    );
    let wrong = assert_status!(wrong, StatusCode::BAD_REQUEST);
    assert_eq!(wrong.detail(), "当前密码错误");

    let same = send!(
        app,
        patch_json_with(
            "/api/auth/me/password",
            &json!({"current_password": PASSWORD, "new_password": PASSWORD}),
            &[("sid", current.as_str())]
        )
    );
    let same = assert_status!(same, StatusCode::BAD_REQUEST);
    assert_eq!(same.detail(), "新密码不能与当前密码相同");

    let short = send!(
        app,
        patch_json_with(
            "/api/auth/me/password",
            &json!({"current_password": PASSWORD, "new_password": "short"}),
            &[("sid", current.as_str())]
        )
    );
    let short = assert_status!(short, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(short.detail(), "密码长度需在 8 到 256 位之间");

    let changed = send!(
        app,
        patch_json_with(
            "/api/auth/me/password",
            &json!({"current_password": PASSWORD, "new_password": new_password}),
            &[("sid", current.as_str())]
        )
    );
    let changed = assert_status!(changed, StatusCode::OK);
    assert_eq!(changed.json(), json!({"ok": true}));

    // 保留当前会话，撤销其他设备。
    assert_status!(
        send!(app, get_with("/api/auth/me", &[("sid", current.as_str())])),
        StatusCode::OK
    );
    assert_status!(
        send!(app, get_with("/api/auth/me", &[("sid", other.as_str())])),
        StatusCode::UNAUTHORIZED
    );

    let old_login = send!(
        app,
        post_json(
            "/api/auth/login",
            &json!({"account": account.email, "password": PASSWORD})
        )
    );
    assert_status!(old_login, StatusCode::UNAUTHORIZED);

    let new_login = send!(
        app,
        post_json(
            "/api/auth/login",
            &json!({"account": account.email, "password": new_password})
        )
    );
    assert_status!(new_login, StatusCode::OK);
}

#[actix_web::test]
async fn oauth_account_sets_password_without_current() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let account = make_account(&fixture, "oauthuser", None, ROLE_USER, STATUS_ACTIVE).await;
    let token = token_for(&fixture, account.id).await;
    let new_password = "OAuthPassw0rd!";

    let before = send!(app, get_with("/api/auth/me", &[("sid", token.as_str())]));
    assert_eq!(before.json()["has_password"], json!(false));

    let changed = send!(
        app,
        patch_json_with(
            "/api/auth/me/password",
            &json!({"new_password": new_password}),
            &[("sid", token.as_str())]
        )
    );
    let changed = assert_status!(changed, StatusCode::OK);
    assert_eq!(changed.json(), json!({"ok": true}));

    let after = send!(app, get_with("/api/auth/me", &[("sid", token.as_str())]));
    assert_eq!(after.json()["has_password"], json!(true));

    let login = send!(
        app,
        post_json(
            "/api/auth/login",
            &json!({"account": account.email, "password": new_password})
        )
    );
    assert_status!(login, StatusCode::OK);
}

#[actix_web::test]
async fn oauth_account_sets_password_requires_code_when_mail_configured() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    fixture.configure_mail();
    let account = make_account(&fixture, "oauthcode", None, ROLE_USER, STATUS_ACTIVE).await;
    let token = token_for(&fixture, account.id).await;
    let new_password = "OAuthCodePassw0rd!";

    let missing = send!(
        app,
        patch_json_with(
            "/api/auth/me/password",
            &json!({"new_password": new_password}),
            &[("sid", token.as_str())]
        )
    );
    let missing = assert_status!(missing, StatusCode::BAD_REQUEST);
    assert_eq!(missing.detail(), "请填写邮箱验证码");

    insert_email_code(
        &fixture,
        &account.email,
        "set_password",
        "246810",
        Utc::now().naive_utc(),
        false,
    )
    .await;
    let changed = send!(
        app,
        patch_json_with(
            "/api/auth/me/password",
            &json!({"new_password": new_password, "email_code": "246810"}),
            &[("sid", token.as_str())]
        )
    );
    let changed = assert_status!(changed, StatusCode::OK);
    assert_eq!(changed.json(), json!({"ok": true}));

    let after = send!(app, get_with("/api/auth/me", &[("sid", token.as_str())]));
    assert_eq!(after.json()["has_password"], json!(true));
}

// --------------------------------------------------------------------------- 邮箱验证码

#[actix_web::test]
async fn mail_unconfigured_providers_and_errors() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let account = make_account(&fixture, "nomail", None, ROLE_USER, STATUS_ACTIVE).await;
    let token = token_for(&fixture, account.id).await;

    let providers = send!(app, get("/api/auth/providers"));
    let providers = assert_status!(providers, StatusCode::OK);
    assert_eq!(providers.json()["email_code_enabled"], json!(false));

    let code_request = send!(
        app,
        post_json(
            "/api/auth/email-code",
            &json!({"email": account.email, "purpose": "reset_password"})
        )
    );
    let code_request = assert_status!(code_request, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(code_request.detail(), "邮件服务未配置");

    let reset = send!(
        app,
        post_json(
            "/api/auth/password/reset",
            &json!({"email": account.email, "code": "123456", "new_password": OTHER_PASSWORD})
        )
    );
    let reset = assert_status!(reset, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(reset.detail(), "邮件服务未配置");

    let me_code = send!(
        app,
        post_json_with(
            "/api/auth/me/password-code",
            &json!({}),
            &[("sid", token.as_str())]
        )
    );
    let me_code = assert_status!(me_code, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(me_code.detail(), "邮件服务未配置");

    // 邮件未配置时，注册不强制邮箱验证码，仍可凭邀请码完成。
    fixture.enable_register();
    let invite = create_invite(
        &fixture,
        "nomailreg",
        1,
        None,
        Some(Utc::now().naive_utc() + Duration::days(1)),
        None,
    )
    .await;
    let register = send!(
        app,
        post_json(
            "/api/auth/register",
            &json!({
                "invite_code": invite,
                "email": format!("{}-nomailreg@example.com", fixture.prefix),
                "password": PASSWORD,
                "name": format!("{}-nomailreg", fixture.prefix),
            })
        )
    );
    let register = assert_status!(register, StatusCode::OK);
    assert_eq!(
        register.json()["email"],
        json!(format!("{}-nomailreg@example.com", fixture.prefix))
    );
}

#[actix_web::test]
async fn smtp_password_is_encrypted_and_audited() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let (_admin, admin_token) = make_admin(&fixture, "adminmail").await;
    let secret = "SmtpSuperSecret123";

    let patched = send!(
        app,
        patch_json_with(
            "/api/admin/settings",
            &json!({
                "smtp_host": "smtp.example.com",
                "smtp_from": "noreply@example.com",
                "smtp_password": secret,
            }),
            &[("sid", admin_token.as_str())]
        )
    );
    let patched = assert_status!(patched, StatusCode::OK);
    let patched_body = patched.json();
    let item = find_setting(&patched_body, "smtp_password");
    assert_eq!(item["value"], json!(""));
    assert_eq!(item["secret"], json!(true));
    assert_eq!(item["has_value"], json!(true));

    let stored: String =
        sqlx::query_scalar("SELECT `value` FROM system_settings WHERE `key` = 'smtp_password'")
            .fetch_one(&fixture.pool)
            .await
            .expect("设置未落库");
    assert!(
        stored.starts_with("enc1:"),
        "smtp_password 必须是密文：{stored}"
    );
    assert!(!stored.contains(secret));
    assert_eq!(
        crypto::decrypt_secret(&stored, Some(&fixture.fernet_key)).unwrap(),
        secret
    );

    let detail: Option<String> = sqlx::query_scalar(
        "SELECT CAST(detail AS CHAR) FROM admin_audit_logs \
         WHERE action = 'settings.update' ORDER BY id DESC LIMIT 1",
    )
    .fetch_one(&fixture.pool)
    .await
    .unwrap();
    let detail = detail.expect("缺少审计记录");
    assert!(detail.contains("******"), "{detail}");
    assert!(!detail.contains(secret), "审计日志不得包含明文：{detail}");

    let settings = send!(
        app,
        get_with("/api/admin/settings", &[("sid", admin_token.as_str())])
    );
    let settings = assert_status!(settings, StatusCode::OK);
    assert!(
        !settings.text().contains(secret),
        "设置响应不得回显明文密码"
    );
}

#[actix_web::test]
async fn register_requires_email_code_when_mail_configured() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    fixture.enable_register();
    fixture.configure_mail();
    let code = create_invite(
        &fixture,
        "mailreg",
        3,
        None,
        Some(Utc::now().naive_utc() + Duration::days(1)),
        None,
    )
    .await;
    let email = format!("{}-mailreg@example.com", fixture.prefix);

    let missing = send!(
        app,
        post_json(
            "/api/auth/register",
            &json!({
                "invite_code": code,
                "email": email,
                "password": PASSWORD,
                "name": format!("{}-mailreg", fixture.prefix),
            })
        )
    );
    let missing = assert_status!(missing, StatusCode::BAD_REQUEST);
    assert_eq!(missing.detail(), "请填写邮箱验证码");

    let wrong = send!(
        app,
        post_json(
            "/api/auth/register",
            &json!({
                "invite_code": code,
                "email": email,
                "password": PASSWORD,
                "name": format!("{}-mailreg", fixture.prefix),
                "email_code": "000000",
            })
        )
    );
    let wrong = assert_status!(wrong, StatusCode::BAD_REQUEST);
    assert_eq!(wrong.detail(), "邮箱验证码错误或已过期");

    insert_email_code(
        &fixture,
        &email,
        "register",
        "135790",
        Utc::now().naive_utc(),
        false,
    )
    .await;
    let ok = send!(
        app,
        post_json(
            "/api/auth/register",
            &json!({
                "invite_code": code,
                "email": email,
                "password": PASSWORD,
                "name": format!("{}-mailreg", fixture.prefix),
                "email_code": "135790",
            })
        )
    );
    let ok = assert_status!(ok, StatusCode::OK);
    assert_eq!(ok.json()["email"], json!(email));
    assert_eq!(invite_used_count(&fixture, &code).await, 1);
}

#[actix_web::test]
async fn email_code_resend_cooldown_and_hourly_quota() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    fixture.enable_register();
    fixture.configure_mail();
    let account = make_account(
        &fixture,
        "cooldown",
        Some(PASSWORD),
        ROLE_USER,
        STATUS_ACTIVE,
    )
    .await;

    insert_email_code(
        &fixture,
        &account.email,
        "reset_password",
        "111111",
        Utc::now().naive_utc(),
        false,
    )
    .await;
    let cooled = send!(
        app,
        post_json(
            "/api/auth/email-code",
            &json!({"email": account.email, "purpose": "reset_password"})
        )
    );
    let cooled = assert_status!(cooled, StatusCode::TOO_MANY_REQUESTS);
    assert!(
        cooled.detail().contains("发送过于频繁"),
        "{}",
        cooled.detail()
    );
    let retry_after = cooled
        .headers
        .get(header::RETRY_AFTER)
        .expect("429 必须带 Retry-After")
        .to_str()
        .unwrap()
        .parse::<i64>()
        .unwrap();
    assert!(retry_after > 0 && retry_after <= 60, "{retry_after}");

    // 小时配额：5 条记录（含最新一条）即达到默认上限。
    let quota_user =
        make_account(&fixture, "quota", Some(PASSWORD), ROLE_USER, STATUS_ACTIVE).await;
    let old = Utc::now().naive_utc() - Duration::seconds(120);
    for _ in 0..5 {
        insert_email_code(
            &fixture,
            &quota_user.email,
            "reset_password",
            "222222",
            old,
            false,
        )
        .await;
    }
    let quota = send!(
        app,
        post_json(
            "/api/auth/email-code",
            &json!({"email": quota_user.email, "purpose": "reset_password"})
        )
    );
    let quota = assert_status!(quota, StatusCode::TOO_MANY_REQUESTS);
    assert!(
        quota.detail().contains("发送次数过多"),
        "{}",
        quota.detail()
    );

    // 已注册邮箱请求注册验证码时静默成功且不发信（防枚举）。
    let before: i64 = sqlx::query_scalar(
        "SELECT CAST(COUNT(*) AS SIGNED) FROM email_verification_codes WHERE email = ? AND purpose = 'register'",
    )
    .bind(&account.email)
    .fetch_one(&fixture.pool)
    .await
    .unwrap();
    let silent = send!(
        app,
        post_json(
            "/api/auth/email-code",
            &json!({"email": account.email, "purpose": "register"})
        )
    );
    let silent = assert_status!(silent, StatusCode::OK);
    assert_eq!(silent.json()["ok"], json!(true));
    let after: i64 = sqlx::query_scalar(
        "SELECT CAST(COUNT(*) AS SIGNED) FROM email_verification_codes WHERE email = ? AND purpose = 'register'",
    )
    .bind(&account.email)
    .fetch_one(&fixture.pool)
    .await
    .unwrap();
    assert_eq!(before, after, "已注册邮箱不应真的发码");
}

/// 发码接口按来源地址限速：额度用尽后同一来源被拒，其他来源不受影响。
///
/// 邮箱已注册时该接口静默成功且不发信，正好用来验证限额判定，
/// 不依赖真实 SMTP。
#[actix_web::test]
async fn email_code_rate_limited_by_source_ip() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    fixture.enable_register();
    fixture.configure_mail();
    fixture.apply_settings(json!({"email_code_ip_hourly_limit": 2}));
    let account = make_account(
        &fixture,
        "iplimit",
        Some(PASSWORD),
        ROLE_USER,
        STATUS_ACTIVE,
    )
    .await;

    for _ in 0..2 {
        let ok = send!(
            app,
            post_json_from(
                "203.0.113.5",
                "/api/auth/email-code",
                &json!({"email": account.email, "purpose": "register"})
            )
        );
        assert_status!(ok, StatusCode::OK);
    }

    let blocked = send!(
        app,
        post_json_from(
            "203.0.113.5",
            "/api/auth/email-code",
            &json!({"email": account.email, "purpose": "register"})
        )
    );
    let blocked = assert_status!(blocked, StatusCode::TOO_MANY_REQUESTS);
    assert!(
        blocked.detail().contains("发码请求过于频繁"),
        "{}",
        blocked.detail()
    );
    let retry_after = blocked
        .headers
        .get(header::RETRY_AFTER)
        .expect("429 必须带 Retry-After")
        .to_str()
        .unwrap()
        .parse::<i64>()
        .unwrap();
    assert!(retry_after > 0 && retry_after <= 3600, "{retry_after}");

    // 限额判定在账号查询之前：已注册与未注册邮箱的响应一致，不泄露账号是否存在。
    let unknown = send!(
        app,
        post_json_from(
            "203.0.113.5",
            "/api/auth/email-code",
            &json!({
                "email": format!("{}-nobody@example.com", fixture.prefix),
                "purpose": "register"
            })
        )
    );
    assert_status!(unknown, StatusCode::TOO_MANY_REQUESTS);

    // 别的来源地址不受牵连。
    let other = send!(
        app,
        post_json_from(
            "203.0.113.7",
            "/api/auth/email-code",
            &json!({"email": account.email, "purpose": "register"})
        )
    );
    assert_status!(other, StatusCode::OK);
}

/// 并发提交错误验证码时尝试计数由数据库原子推进：一次只 +1，
/// 计满 `MAX_ATTEMPTS` 后立即作废，不允许通过竞争突破上限。
#[tokio::test]
async fn email_code_attempts_increment_atomically_under_concurrency() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let email = format!("{}-race@example.com", fixture.prefix);
    insert_email_code(
        &fixture,
        &email,
        "reset_password",
        "999999",
        Utc::now().naive_utc(),
        false,
    )
    .await;

    // 一个错误码、并发打满上限之后再补一轮，全部应返回 false。
    let rounds = email_codes::MAX_ATTEMPTS + 3;
    let mut joins = Vec::with_capacity(rounds as usize);
    for _ in 0..rounds {
        let pool = fixture.pool.clone();
        let email = email.clone();
        joins.push(tokio::spawn(async move {
            email_codes::verify_code(&pool, &email, "reset_password", "000000").await
        }));
    }
    for join in joins {
        assert!(!join.await.expect("verify 任务 panic").expect("verify 失败"));
    }

    let (attempts, consumed): (i32, Option<NaiveDateTime>) = sqlx::query_as(
        "SELECT attempts, consumed_at FROM email_verification_codes WHERE email = ?",
    )
    .bind(&email)
    .fetch_one(&fixture.pool)
    .await
    .unwrap();
    assert_eq!(attempts, email_codes::MAX_ATTEMPTS);
    assert!(consumed.is_some(), "计满上限后必须作废");

    // 已作废后正确码也无效。
    let ok = email_codes::verify_code(&fixture.pool, &email, "reset_password", "999999")
        .await
        .unwrap();
    assert!(!ok);
}

/// 同一邮箱的小时配额在并发签发下不可绕过：签发被行锁串行化，
/// 只有额度内的请求能插入记录，其余一律 429。
#[tokio::test]
async fn email_code_hourly_quota_not_bypassed_under_concurrency() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let email = format!("{}-quota-race@example.com", fixture.prefix);

    // 关闭冷却（resend_seconds = 0），只让小时配额生效。
    let limit = 3;
    let rounds = 12;
    let mut joins = Vec::with_capacity(rounds);
    for _ in 0..rounds {
        let pool = fixture.pool.clone();
        let email = email.clone();
        joins.push(tokio::spawn(async move {
            email_codes::issue_code(&pool, &email, "reset_password", 10, 0, limit, None).await
        }));
    }
    let mut issued = 0;
    for join in joins {
        match join.await.expect("issue 任务 panic") {
            Ok(_) => issued += 1,
            Err(err) => assert!(
                matches!(err, qbotmessager::error::AppError::RateLimited { .. }),
                "超限必须返回 429：{err}"
            ),
        }
    }
    assert_eq!(issued, limit);

    let stored: i64 = sqlx::query_scalar(
        "SELECT CAST(COUNT(*) AS SIGNED) FROM email_verification_codes WHERE email = ?",
    )
    .bind(&email)
    .fetch_one(&fixture.pool)
    .await
    .unwrap();
    assert_eq!(stored, limit, "落库条数必须与放行数一致");
}

#[actix_web::test]
async fn password_reset_with_email_code() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    fixture.configure_mail();
    let account = make_account(&fixture, "reset", Some(PASSWORD), ROLE_USER, STATUS_ACTIVE).await;
    let session = token_for(&fixture, account.id).await;
    let new_password = "ResetPassw0rd!";
    insert_email_code(
        &fixture,
        &account.email,
        "reset_password",
        "654321",
        Utc::now().naive_utc(),
        false,
    )
    .await;

    let short_code = send!(
        app,
        post_json(
            "/api/auth/password/reset",
            &json!({"email": account.email, "code": "1", "new_password": new_password})
        )
    );
    let short_code = assert_status!(short_code, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(short_code.detail(), "验证码长度需在 4 到 12 位之间");

    let wrong = send!(
        app,
        post_json(
            "/api/auth/password/reset",
            &json!({"email": account.email, "code": "000000", "new_password": new_password})
        )
    );
    let wrong = assert_status!(wrong, StatusCode::BAD_REQUEST);
    assert_eq!(wrong.detail(), "验证码错误或已过期");

    let ok = send!(
        app,
        post_json(
            "/api/auth/password/reset",
            &json!({"email": account.email, "code": "654321", "new_password": new_password})
        )
    );
    let ok = assert_status!(ok, StatusCode::OK);
    assert_eq!(ok.json(), json!({"ok": true}));

    // 重置成功撤销该用户全部会话。
    assert_status!(
        send!(app, get_with("/api/auth/me", &[("sid", session.as_str())])),
        StatusCode::UNAUTHORIZED
    );

    let old_login = send!(
        app,
        post_json(
            "/api/auth/login",
            &json!({"account": account.email, "password": PASSWORD})
        )
    );
    assert_status!(old_login, StatusCode::UNAUTHORIZED);

    let new_login = send!(
        app,
        post_json(
            "/api/auth/login",
            &json!({"account": account.email, "password": new_password})
        )
    );
    assert_status!(new_login, StatusCode::OK);
}

// --------------------------------------------------------------------------- OAuth

#[derive(Clone)]
struct OAuthMock {
    token_form: Arc<StdMutex<Option<String>>>,
    profile: Arc<StdMutex<Value>>,
    userinfo_hits: Arc<AtomicU64>,
}

async fn mock_token(state: web::Data<OAuthMock>, body: web::Bytes) -> HttpResponse {
    // 原样记录表单，便于断言 client_secret 使用了解密后的明文。
    *state.token_form.lock().unwrap() = Some(String::from_utf8_lossy(&body).to_string());
    HttpResponse::Ok().json(json!({"access_token": "mock-access-token", "token_type": "bearer"}))
}

async fn mock_userinfo(state: web::Data<OAuthMock>) -> HttpResponse {
    state.userinfo_hits.fetch_add(1, Ordering::SeqCst);
    HttpResponse::Ok().json(state.profile.lock().unwrap().clone())
}

async fn start_oauth_mock(profile: Value) -> (String, OAuthMock, actix_web::dev::ServerHandle) {
    let mock = OAuthMock {
        token_form: Arc::new(StdMutex::new(None)),
        profile: Arc::new(StdMutex::new(profile)),
        userinfo_hits: Arc::new(AtomicU64::new(0)),
    };
    let data = web::Data::new(mock.clone());
    let server = HttpServer::new(move || {
        App::new()
            .app_data(data.clone())
            .route("/token", web::post().to(mock_token))
            .route("/userinfo", web::get().to(mock_userinfo))
    })
    .workers(1);
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("绑定 mock OAuth 端口失败");
    let addr = listener.local_addr().expect("读取 mock OAuth 端口失败");
    let server = server.listen(listener).expect("监听 mock OAuth 失败").run();
    let handle = server.handle();
    actix_web::rt::spawn(server);
    (format!("http://127.0.0.1:{}", addr.port()), mock, handle)
}

macro_rules! create_provider {
    ($app:expr, $token:expr, $key:expr, $base:expr, $verified:expr, $preset:expr) => {{
        let session = $token.to_string();
        let body = json!({
            "key": $key,
            "display_name": "Mock Provider",
            "client_id": "mock-client-id",
            "client_secret": "oauth-plain-secret",
            "authorization_url": format!("{}/authorize", $base),
            "token_url": format!("{}/token", $base),
            "userinfo_url": format!("{}/userinfo", $base),
            "scopes": "read:user",
            "email_field": "email",
            "id_field": "id",
            "name_field": "login",
            "enabled": true,
            "email_verified": $verified,
            "use_github_preset": $preset,
        });
        send!($app, post_json_with(
            "/api/admin/oauth-providers",
            &body,
            &[("sid", session.as_str())]
        ))
    }};
}

macro_rules! oauth_start {
    ($app:expr, $key:expr) => {{ send!($app, get(&format!("/api/auth/oauth/{}/start", $key))) }};
}

/// 从 Location 的 state 参数（"{flow16}.{state32}"）提取 flow 后缀。
fn state_flow(location: &str) -> String {
    query_param(location, "state")
        .and_then(|state| state.split_once('.').map(|(flow, _)| flow.to_string()))
        .unwrap_or_default()
}

/// 与服务端一致：flow 为空时退回不带后缀的回退名。
fn flow_cookie_name(base: &str, flow: &str) -> String {
    if flow.is_empty() {
        base.to_string()
    } else {
        format!("{base}_{flow}")
    }
}

macro_rules! oauth_callback {
    ($app:expr, $key:expr, $code:expr, $state:expr, $state_cookie:expr, $provider_cookie:expr) => {{
        // state 参数为 "{flow16}.{state32}"，从 flow 拼 Cookie 名，与服务端解析一致。
        let full_state: String = $state.to_string();
        let flow = full_state
            .split_once('.')
            .map(|(flow, _)| flow.to_string())
            .unwrap_or_default();
        let state_name = flow_cookie_name("oauth_state", &flow);
        let provider_name = flow_cookie_name("oauth_provider", &flow);
        let uri = format!(
            "/api/auth/oauth/{}/callback?code={}&state={}",
            $key, $code, full_state
        );
        send!(
            $app,
            get_with(
                &uri,
                &[
                    (state_name.as_str(), $state_cookie.as_str()),
                    (provider_name.as_str(), $provider_cookie.as_str()),
                ]
            )
        )
    }};
}

macro_rules! oauth_callback_with_invite {
    ($app:expr, $key:expr, $code:expr, $state:expr, $state_cookie:expr, $provider_cookie:expr, $invite:expr) => {{
        let full_state: String = $state.to_string();
        let flow = full_state
            .split_once('.')
            .map(|(flow, _)| flow.to_string())
            .unwrap_or_default();
        let state_name = flow_cookie_name("oauth_state", &flow);
        let provider_name = flow_cookie_name("oauth_provider", &flow);
        let invite_name = flow_cookie_name("oauth_invite", &flow);
        let uri = format!(
            "/api/auth/oauth/{}/callback?code={}&state={}",
            $key, $code, full_state
        );
        send!(
            $app,
            get_with(
                &uri,
                &[
                    (state_name.as_str(), $state_cookie.as_str()),
                    (provider_name.as_str(), $provider_cookie.as_str()),
                    (invite_name.as_str(), $invite),
                ]
            )
        )
    }};
}

fn query_param(url: &str, name: &str) -> Option<String> {
    // 相对路径（如 /oauth/failure?message=…）不是合法绝对 URL，直接取问号后的部分。
    let query = match url::Url::parse(url) {
        Ok(parsed) => {
            return parsed
                .query_pairs()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.into_owned());
        }
        Err(_) => url.split_once('?')?.1,
    };
    url::form_urlencoded::parse(query.as_bytes())
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
}

/// 回调失败统一 302 到提示页；断言 Location 与 message 参数。
fn assert_oauth_failure(reply: Reply, message_contains: &str) -> String {
    let reply = assert_status!(reply, StatusCode::FOUND);
    let location = reply
        .headers
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("失败必须重定向到提示页")
        .to_string();
    assert!(
        location.starts_with("/oauth/failure?"),
        "应重定向到提示页：{location}"
    );
    let message = query_param(&location, "message").unwrap_or_default();
    assert!(
        message.contains(message_contains),
        "提示信息应包含「{message_contains}」：{message}"
    );
    assert!(reply.cookie("sid").is_none(), "失败时不得下发会话");
    location
}

#[actix_web::test]
async fn oauth_state_cookie_validation() {
    // OAuth state 双提交校验（规格书 6.2）
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let (_admin, admin_token) = make_admin(&fixture, "adminstate").await;
    let (_mock_base, _mock, handle) = start_oauth_mock(json!({})).await;
    let key = format!("{}-state", fixture.prefix);

    let created = create_provider!(
        app,
        admin_token,
        key.clone(),
        "http://127.0.0.1:9",
        Value::Bool(true),
        false
    );
    let created = assert_status!(created, StatusCode::CREATED);
    assert_eq!(created.json()["key"], json!(key));

    let start = oauth_start!(app, key);
    let start = assert_status!(start, StatusCode::FOUND);
    let location = start
        .headers
        .get(header::LOCATION)
        .expect("start 必须返回 Location")
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        location.starts_with("http://127.0.0.1:9/authorize?"),
        "{location}"
    );
    let state = query_param(&location, "state").expect("Location 缺少 state");
    // state 参数为 "{flow16}.{state32}"，共 49 字符。
    assert_eq!(state.len(), 49, "{state}");
    let (flow_part, state_body) = state.split_once('.').expect("state 必须含 flow 分隔符");
    assert_eq!(flow_part.len(), 16, "{state}");
    assert_eq!(state_body.len(), 32, "{state}");
    let state_cookie = start
        .cookie(&format!("oauth_state_{flow_part}"))
        .expect("缺少 oauth_state Cookie");
    let provider_cookie = start
        .cookie(&format!("oauth_provider_{flow_part}"))
        .expect("缺少 oauth_provider Cookie");
    let raw_state_cookie = start
        .raw_cookie(&format!("oauth_state_{flow_part}"))
        .unwrap();
    assert!(
        raw_state_cookie.contains("Max-Age=600"),
        "{raw_state_cookie}"
    );
    assert!(raw_state_cookie.contains("HttpOnly"), "{raw_state_cookie}");
    // Cookie 值仍是 state 主体（不含 flow 前缀）。
    assert_eq!(state_cookie, state_body);

    let mismatch = oauth_callback!(
        app,
        key,
        "abc",
        "wrong-state",
        state_cookie,
        provider_cookie
    );
    let mismatch = assert_oauth_failure(mismatch, "state 校验失败");

    let missing_cookie = send!(
        app,
        get(&format!(
            "/api/auth/oauth/{key}/callback?code=abc&state={state}"
        ))
    );
    let missing_cookie = assert_oauth_failure(missing_cookie, "state 校验失败");

    let wrong_provider = oauth_callback!(
        app,
        key,
        "abc",
        state,
        state_cookie,
        "another-provider".to_string()
    );
    let wrong_provider = assert_oauth_failure(wrong_provider, "state 校验失败");

    let no_code = oauth_callback!(app, key, "", state, state_cookie, provider_cookie);
    let no_code = assert_oauth_failure(no_code, "缺少授权码");
    let _ = (mismatch, missing_cookie, wrong_provider, no_code);

    let _ = handle.stop(true).await;
}

#[actix_web::test]
async fn oauth_login_keeps_secret_encrypted_and_uses_plaintext() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let (_admin, admin_token) = make_admin(&fixture, "adminoauth").await;
    let email = format!("{}-gh@example.com", fixture.prefix);
    let (base, mock, handle) = start_oauth_mock(json!({
        "id": "4242",
        "login": "octocat",
        "name": "Octo Cat",
        "email": email,
        "email_verified": true,
    }))
    .await;
    let key = format!("{}-oauth", fixture.prefix);

    let created = create_provider!(
        app,
        admin_token,
        key.clone(),
        base,
        Value::Bool(true),
        false
    );
    assert_status!(created, StatusCode::CREATED);
    let stored_before: String =
        sqlx::query_scalar("SELECT client_secret FROM oauth_providers WHERE `key` = ?")
            .bind(&key)
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
    assert!(stored_before.starts_with("enc1:"), "{stored_before}");

    fixture.enable_register();
    let invite = create_invite(
        &fixture,
        "oauthreg",
        1,
        None,
        Some(Utc::now().naive_utc() + Duration::days(1)),
        None,
    )
    .await;
    let start = send!(
        app,
        get(&format!("/api/auth/oauth/{key}/start?invite_code={invite}"))
    );
    let start = assert_status!(start, StatusCode::FOUND);
    let location = start
        .headers
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let state = query_param(&location, "state").unwrap();
    let flow = state_flow(&location);
    let state_cookie = start
        .cookie(&flow_cookie_name("oauth_state", &flow))
        .unwrap();
    let provider_cookie = start
        .cookie(&flow_cookie_name("oauth_provider", &flow))
        .unwrap();

    let callback = oauth_callback_with_invite!(
        app,
        key,
        "mock-code",
        state,
        state_cookie,
        provider_cookie,
        invite.as_str()
    );
    let callback = assert_status!(callback, StatusCode::FOUND);
    assert_eq!(
        callback
            .headers
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some("/")
    );
    let sid = callback.cookie("sid").expect("OAuth 登录必须下发会话");
    assert_eq!(invite_used_count(&fixture, &invite).await, 1);
    let _ = handle.stop(true).await;

    let me = send!(app, get_with("/api/auth/me", &[("sid", sid.as_str())]));
    let me = assert_status!(me, StatusCode::OK);
    assert_eq!(me.json()["email"], json!(email));

    // 兑换 token 时使用解密后的明文 secret。
    let form_raw = mock
        .token_form
        .lock()
        .unwrap()
        .clone()
        .expect("mock 未收到 token 请求");
    let form: HashMap<String, String> = url::form_urlencoded::parse(form_raw.as_bytes())
        .into_owned()
        .collect();
    assert_eq!(
        form.get("client_secret").map(String::as_str),
        Some("oauth-plain-secret")
    );
    assert_eq!(
        form.get("grant_type").map(String::as_str),
        Some("authorization_code")
    );
    assert_eq!(form.get("code").map(String::as_str), Some("mock-code"));
    assert_eq!(mock.userinfo_hits.load(Ordering::SeqCst), 1);

    // 明文绝不能写回数据库。
    let stored_after: String =
        sqlx::query_scalar("SELECT client_secret FROM oauth_providers WHERE `key` = ?")
            .bind(&key)
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
    assert_eq!(stored_after, stored_before, "client_secret 不应被改写");
    assert!(stored_after.starts_with("enc1:"));
    assert_eq!(
        crypto::decrypt_secret(&stored_after, Some(&fixture.fernet_key)).unwrap(),
        "oauth-plain-secret"
    );

    let users: i64 =
        sqlx::query_scalar("SELECT CAST(COUNT(*) AS SIGNED) FROM users WHERE email = ?")
            .bind(&email)
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
    assert_eq!(users, 1);
}

#[actix_web::test]
async fn oauth_untrusted_email_cannot_take_over_account() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let (_admin, admin_token) = make_admin(&fixture, "adminuntrust").await;
    let victim = make_account(&fixture, "victim", Some(PASSWORD), ROLE_USER, STATUS_ACTIVE).await;
    let (base, _mock, handle) = start_oauth_mock(json!({
        "id": "777",
        "login": "attacker",
        "email": victim.email,
        "email_verified": false,
    }))
    .await;
    let key = format!("{}-untrusted", fixture.prefix);
    // 管理端信任该提供方，但本次响应声明邮箱未验证：仍不得自动关联。
    assert_status!(
        create_provider!(
            app,
            admin_token,
            key.clone(),
            base,
            Value::Bool(true),
            false
        ),
        StatusCode::CREATED
    );
    fixture.enable_register();

    let start = oauth_start!(app, key);
    let start = assert_status!(start, StatusCode::FOUND);
    let location = start
        .headers
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let state = query_param(&location, "state").unwrap();
    let flow = state_flow(&location);
    let state_cookie = start
        .cookie(&flow_cookie_name("oauth_state", &flow))
        .unwrap();
    let provider_cookie = start
        .cookie(&flow_cookie_name("oauth_provider", &flow))
        .unwrap();

    let callback = oauth_callback!(app, key, "mock-code", state, state_cookie, provider_cookie);
    let location = assert_oauth_failure(callback, "可信验证");
    let _ = location;
    let _ = handle.stop(true).await;

    let identities: i64 = sqlx::query_scalar(
        "SELECT CAST(COUNT(*) AS SIGNED) FROM auth_identities WHERE user_id = ?",
    )
    .bind(victim.id)
    .fetch_one(&fixture.pool)
    .await
    .unwrap();
    assert_eq!(identities, 0, "不得写入身份绑定");

    // 原账号密码仍然可用。
    let login = send!(
        app,
        post_json(
            "/api/auth/login",
            &json!({"account": victim.email, "password": PASSWORD})
        )
    );
    assert_status!(login, StatusCode::OK);
}

#[actix_web::test]
async fn oauth_signup_without_invite_is_rejected() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let (_admin, admin_token) = make_admin(&fixture, "adminnoinvite").await;
    let email = format!("{}-noinvite@example.com", fixture.prefix);
    let (base, _mock, handle) = start_oauth_mock(json!({
        "id": "noinvite-1",
        "login": "noinvite",
        "email": email,
        "email_verified": true,
    }))
    .await;
    let key = format!("{}-noinvite", fixture.prefix);
    assert_status!(
        create_provider!(
            app,
            admin_token,
            key.clone(),
            base,
            Value::Bool(true),
            false
        ),
        StatusCode::CREATED
    );
    fixture.enable_register();

    let start = oauth_start!(app, key);
    let start = assert_status!(start, StatusCode::FOUND);
    let location = start
        .headers
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let state = query_param(&location, "state").unwrap();
    let flow = state_flow(&location);
    let state_cookie = start
        .cookie(&flow_cookie_name("oauth_state", &flow))
        .unwrap();
    let provider_cookie = start
        .cookie(&flow_cookie_name("oauth_provider", &flow))
        .unwrap();

    let callback = oauth_callback!(app, key, "mock-code", state, state_cookie, provider_cookie);
    assert_oauth_failure(callback, "需要邀请码");
    let _ = handle.stop(true).await;

    let users: i64 =
        sqlx::query_scalar("SELECT CAST(COUNT(*) AS SIGNED) FROM users WHERE email = ?")
            .bind(&email)
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
    assert_eq!(users, 0, "未携带邀请码不得创建账号");
}

#[actix_web::test]
async fn oauth_provider_must_trust_email_for_signup() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let (_admin, admin_token) = make_admin(&fixture, "adminuntrustedcfg").await;
    let email = format!("{}-untrustedcfg@example.com", fixture.prefix);
    let (base, _mock, handle) = start_oauth_mock(json!({
        "id": "untrustedcfg-1",
        "login": "untrustedcfg",
        "email": email,
        "email_verified": true,
    }))
    .await;
    let key = format!("{}-untrustedcfg", fixture.prefix);
    // 提供方返回已验证，但管理端未信任该提供方：不得据此建号。
    assert_status!(
        create_provider!(
            app,
            admin_token,
            key.clone(),
            base,
            Value::Bool(false),
            false
        ),
        StatusCode::CREATED
    );
    fixture.enable_register();
    let invite = create_invite(
        &fixture,
        "untrustedcfg",
        1,
        None,
        Some(Utc::now().naive_utc() + Duration::days(1)),
        None,
    )
    .await;

    let start = send!(
        app,
        get(&format!("/api/auth/oauth/{key}/start?invite_code={invite}"))
    );
    let start = assert_status!(start, StatusCode::FOUND);
    let location = start
        .headers
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let state = query_param(&location, "state").unwrap();
    let flow = state_flow(&location);
    let state_cookie = start
        .cookie(&flow_cookie_name("oauth_state", &flow))
        .unwrap();
    let provider_cookie = start
        .cookie(&flow_cookie_name("oauth_provider", &flow))
        .unwrap();

    let callback = oauth_callback_with_invite!(
        app,
        key,
        "mock-code",
        state,
        state_cookie,
        provider_cookie,
        invite.as_str()
    );
    assert_oauth_failure(callback, "可信验证");
    let _ = handle.stop(true).await;

    let users: i64 =
        sqlx::query_scalar("SELECT CAST(COUNT(*) AS SIGNED) FROM users WHERE email = ?")
            .bind(&email)
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
    assert_eq!(users, 0);
    assert_eq!(invite_used_count(&fixture, &invite).await, 0);
}

#[actix_web::test]
async fn oauth_trusted_email_links_existing_account() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let (_admin, admin_token) = make_admin(&fixture, "admintrust").await;
    let local = make_account(
        &fixture,
        "trusted",
        Some(PASSWORD),
        ROLE_USER,
        STATUS_ACTIVE,
    )
    .await;
    let (base, _mock, handle) = start_oauth_mock(json!({
        "id": "888",
        "login": "trusted-login",
        "email": local.email,
        "email_verified": true,
    }))
    .await;
    let key = format!("{}-trusted", fixture.prefix);
    assert_status!(
        create_provider!(
            app,
            admin_token,
            key.clone(),
            base,
            Value::Bool(true),
            false
        ),
        StatusCode::CREATED
    );

    let start = oauth_start!(app, key);
    let start = assert_status!(start, StatusCode::FOUND);
    let location = start
        .headers
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let state = query_param(&location, "state").unwrap();
    let flow = state_flow(&location);
    let state_cookie = start
        .cookie(&flow_cookie_name("oauth_state", &flow))
        .unwrap();
    let provider_cookie = start
        .cookie(&flow_cookie_name("oauth_provider", &flow))
        .unwrap();

    let callback = oauth_callback!(app, key, "mock-code", state, state_cookie, provider_cookie);
    let callback = assert_status!(callback, StatusCode::FOUND);
    let sid = callback.cookie("sid").expect("应下发会话");
    let _ = handle.stop(true).await;

    let me = send!(app, get_with("/api/auth/me", &[("sid", sid.as_str())]));
    let me = assert_status!(me, StatusCode::OK);
    assert_eq!(me.json()["id"], json!(local.id));

    let bound_user: i64 = sqlx::query_scalar(
        "SELECT user_id FROM auth_identities WHERE provider = ? AND provider_user_id = '888'",
    )
    .bind(&key)
    .fetch_one(&fixture.pool)
    .await
    .expect("缺少身份绑定");
    assert_eq!(bound_user, local.id);

    let users: i64 =
        sqlx::query_scalar("SELECT CAST(COUNT(*) AS SIGNED) FROM users WHERE email = ?")
            .bind(&local.email)
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
    assert_eq!(users, 1, "不得复制本地账号");

    // OAuth 登录不影响原有密码登录。
    let login = send!(
        app,
        post_json(
            "/api/auth/login",
            &json!({"account": local.email, "password": PASSWORD})
        )
    );
    assert_status!(login, StatusCode::OK);
}

#[actix_web::test]
async fn oauth_github_preset_defaults_email_unverified() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let (_admin, admin_token) = make_admin(&fixture, "admingh").await;
    // 固定 key `github` 在重复运行间可能残留，先清理保证幂等。
    sqlx::query("DELETE FROM oauth_providers WHERE `key` = 'github'")
        .execute(&fixture.pool)
        .await
        .unwrap();

    let github = send!(
        app,
        post_json_with(
            "/api/admin/oauth-providers",
            &json!({
                "key": "github",
                "display_name": "GitHub",
                "client_id": "gh-client",
                "client_secret": "gh-secret",
                "use_github_preset": true,
            }),
            &[("sid", admin_token.as_str())]
        )
    );
    assert_status!(github, StatusCode::CREATED);

    let custom_key = format!("{}-custom", fixture.prefix);
    let custom = send!(
        app,
        post_json_with(
            "/api/admin/oauth-providers",
            &json!({
                "key": custom_key,
                "display_name": "Custom",
                "client_id": "custom-client",
                "client_secret": "custom-secret",
                "authorization_url": "https://custom.example/authorize",
                "token_url": "https://custom.example/token",
                "userinfo_url": "https://custom.example/userinfo",
            }),
            &[("sid", admin_token.as_str())]
        )
    );
    assert_status!(custom, StatusCode::CREATED);

    let list = send!(
        app,
        get_with(
            "/api/admin/oauth-providers",
            &[("sid", admin_token.as_str())]
        )
    );
    let list = assert_status!(list, StatusCode::OK);
    let items = list.json();
    let items = items.as_array().unwrap();
    let github_item = items
        .iter()
        .find(|item| item["key"] == json!("github"))
        .expect("缺少 github 提供方");
    assert_eq!(github_item["email_verified"], json!(false));
    assert_eq!(
        github_item["authorization_url"],
        json!("https://github.com/login/oauth/authorize")
    );
    assert_eq!(
        github_item["token_url"],
        json!("https://github.com/login/oauth/access_token")
    );
    assert_eq!(
        github_item["userinfo_url"],
        json!("https://api.github.com/user")
    );

    let custom_item = items
        .iter()
        .find(|item| item["key"] == json!(custom_key))
        .expect("缺少自定义提供方");
    assert_eq!(custom_item["email_verified"], json!(false));
}

#[actix_web::test]
async fn oauth_login_does_not_break_password_login() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let (admin, _admin_token) = make_admin(&fixture, "adminpw").await;
    // 配置一个提供方后管理员仍可用密码登录。
    let (_admin2, admin_token) = make_admin(&fixture, "adminpw2").await;
    let key = format!("{}-pw", fixture.prefix);
    assert_status!(
        create_provider!(
            app,
            admin_token,
            key,
            "http://127.0.0.1:9",
            Value::Bool(false),
            false
        ),
        StatusCode::CREATED
    );

    let login = send!(
        app,
        post_json(
            "/api/auth/login",
            &json!({"account": admin.email, "password": PASSWORD})
        )
    );
    let login = assert_status!(login, StatusCode::OK);
    assert_eq!(login.json()["role"], json!("super_admin"));
}

#[actix_web::test]
async fn oauth_link_binds_identity_to_logged_in_user() {
    // 登录态下发起 OAuth：绑定到当前用户，不产生新账号，也不换发会话。
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let (_admin, admin_token) = make_admin(&fixture, "adminlink").await;
    let (base, _mock, handle) = start_oauth_mock(json!({
        "id": "link-4242",
        "login": "link-octo",
        "name": "Link Cat",
        "email_verified": false,
    }))
    .await;
    let key = format!("{}-link", fixture.prefix);
    assert_status!(
        create_provider!(
            app,
            admin_token,
            key.clone(),
            base,
            Value::Bool(false),
            false
        ),
        StatusCode::CREATED
    );

    let (linker, sid) = make_admin(&fixture, "linker").await;
    let start = send!(
        app,
        get_with(
            &format!("/api/auth/oauth/{key}/start"),
            &[("sid", sid.as_str())]
        )
    );
    let start = assert_status!(start, StatusCode::FOUND);
    let location = start
        .headers
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .unwrap()
        .to_string();
    let state = query_param(&location, "state").unwrap();
    let flow = state_flow(&location);
    let state_cookie = start
        .cookie(&flow_cookie_name("oauth_state", &flow))
        .unwrap();
    let provider_cookie = start
        .cookie(&flow_cookie_name("oauth_provider", &flow))
        .unwrap();
    assert!(
        start
            .cookie(&flow_cookie_name("oauth_link", &flow))
            .is_some(),
        "登录态应签发绑定标记"
    );

    let callback = send!(
        app,
        get_with(
            &format!("/api/auth/oauth/{key}/callback?code=mock-code&state={state}"),
            &[
                ("sid", sid.as_str()),
                (
                    flow_cookie_name("oauth_state", &flow).as_str(),
                    state_cookie.as_str()
                ),
                (
                    flow_cookie_name("oauth_provider", &flow).as_str(),
                    provider_cookie.as_str()
                ),
                (flow_cookie_name("oauth_link", &flow).as_str(), "1"),
            ]
        )
    );
    let callback = assert_status!(callback, StatusCode::FOUND);
    let redirect = callback
        .headers
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .unwrap()
        .to_string();
    assert!(
        redirect.starts_with("/security"),
        "绑定后应回到安全设置页：{redirect}"
    );
    assert_eq!(query_param(&redirect, "oauth").as_deref(), Some("ok"));
    assert!(callback.cookie("sid").is_none(), "绑定流程不换发会话");
    let _ = handle.stop(true).await;

    let bound_user: i64 = sqlx::query_scalar(
        "SELECT user_id FROM auth_identities WHERE provider = ? AND provider_user_id = 'link-4242'",
    )
    .bind(&key)
    .fetch_one(&fixture.pool)
    .await
    .expect("缺少身份绑定");
    assert_eq!(bound_user, linker.id);

    // 列表端点返回该绑定。
    let list = send!(
        app,
        get_with("/api/auth/oauth/identities", &[("sid", sid.as_str())])
    );
    let list = assert_status!(list, StatusCode::OK);
    let items = list.json();
    let items = items.as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["provider"], json!(key));
    assert_eq!(items[0]["provider_login"], json!("link-octo"));
}

#[actix_web::test]
async fn oauth_link_rejects_identity_bound_to_other_user() {
    // 第三方账号已被他人绑定：返回提示页，不写入新绑定。
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let (_admin, admin_token) = make_admin(&fixture, "adminoccu").await;
    let (base, mock, handle) = start_oauth_mock(json!({
        "id": "occu-1",
        "login": "occu-login",
        "email": format!("occu-{}@example.com", fixture.prefix),
        "email_verified": true,
    }))
    .await;
    let key = format!("{}-occu", fixture.prefix);
    assert_status!(
        create_provider!(
            app,
            admin_token,
            key.clone(),
            base,
            Value::Bool(true),
            false
        ),
        StatusCode::CREATED
    );
    fixture.enable_register();
    let invite = create_invite(
        &fixture,
        "occu-reg",
        1,
        None,
        Some(Utc::now().naive_utc() + Duration::days(1)),
        None,
    )
    .await;

    // 第一个用户先通过 OAuth 登录占住该第三方账号。
    let first_start = send!(
        app,
        get(&format!(
            "/api/auth/oauth/{}/start?invite_code={invite}",
            key
        ))
    );
    let first_start = assert_status!(first_start, StatusCode::FOUND);
    let location = first_start
        .headers
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .unwrap()
        .to_string();
    let state = query_param(&location, "state").unwrap();
    let flow = state_flow(&location);
    let state_cookie = first_start
        .cookie(&flow_cookie_name("oauth_state", &flow))
        .unwrap();
    let provider_cookie = first_start
        .cookie(&flow_cookie_name("oauth_provider", &flow))
        .unwrap();
    let first = oauth_callback_with_invite!(
        app,
        key.clone(),
        "mock-code",
        state,
        state_cookie,
        provider_cookie,
        invite.as_str()
    );
    assert_status!(first, StatusCode::FOUND);
    assert_eq!(invite_used_count(&fixture, &invite).await, 1);
    let _ = mock;

    // 第二个已登录用户尝试绑定同一个第三方账号。
    let (occupier, sid) = make_admin(&fixture, "occupier").await;
    let second_start = send!(
        app,
        get_with(
            &format!("/api/auth/oauth/{key}/start"),
            &[("sid", sid.as_str())]
        )
    );
    let second_start = assert_status!(second_start, StatusCode::FOUND);
    let location = second_start
        .headers
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .unwrap()
        .to_string();
    let state = query_param(&location, "state").unwrap();
    let flow = state_flow(&location);
    let state_cookie = second_start
        .cookie(&flow_cookie_name("oauth_state", &flow))
        .unwrap();
    let provider_cookie = second_start
        .cookie(&flow_cookie_name("oauth_provider", &flow))
        .unwrap();

    let callback = send!(
        app,
        get_with(
            &format!("/api/auth/oauth/{key}/callback?code=mock-code&state={state}"),
            &[
                ("sid", sid.as_str()),
                (
                    flow_cookie_name("oauth_state", &flow).as_str(),
                    state_cookie.as_str()
                ),
                (
                    flow_cookie_name("oauth_provider", &flow).as_str(),
                    provider_cookie.as_str()
                ),
                (flow_cookie_name("oauth_link", &flow).as_str(), "1"),
            ]
        )
    );
    let location = assert_oauth_failure(callback, "已绑定到其他用户");
    let _ = location;
    let _ = handle.stop(true).await;

    let identities: i64 = sqlx::query_scalar(
        "SELECT CAST(COUNT(*) AS SIGNED) FROM auth_identities WHERE provider = ? AND provider_user_id = 'occu-1'",
    )
    .bind(&key)
    .fetch_one(&fixture.pool)
    .await
    .unwrap();
    assert_eq!(identities, 1, "仍只有一条绑定");
    let _ = occupier;
}

#[actix_web::test]
async fn oauth_unlink_guards_last_login_method() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    // 提供方无需真实交互：identity 直接落库即可。
    let key = format!("{}-unl", fixture.prefix);
    sqlx::query(
        "INSERT INTO oauth_providers (`key`, display_name, client_id, client_secret, \
         authorization_url, token_url, userinfo_url, scopes, email_field, id_field, \
         name_field, enabled, email_verified, created_at) \
         VALUES (?, 'Unlink', 'c', 'enc1:x', 'http://a', 'http://t', 'http://u', 's', \
         'email', 'id', 'name', TRUE, TRUE, ?)",
    )
    .bind(&key)
    .bind(Utc::now().naive_utc())
    .execute(&fixture.pool)
    .await
    .unwrap();

    // 无密码、无 passkey、仅一个 OAuth 绑定：拒绝解绑。
    let (owner, sid) = make_admin(&fixture, "unlowner").await;
    sqlx::query("UPDATE users SET password_hash = NULL WHERE id = ?")
        .bind(owner.id)
        .execute(&fixture.pool)
        .await
        .unwrap();
    let identity_id = sqlx::query(
        "INSERT INTO auth_identities (user_id, provider, provider_user_id, provider_login, \
         created_at) VALUES (?, ?, '9413', 'unl-login', ?)",
    )
    .bind(owner.id)
    .bind(&key)
    .bind(Utc::now().naive_utc())
    .execute(&fixture.pool)
    .await
    .unwrap()
    .last_insert_id() as i64;

    let unlink = send!(
        app,
        delete_with(
            &format!("/api/auth/oauth/identities/{identity_id}"),
            &[("sid", sid.as_str())]
        )
    );
    let unlink = assert_status!(unlink, StatusCode::CONFLICT);
    assert!(unlink.detail().contains("登录方式"), "{}", unlink.detail());

    // 设置密码后解绑成功。
    let hash = passwords::hash_password_with("dummy-unlink-pw", b"test-salt-16byte", 1_000);
    sqlx::query("UPDATE users SET password_hash = ? WHERE id = ?")
        .bind(&hash)
        .bind(owner.id)
        .execute(&fixture.pool)
        .await
        .unwrap();

    let unlink = send!(
        app,
        delete_with(
            &format!("/api/auth/oauth/identities/{identity_id}"),
            &[("sid", sid.as_str())]
        )
    );
    let unlink = assert_status!(unlink, StatusCode::OK);
    assert_eq!(unlink.json()["ok"], json!(true));

    let remaining: i64 =
        sqlx::query_scalar("SELECT CAST(COUNT(*) AS SIGNED) FROM auth_identities WHERE id = ?")
            .bind(identity_id)
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
    assert_eq!(remaining, 0, "绑定应已删除");
}

#[actix_web::test]
async fn oauth_no_identity_with_register_closed_redirects_to_failure_page() {
    // 注册关闭且无关联账号：不再返回 JSON，而是 302 到提示页。
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let (_admin, admin_token) = make_admin(&fixture, "adminnoclose").await;
    let (base, _mock, handle) = start_oauth_mock(json!({
        "id": "closed-1",
        "login": "closed-login",
        "email": format!("closed-{}@example.com", fixture.prefix),
        "email_verified": true,
    }))
    .await;
    let key = format!("{}-closed", fixture.prefix);
    assert_status!(
        create_provider!(
            app,
            admin_token,
            key.clone(),
            base,
            Value::Bool(true),
            false
        ),
        StatusCode::CREATED
    );
    // 默认注册关闭。

    let start = oauth_start!(app, key);
    let start = assert_status!(start, StatusCode::FOUND);
    let location = start
        .headers
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .unwrap()
        .to_string();
    let state = query_param(&location, "state").unwrap();
    let flow = state_flow(&location);
    let state_cookie = start
        .cookie(&flow_cookie_name("oauth_state", &flow))
        .unwrap();
    let provider_cookie = start
        .cookie(&flow_cookie_name("oauth_provider", &flow))
        .unwrap();
    assert!(
        start
            .cookie(&flow_cookie_name("oauth_link", &flow))
            .is_none(),
        "未登录不得签发绑定标记"
    );

    let callback = oauth_callback!(app, key, "mock-code", state, state_cookie, provider_cookie);
    let location = assert_oauth_failure(callback, "注册入口已关闭");
    let _ = location;
    let _ = handle.stop(true).await;

    let users: i64 =
        sqlx::query_scalar("SELECT CAST(COUNT(*) AS SIGNED) FROM users WHERE email = ?")
            .bind(format!("closed-{}@example.com", fixture.prefix))
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
    assert_eq!(users, 0, "注册关闭时不得自动建号");
}

#[actix_web::test]
async fn oauth_unlink_rejects_foreign_identity() {
    // 不能删别人的绑定。
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let (owner, owner_sid) = make_admin(&fixture, "ownerfgn").await;
    let (other, other_sid) = make_admin(&fixture, "otherfgn").await;
    let provider_key = format!("{}-fgn", fixture.prefix);
    let identity_id = sqlx::query(
        "INSERT INTO auth_identities (user_id, provider, provider_user_id, provider_login, \
         created_at) VALUES (?, ?, 'fgn-1', 'fgn-login', ?)",
    )
    .bind(owner.id)
    .bind(&provider_key)
    .bind(Utc::now().naive_utc())
    .execute(&fixture.pool)
    .await
    .unwrap()
    .last_insert_id() as i64;

    let unlink = send!(
        app,
        delete_with(
            &format!("/api/auth/oauth/identities/{identity_id}"),
            &[("sid", other_sid.as_str())]
        )
    );
    assert_status!(unlink, StatusCode::NOT_FOUND);

    let remaining: i64 =
        sqlx::query_scalar("SELECT CAST(COUNT(*) AS SIGNED) FROM auth_identities WHERE id = ?")
            .bind(identity_id)
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
    assert_eq!(remaining, 1);
    let _ = (other.id, owner_sid);
}

// --------------------------------------------------------------------------- Passkey

fn b64(raw: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(raw)
}

fn sha256(raw: &[u8]) -> Vec<u8> {
    Sha256::digest(raw).to_vec()
}

/// P-256 生成元的坐标（在曲线上，`COSEKey::validate` 可以通过）。
const P256_GX: &str = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
const P256_GY: &str = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";

fn hex32(raw: &str) -> Vec<u8> {
    (0..raw.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&raw[index..index + 2], 16).unwrap())
        .collect()
}

fn cbor_head(major: u8, value: u64) -> Vec<u8> {
    match value {
        0..=23 => vec![(major << 5) | value as u8],
        24..=0xff => vec![(major << 5) | 24, value as u8],
        0x100..=0xffff => {
            let mut out = vec![(major << 5) | 25];
            out.extend_from_slice(&(value as u16).to_be_bytes());
            out
        }
        _ => {
            let mut out = vec![(major << 5) | 26];
            out.extend_from_slice(&(value as u32).to_be_bytes());
            out
        }
    }
}

fn cbor_int(value: i64) -> Vec<u8> {
    if value >= 0 {
        cbor_head(0, value as u64)
    } else {
        cbor_head(1, (-1i128 - i128::from(value)) as u64)
    }
}

fn cbor_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut out = cbor_head(2, bytes.len() as u64);
    out.extend_from_slice(bytes);
    out
}

fn cbor_text(text: &str) -> Vec<u8> {
    let mut out = cbor_head(3, text.len() as u64);
    out.extend_from_slice(text.as_bytes());
    out
}

fn cbor_map(entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut out = cbor_head(5, entries.len() as u64);
    for (key, value) in entries {
        out.extend_from_slice(key);
        out.extend_from_slice(value);
    }
    out
}

fn cose_es256() -> Vec<u8> {
    cbor_map(&[
        (cbor_int(1), cbor_int(2)),  // kty: EC2
        (cbor_int(3), cbor_int(-7)), // alg: ES256
        (cbor_int(-1), cbor_int(1)), // crv: P-256
        (cbor_int(-2), cbor_bytes(&hex32(P256_GX))),
        (cbor_int(-3), cbor_bytes(&hex32(P256_GY))),
    ])
}

fn registration_credential(
    challenge: &str,
    rp_id: &str,
    origin: &str,
    credential_id: &[u8],
) -> Value {
    let client_data = json!({
        "type": "webauthn.create",
        "challenge": challenge,
        "origin": origin,
        "crossOrigin": false,
    });
    let client_data_json = serde_json::to_vec(&client_data).unwrap();

    let mut auth_data = sha256(rp_id.as_bytes());
    auth_data.push(0x41); // UP | AT
    auth_data.extend_from_slice(&0u32.to_be_bytes());
    auth_data.extend_from_slice(&[0x11u8; 16]); // AAGUID
    auth_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
    auth_data.extend_from_slice(credential_id);
    auth_data.extend_from_slice(&cose_es256());

    let attestation = cbor_map(&[
        (cbor_text("fmt"), cbor_text("none")),
        (cbor_text("attStmt"), cbor_map(&[])),
        (cbor_text("authData"), cbor_bytes(&auth_data)),
    ]);

    json!({
        "id": b64(credential_id),
        "rawId": b64(credential_id),
        "response": {
            "attestationObject": b64(&attestation),
            "clientDataJSON": b64(&client_data_json),
            "transports": ["internal"],
        },
        "type": "public-key",
        "label": "我的手机",
    })
}

fn assertion_credential(
    challenge: &str,
    rp_id: &str,
    origin: &str,
    credential_id: &[u8],
    sign_count: u32,
) -> Value {
    let client_data = json!({
        "type": "webauthn.get",
        "challenge": challenge,
        "origin": origin,
        "crossOrigin": false,
    });
    let client_data_json = serde_json::to_vec(&client_data).unwrap();
    let mut auth_data = sha256(rp_id.as_bytes());
    auth_data.push(0x01); // UP
    auth_data.extend_from_slice(&sign_count.to_be_bytes());

    json!({
        "id": b64(credential_id),
        "rawId": b64(credential_id),
        "response": {
            "authenticatorData": b64(&auth_data),
            "clientDataJSON": b64(&client_data_json),
            "signature": b64(&[1u8, 2, 3]),
            "userHandle": null,
        },
        "type": "public-key",
    })
}

/// 用 p256 生成密钥并产生真实 ES256 断言（DER 签名）。
///
/// 返回 (COSE 公钥字节, 凭据 JSON)。签名原文 = authenticatorData || SHA256(clientDataJSON)。
fn signed_assertion_credential(
    challenge: &str,
    rp_id: &str,
    origin: &str,
    credential_id: &[u8],
    sign_count: u32,
    signing_key: &p256::ecdsa::SigningKey,
) -> (Vec<u8>, Value) {
    let client_data = json!({
        "type": "webauthn.get",
        "challenge": challenge,
        "origin": origin,
        "crossOrigin": false,
    });
    let client_data_json = serde_json::to_vec(&client_data).unwrap();
    let mut auth_data = sha256(rp_id.as_bytes());
    auth_data.push(0x01); // UP
    auth_data.extend_from_slice(&sign_count.to_be_bytes());

    let client_hash = sha256(&client_data_json);
    let signature: p256::ecdsa::Signature = {
        use p256::ecdsa::signature::Signer as _;
        signing_key.sign(&[auth_data.as_slice(), client_hash.as_slice()].concat())
    };
    let der = signature.to_der();

    (
        cose_from_signing_key(signing_key),
        json!({
            "id": b64(credential_id),
            "rawId": b64(credential_id),
            "response": {
                "authenticatorData": b64(&auth_data),
                "clientDataJSON": b64(&client_data_json),
                "signature": b64(der.as_bytes()),
                "userHandle": null,
            },
            "type": "public-key",
        }),
    )
}

/// 由 p256 私钥导出 ES256 COSE 公钥 CBOR 字节（kty=2, alg=-7, crv=1, x, y）。
fn cose_from_signing_key(signing_key: &p256::ecdsa::SigningKey) -> Vec<u8> {
    let point = signing_key.verifying_key().to_sec1_point(false);
    let x: &[u8] = &point.as_bytes()[1..33];
    let y: &[u8] = &point.as_bytes()[33..65];
    cbor_map(&[
        (cbor_int(1), cbor_int(2)),  // kty: EC2
        (cbor_int(3), cbor_int(-7)), // alg: ES256
        (cbor_int(-1), cbor_int(1)), // crv: P-256
        (cbor_int(-2), cbor_bytes(x)),
        (cbor_int(-3), cbor_bytes(y)),
    ])
}

async fn insert_passkey(fixture: &Fixture, user_id: i64, credential_id: &[u8], sign_count: i64) {
    sqlx::query(
        "INSERT INTO webauthn_credentials \
         (user_id, credential_id, public_key, sign_count, aaguid, transports, device_type, \
          backed_up, label, last_used_at, created_at) \
         VALUES (?, ?, ?, ?, ?, NULL, 'single_device', FALSE, '测试凭据', NULL, ?)",
    )
    .bind(user_id)
    .bind(credential_id)
    .bind(cose_es256())
    .bind(sign_count)
    .bind("11111111-1111-1111-1111-111111111111")
    .bind(Utc::now().naive_utc())
    .execute(&fixture.pool)
    .await
    .expect("插入 Passkey 失败");
}

// 用宏避免为 actix 的私有 Request 类型写泛型约束。
// 返回 (reply, challenge, flow)；flow 来自 begin 响应外层，finish 用它拼
// `webauthn_*_{flow}` 临时 Cookie 名，并发流程互不覆盖。
macro_rules! passkey_begin_macro {
    ($app:expr, $uri:expr, $cookies:expr) => {{
        let reply = send!($app, post_json_with($uri, &json!({}), $cookies));
        let reply = assert_status!(reply, StatusCode::OK);
        let body = reply.json();
        let challenge = body["publicKey"]["challenge"]
            .as_str()
            .expect("begin 响应缺少 challenge")
            .to_string();
        let flow = body["flow"]
            .as_str()
            .expect("begin 响应缺少 flow")
            .to_string();
        assert!(
            qbotmessager::auth::passkey::is_valid_flow(&flow),
            "flow 必须是 16 个小写 hex 字符：{flow}"
        );
        (reply, challenge, flow)
    }};
}

#[actix_web::test]
async fn passkey_register_stores_single_device() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let account = make_account(
        &fixture,
        "passkey",
        Some(PASSWORD),
        ROLE_USER,
        STATUS_ACTIVE,
    )
    .await;
    let token = token_for(&fixture, account.id).await;
    fixture.configure_webauthn();

    let (begin_reply, challenge, flow) = passkey_begin_macro!(
        app,
        "/api/auth/passkey/register/begin",
        &[("sid", token.as_str())]
    );
    assert_eq!(
        begin_reply.json()["publicKey"]["rp"]["id"],
        json!("passkey.example"),
        "{}",
        begin_reply.text()
    );
    assert_eq!(
        begin_reply.json()["publicKey"]["user"]["id"],
        json!(b64(account.id.to_string().as_bytes()))
    );
    let challenge_cookie = begin_reply
        .cookie(&passkey::cookie_name(passkey::CHALLENGE_COOKIE, &flow))
        .expect("缺少 webauthn_challenge");
    let user_cookie = begin_reply
        .cookie(&passkey::cookie_name(passkey::USER_COOKIE, &flow))
        .expect("缺少 webauthn_user");
    let state_cookie = begin_reply
        .cookie(&passkey::cookie_name(passkey::STATE_COOKIE, &flow))
        .expect("缺少 webauthn_state");
    assert_eq!(user_cookie, account.id.to_string());
    // 非 flow 后缀的旧 Cookie 名不应再签发。
    assert!(begin_reply.cookie("webauthn_challenge").is_none());

    let credential_id = format!("credential-1-{}", fixture.prefix).into_bytes();
    let credential = registration_credential(
        &challenge,
        "passkey.example",
        "https://passkey.example",
        &credential_id,
    );
    let finish = send!(
        app,
        post_json_with(
            "/api/auth/passkey/register/finish",
            &json!({"credential": credential, "flow": flow}),
            &[
                ("sid", token.as_str()),
                (
                    &passkey::cookie_name(passkey::CHALLENGE_COOKIE, &flow),
                    challenge_cookie.as_str()
                ),
                (
                    &passkey::cookie_name(passkey::USER_COOKIE, &flow),
                    user_cookie.as_str()
                ),
                (
                    &passkey::cookie_name(passkey::STATE_COOKIE, &flow),
                    state_cookie.as_str()
                ),
            ]
        )
    );
    let finish = assert_status!(finish, StatusCode::OK);
    assert_eq!(finish.json(), json!({"ok": true}));

    let row = sqlx::query(
        "SELECT credential_id, public_key, sign_count, aaguid, device_type, backed_up, label \
         FROM webauthn_credentials WHERE user_id = ?",
    )
    .bind(account.id)
    .fetch_one(&fixture.pool)
    .await
    .expect("凭据未落库");
    let stored_id: Vec<u8> = row.get("credential_id");
    assert_eq!(stored_id, credential_id);
    let public_key: Vec<u8> = row.get("public_key");
    assert_eq!(public_key, cose_es256());
    assert_eq!(row.get::<i64, _>("sign_count"), 0);
    assert_eq!(
        row.get::<Option<String>, _>("aaguid").as_deref(),
        Some("11111111-1111-1111-1111-111111111111")
    );
    let device_type: Option<String> = row.get("device_type");
    assert_eq!(device_type.as_deref(), Some("single_device"));
    assert!(device_type.unwrap().len() <= 32);
    assert!(!row.get::<bool, _>("backed_up"));
    assert_eq!(row.get::<String, _>("label"), "我的手机");

    let me = send!(app, get_with("/api/auth/me", &[("sid", token.as_str())]));
    assert_eq!(me.json()["passkey_count"], json!(1));

    let list = send!(
        app,
        get_with("/api/auth/passkey", &[("sid", token.as_str())])
    );
    let list = assert_status!(list, StatusCode::OK);
    let items = list.json();
    assert_eq!(items.as_array().unwrap().len(), 1);
    assert_eq!(items[0]["device_type"], json!("single_device"));
    assert_eq!(items[0]["label"], json!("我的手机"));
    assert_eq!(items[0]["backed_up"], json!(false));
}

#[actix_web::test]
async fn passkey_register_duplicate_and_delete() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let account = make_account(&fixture, "pkdup", Some(PASSWORD), ROLE_USER, STATUS_ACTIVE).await;
    let other = make_account(
        &fixture,
        "pkother",
        Some(PASSWORD),
        ROLE_USER,
        STATUS_ACTIVE,
    )
    .await;
    let token = token_for(&fixture, account.id).await;
    let other_token = token_for(&fixture, other.id).await;
    fixture.configure_webauthn();

    // 缺少 flow 对应的 webauthn_state Cookie 时拒绝。
    let missing = send!(
        app,
        post_json_with(
            "/api/auth/passkey/register/finish",
            &json!({"credential": {"id": "x"}, "flow": "0123456789abcdef"}),
            &[("sid", token.as_str())]
        )
    );
    let missing = assert_status!(missing, StatusCode::BAD_REQUEST);
    assert_eq!(missing.detail(), "注册会话已过期，请重试");

    // 缺少 flow 字段：serde 直接拒绝。
    let missing_flow = send!(
        app,
        post_json_with(
            "/api/auth/passkey/register/finish",
            &json!({"credential": {"id": "x"}}),
            &[("sid", token.as_str())]
        )
    );
    assert_status!(missing_flow, StatusCode::UNPROCESSABLE_ENTITY);

    let credential_id = format!("credential-dup-{}", fixture.prefix).into_bytes();
    let register =
        |challenge: String, flow: String, challenge_cookie: String, state_cookie: String| {
            let credential = registration_credential(
                &challenge,
                "passkey.example",
                "https://passkey.example",
                &credential_id,
            );
            post_json_with(
                "/api/auth/passkey/register/finish",
                &json!({"credential": credential, "flow": flow}),
                &[
                    ("sid", token.as_str()),
                    (
                        &passkey::cookie_name(passkey::CHALLENGE_COOKIE, &flow),
                        challenge_cookie.as_str(),
                    ),
                    (
                        &passkey::cookie_name(passkey::USER_COOKIE, &flow),
                        account.id.to_string().as_str(),
                    ),
                    (
                        &passkey::cookie_name(passkey::STATE_COOKIE, &flow),
                        state_cookie.as_str(),
                    ),
                ],
            )
        };

    let (first_begin, challenge, first_flow) = passkey_begin_macro!(
        app,
        "/api/auth/passkey/register/begin",
        &[("sid", token.as_str())]
    );
    let first = send!(
        app,
        register(
            challenge,
            first_flow.clone(),
            first_begin
                .cookie(&passkey::cookie_name(
                    passkey::CHALLENGE_COOKIE,
                    &first_flow
                ))
                .unwrap(),
            first_begin
                .cookie(&passkey::cookie_name(passkey::STATE_COOKIE, &first_flow))
                .unwrap()
        )
    );
    assert_status!(first, StatusCode::OK);

    let (second_begin, challenge, second_flow) = passkey_begin_macro!(
        app,
        "/api/auth/passkey/register/begin",
        &[("sid", token.as_str())]
    );
    let duplicate = send!(
        app,
        register(
            challenge,
            second_flow.clone(),
            second_begin
                .cookie(&passkey::cookie_name(
                    passkey::CHALLENGE_COOKIE,
                    &second_flow
                ))
                .unwrap(),
            second_begin
                .cookie(&passkey::cookie_name(passkey::STATE_COOKIE, &second_flow))
                .unwrap()
        )
    );
    let duplicate = assert_status!(duplicate, StatusCode::CONFLICT);
    assert_eq!(duplicate.detail(), "该 Passkey 已绑定");

    let list = send!(
        app,
        get_with("/api/auth/passkey", &[("sid", token.as_str())])
    );
    let id = list.json()[0]["id"].as_i64().unwrap();

    // 其他用户不能删除。
    let forbidden = send!(
        app,
        delete_with(
            &format!("/api/auth/passkey/{id}"),
            &[("sid", other_token.as_str())]
        )
    );
    assert_status!(forbidden, StatusCode::NOT_FOUND);

    let deleted = send!(
        app,
        delete_with(
            &format!("/api/auth/passkey/{id}"),
            &[("sid", token.as_str())]
        )
    );
    let deleted = assert_status!(deleted, StatusCode::OK);
    assert_eq!(deleted.json(), json!({"ok": true}));
    let count: i64 = sqlx::query_scalar(
        "SELECT CAST(COUNT(*) AS SIGNED) FROM webauthn_credentials WHERE user_id = ?",
    )
    .bind(account.id)
    .fetch_one(&fixture.pool)
    .await
    .unwrap();
    assert_eq!(count, 0);
}

#[actix_web::test]
async fn step_up_verification_refreshes_session() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let account = make_account(&fixture, "stepup", Some(PASSWORD), ROLE_USER, STATUS_ACTIVE).await;
    let token = token_for(&fixture, account.id).await;
    fixture.configure_webauthn();

    let fresh = send!(app, get_with("/api/auth/me", &[("sid", token.as_str())]));
    assert_eq!(fresh.json()["step_up_valid"], json!(true));

    expire_step_up(&fixture, &token).await;
    let stale = send!(app, get_with("/api/auth/me", &[("sid", token.as_str())]));
    assert_eq!(stale.json()["step_up_valid"], json!(false));

    let blocked = send!(
        app,
        post_json_with(
            "/api/auth/passkey/register/begin",
            &json!({}),
            &[("sid", token.as_str())]
        )
    );
    let blocked = assert_status!(blocked, StatusCode::FORBIDDEN);
    assert_eq!(blocked.detail(), "请重新验证身份后再操作");

    let wrong = send!(
        app,
        post_json_with(
            "/api/auth/me/verify",
            &json!({"password": "WrongPassw0rd!"}),
            &[("sid", token.as_str())]
        )
    );
    let wrong = assert_status!(wrong, StatusCode::BAD_REQUEST);
    assert_eq!(wrong.detail(), "当前密码错误");

    let verified = send!(
        app,
        post_json_with(
            "/api/auth/me/verify",
            &json!({"password": PASSWORD}),
            &[("sid", token.as_str())]
        )
    );
    assert_status!(verified, StatusCode::OK);
    let refreshed = send!(app, get_with("/api/auth/me", &[("sid", token.as_str())]));
    assert_eq!(refreshed.json()["step_up_valid"], json!(true));

    let begin = send!(
        app,
        post_json_with(
            "/api/auth/passkey/register/begin",
            &json!({}),
            &[("sid", token.as_str())]
        )
    );
    assert_status!(begin, StatusCode::OK);
}

#[actix_web::test]
async fn step_up_verification_is_rate_limited() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let account = make_account(
        &fixture,
        "steprate",
        Some(PASSWORD),
        ROLE_USER,
        STATUS_ACTIVE,
    )
    .await;
    let token = token_for(&fixture, account.id).await;

    for _ in 0..5 {
        let reply = send!(
            app,
            post_json_with(
                "/api/auth/me/verify",
                &json!({"password": "WrongPassw0rd!"}),
                &[("sid", token.as_str())]
            )
        );
        assert_status!(reply, StatusCode::BAD_REQUEST);
    }
    let limited = send!(
        app,
        post_json_with(
            "/api/auth/me/verify",
            &json!({"password": PASSWORD}),
            &[("sid", token.as_str())]
        )
    );
    let limited = assert_status!(limited, StatusCode::TOO_MANY_REQUESTS);
    assert!(
        limited.detail().contains("验证过于频繁"),
        "{}",
        limited.detail()
    );
}

#[actix_web::test]
async fn deleting_last_passkey_requires_another_login_method() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let account = make_account(&fixture, "pklast", None, ROLE_USER, STATUS_ACTIVE).await;
    let token = token_for(&fixture, account.id).await;
    let credential_id = format!("last-credential-{}", fixture.prefix).into_bytes();
    insert_passkey(&fixture, account.id, &credential_id, 0).await;
    let id: i64 =
        sqlx::query_scalar("SELECT id FROM webauthn_credentials WHERE user_id = ? LIMIT 1")
            .bind(account.id)
            .fetch_one(&fixture.pool)
            .await
            .unwrap();

    let blocked = send!(
        app,
        delete_with(
            &format!("/api/auth/passkey/{id}"),
            &[("sid", token.as_str())]
        )
    );
    let blocked = assert_status!(blocked, StatusCode::CONFLICT);
    assert!(
        blocked.detail().contains("登录方式"),
        "{}",
        blocked.detail()
    );

    // 设置密码后允许删除。
    let hash = passwords::hash_password_with("LastPassKeyPw!", b"test-salt-16byte", 1_000);
    sqlx::query("UPDATE users SET password_hash = ? WHERE id = ?")
        .bind(&hash)
        .bind(account.id)
        .execute(&fixture.pool)
        .await
        .unwrap();
    let deleted = send!(
        app,
        delete_with(
            &format!("/api/auth/passkey/{id}"),
            &[("sid", token.as_str())]
        )
    );
    assert_status!(deleted, StatusCode::OK);
}

#[actix_web::test]
async fn oauth_link_start_requires_step_up() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let account = make_account(
        &fixture,
        "oauthstep",
        Some(PASSWORD),
        ROLE_USER,
        STATUS_ACTIVE,
    )
    .await;
    let token = token_for(&fixture, account.id).await;
    let key = format!("{}-step", fixture.prefix);
    sqlx::query(
        "INSERT INTO oauth_providers (`key`, display_name, client_id, client_secret, \
         authorization_url, token_url, userinfo_url, scopes, email_field, id_field, \
         name_field, enabled, email_verified, created_at) \
         VALUES (?, 'Step', 'c', 'secret', 'https://example.com/authorize', \
         'https://example.com/token', 'https://example.com/userinfo', 's', \
         'email', 'id', 'name', TRUE, FALSE, ?)",
    )
    .bind(&key)
    .bind(Utc::now().naive_utc())
    .execute(&fixture.pool)
    .await
    .unwrap();

    expire_step_up(&fixture, &token).await;
    let blocked = send!(
        app,
        get_with(
            &format!("/api/auth/oauth/{key}/start"),
            &[("sid", token.as_str())]
        )
    );
    let blocked = assert_status!(blocked, StatusCode::FOUND);
    let location = blocked
        .headers
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    assert!(location.starts_with("/security?"), "{location}");

    let verified = send!(
        app,
        post_json_with(
            "/api/auth/me/verify",
            &json!({"password": PASSWORD}),
            &[("sid", token.as_str())]
        )
    );
    assert_status!(verified, StatusCode::OK);
    let start = send!(
        app,
        get_with(
            &format!("/api/auth/oauth/{key}/start"),
            &[("sid", token.as_str())]
        )
    );
    let start = assert_status!(start, StatusCode::FOUND);
    let location = start
        .headers
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    assert!(
        location.starts_with("https://example.com/authorize?"),
        "{location}"
    );
}

#[actix_web::test]
async fn passkey_login_rejects_unknown_and_rollback() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let account = make_account(
        &fixture,
        "pklogin",
        Some(PASSWORD),
        ROLE_USER,
        STATUS_ACTIVE,
    )
    .await;
    fixture.configure_webauthn();
    let stored_id = format!("stored-credential-{}", fixture.prefix).into_bytes();
    insert_passkey(&fixture, account.id, &stored_id, 5).await;

    // 未知凭据：401 且不进入签名校验。
    let (begin, challenge, flow) = passkey_begin_macro!(app, "/api/auth/passkey/login/begin", &[]);
    let unknown = assertion_credential(
        &challenge,
        "passkey.example",
        "https://passkey.example",
        b"unknown-cred",
        1,
    );
    let reply = send!(
        app,
        post_json_with(
            "/api/auth/passkey/login/finish",
            &json!({"credential": unknown, "flow": flow}),
            &[
                (
                    &passkey::cookie_name(passkey::CHALLENGE_COOKIE, &flow),
                    begin
                        .cookie(&passkey::cookie_name(passkey::CHALLENGE_COOKIE, &flow))
                        .unwrap()
                        .as_str()
                ),
                (
                    &passkey::cookie_name(passkey::STATE_COOKIE, &flow),
                    begin
                        .cookie(&passkey::cookie_name(passkey::STATE_COOKIE, &flow))
                        .unwrap()
                        .as_str()
                ),
            ]
        )
    );
    let reply = assert_status!(reply, StatusCode::UNAUTHORIZED);
    assert_eq!(reply.detail(), "该 Passkey 未绑定");

    // 签名计数回退：库内 5，断言 1。
    let (begin, challenge, flow) = passkey_begin_macro!(app, "/api/auth/passkey/login/begin", &[]);
    let rollback = assertion_credential(
        &challenge,
        "passkey.example",
        "https://passkey.example",
        &stored_id,
        1,
    );
    let reply = send!(
        app,
        post_json_with(
            "/api/auth/passkey/login/finish",
            &json!({"credential": rollback, "flow": flow}),
            &[
                (
                    &passkey::cookie_name(passkey::CHALLENGE_COOKIE, &flow),
                    begin
                        .cookie(&passkey::cookie_name(passkey::CHALLENGE_COOKIE, &flow))
                        .unwrap()
                        .as_str()
                ),
                (
                    &passkey::cookie_name(passkey::STATE_COOKIE, &flow),
                    begin
                        .cookie(&passkey::cookie_name(passkey::STATE_COOKIE, &flow))
                        .unwrap()
                        .as_str()
                ),
            ]
        )
    );
    let reply = assert_status!(reply, StatusCode::UNAUTHORIZED);
    assert_eq!(
        reply.detail(),
        "Passkey 校验失败：签名计数回退，凭据可能已被复制"
    );

    // challenge 不匹配。
    let (begin, _challenge, flow) = passkey_begin_macro!(app, "/api/auth/passkey/login/begin", &[]);
    let mismatch = assertion_credential(
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "passkey.example",
        "https://passkey.example",
        &stored_id,
        6,
    );
    let reply = send!(
        app,
        post_json_with(
            "/api/auth/passkey/login/finish",
            &json!({"credential": mismatch, "flow": flow}),
            &[
                (
                    &passkey::cookie_name(passkey::CHALLENGE_COOKIE, &flow),
                    begin
                        .cookie(&passkey::cookie_name(passkey::CHALLENGE_COOKIE, &flow))
                        .unwrap()
                        .as_str()
                ),
                (
                    &passkey::cookie_name(passkey::STATE_COOKIE, &flow),
                    begin
                        .cookie(&passkey::cookie_name(passkey::STATE_COOKIE, &flow))
                        .unwrap()
                        .as_str()
                ),
            ]
        )
    );
    let reply = assert_status!(reply, StatusCode::UNAUTHORIZED);
    assert_eq!(reply.detail(), "Passkey 校验失败：challenge 不匹配");

    // 缺少 flow 对应的 state Cookie。
    let reply = send!(
        app,
        post_json_with(
            "/api/auth/passkey/login/finish",
            &json!({"credential": {"id": "x"}, "flow": "0123456789abcdef"}),
            &[(
                &passkey::cookie_name(passkey::CHALLENGE_COOKIE, "0123456789abcdef"),
                "AAAA"
            )]
        )
    );
    let reply = assert_status!(reply, StatusCode::BAD_REQUEST);
    assert_eq!(reply.detail(), "登录会话已过期，请重试");
}

/// Passkey 登录成功全路径：真实 P-256 签名 → 下发会话 → 回写签名计数。
#[tokio::test]
async fn passkey_login_succeeds_with_real_signature() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let account = make_account(&fixture, "pkok", Some(PASSWORD), ROLE_USER, STATUS_ACTIVE).await;
    fixture.configure_webauthn();

    // 生成真实 P-256 密钥并把 COSE 公钥写入凭据表（计数 0：浏览器首登即此状态）。
    let signing_key =
        p256::ecdsa::SigningKey::from_slice(&sha256(format!("seed-{}", fixture.prefix).as_bytes()))
            .expect("构造 P-256 私钥失败");
    let public_key = cose_from_signing_key(&signing_key);
    let credential_id = format!("signed-cred-{}", fixture.prefix).into_bytes();
    sqlx::query(
        "INSERT INTO webauthn_credentials          (user_id, credential_id, public_key, sign_count, aaguid, transports, device_type,           backed_up, label, last_used_at, created_at)          VALUES (?, ?, ?, 0, '11111111-1111-1111-1111-111111111111', NULL, 'single_device',           FALSE, '测试凭据', NULL, ?)",
    )
    .bind(account.id)
    .bind(&credential_id)
    .bind(&public_key)
    .bind(Utc::now().naive_utc())
    .execute(&fixture.pool)
    .await
    .expect("插入签名凭据失败");

    let (begin, challenge, flow) = passkey_begin_macro!(app, "/api/auth/passkey/login/begin", &[]);
    let (_, credential) = signed_assertion_credential(
        &challenge,
        "passkey.example",
        "https://passkey.example",
        &credential_id,
        3,
        &signing_key,
    );
    let reply = send!(
        app,
        post_json_with(
            "/api/auth/passkey/login/finish",
            &json!({"credential": credential, "flow": flow}),
            &[
                (
                    &passkey::cookie_name(passkey::CHALLENGE_COOKIE, &flow),
                    begin
                        .cookie(&passkey::cookie_name(passkey::CHALLENGE_COOKIE, &flow))
                        .unwrap()
                        .as_str()
                ),
                (
                    &passkey::cookie_name(passkey::STATE_COOKIE, &flow),
                    begin
                        .cookie(&passkey::cookie_name(passkey::STATE_COOKIE, &flow))
                        .unwrap()
                        .as_str()
                ),
            ]
        )
    );
    let reply = assert_status!(reply, StatusCode::OK);
    assert_eq!(reply.json(), json!({"ok": true}));
    let sid = reply
        .cookie("__Host-sid")
        .expect("HTTPS 下登录成功必须下发 __Host-sid");
    assert!(!sid.is_empty());

    // 会话确实可用。
    let me = send!(
        app,
        get_with("/api/auth/me", &[("__Host-sid", sid.as_str())])
    );
    let me = assert_status!(me, StatusCode::OK);
    assert_eq!(me.json()["email"], json!(account.email));

    // 签名计数回写为断言值 3。
    let stored: (i64,) =
        sqlx::query_as("SELECT sign_count FROM webauthn_credentials WHERE user_id = ?")
            .bind(account.id)
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
    assert_eq!(stored.0, 3);

    // 当前 flow 的临时 Cookie 被清理（Max-Age=0 的删除指令）。
    for base in [passkey::CHALLENGE_COOKIE, passkey::STATE_COOKIE] {
        let line = reply
            .raw_cookie(&passkey::cookie_name(base, &flow))
            .expect("成功后应清除临时 Cookie");
        assert!(line.contains("Max-Age=0"), "Cookie 未被删除：{line}");
    }
}
