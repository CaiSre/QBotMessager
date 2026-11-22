//! 管理端集成测试。
//!
//! 覆盖范围：
//! - 统计接口（时区、平台分布）
//! - 通道与机器人的 QQ 主机白名单、通道凭据轮换
//! - 系统设置目录导出、持久化、校验与即时生效
//! - 用户管理（角色与状态保护、邀请码）与资源隔离
//! - OAuth 提供方 CRUD、密钥回显掩码、GitHub 预设
//! - 推送日志分页 / 过滤
//!
//! 驱动方式：`actix_web::test::init_service` + `TestRequest`，数据库为真实 MySQL。
//! 进程内只执行一次 `sqlx::migrate!`，并用全局互斥锁串行化测试：
//! `system_settings` 与登录失败计数是全局状态，测试之间不能并行改写。
//! 每个用例都使用随机前缀创建独立账号/资源，避免互相干扰。

mod common;

use std::fmt::Debug;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use actix_web::body::MessageBody;
use actix_web::dev::{Service, ServiceResponse};
use actix_web::http::header::{self, HeaderMap};
use actix_web::http::{Method, StatusCode};
use actix_web::test::{self, TestRequest};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE;
use chrono::{Duration as ChronoDuration, NaiveDateTime, Utc};
use qbotmessager::auth::{passwords, sessions};
use qbotmessager::config::Config;
use qbotmessager::db::models::{ROLE_SUPER_ADMIN, ROLE_USER, STATUS_ACTIVE, STATUS_DISABLED};
use qbotmessager::db::queries;
use qbotmessager::services::runtime_settings::RuntimeSettings;
use qbotmessager::state::AppState;
use serde_json::{Value, json};
use sqlx::mysql::{MySqlPool, MySqlPoolOptions};

/// 测试账号统一密码。
const PASSWORD: &str = "TestPassw0rd!";

/// 进程内串行化：运行期设置与登录限速器都是全局可变状态。
static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
/// 进程内只执行一次迁移，避免并发 DDL 冲突。
static MIGRATED: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();

fn database_url() -> String {
    let url = std::env::var("MYSQL_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| {
            "mysql://qbotmessager:testpw@127.0.0.1:13306/qbot_test_admin".to_string()
        });
    // 库名固定为本套件的库：与其它套件隔离，避免并跑时互相清库。
    common::with_database(&url, "qbot_test_admin")
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
        prefix: format!("admin{}", uuid::Uuid::new_v4().simple()),
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

fn get_with(uri: &str, cookies: &[(&str, &str)]) -> TestRequest {
    request(Method::GET, uri, None, cookies)
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

fn cookies(token: &str) -> Vec<(&str, &str)> {
    vec![("sid", token)]
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

async fn make_user(fixture: &Fixture, label: &str) -> (Account, String) {
    let account = make_account(fixture, label, Some(PASSWORD), ROLE_USER, STATUS_ACTIVE).await;
    let token = token_for(fixture, account.id).await;
    (account, token)
}

/// 与 `src/crypto.rs::mask_secret` 相同的掩码规则（保留首尾各 2 位）。
fn mask_expected(value: &str) -> String {
    if value.is_empty() {
        return String::new();
    }
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= 8 {
        return "*".repeat(chars.len());
    }
    let head: String = chars[..2].iter().collect();
    let tail: String = chars[chars.len() - 2..].iter().collect();
    format!("{head}{}{tail}", "*".repeat(6))
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

/// 插入一条推送日志，返回主键。
async fn insert_push_log(
    fixture: &Fixture,
    owner_id: i64,
    platform: &str,
    status: &str,
    content_preview: &str,
    request_id: &str,
    created_at: NaiveDateTime,
) -> i64 {
    let (error_code, error_message) = if status == "failed" {
        (Some("50012"), Some("机器人已被移除"))
    } else {
        (None, None)
    };
    sqlx::query(
        "INSERT INTO push_logs (owner_user_id, platform, source_msgtype, target, \
         content_preview, content_len, status, error_code, error_message, duration_ms, \
         request_id, created_at) VALUES (?, ?, 'text', ?, ?, ?, ?, ?, ?, 12.5, ?, ?)",
    )
    .bind(owner_id)
    .bind(platform)
    .bind(format!("user:{request_id}"))
    .bind(content_preview)
    .bind(content_preview.chars().count() as i32)
    .bind(status)
    .bind(error_code)
    .bind(error_message)
    .bind(request_id)
    .bind(created_at)
    .execute(&fixture.pool)
    .await
    .expect("插入推送日志失败")
    .last_insert_id() as i64
}

// --------------------------------------------------------------------------- 权限

#[actix_web::test]
async fn requires_login_returns_401() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());

    for uri in [
        "/api/admin/bot-profiles",
        "/api/admin/channels",
        "/api/admin/logs",
        "/api/admin/users",
        "/api/admin/invites",
        "/api/admin/oauth-providers",
        "/api/admin/settings",
        "/api/admin/stats",
    ] {
        let reply = send!(app, request(Method::GET, uri, None, &[]));
        let reply = assert_status!(reply, StatusCode::UNAUTHORIZED);
        assert_eq!(reply.detail(), "未登录", "{uri}");
    }

    let reply = send!(
        app,
        request(
            Method::POST,
            "/api/admin/invites",
            Some(&json!({"max_uses": 1})),
            &[]
        )
    );
    assert_status!(reply, StatusCode::UNAUTHORIZED);

    let reply = send!(
        app,
        get_with("/api/admin/bot-profiles", &[("sid", "bad-token")])
    );
    let reply = assert_status!(reply, StatusCode::UNAUTHORIZED);
    assert_eq!(reply.detail(), "未登录");
}

#[actix_web::test]
async fn non_super_admin_is_scoped_and_forbidden() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let (user, token) = make_user(&fixture, "scope").await;
    let auth = cookies(&token);

    // 资源端点可用，但只见自己的数据。
    let bots = send!(app, get_with("/api/admin/bot-profiles", &auth));
    let bots = assert_status!(bots, StatusCode::OK);
    assert_eq!(bots.json(), json!([]));

    let channels = send!(app, get_with("/api/admin/channels", &auth));
    assert_status!(channels, StatusCode::OK);

    let logs = send!(app, get_with("/api/admin/logs", &auth));
    let logs = assert_status!(logs, StatusCode::OK);
    assert_eq!(logs.json()["total"], json!(0));
    assert_eq!(logs.json()["items"], json!([]));

    let own = send!(
        app,
        post_json_with(
            "/api/admin/bot-profiles",
            &json!({"name": "x", "qq_appid": "1", "qq_app_secret": "s"}),
            &auth
        )
    );
    let own = assert_status!(own, StatusCode::CREATED);
    let own_id = own.json()["id"].as_i64().unwrap();
    let list = send!(app, get_with("/api/admin/bot-profiles", &auth));
    let list = assert_status!(list, StatusCode::OK);
    assert_eq!(list.json()[0]["id"], json!(own_id));
    assert_eq!(list.json()[0]["owner_email"], json!(user.email));

    // 超管专属端点一律 403。
    for uri in [
        "/api/admin/users",
        "/api/admin/invites",
        "/api/admin/oauth-providers",
        "/api/admin/settings",
    ] {
        let reply = send!(app, get_with(uri, &auth));
        let reply = assert_status!(reply, StatusCode::FORBIDDEN);
        assert_eq!(reply.detail(), "仅超级管理员可操作", "{uri}");
    }

    let patch = send!(
        app,
        patch_json_with(
            "/api/admin/settings",
            &json!({"register_enabled": false}),
            &auth
        )
    );
    let patch = assert_status!(patch, StatusCode::FORBIDDEN);
    assert_eq!(patch.detail(), "仅超级管理员可操作");

    let create_invite = send!(
        app,
        post_json_with("/api/admin/invites", &json!({"max_uses": 1}), &auth)
    );
    assert_status!(create_invite, StatusCode::FORBIDDEN);

    let revoke = send!(app, delete_with("/api/admin/invites/1", &auth));
    assert_status!(revoke, StatusCode::FORBIDDEN);

    let create_provider = send!(
        app,
        post_json_with(
            "/api/admin/oauth-providers",
            &json!({
                "key": "x",
                "display_name": "x",
                "client_id": "x",
                "client_secret": "x",
                "authorization_url": "https://x.example/auth",
                "token_url": "https://x.example/token",
                "userinfo_url": "https://x.example/me",
            }),
            &auth
        )
    );
    assert_status!(create_provider, StatusCode::FORBIDDEN);

    // 统计对普通用户开放，但只统计自己。
    let stats = send!(app, get_with("/api/admin/stats", &auth));
    let stats = assert_status!(stats, StatusCode::OK);
    assert_eq!(stats.json()["scope"], json!("mine"));

    // 停用账号的会话被拒绝。
    let disabled = make_account(
        &fixture,
        "disabled",
        Some(PASSWORD),
        ROLE_USER,
        STATUS_DISABLED,
    )
    .await;
    let disabled_token = token_for(&fixture, disabled.id).await;
    let reply = send!(
        app,
        get_with("/api/admin/bot-profiles", &cookies(&disabled_token))
    );
    let reply = assert_status!(reply, StatusCode::FORBIDDEN);
    assert_eq!(reply.detail(), "账号已停用");
}

// ------------------------------------------------------------------------- 机器人

#[actix_web::test]
async fn bot_create_validates_qq_host_allowlist() {
    // 与 test_create_bot_rejects_qq_host_outside_allowlist
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let (_user, token) = make_user(&fixture, "host").await;
    let auth = cookies(&token);

    let ok = send!(
        app,
        post_json_with(
            "/api/admin/bot-profiles",
            &json!({
                "name": "白名单机器人",
                "qq_appid": "102000002",
                "qq_app_secret": "s",
                "qq_host": "https://api.bot.qq.com",
            }),
            &auth
        )
    );
    let ok = assert_status!(ok, StatusCode::CREATED);
    assert!(ok.json()["id"].as_i64().unwrap() > 0);

    let bad_host = send!(
        app,
        post_json_with(
            "/api/admin/bot-profiles",
            &json!({
                "name": "白名单机器人",
                "qq_appid": "102000002",
                "qq_app_secret": "s",
                "qq_host": "https://169.254.169.254",
            }),
            &auth
        )
    );
    let bad_host = assert_status!(bad_host, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(bad_host.detail(), "QQ 接口地址不在允许的主机列表中");

    let bad_scheme = send!(
        app,
        post_json_with(
            "/api/admin/bot-profiles",
            &json!({
                "name": "x",
                "qq_appid": "1",
                "qq_app_secret": "s",
                "qq_host": "http://api.bot.qq.com",
            }),
            &auth
        )
    );
    let bad_scheme = assert_status!(bad_scheme, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        bad_scheme.detail(),
        "QQ 接口地址必须是以 https:// 开头的完整地址"
    );

    let empty_name = send!(
        app,
        post_json_with(
            "/api/admin/bot-profiles",
            &json!({"name": "", "qq_appid": "1", "qq_app_secret": "s"}),
            &auth
        )
    );
    let empty_name = assert_status!(empty_name, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(empty_name.detail(), "名称至少 1 个字符");

    let too_many = (0..51).map(|index| format!("u{index}")).collect::<Vec<_>>();
    let too_many = send!(
        app,
        post_json_with(
            "/api/admin/bot-profiles",
            &json!({
                "name": "x",
                "qq_appid": "1",
                "qq_app_secret": "s",
                "default_openids": too_many,
            }),
            &auth
        )
    );
    let too_many = assert_status!(too_many, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(too_many.detail(), "默认目标最多 50 个");

    // 只有第一个请求成功。
    let list = send!(app, get_with("/api/admin/bot-profiles", &auth));
    let list = assert_status!(list, StatusCode::OK);
    assert_eq!(list.json().as_array().unwrap().len(), 1);
}

#[actix_web::test]
async fn bot_profile_crud_and_secret_masking() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let (user, token) = make_user(&fixture, "botcrud").await;
    let auth = cookies(&token);

    let plaintext = "super-secret-value-1234";
    let created = send!(
        app,
        post_json_with(
            "/api/admin/bot-profiles",
            &json!({
                "name": "主机器人",
                "qq_appid": "102000001",
                "qq_app_secret": plaintext,
                "default_openids": [" u1 ", "", "u2"],
                "default_group_openid": "g1",
            }),
            &auth
        )
    );
    let created = assert_status!(created, StatusCode::CREATED);
    let bot_id = created.json()["id"].as_i64().unwrap();

    let list = send!(app, get_with("/api/admin/bot-profiles", &auth));
    let list = assert_status!(list, StatusCode::OK);
    let item = &list.json()[0];
    assert_eq!(item["id"], json!(bot_id));
    assert_eq!(item["owner_email"], json!(user.email));
    assert_eq!(item["qq_appid"], json!("102000001"));
    assert_eq!(item["qq_host"], json!("https://api.bot.qq.com"));
    assert_eq!(item["default_openids"], json!(["u1", "u2"]));
    assert_eq!(item["default_group_openid"], json!("g1"));
    assert_eq!(item["enabled"], json!(true));
    assert_eq!(item["has_secret"], json!(true));

    let stored: String = sqlx::query_scalar("SELECT qq_app_secret FROM bot_profiles WHERE id = ?")
        .bind(bot_id)
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
    assert!(stored.starts_with("enc1:"), "{stored}");
    assert!(!stored.contains(plaintext));
    let masked = mask_expected(&stored);
    assert_eq!(item["qq_app_secret_masked"], json!(masked));
    assert!(!list.text().contains(plaintext), "列表不得回显明文密钥");

    // 修改：名称、密钥、主机（带尾斜杠应被规范化）、目标与启用状态。
    let patched = send!(
        app,
        patch_json_with(
            &format!("/api/admin/bot-profiles/{bot_id}"),
            &json!({
                "name": "改过的机器人",
                "qq_app_secret": "rotated-secret-abcdef",
                "qq_host": "https://api.bot.qq.com/",
                "default_openids": ["x"],
                "default_group_openid": "",
                "enabled": false,
            }),
            &auth
        )
    );
    let patched = assert_status!(patched, StatusCode::OK);
    assert_eq!(patched.json(), json!({"id": bot_id}));

    let list = send!(app, get_with("/api/admin/bot-profiles", &auth));
    let list = assert_status!(list, StatusCode::OK);
    let item = &list.json()[0];
    assert_eq!(item["name"], json!("改过的机器人"));
    assert_eq!(item["qq_host"], json!("https://api.bot.qq.com"));
    assert_eq!(item["default_openids"], json!(["x"]));
    assert_eq!(item["default_group_openid"], Value::Null);
    assert_eq!(item["enabled"], json!(false));
    let stored_after: String =
        sqlx::query_scalar("SELECT qq_app_secret FROM bot_profiles WHERE id = ?")
            .bind(bot_id)
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
    assert!(stored_after.starts_with("enc1:"));
    assert_ne!(stored_after, stored);
    assert_eq!(
        item["qq_app_secret_masked"],
        json!(mask_expected(&stored_after))
    );

    // 空串清空密钥。
    let cleared = send!(
        app,
        patch_json_with(
            &format!("/api/admin/bot-profiles/{bot_id}"),
            &json!({"qq_app_secret": ""}),
            &auth
        )
    );
    assert_status!(cleared, StatusCode::OK);
    let list = send!(app, get_with("/api/admin/bot-profiles", &auth));
    let item = &list.json()[0];
    assert_eq!(item["qq_app_secret_masked"], json!(""));
    assert_eq!(item["has_secret"], json!(false));

    let deleted = send!(
        app,
        delete_with(&format!("/api/admin/bot-profiles/{bot_id}"), &auth)
    );
    let deleted = assert_status!(deleted, StatusCode::OK);
    assert_eq!(deleted.json(), json!({"ok": true}));

    let list = send!(app, get_with("/api/admin/bot-profiles", &auth));
    assert_eq!(list.json(), json!([]));

    let missing = send!(
        app,
        delete_with(&format!("/api/admin/bot-profiles/{bot_id}"), &auth)
    );
    let missing = assert_status!(missing, StatusCode::NOT_FOUND);
    assert_eq!(missing.detail(), "机器人配置不存在");
}

#[actix_web::test]
async fn bot_ownership_isolation() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let (admin, admin_token) = make_admin(&fixture, "botadmin").await;
    let (user, user_token) = make_user(&fixture, "botuser").await;

    let admin_bot = send!(
        app,
        post_json_with(
            "/api/admin/bot-profiles",
            &json!({"name": "管理员机器人", "qq_appid": "1", "qq_app_secret": "s"}),
            &cookies(&admin_token)
        )
    );
    let admin_bot = assert_status!(admin_bot, StatusCode::CREATED).json()["id"]
        .as_i64()
        .unwrap();

    let user_bot = send!(
        app,
        post_json_with(
            "/api/admin/bot-profiles",
            &json!({"name": "用户机器人", "qq_appid": "2", "qq_app_secret": "s"}),
            &cookies(&user_token)
        )
    );
    let user_bot = assert_status!(user_bot, StatusCode::CREATED).json()["id"]
        .as_i64()
        .unwrap();

    // 普通用户看不到、也改不了他人的机器人。
    let list = send!(
        app,
        get_with("/api/admin/bot-profiles", &cookies(&user_token))
    );
    let list = assert_status!(list, StatusCode::OK);
    assert_eq!(
        list.json(),
        json!([{
            "id": user_bot,
            "owner_user_id": user.id,
            "owner_email": user.email,
            "name": "用户机器人",
            "qq_appid": "2",
            "qq_app_secret_masked": mask_expected(
                &sqlx::query_scalar::<_, String>("SELECT qq_app_secret FROM bot_profiles WHERE id = ?")
                    .bind(user_bot)
                    .fetch_one(&fixture.pool)
                    .await
                    .unwrap()
            ),
            "has_secret": true,
            "qq_host": "https://api.bot.qq.com",
            "default_openids": [],
            "default_group_openid": null,
            "enabled": true,
        }])
    );

    let hijack = send!(
        app,
        patch_json_with(
            &format!("/api/admin/bot-profiles/{admin_bot}"),
            &json!({"name": "hijack"}),
            &cookies(&user_token)
        )
    );
    let hijack = assert_status!(hijack, StatusCode::NOT_FOUND);
    assert_eq!(hijack.detail(), "机器人配置不存在");

    let remove = send!(
        app,
        delete_with(
            &format!("/api/admin/bot-profiles/{admin_bot}"),
            &cookies(&user_token)
        )
    );
    assert_status!(remove, StatusCode::NOT_FOUND);

    // 超级管理员可见全部用户资源。
    let all = send!(
        app,
        get_with("/api/admin/bot-profiles", &cookies(&admin_token))
    );
    let all = assert_status!(all, StatusCode::OK);
    let rows = all.json();
    let find = |id: i64| {
        rows.as_array()
            .unwrap()
            .iter()
            .find(|row| row["id"] == json!(id))
            .cloned()
            .unwrap_or_else(|| panic!("管理员列表缺少机器人 {id}"))
    };
    assert_eq!(find(admin_bot)["owner_email"], json!(admin.email));
    assert_eq!(find(user_bot)["owner_email"], json!(user.email));

    let stats = send!(app, get_with("/api/admin/stats", &cookies(&admin_token)));
    assert_eq!(
        assert_status!(stats, StatusCode::OK).json()["scope"],
        json!("all")
    );
}

// ------------------------------------------------------------------------- 通道

#[actix_web::test]
async fn channel_crud_rotate_and_secret() {
    // 以及 test_admin_api.py 中的通道 CRUD 契约
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let (_user, token) = make_user(&fixture, "channel").await;
    let auth = cookies(&token);

    let bot = send!(
        app,
        post_json_with(
            "/api/admin/bot-profiles",
            &json!({"name": "通道机器人", "qq_appid": "1", "qq_app_secret": "s"}),
            &auth
        )
    );
    let bot_id = assert_status!(bot, StatusCode::CREATED).json()["id"]
        .as_i64()
        .unwrap();

    let dingtalk = send!(
        app,
        post_json_with(
            "/api/admin/channels",
            &json!({"platform": "dingtalk", "bot_profile_id": bot_id}),
            &auth
        )
    );
    let dingtalk = assert_status!(dingtalk, StatusCode::CREATED).json();
    let dingtalk_id = dingtalk["id"].as_i64().unwrap();
    let dingtalk_token = dingtalk["webhook_token"].as_str().unwrap().to_string();
    assert_eq!(dingtalk_token.len(), 32);
    assert!(dingtalk.get("secret").is_none());

    let list = send!(app, get_with("/api/admin/channels", &auth));
    let list = assert_status!(list, StatusCode::OK);
    let item = &list.json()[0];
    assert_eq!(item["id"], json!(dingtalk_id));
    assert_eq!(item["platform"], json!("dingtalk"));
    assert_eq!(item["bot_profile_id"], json!(bot_id));
    assert_eq!(item["webhook_token"], json!(dingtalk_token));
    assert_eq!(item["has_secret"], json!(false));
    assert_eq!(item["enabled"], json!(true));
    let url = item["webhook_url"].as_str().unwrap();
    assert!(url.ends_with("/webhook/dingtalk"), "{url}");
    assert!(!url.contains(&dingtalk_token));

    let patched = send!(
        app,
        patch_json_with(
            &format!("/api/admin/channels/{dingtalk_id}"),
            &json!({"enabled": false}),
            &auth
        )
    );
    let patched = assert_status!(patched, StatusCode::OK);
    assert_eq!(patched.json(), json!({"id": dingtalk_id, "enabled": false}));
    let list = send!(app, get_with("/api/admin/channels", &auth));
    assert_eq!(list.json()[0]["enabled"], json!(false));

    let rotated = send!(
        app,
        post_json_with(
            &format!("/api/admin/channels/{dingtalk_id}/rotate"),
            &json!({}),
            &auth
        )
    );
    let rotated = assert_status!(rotated, StatusCode::OK).json();
    let new_token = rotated["webhook_token"].as_str().unwrap();
    assert_ne!(new_token, dingtalk_token);
    assert_eq!(new_token.len(), 32);
    assert!(rotated.get("secret").is_none());

    // GitHub 通道：创建时生成签名密钥，轮换时 token 与 secret 一起变化。
    let github = send!(
        app,
        post_json_with(
            "/api/admin/channels",
            &json!({"platform": "github", "bot_profile_id": bot_id}),
            &auth
        )
    );
    let github = assert_status!(github, StatusCode::CREATED).json();
    let github_id = github["id"].as_i64().unwrap();
    let github_token = github["webhook_token"].as_str().unwrap().to_string();
    let github_secret = github["secret"].as_str().unwrap().to_string();
    assert!(!github_secret.is_empty());
    assert!(
        github["webhook_url"]
            .as_str()
            .unwrap()
            .ends_with(&format!("/webhook/github/{github_token}"))
    );

    let stored_extra: Value = sqlx::query_scalar("SELECT extra FROM channels WHERE id = ?")
        .bind(github_id)
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
    let secret_cipher = stored_extra["secret_cipher"].as_str().unwrap();
    assert!(secret_cipher.starts_with("enc1:"));
    assert!(!secret_cipher.contains(&github_secret));

    let github_rotated = send!(
        app,
        post_json_with(
            &format!("/api/admin/channels/{github_id}/rotate"),
            &json!({}),
            &auth
        )
    );
    let github_rotated = assert_status!(github_rotated, StatusCode::OK).json();
    assert_ne!(
        github_rotated["webhook_token"].as_str().unwrap(),
        github_token
    );
    assert_ne!(github_rotated["secret"].as_str().unwrap(), github_secret);

    // 非法平台与越权操作。
    let bad_platform = send!(
        app,
        post_json_with(
            "/api/admin/channels",
            &json!({"platform": "slack", "bot_profile_id": bot_id}),
            &auth
        )
    );
    let bad_platform = assert_status!(bad_platform, StatusCode::BAD_REQUEST);
    assert_eq!(bad_platform.detail(), "平台不受支持");

    let (_other, other_token) = make_user(&fixture, "channelother").await;
    let other_auth = cookies(&other_token);
    let foreign_create = send!(
        app,
        post_json_with(
            "/api/admin/channels",
            &json!({"platform": "dingtalk", "bot_profile_id": bot_id}),
            &other_auth
        )
    );
    let foreign_create = assert_status!(foreign_create, StatusCode::NOT_FOUND);
    assert_eq!(foreign_create.detail(), "机器人配置不存在");

    let foreign_patch = send!(
        app,
        patch_json_with(
            &format!("/api/admin/channels/{dingtalk_id}"),
            &json!({"enabled": true}),
            &other_auth
        )
    );
    let foreign_patch = assert_status!(foreign_patch, StatusCode::NOT_FOUND);
    assert_eq!(foreign_patch.detail(), "通道不存在");

    let deleted = send!(
        app,
        delete_with(&format!("/api/admin/channels/{dingtalk_id}"), &auth)
    );
    assert_eq!(
        assert_status!(deleted, StatusCode::OK).json(),
        json!({"ok": true})
    );
    let list = send!(app, get_with("/api/admin/channels", &auth));
    let rows = list.json();
    assert!(
        rows.as_array()
            .unwrap()
            .iter()
            .all(|row| row["id"] != json!(dingtalk_id))
    );
}

// ------------------------------------------------------------------------- 日志

#[actix_web::test]
async fn logs_pagination_and_filters() {
    // test_failure_returns_502_and_logs_error 的读取侧）
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let (owner, owner_token) = make_user(&fixture, "logs").await;
    let auth = cookies(&owner_token);
    let (other, other_token) = make_user(&fixture, "logsother").await;

    let keyword = format!("{}-kw", fixture.prefix);
    let now = Utc::now().naive_utc();
    let mut ids = Vec::new();
    for index in 0..25 {
        let platform = if index % 2 == 0 { "dingtalk" } else { "wecom" };
        let status = if index % 2 == 0 { "success" } else { "failed" };
        let preview = if index % 5 == 0 {
            format!("{keyword}-{index}")
        } else {
            format!("{}-plain-{index}", fixture.prefix)
        };
        let request_id = format!("{}-log-{index}", fixture.prefix);
        ids.push(
            insert_push_log(
                &fixture,
                owner.id,
                platform,
                status,
                &preview,
                &request_id,
                now - ChronoDuration::seconds(index as i64),
            )
            .await,
        );
    }

    // 默认分页。
    let first = send!(app, get_with("/api/admin/logs", &auth));
    let first = assert_status!(first, StatusCode::OK).json();
    assert_eq!(first["total"], json!(25));
    assert_eq!(first["page"], json!(1));
    assert_eq!(first["page_size"], json!(20));
    assert_eq!(first["items"].as_array().unwrap().len(), 20);
    let first_item = &first["items"][0];
    assert_eq!(first_item["owner_email"], json!(owner.email));
    assert_eq!(first_item["platform"], json!("dingtalk"));
    assert_eq!(first_item["status"], json!("success"));
    assert_eq!(
        first_item["target"],
        json!(format!("user:{}-log-24", fixture.prefix))
    );
    assert!(first_item["created_at"].as_str().is_some());
    assert_eq!(first_item["duration_ms"], json!(12.5));

    // 分页边界。
    let page_two = send!(app, get_with("/api/admin/logs?page=2&page_size=10", &auth));
    let page_two = assert_status!(page_two, StatusCode::OK).json();
    assert_eq!(page_two["page"], json!(2));
    assert_eq!(page_two["page_size"], json!(10));
    assert_eq!(page_two["items"].as_array().unwrap().len(), 10);
    let page_three = send!(app, get_with("/api/admin/logs?page=3&page_size=10", &auth));
    let page_three = assert_status!(page_three, StatusCode::OK).json();
    assert_eq!(page_three["items"].as_array().unwrap().len(), 5);

    // 平台、状态、关键词过滤。
    let dingtalk = send!(app, get_with("/api/admin/logs?platform=dingtalk", &auth));
    let dingtalk = assert_status!(dingtalk, StatusCode::OK).json();
    assert_eq!(dingtalk["total"], json!(13));
    assert!(
        dingtalk["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["platform"] == json!("dingtalk"))
    );

    let failed = send!(app, get_with("/api/admin/logs?status=failed", &auth));
    let failed = assert_status!(failed, StatusCode::OK).json();
    assert_eq!(failed["total"], json!(12));
    assert_eq!(failed["items"][0]["error_code"], json!("50012"));

    let keyword_rows = send!(
        app,
        get_with(&format!("/api/admin/logs?keyword={keyword}"), &auth)
    );
    let keyword_rows = assert_status!(keyword_rows, StatusCode::OK).json();
    assert_eq!(keyword_rows["total"], json!(5));

    let combined = send!(
        app,
        get_with("/api/admin/logs?platform=wecom&status=failed", &auth)
    );
    let combined = assert_status!(combined, StatusCode::OK).json();
    assert_eq!(combined["total"], json!(12));

    // 非法分页参数。
    for query in [
        "page=0",
        "page=abc",
        "page_size=0",
        "page_size=201",
        "page_size=abc",
    ] {
        let reply = send!(app, get_with(&format!("/api/admin/logs?{query}"), &auth));
        let reply = assert_status!(reply, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(!reply.detail().is_empty(), "{query}");
    }

    // 超管按关键词可见全部用户的日志。
    let (_admin, admin_token) = make_admin(&fixture, "logsadmin").await;
    let super_rows = send!(
        app,
        get_with(
            &format!("/api/admin/logs?keyword={keyword}"),
            &cookies(&admin_token)
        )
    );
    let super_rows = assert_status!(super_rows, StatusCode::OK).json();
    assert_eq!(super_rows["total"], json!(5));

    // 详情：本人可读，他人 404。
    let detail_id = ids[7];
    let detail = send!(
        app,
        get_with(&format!("/api/admin/logs/{detail_id}"), &auth)
    );
    let detail = assert_status!(detail, StatusCode::OK).json();
    assert_eq!(detail["id"], json!(detail_id));
    assert_eq!(detail["owner_email"], json!(owner.email));
    assert_eq!(
        detail["request_id"],
        json!(format!("{}-log-7", fixture.prefix))
    );

    let foreign = send!(
        app,
        get_with(
            &format!("/api/admin/logs/{detail_id}"),
            &cookies(&other_token)
        )
    );
    let foreign = assert_status!(foreign, StatusCode::NOT_FOUND);
    assert_eq!(foreign.detail(), "日志不存在");

    let ghost = send!(app, get_with("/api/admin/logs/999999999", &auth));
    let ghost = assert_status!(ghost, StatusCode::NOT_FOUND);
    assert_eq!(ghost.detail(), "日志不存在");

    // 他人的日志不出现在自己的列表里。
    insert_push_log(
        &fixture,
        other.id,
        "feishu",
        "success",
        &format!("{}-other", fixture.prefix),
        &format!("{}-other-log", fixture.prefix),
        now,
    )
    .await;
    let own = send!(app, get_with("/api/admin/logs", &auth));
    let own = assert_status!(own, StatusCode::OK).json();
    assert_eq!(own["total"], json!(25));
    let other_scope = send!(app, get_with("/api/admin/logs", &cookies(&other_token)));
    let other_scope = assert_status!(other_scope, StatusCode::OK).json();
    assert_eq!(other_scope["total"], json!(1));
}

// ------------------------------------------------------------------------- 用户

#[actix_web::test]
async fn users_list_and_patch() {
    // 与 test_super_admin_cannot_change_own_role_or_status
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let (admin, admin_token) = make_admin(&fixture, "useradmin").await;
    let auth = cookies(&admin_token);
    let target = make_account(&fixture, "target", None, ROLE_USER, STATUS_ACTIVE).await;
    let duplicate = make_account(&fixture, "dup", None, ROLE_USER, STATUS_ACTIVE).await;

    let users = send!(app, get_with("/api/admin/users", &auth));
    let users = assert_status!(users, StatusCode::OK).json();
    let row = users
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == json!(target.id))
        .expect("用户列表缺少目标账号");
    assert_eq!(row["email"], json!(target.email));
    assert_eq!(row["name"], json!(target.name));
    assert_eq!(row["role"], json!(ROLE_USER));
    assert_eq!(row["status"], json!(STATUS_ACTIVE));
    assert_eq!(row["last_login_at"], Value::Null);

    let renamed = format!("{}-renamed", fixture.prefix);
    let ok = send!(
        app,
        patch_json_with(
            &format!("/api/admin/users/{}", target.id),
            &json!({"name": renamed}),
            &auth
        )
    );
    let ok = assert_status!(ok, StatusCode::OK);
    assert_eq!(ok.json(), json!({"id": target.id}));

    let users = send!(app, get_with("/api/admin/users", &auth));
    let users = users.json();
    let row = users
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == json!(target.id))
        .unwrap();
    assert_eq!(row["name"], json!(renamed));

    // 用户名忽略大小写唯一。
    let conflict = send!(
        app,
        patch_json_with(
            &format!("/api/admin/users/{}", duplicate.id),
            &json!({"name": renamed.to_uppercase()}),
            &auth
        )
    );
    let conflict = assert_status!(conflict, StatusCode::CONFLICT);
    assert_eq!(conflict.detail(), "该用户名已被使用");

    // 不能修改自己的角色/状态。
    let self_role = send!(
        app,
        patch_json_with(
            &format!("/api/admin/users/{}", admin.id),
            &json!({"role": ROLE_USER}),
            &auth
        )
    );
    let self_role = assert_status!(self_role, StatusCode::BAD_REQUEST);
    assert_eq!(self_role.detail(), "不能修改自己的角色");

    let self_status = send!(
        app,
        patch_json_with(
            &format!("/api/admin/users/{}", admin.id),
            &json!({"status": STATUS_DISABLED}),
            &auth
        )
    );
    let self_status = assert_status!(self_status, StatusCode::BAD_REQUEST);
    assert_eq!(self_status.detail(), "不能修改自己的账号状态");

    // 非法角色/状态。
    let bad_role = send!(
        app,
        patch_json_with(
            &format!("/api/admin/users/{}", target.id),
            &json!({"role": "root"}),
            &auth
        )
    );
    let bad_role = assert_status!(bad_role, StatusCode::BAD_REQUEST);
    assert_eq!(bad_role.detail(), "角色非法");

    let bad_status = send!(
        app,
        patch_json_with(
            &format!("/api/admin/users/{}", target.id),
            &json!({"status": "gone"}),
            &auth
        )
    );
    let bad_status = assert_status!(bad_status, StatusCode::BAD_REQUEST);
    assert_eq!(bad_status.detail(), "状态非法");

    let missing = send!(
        app,
        patch_json_with("/api/admin/users/999999999", &json!({"name": "x"}), &auth)
    );
    let missing = assert_status!(missing, StatusCode::NOT_FOUND);
    assert_eq!(missing.detail(), "用户不存在");

    // 停用后该账号的既有会话立即失效。
    let target_token = token_for(&fixture, target.id).await;
    let disable = send!(
        app,
        patch_json_with(
            &format!("/api/admin/users/{}", target.id),
            &json!({"status": STATUS_DISABLED}),
            &auth
        )
    );
    assert_status!(disable, StatusCode::OK);
    let blocked = send!(
        app,
        get_with("/api/admin/bot-profiles", &cookies(&target_token))
    );
    let blocked = assert_status!(blocked, StatusCode::FORBIDDEN);
    assert_eq!(blocked.detail(), "账号已停用");
}

// ----------------------------------------------------------------------- 邀请码

#[actix_web::test]
async fn invites_crud_and_validation() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let (_admin, admin_token) = make_admin(&fixture, "inviteadmin").await;
    let auth = cookies(&admin_token);

    let created = send!(
        app,
        post_json_with(
            "/api/admin/invites",
            &json!({"max_uses": 2, "expires_in_days": 7, "email": "User@Example.com"}),
            &auth
        )
    );
    let created = assert_status!(created, StatusCode::CREATED).json();
    let invite_id = created["id"].as_i64().unwrap();
    let code = created["code"].as_str().unwrap().to_string();
    assert_eq!(code.len(), 22);
    assert!(created["expires_at"].as_str().unwrap().ends_with("+00:00"));
    assert!(created.get("role").is_none());

    let list = send!(app, get_with("/api/admin/invites", &auth));
    let list = assert_status!(list, StatusCode::OK).json();
    let row = list
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == json!(invite_id))
        .expect("邀请码列表缺少刚创建的项");
    assert_eq!(row["code"], json!(code));
    assert_eq!(row["email"], json!("user@example.com"));
    assert_eq!(row["max_uses"], json!(2));
    assert_eq!(row["used_count"], json!(0));
    assert_eq!(row["revoked"], json!(false));
    assert!(row["created_at"].as_str().is_some());

    let revoked = send!(
        app,
        delete_with(&format!("/api/admin/invites/{invite_id}"), &auth)
    );
    let revoked = assert_status!(revoked, StatusCode::OK);
    assert_eq!(revoked.json(), json!({"ok": true}));

    let list = send!(app, get_with("/api/admin/invites", &auth));
    let list = list.json();
    let row = list
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == json!(invite_id))
        .unwrap();
    assert_eq!(row["revoked"], json!(true));

    let missing = send!(app, delete_with("/api/admin/invites/999999999", &auth));
    let missing = assert_status!(missing, StatusCode::NOT_FOUND);
    assert_eq!(missing.detail(), "邀请码不存在");

    for (body, fragment) in [
        (json!({"max_uses": 0}), "max_uses"),
        (json!({"max_uses": 101}), "max_uses"),
        (json!({"expires_in_days": 0}), "expires_in_days"),
        (json!({"expires_in_days": 366}), "expires_in_days"),
    ] {
        let reply = send!(app, post_json_with("/api/admin/invites", &body, &auth));
        let reply = assert_status!(reply, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            reply.detail().contains(fragment),
            "{}：{}",
            body,
            reply.detail()
        );
    }
}

// ------------------------------------------------------------------ OAuth 提供方

#[actix_web::test]
async fn oauth_provider_crud_and_secret_masking() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let (_admin, admin_token) = make_admin(&fixture, "oauthadmin").await;
    let auth = cookies(&admin_token);

    let plaintext = "demo-client-secret-xyz";
    let key = format!("demo{}", fixture.prefix);
    let created = send!(
        app,
        post_json_with(
            "/api/admin/oauth-providers",
            &json!({
                "key": key,
                "display_name": "演示提供方",
                "client_id": "demo-client-id",
                "client_secret": plaintext,
                "authorization_url": "https://demo.example.com/authorize",
                "token_url": "https://demo.example.com/token",
                "userinfo_url": "https://demo.example.com/userinfo",
            }),
            &auth
        )
    );
    let created = assert_status!(created, StatusCode::CREATED).json();
    let provider_id = created["id"].as_i64().unwrap();
    assert_eq!(created["key"], json!(key));
    assert!(created.get("client_secret").is_none());

    let list = send!(app, get_with("/api/admin/oauth-providers", &auth));
    let list = assert_status!(list, StatusCode::OK);
    let rows = list.json();
    let row = rows
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == json!(provider_id))
        .expect("提供方列表缺少刚创建的项")
        .clone();
    assert_eq!(row["key"], json!(key));
    assert_eq!(row["display_name"], json!("演示提供方"));
    assert_eq!(row["client_id"], json!("demo-client-id"));
    assert_eq!(row["email_verified"], json!(false));
    assert_eq!(row["enabled"], json!(true));
    assert_eq!(row["email_field"], json!("email"));
    assert_eq!(row["id_field"], json!("id"));
    assert_eq!(row["name_field"], json!("name"));
    assert_eq!(row["scopes"], json!(""));
    assert!(!list.text().contains(plaintext), "列表不得回显明文密钥");

    let stored: String =
        sqlx::query_scalar("SELECT client_secret FROM oauth_providers WHERE id = ?")
            .bind(provider_id)
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
    assert!(stored.starts_with("enc1:"), "{stored}");
    assert!(!stored.contains(plaintext));
    assert_eq!(row["client_secret_masked"], json!(mask_expected(&stored)));

    // 重复 key。
    let duplicate = send!(
        app,
        post_json_with(
            "/api/admin/oauth-providers",
            &json!({
                "key": key,
                "display_name": "x",
                "client_id": "x",
                "client_secret": "x",
                "authorization_url": "https://x.example/auth",
                "token_url": "https://x.example/token",
                "userinfo_url": "https://x.example/me",
            }),
            &auth
        )
    );
    let duplicate = assert_status!(duplicate, StatusCode::CONFLICT);
    assert_eq!(duplicate.detail(), "提供方已存在");

    // URL 必填且仅允许 https。
    let empty_url = send!(
        app,
        post_json_with(
            "/api/admin/oauth-providers",
            &json!({
                "key": "nourl",
                "display_name": "x",
                "client_id": "x",
                "client_secret": "x",
            }),
            &auth
        )
    );
    let empty_url = assert_status!(empty_url, StatusCode::BAD_REQUEST);
    assert_eq!(empty_url.detail(), "authorization_url 不能为空");

    let http_url = send!(
        app,
        post_json_with(
            "/api/admin/oauth-providers",
            &json!({
                "key": "httpurl",
                "display_name": "x",
                "client_id": "x",
                "client_secret": "x",
                "authorization_url": "http://evil.example/auth",
                "token_url": "https://x.example/token",
                "userinfo_url": "https://x.example/me",
            }),
            &auth
        )
    );
    let http_url = assert_status!(http_url, StatusCode::BAD_REQUEST);
    assert_eq!(
        http_url.detail(),
        "提供方 URL 必须为 https（本地开发可用 localhost）"
    );

    // 修改：密钥重新加密，邮箱可信度可切换。
    let new_secret = "rotated-client-secret";
    let patched = send!(
        app,
        patch_json_with(
            &format!("/api/admin/oauth-providers/{provider_id}"),
            &json!({
                "display_name": "改名提供方",
                "client_secret": new_secret,
                "email_verified": true,
            }),
            &auth
        )
    );
    let patched = assert_status!(patched, StatusCode::OK);
    assert_eq!(patched.json(), json!({"id": provider_id}));

    let list = send!(app, get_with("/api/admin/oauth-providers", &auth));
    let rows = list.json();
    let row = rows
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == json!(provider_id))
        .unwrap();
    assert_eq!(row["display_name"], json!("改名提供方"));
    assert_eq!(row["email_verified"], json!(true));
    let stored_after: String =
        sqlx::query_scalar("SELECT client_secret FROM oauth_providers WHERE id = ?")
            .bind(provider_id)
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
    assert!(stored_after.starts_with("enc1:"));
    assert_ne!(stored_after, stored);
    assert!(!stored_after.contains(new_secret));
    assert_eq!(
        row["client_secret_masked"],
        json!(mask_expected(&stored_after))
    );

    let bad_patch = send!(
        app,
        patch_json_with(
            &format!("/api/admin/oauth-providers/{provider_id}"),
            &json!({"authorization_url": "http://evil.example/auth"}),
            &auth
        )
    );
    let bad_patch = assert_status!(bad_patch, StatusCode::BAD_REQUEST);
    assert_eq!(
        bad_patch.detail(),
        "提供方 URL 必须为 https（本地开发可用 localhost）"
    );

    // PATCH 传空串同样是非法值，不得把已有 https URL 清空落库。
    let empty_patch = send!(
        app,
        patch_json_with(
            &format!("/api/admin/oauth-providers/{provider_id}"),
            &json!({"authorization_url": ""}),
            &auth
        )
    );
    let empty_patch = assert_status!(empty_patch, StatusCode::BAD_REQUEST);
    assert_eq!(empty_patch.detail(), "authorization_url 不能为空");

    let missing = send!(
        app,
        patch_json_with(
            "/api/admin/oauth-providers/999999999",
            &json!({"display_name": "x"}),
            &auth
        )
    );
    let missing = assert_status!(missing, StatusCode::NOT_FOUND);
    assert_eq!(missing.detail(), "提供方不存在");

    let deleted = send!(
        app,
        delete_with(&format!("/api/admin/oauth-providers/{provider_id}"), &auth)
    );
    assert_eq!(
        assert_status!(deleted, StatusCode::OK).json(),
        json!({"ok": true})
    );
    let list = send!(app, get_with("/api/admin/oauth-providers", &auth));
    assert!(
        list.json()
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["id"] != json!(provider_id))
    );

    let missing_delete = send!(
        app,
        delete_with("/api/admin/oauth-providers/999999999", &auth)
    );
    let missing_delete = assert_status!(missing_delete, StatusCode::NOT_FOUND);
    assert_eq!(missing_delete.detail(), "提供方不存在");
}

#[actix_web::test]
async fn oauth_github_preset_defaults_unverified_email() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let (_admin, admin_token) = make_admin(&fixture, "ghadmin").await;
    let auth = cookies(&admin_token);
    let custom_key = format!("custom{}", fixture.prefix);
    // 预设要求 key 必须为 github；清理历史运行可能留下的同名提供方。
    sqlx::query("DELETE FROM oauth_providers WHERE `key` = 'github'")
        .execute(&fixture.pool)
        .await
        .expect("清理 GitHub 提供方失败");

    let custom = send!(
        app,
        post_json_with(
            "/api/admin/oauth-providers",
            &json!({
                "key": custom_key,
                "display_name": "自定义",
                "client_id": "custom-id",
                "client_secret": "custom-secret",
                "authorization_url": "https://custom.example/authorize",
                "token_url": "https://custom.example/token",
                "userinfo_url": "https://custom.example/userinfo",
            }),
            &auth
        )
    );
    assert_status!(custom, StatusCode::CREATED);

    let github = send!(
        app,
        post_json_with(
            "/api/admin/oauth-providers",
            &json!({
                "key": "github",
                "display_name": "GitHub",
                "client_id": "gh-client-id",
                "client_secret": "gh-client-secret",
                "use_github_preset": true,
            }),
            &auth
        )
    );
    let github = assert_status!(github, StatusCode::CREATED).json();
    let github_id = github["id"].as_i64().unwrap();

    let list = send!(app, get_with("/api/admin/oauth-providers", &auth));
    let rows = list.json();
    let github_row = rows
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["key"] == json!("github"))
        .unwrap();
    assert_eq!(github_row["email_verified"], json!(false));
    assert_eq!(
        github_row["authorization_url"],
        json!("https://github.com/login/oauth/authorize")
    );
    assert_eq!(
        github_row["token_url"],
        json!("https://github.com/login/oauth/access_token")
    );
    assert_eq!(
        github_row["userinfo_url"],
        json!("https://api.github.com/user")
    );
    assert_eq!(github_row["scopes"], json!("read:user user:email"));

    let custom_row = rows
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["key"] == json!(custom_key))
        .unwrap();
    assert_eq!(custom_row["email_verified"], json!(false));

    // 显式关闭时保留关闭。
    let deleted = send!(
        app,
        delete_with(&format!("/api/admin/oauth-providers/{github_id}"), &auth)
    );
    assert_status!(deleted, StatusCode::OK);
    let github_off = send!(
        app,
        post_json_with(
            "/api/admin/oauth-providers",
            &json!({
                "key": "github",
                "display_name": "GitHub",
                "client_id": "gh-client-id-2",
                "client_secret": "gh-client-secret-2",
                "use_github_preset": true,
                "email_verified": false,
            }),
            &auth
        )
    );
    assert_status!(github_off, StatusCode::CREATED);
    let list = send!(app, get_with("/api/admin/oauth-providers", &auth));
    let rows = list.json();
    let github_row = rows
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["key"] == json!("github"))
        .unwrap();
    assert_eq!(github_row["email_verified"], json!(false));
}

// ------------------------------------------------------------------- 系统设置

#[actix_web::test]
async fn settings_catalog_patch_and_secret() {
    // 与 test_settings_patch_persists_and_returns、test_settings_reload_from_database
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let (_admin, admin_token) = make_admin(&fixture, "setadmin").await;
    let auth = cookies(&admin_token);

    let payload = send!(app, get_with("/api/admin/settings", &auth));
    let payload = assert_status!(payload, StatusCode::OK).json();
    let qps = find_setting(&payload, "qq_qps");
    assert_eq!(qps["kind"], json!("int"));
    assert_eq!(qps["value"], json!(5));
    assert_eq!(qps["source"], json!("default"));
    let log_level = find_setting(&payload, "log_level");
    assert_eq!(log_level["kind"], json!("select"));
    assert_eq!(log_level["options"][0], json!("DEBUG"));
    assert_eq!(log_level["default"], json!("INFO"));
    assert_eq!(
        find_setting(&payload, "smtp_password")["secret"],
        json!(true)
    );

    let plaintext = "smtp-secret-pass-123";
    let patched = send!(
        app,
        patch_json_with(
            "/api/admin/settings",
            &json!({
                "qq_qps": 9,
                "log_level": "DEBUG",
                "webhook_allow_query_token": true,
                "smtp_password": plaintext,
            }),
            &auth
        )
    );
    let patched = assert_status!(patched, StatusCode::OK);
    assert!(
        !patched.text().contains(plaintext),
        "设置响应不得回显明文密码"
    );
    let patched = patched.json();
    let qps = find_setting(&patched, "qq_qps");
    assert_eq!(qps["value"], json!(9));
    assert_eq!(qps["source"], json!("database"));
    assert_eq!(find_setting(&patched, "log_level")["value"], json!("DEBUG"));
    assert_eq!(
        find_setting(&patched, "webhook_allow_query_token")["value"],
        json!(true)
    );
    let smtp = find_setting(&patched, "smtp_password");
    assert_eq!(smtp["value"], json!(""));
    assert_eq!(smtp["secret"], json!(true));
    assert_eq!(smtp["has_value"], json!(true));
    assert_eq!(smtp["source"], json!("database"));

    let stored_qps: String =
        sqlx::query_scalar("SELECT `value` FROM system_settings WHERE `key` = 'qq_qps'")
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
    assert_eq!(stored_qps, "9");
    let stored_smtp: String =
        sqlx::query_scalar("SELECT `value` FROM system_settings WHERE `key` = 'smtp_password'")
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
    assert!(stored_smtp.starts_with("enc1:"), "{stored_smtp}");
    assert!(!stored_smtp.contains(plaintext));

    // 新建一个 RuntimeSettings 从库中重新装载，取值应即时生效。
    let mut reloaded = RuntimeSettings::new(Some(fixture.fernet_key.clone()));
    reloaded
        .load(&fixture.pool)
        .await
        .expect("重新加载设置失败");
    assert_eq!(reloaded.get("qq_qps").unwrap().as_i64(), 9);
    assert_eq!(reloaded.get("log_level").unwrap().as_str(), "DEBUG");
    assert_eq!(reloaded.get("smtp_password").unwrap().as_str(), plaintext);
    assert_eq!(reloaded.source_of("qq_qps").as_str(), "database");
}

#[actix_web::test]
async fn settings_env_seed_imports_non_default() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;

    sqlx::query("DELETE FROM system_settings WHERE `key` = 'public_base_url'")
        .execute(&fixture.pool)
        .await
        .expect("清理旧设置失败");
    // 测试串行执行（持有 TEST_LOCK），此处修改进程环境变量不会与其他用例并发。
    unsafe {
        std::env::set_var("PUBLIC_BASE_URL", "https://env-seed.example");
    }
    let mut runtime = RuntimeSettings::new(Some(fixture.fernet_key.clone()));
    let loaded = runtime.load(&fixture.pool).await;
    unsafe {
        std::env::remove_var("PUBLIC_BASE_URL");
    }
    loaded.expect("环境变量导入设置失败");

    assert_eq!(runtime.public_base_url(), "https://env-seed.example");
    assert_eq!(runtime.source_of("public_base_url").as_str(), "environment");
    let stored: String =
        sqlx::query_scalar("SELECT `value` FROM system_settings WHERE `key` = 'public_base_url'")
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
    assert_eq!(stored, "https://env-seed.example");
}

#[actix_web::test]
async fn settings_invalid_values_are_rejected() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let (_admin, admin_token) = make_admin(&fixture, "setbad").await;
    let auth = cookies(&admin_token);

    let cases = [
        json!({"qq_qps": 0}),
        json!({"log_level": "TRACE"}),
        json!({"session_ttl_hours": "abc"}),
        json!({"unknown_key": 1}),
        json!({"qq_min_interval": 61}),
        json!({"rp_name": "x".repeat(129)}),
    ];
    for body in cases {
        let reply = send!(app, patch_json_with("/api/admin/settings", &body, &auth));
        let reply = assert_status!(reply, StatusCode::BAD_REQUEST);
        assert!(!reply.detail().is_empty(), "{body}");
        assert!(reply.json().get("detail").is_some());
    }

    let unknown = send!(
        app,
        patch_json_with("/api/admin/settings", &json!({"unknown_key": 1}), &auth)
    );
    let unknown = assert_status!(unknown, StatusCode::BAD_REQUEST);
    assert!(
        unknown.detail().contains("未知设置项"),
        "{}",
        unknown.detail()
    );
}

#[actix_web::test]
async fn settings_public_base_url_applies_immediately() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let (_admin, admin_token) = make_admin(&fixture, "baseadmin").await;
    let auth = cookies(&admin_token);

    let patched = send!(
        app,
        patch_json_with(
            "/api/admin/settings",
            &json!({"public_base_url": "https://push.example.com/"}),
            &auth
        )
    );
    assert_status!(patched, StatusCode::OK);

    let (_user, user_token) = make_user(&fixture, "baseuser").await;
    let user_auth = cookies(&user_token);
    let bot = send!(
        app,
        post_json_with(
            "/api/admin/bot-profiles",
            &json!({"name": "x", "qq_appid": "1", "qq_app_secret": "s"}),
            &user_auth
        )
    );
    let bot_id = assert_status!(bot, StatusCode::CREATED).json()["id"]
        .as_i64()
        .unwrap();
    let channel = send!(
        app,
        post_json_with(
            "/api/admin/channels",
            &json!({"platform": "dingtalk", "bot_profile_id": bot_id}),
            &user_auth
        )
    );
    assert_status!(channel, StatusCode::CREATED);
    let github = send!(
        app,
        post_json_with(
            "/api/admin/channels",
            &json!({"platform": "github", "bot_profile_id": bot_id}),
            &user_auth
        )
    );
    let github = assert_status!(github, StatusCode::CREATED).json();
    let github_token = github["webhook_token"].as_str().unwrap().to_string();

    let channels = send!(app, get_with("/api/admin/channels", &user_auth));
    let channels = assert_status!(channels, StatusCode::OK).json();
    let rows = channels.as_array().unwrap();
    assert_eq!(rows.len(), 2);
    let dingtalk_row = rows
        .iter()
        .find(|row| row["platform"] == json!("dingtalk"))
        .unwrap();
    assert_eq!(
        dingtalk_row["webhook_url"],
        json!("https://push.example.com/webhook/dingtalk")
    );
    let github_row = rows
        .iter()
        .find(|row| row["platform"] == json!("github"))
        .unwrap();
    assert_eq!(
        github_row["webhook_url"],
        json!(format!(
            "https://push.example.com/webhook/github/{github_token}"
        ))
    );
}

#[actix_web::test]
async fn settings_login_limiter_applies_immediately() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let (_admin, admin_token) = make_admin(&fixture, "limitadmin").await;
    let auth = cookies(&admin_token);

    let patched = send!(
        app,
        patch_json_with(
            "/api/admin/settings",
            &json!({"login_max_failures": 1, "login_window_seconds": 60}),
            &auth
        )
    );
    assert_status!(patched, StatusCode::OK);

    let account = make_account(
        &fixture,
        "limited",
        Some(PASSWORD),
        ROLE_USER,
        STATUS_ACTIVE,
    )
    .await;
    let wrong = json!({"account": account.email, "password": "WrongPassw0rd!"});

    let first = send!(
        app,
        request(Method::POST, "/api/auth/login", Some(&wrong), &[])
    );
    let first = assert_status!(first, StatusCode::UNAUTHORIZED);
    assert_eq!(first.detail(), "用户名或密码错误");

    let second = send!(
        app,
        request(Method::POST, "/api/auth/login", Some(&wrong), &[])
    );
    let second = assert_status!(second, StatusCode::TOO_MANY_REQUESTS);
    assert!(
        second.detail().contains("尝试过于频繁"),
        "{}",
        second.detail()
    );
    let retry_after = second
        .headers
        .get(header::RETRY_AFTER)
        .expect("429 必须带 Retry-After")
        .to_str()
        .unwrap()
        .parse::<u64>()
        .expect("Retry-After 必须是数字");
    assert!(retry_after > 0);
}

// ----------------------------------------------------------------------- 统计

#[actix_web::test]
async fn stats_today_follows_timezone_and_trend() {
    // `_local_midnight_utc` 是私有函数，改为通过 HTTP + UTC 时区验证边界行为。
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    fixture.apply_settings(json!({"timezone": "UTC"}));

    let (owner, owner_token) = make_user(&fixture, "stats").await;
    let auth = cookies(&owner_token);
    let (other, _other_token) = make_user(&fixture, "statsother").await;

    let today = Utc::now().date_naive();
    let midnight = today.and_hms_opt(0, 0, 0).expect("合法零点");
    let before = insert_push_log(
        &fixture,
        owner.id,
        "dingtalk",
        "success",
        "本地昨天",
        &format!("{}-before", fixture.prefix),
        midnight - ChronoDuration::seconds(1),
    )
    .await;
    let after_success = insert_push_log(
        &fixture,
        owner.id,
        "dingtalk",
        "success",
        "本地今天成功",
        &format!("{}-after-ok", fixture.prefix),
        midnight + ChronoDuration::seconds(1),
    )
    .await;
    let after_failed = insert_push_log(
        &fixture,
        owner.id,
        "wecom",
        "failed",
        "本地今天失败",
        &format!("{}-after-fail", fixture.prefix),
        midnight + ChronoDuration::seconds(2),
    )
    .await;
    // 其他用户今天的日志不应计入。
    insert_push_log(
        &fixture,
        other.id,
        "feishu",
        "success",
        "别人的今天",
        &format!("{}-other", fixture.prefix),
        midnight + ChronoDuration::seconds(3),
    )
    .await;

    let stats = send!(app, get_with("/api/admin/stats", &auth));
    let stats = assert_status!(stats, StatusCode::OK).json();
    assert_eq!(stats["scope"], json!("mine"));
    assert_eq!(stats["today"]["total"], json!(2));
    assert_eq!(stats["today"]["success"], json!(1));
    assert_eq!(stats["success_rate"], json!(0.5));

    let platforms = stats["by_platform"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            (
                row["platform"].as_str().unwrap().to_string(),
                row["count"].as_i64().unwrap(),
            )
        })
        .collect::<Vec<_>>();
    assert!(
        platforms.contains(&("dingtalk".to_string(), 1)),
        "{platforms:?}"
    );
    assert!(
        platforms.contains(&("wecom".to_string(), 1)),
        "{platforms:?}"
    );
    assert_eq!(platforms.len(), 2);

    let failures = stats["recent_failures"].as_array().unwrap();
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0]["id"], json!(after_failed));
    assert_eq!(failures[0]["platform"], json!("wecom"));
    assert_eq!(failures[0]["error_code"], json!("50012"));
    assert_eq!(failures[0]["error_message"], json!("机器人已被移除"));

    let trend = stats["trend"].as_array().unwrap();
    assert_eq!(trend.len(), 7);
    let expected_dates = (0..7)
        .rev()
        .map(|offset| {
            (today - ChronoDuration::days(offset))
                .format("%Y-%m-%d")
                .to_string()
        })
        .collect::<Vec<_>>();
    let dates = trend
        .iter()
        .map(|row| row["date"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    assert_eq!(dates, expected_dates);
    let counts = trend
        .iter()
        .map(|row| row["count"].as_i64().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(counts, vec![0, 0, 0, 0, 0, 1, 2]);

    // 未使用的日志 id 仅用于确保插入成功。
    assert!(before > 0 && after_success > 0);

    let (_admin, admin_token) = make_admin(&fixture, "statsadmin").await;
    let all = send!(app, get_with("/api/admin/stats", &cookies(&admin_token)));
    let all = assert_status!(all, StatusCode::OK).json();
    assert_eq!(all["scope"], json!("all"));
    assert!(all["today"]["total"].as_i64().unwrap() >= 2);
}

// --------------------------------------------------------------------------- 超管保护

/// 两个超管并发互踢（A 降 B、B 降 A）时，事务先锁全部启用超管行再评估
/// 「除目标外还有超管」，两个事务在同行集上串行：先提交者胜出，后者基于
/// 已提交的新状态重新评估而拒绝，系统始终保留一个启用超管。
#[tokio::test]
async fn concurrent_super_admin_demotion_keeps_one_admin() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;

    // 清空残留超管构造封闭世界；本套件各测试均自建管理员，不受影响。
    sqlx::query("UPDATE users SET role = ? WHERE role = ?")
        .bind(ROLE_USER)
        .bind(ROLE_SUPER_ADMIN)
        .execute(&fixture.pool)
        .await
        .expect("清空残留超管失败");

    let account_a = make_account(
        &fixture,
        "kick-a",
        Some(PASSWORD),
        ROLE_SUPER_ADMIN,
        STATUS_ACTIVE,
    )
    .await;
    let account_b = make_account(
        &fixture,
        "kick-b",
        Some(PASSWORD),
        ROLE_SUPER_ADMIN,
        STATUS_ACTIVE,
    )
    .await;
    let admin_a = queries::users::find_by_id(&fixture.pool, account_a.id)
        .await
        .expect("查询超管 A 失败")
        .expect("超管 A 缺失");
    let admin_b = queries::users::find_by_id(&fixture.pool, account_b.id)
        .await
        .expect("查询超管 B 失败")
        .expect("超管 B 缺失");

    // A 降 B，B 降 A：审查发现的互踢并发。任一事务提交前，双方各自都能
    // 观察到「除目标外还有另一个超管」，无条件 UPDATE 将双双通过。
    let mut joins = Vec::new();
    for (actor, target_id) in [
        (admin_a.clone(), account_b.id),
        (admin_b.clone(), account_a.id),
    ] {
        let pool = fixture.pool.clone();
        joins.push(tokio::spawn(async move {
            qbotmessager::services::users::admin_update_user(
                &pool,
                &actor,
                target_id,
                qbotmessager::services::users::AdminUserPatch {
                    role: Some(ROLE_USER),
                    status: None,
                    name: None,
                },
                None,
            )
            .await
        }));
    }
    let mut succeeded = 0usize;
    for join in joins {
        if join.await.expect("降级任务 panic").is_ok() {
            succeeded += 1;
        }
    }

    let active_super: Vec<i64> =
        sqlx::query_scalar("SELECT id FROM users WHERE role = ? AND status = ?")
            .bind(ROLE_SUPER_ADMIN)
            .bind(STATUS_ACTIVE)
            .fetch_all(&fixture.pool)
            .await
            .expect("查询超管失败");
    assert_eq!(active_super.len(), 1, "互踢后必须仍有一个启用超管");
    assert_eq!(succeeded, 1, "两个并发降级至多一个成功");
}
