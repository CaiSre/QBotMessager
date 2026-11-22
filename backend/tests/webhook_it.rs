//! Webhook / Markdown 渲染 / 消息体转换集成测试。
//!
//! 覆盖范围：通道鉴权与投递去重、四平台适配器解析、Markdown 清洗与
//! 渲染降级、推送日志写入与频控。
//!
//! 驱动方式：`actix_web::test::init_service` + `TestRequest`，数据库为真实 MySQL。
//! 出站 QQ 请求改为本进程内的 Actix mock（`127.0.0.1:0`），机器人 `qq_host`
//! 直接指向 mock，从而不触达真实 QQ 接口。进程内只执行一次 `sqlx::migrate!`，
//! 并用全局互斥锁串行化数据库 / 运行期设置相关用例；每个用例使用随机前缀。
//!
//! 队列去重键存于 MySQL `jobs.idempotency_key`（varchar(36)），为 SHA-256
//! 十六进制的前 36 位。

mod common;

use std::collections::HashMap;
use std::fmt::Debug;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration as StdDuration;

use actix_web::body::MessageBody;
use actix_web::dev::{ServerHandle, Service, ServiceResponse};
use actix_web::http::header;
use actix_web::http::{Method, StatusCode};
use actix_web::test::{self, TestRequest};
use actix_web::{App, HttpServer, web};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE;
use chrono::Utc;
use hmac::{Hmac, Mac};
use qbotmessager::adapters::{
    Adapter, AdapterError, DingTalkAdapter, FMT_MARKDOWN, FMT_TEXT, FeishuAdapter, GitHubAdapter,
    UnifiedMessage, WeComAdapter,
};
use qbotmessager::auth::sessions;
use qbotmessager::config::Config;
use qbotmessager::crypto::encrypt_secret;
use qbotmessager::db::queries;
use qbotmessager::markdown::{degrade_tables, sanitize_markdown, sanitize_text};
use qbotmessager::renderer::{MSG_TYPE_MARKDOWN, MSG_TYPE_TEXT, render_qq, render_qq_with_limits};
use qbotmessager::services::push::PushJob;
use qbotmessager::services::queue::{PushQueue, dedupe_key};
use qbotmessager::services::runtime_settings::RuntimeSettings;
use qbotmessager::state::AppState;
use serde_json::{Value, json};
use sha2::Sha256;
use sqlx::mysql::{MySqlPool, MySqlPoolOptions};

/// 进程内串行化：运行期设置与队列内容都是共享状态。
static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
/// 进程内只执行一次迁移，避免并发 DDL 冲突。
static MIGRATED: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();

fn database_url() -> String {
    let url = std::env::var("MYSQL_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| {
            "mysql://qbotmessager:testpw@127.0.0.1:13306/qbot_test_webhook".to_string()
        });
    // 库名固定为本套件的库：与其它套件隔离，避免并跑时互相清库。
    common::with_database(&url, "qbot_test_webhook")
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

// ----------------------------------------------------------------------- mock QQ

#[derive(Debug, Clone)]
struct MockCall {
    target: String,
    body: Value,
}

#[derive(Debug, Clone)]
struct MockFailure {
    code: String,
    message: String,
}

#[derive(Default)]
struct MockQqState {
    calls: Mutex<Vec<MockCall>>,
    failures: Mutex<HashMap<String, MockFailure>>,
    token_calls: AtomicUsize,
}

impl MockQqState {
    fn calls(&self) -> Vec<MockCall> {
        self.calls.lock().unwrap().clone()
    }

    fn fail(&self, target: &str, code: &str, message: &str) {
        self.failures.lock().unwrap().insert(
            target.to_string(),
            MockFailure {
                code: code.to_string(),
                message: message.to_string(),
            },
        );
    }
}

/// 本进程内的 QQ 接口替身。
struct MockQq {
    base_url: String,
    state: Arc<MockQqState>,
    handle: Option<ServerHandle>,
}

impl MockQq {
    fn start() -> Self {
        let listener =
            std::net::TcpListener::bind(("127.0.0.1", 0)).expect("绑定 mock QQ 端口失败");
        let addr = listener.local_addr().expect("读取 mock QQ 地址失败");
        let state = Arc::new(MockQqState::default());
        let factory_state = state.clone();
        let server = HttpServer::new(move || {
            App::new()
                .app_data(web::Data::from(factory_state.clone()))
                .route("/app/getAppAccessToken", web::post().to(mock_token))
                .route("/v2/{kind}/{id}/messages", web::post().to(mock_message))
        })
        .workers(1)
        .listen(listener)
        .expect("启动 mock QQ 服务失败")
        .run();
        let handle = server.handle();
        actix_web::rt::spawn(server);
        Self {
            base_url: format!("http://{addr}"),
            state,
            handle: Some(handle),
        }
    }

    fn calls(&self) -> Vec<MockCall> {
        self.state.calls()
    }

    fn fail(&self, target: &str, code: &str, message: &str) {
        self.state.fail(target, code, message);
    }
}

impl Drop for MockQq {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            // 命令在调用时同步发出，返回的 future 无需再等待。
            drop(handle.stop(false));
        }
    }
}

async fn mock_token(state: web::Data<MockQqState>) -> actix_web::HttpResponse {
    state.token_calls.fetch_add(1, Ordering::SeqCst);
    actix_web::HttpResponse::Ok().json(json!({
        "access_token": "mock-token",
        "expires_in": 7200,
    }))
}

async fn mock_message(
    path: web::Path<(String, String)>,
    body: web::Json<Value>,
    state: web::Data<MockQqState>,
) -> actix_web::HttpResponse {
    let (kind, id) = path.into_inner();
    let prefix = if kind == "groups" { "group" } else { "user" };
    let target = format!("{prefix}:{id}");
    state.calls.lock().unwrap().push(MockCall {
        target: target.clone(),
        body: body.into_inner(),
    });
    let failure = state.failures.lock().unwrap().get(&target).cloned();
    match failure {
        Some(failure) => actix_web::HttpResponse::BadRequest().json(json!({
            "code": failure.code,
            "message": failure.message,
        })),
        None => actix_web::HttpResponse::Ok().json(json!({"id": "msg-stub"})),
    }
}

// --------------------------------------------------------------------------- 夹具

struct Fixture {
    pool: MySqlPool,
    state: Arc<AppState>,
    prefix: String,
    fernet_key: String,
    mock: MockQq,
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

async fn setup_with_queue(max_pending: Option<usize>) -> Fixture {
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
    let mock = MockQq::start();
    let queue = match max_pending {
        Some(max_pending) => Some(Arc::new(
            PushQueue::connect(pool.clone(), max_pending)
                .await
                .expect("连接推送队列失败"),
        )),
        None => None,
    };
    let state = Arc::new(AppState::new(
        pool.clone(),
        Arc::new(config),
        runtime,
        http,
        queue,
    ));
    Fixture {
        pool,
        state,
        prefix: format!("wh{}", uuid::Uuid::new_v4().simple()),
        fernet_key,
        mock,
    }
}

async fn setup() -> Fixture {
    setup_with_queue(None).await
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
}

async fn call<S, R, B, E>(app: &S, request: R) -> Reply
where
    S: Service<R, Response = ServiceResponse<B>, Error = E>,
    B: MessageBody,
    E: Debug,
{
    let response = test::call_service(app, request).await;
    let status = response.status();
    let body = test::read_body(response).await.to_vec();
    Reply { status, body }
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

fn json_request(uri: &str, body: &Value) -> TestRequest {
    TestRequest::default()
        .method(Method::POST)
        .uri(uri)
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .set_payload(body.to_string())
}

fn webhook_request(uri: &str, body: &Value, token: &str) -> TestRequest {
    json_request(uri, body).insert_header(("X-Webhook-Token", token))
}

fn raw_request(uri: &str, body: Vec<u8>, token: &str) -> TestRequest {
    TestRequest::default()
        .method(Method::POST)
        .uri(uri)
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .insert_header(("X-Webhook-Token", token))
        .set_payload(body)
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn signature_bytes(secret: &str, raw: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC 接受任意长度密钥");
    mac.update(raw);
    format!("sha256={}", hex_lower(&mac.finalize().into_bytes()))
}

fn signature(secret: &str, body: &Value) -> String {
    signature_bytes(
        secret,
        &serde_json::to_vec(body).expect("序列化 GitHub 负载失败"),
    )
}

fn github_request(
    path_token: &str,
    event: &str,
    body: &Value,
    signature: Option<&str>,
) -> TestRequest {
    let mut request = TestRequest::default()
        .method(Method::POST)
        .uri(&format!("/webhook/github/{path_token}"))
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .insert_header(("X-GitHub-Event", event))
        .set_payload(serde_json::to_vec(body).expect("序列化 GitHub 负载失败"));
    if let Some(signature) = signature {
        request = request.insert_header(("X-Hub-Signature-256", signature));
    }
    request
}

// --------------------------------------------------------------------------- 数据

async fn make_user(fixture: &Fixture) -> i64 {
    let email = format!("{}@example.com", fixture.prefix);
    let name = fixture.prefix.clone();
    sqlx::query(
        "INSERT INTO users (email, name, password_hash, role, status, created_at) \
         VALUES (?, ?, NULL, 'user', 'active', ?)",
    )
    .bind(&email)
    .bind(&name)
    .bind(Utc::now().naive_utc())
    .execute(&fixture.pool)
    .await
    .expect("插入测试账号失败")
    .last_insert_id() as i64
}

async fn make_bot(
    fixture: &Fixture,
    owner_user_id: i64,
    openids: &[&str],
    group: Option<&str>,
) -> i64 {
    let default_openids = serde_json::to_value(openids).expect("序列化默认目标失败");
    let secret = encrypt_secret("test-app-secret", Some(&fixture.fernet_key));
    sqlx::query(
        "INSERT INTO bot_profiles (owner_user_id, name, qq_appid, qq_app_secret, qq_host, \
         default_openids, default_group_openid, enabled, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, TRUE, ?)",
    )
    .bind(owner_user_id)
    .bind(format!("{}-bot", fixture.prefix))
    .bind(format!("{}-app", fixture.prefix))
    .bind(secret)
    .bind(fixture.mock.base_url.clone())
    .bind(default_openids)
    .bind(group)
    .bind(Utc::now().naive_utc())
    .execute(&fixture.pool)
    .await
    .expect("插入测试机器人失败")
    .last_insert_id() as i64
}

/// 创建通道；GitHub 通道同时生成签名密钥并加密存入 `extra`。
async fn make_channel(
    fixture: &Fixture,
    bot_id: i64,
    platform: &str,
) -> (i64, String, Option<String>) {
    let token = uuid::Uuid::new_v4().simple().to_string();
    let (extra, secret) = if platform == "github" {
        let plain = uuid::Uuid::new_v4().simple().to_string();
        let cipher = encrypt_secret(&plain, Some(&fixture.fernet_key));
        (Some(json!({"secret_cipher": cipher})), Some(plain))
    } else {
        (None, None)
    };
    let id = sqlx::query(
        "INSERT INTO channels (bot_profile_id, platform, webhook_token, enabled, extra, created_at) \
         VALUES (?, ?, ?, TRUE, ?, ?)",
    )
    .bind(bot_id)
    .bind(platform)
    .bind(&token)
    .bind(extra)
    .bind(Utc::now().naive_utc())
    .execute(&fixture.pool)
    .await
    .expect("插入测试通道失败")
    .last_insert_id() as i64;
    (id, token, secret)
}

async fn session_for(fixture: &Fixture, user_id: i64) -> String {
    let user = queries::users::find_by_id(&fixture.pool, user_id)
        .await
        .expect("查询账号失败")
        .expect("账号不存在");
    sessions::create_session(&fixture.pool, &user, 24, None, None)
        .await
        .expect("创建会话失败")
}

async fn clear_push_jobs(pool: &MySqlPool) {
    sqlx::query("DELETE FROM jobs WHERE job_type = 'push'")
        .execute(pool)
        .await
        .expect("清理推送队列失败");
}

// --------------------------------------------------------------------- Webhook 用例

#[actix_web::test]
async fn text_pushes_to_default_openid() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let owner = make_user(&fixture).await;
    let bot_id = make_bot(&fixture, owner, &["u-default"], None).await;
    let (_channel_id, token, _) = make_channel(&fixture, bot_id, "dingtalk").await;

    let reply = send!(
        app,
        webhook_request(
            "/webhook/dingtalk",
            &json!({"msgtype": "text", "text": {"content": "磁盘告警"}}),
            &token,
        )
    );
    let reply = assert_status!(reply, StatusCode::OK);
    assert_eq!(reply.json(), json!({"errcode": 0, "errmsg": "ok"}));

    let calls = fixture.mock.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].target, "user:u-default");
    assert_eq!(
        calls[0].body,
        json!({
            "msg_type": 0,
            "content": "磁盘告警",
            "msg_id": "",
            "msg_seq": 1,
        })
    );
}

#[actix_web::test]
async fn markdown_uses_msg_type_2() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let owner = make_user(&fixture).await;
    let bot_id = make_bot(&fixture, owner, &[], Some("g-default")).await;
    let (_channel_id, token, _) = make_channel(&fixture, bot_id, "wecom").await;

    let reply = send!(
        app,
        webhook_request(
            "/webhook/wecom",
            &json!({"msgtype": "markdown", "markdown": {"content": "**服务** 异常"}}),
            &token,
        )
    );
    assert_status!(reply, StatusCode::OK);
    let calls = fixture.mock.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].target, "group:g-default");
    assert_eq!(calls[0].body["msg_type"], json!(2));
    assert_eq!(calls[0].body["content"], json!(""));
    assert_eq!(calls[0].body["markdown"]["content"], json!("**服务** 异常"));
}

#[actix_web::test]
async fn request_target_overrides_default() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let owner = make_user(&fixture).await;
    let bot_id = make_bot(&fixture, owner, &["u-default"], None).await;
    let (_channel_id, token, _) = make_channel(&fixture, bot_id, "dingtalk").await;

    for body in [
        json!({"msgtype": "text", "text": {"content": "a"}, "openid": "u-body"}),
        json!({
            "msgtype": "text",
            "text": {"content": "b"},
            "openid": "u-body",
            "group_openid": "g-body",
        }),
    ] {
        let reply = send!(app, webhook_request("/webhook/dingtalk", &body, &token));
        assert_status!(reply, StatusCode::OK);
    }

    let targets = fixture
        .mock
        .calls()
        .into_iter()
        .map(|call| call.target)
        .collect::<Vec<_>>();
    assert_eq!(targets, ["user:u-body", "group:g-body"]);
}

#[actix_web::test]
async fn push_logs_recorded() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let owner = make_user(&fixture).await;
    let bot_id = make_bot(&fixture, owner, &["u-default"], None).await;
    let (_channel_id, token, _) = make_channel(&fixture, bot_id, "feishu").await;

    let reply = send!(
        app,
        webhook_request(
            "/webhook/feishu",
            &json!({"msg_type": "text", "content": {"text": "上线通知"}}),
            &token,
        )
    );
    let reply = assert_status!(reply, StatusCode::OK);
    assert_eq!(
        reply.json(),
        json!({"code": 0, "msg": "success", "data": {}})
    );

    let row: (String, String, String, String, i64) = sqlx::query_as(
        "SELECT platform, status, target, content_preview, owner_user_id FROM push_logs \
         WHERE owner_user_id = ? ORDER BY id DESC LIMIT 1",
    )
    .bind(owner)
    .fetch_one(&fixture.pool)
    .await
    .expect("查询推送日志失败");
    assert_eq!(row.0, "feishu");
    assert_eq!(row.1, "success");
    assert_eq!(row.2, "user:u-default");
    assert!(row.3.contains("上线通知"), "{}", row.3);
    assert_eq!(row.4, owner);
}

#[actix_web::test]
async fn failure_returns_502_and_logs_error() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let owner = make_user(&fixture).await;
    let bot_id = make_bot(&fixture, owner, &["u-default"], None).await;
    let (_channel_id, token, _) = make_channel(&fixture, bot_id, "dingtalk").await;
    fixture
        .mock
        .fail("user:u-default", "50012", "机器人已被移除");

    let reply = send!(
        app,
        webhook_request(
            "/webhook/dingtalk",
            &json!({"msgtype": "text", "text": {"content": "x"}}),
            &token,
        )
    );
    let reply = assert_status!(reply, StatusCode::BAD_GATEWAY);
    // 对外文案固定为通用失败提示，平台细节只进日志。
    assert!(
        reply.json()["errmsg"]
            .as_str()
            .unwrap_or_default()
            .contains("推送失败")
    );

    let (status, error_code): (String, Option<String>) = sqlx::query_as(
        "SELECT status, error_code FROM push_logs WHERE owner_user_id = ? \
         ORDER BY id DESC LIMIT 1",
    )
    .bind(owner)
    .fetch_one(&fixture.pool)
    .await
    .expect("查询失败日志失败");
    assert_eq!(status, "failed");
    assert_eq!(error_code.as_deref(), Some("50012"));
}

#[actix_web::test]
async fn rejects_bad_token_platform_and_body() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let owner = make_user(&fixture).await;
    let bot_id = make_bot(&fixture, owner, &["u-default"], None).await;
    let (_channel_id, token, _) = make_channel(&fixture, bot_id, "dingtalk").await;

    let bad_token = send!(
        app,
        webhook_request(
            "/webhook/dingtalk",
            &json!({"msgtype": "text"}),
            "bad-token"
        )
    );
    assert_status!(bad_token, StatusCode::UNAUTHORIZED);

    let unknown_platform = send!(app, webhook_request("/webhook/unknown", &json!({}), "x"));
    assert_status!(unknown_platform, StatusCode::NOT_FOUND);

    let not_json = send!(
        app,
        raw_request("/webhook/dingtalk", b"not-json".to_vec(), &token)
    );
    assert_status!(not_json, StatusCode::BAD_REQUEST);

    let oversize_body = format!("{{\"a\":\"{}\"}}", "x".repeat(70_000)).into_bytes();
    let oversize = send!(app, raw_request("/webhook/dingtalk", oversize_body, &token));
    assert_status!(oversize, StatusCode::PAYLOAD_TOO_LARGE);

    let unknown_type = send!(
        app,
        webhook_request(
            "/webhook/dingtalk",
            &json!({"msgtype": "video", "video": {}}),
            &token,
        )
    );
    assert_status!(unknown_type, StatusCode::BAD_REQUEST);
    assert!(fixture.mock.calls().is_empty());
}

#[actix_web::test]
async fn authorization_bearer_token_accepted() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let owner = make_user(&fixture).await;
    let bot_id = make_bot(&fixture, owner, &["u-bearer"], None).await;
    let (_channel_id, token, _) = make_channel(&fixture, bot_id, "dingtalk").await;

    let bearer = format!("Bearer {token}");
    let accepted = send!(
        app,
        json_request(
            "/webhook/dingtalk",
            &json!({"msgtype": "text", "text": {"content": "bearer"}})
        )
        .insert_header((header::AUTHORIZATION, bearer))
    );
    assert_status!(accepted, StatusCode::OK);
    assert_eq!(fixture.mock.calls().len(), 1);

    let basic = format!("Basic {token}");
    let rejected = send!(
        app,
        json_request(
            "/webhook/dingtalk",
            &json!({"msgtype": "text", "text": {"content": "basic"}})
        )
        .insert_header((header::AUTHORIZATION, basic))
    );
    assert_status!(rejected, StatusCode::UNAUTHORIZED);
}

#[actix_web::test]
async fn query_token_rejected_by_default() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let owner = make_user(&fixture).await;
    let bot_id = make_bot(&fixture, owner, &["u-query"], None).await;
    let (_channel_id, token, _) = make_channel(&fixture, bot_id, "dingtalk").await;

    let uri = format!("/webhook/dingtalk?token={token}");
    let reply = send!(
        app,
        json_request(
            &uri,
            &json!({"msgtype": "text", "text": {"content": "query"}})
        )
    );
    assert_status!(reply, StatusCode::UNAUTHORIZED);
    assert!(fixture.mock.calls().is_empty());
}

#[actix_web::test]
async fn query_token_allowed_when_enabled() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let owner = make_user(&fixture).await;
    let bot_id = make_bot(&fixture, owner, &["u-query"], None).await;
    let (_channel_id, token, _) = make_channel(&fixture, bot_id, "dingtalk").await;
    fixture.apply_settings(json!({"webhook_allow_query_token": true}));

    let uri = format!("/webhook/dingtalk?token={token}");
    let reply = send!(
        app,
        json_request(
            &uri,
            &json!({"msgtype": "text", "text": {"content": "query"}})
        )
    );
    assert_status!(reply, StatusCode::OK);
    assert_eq!(fixture.mock.calls().len(), 1);
}

#[actix_web::test]
async fn missing_target_returns_400() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let owner = make_user(&fixture).await;
    let bot_id = make_bot(&fixture, owner, &[], None).await;
    let (_channel_id, token, _) = make_channel(&fixture, bot_id, "dingtalk").await;

    let reply = send!(
        app,
        webhook_request(
            "/webhook/dingtalk",
            &json!({"msgtype": "text", "text": {"content": "x"}}),
            &token,
        )
    );
    let reply = assert_status!(reply, StatusCode::BAD_REQUEST);
    assert!(
        reply.json()["errmsg"]
            .as_str()
            .unwrap_or_default()
            .contains("默认目标")
    );
}

// ------------------------------------------------------------------------ GitHub

fn ping_payload() -> Value {
    json!({
        "zen": "Keep it logically awesome.",
        "hook_id": 1,
        "repository": {"full_name": "acme/widgets"},
        "sender": {"login": "octocat"},
    })
}

#[actix_web::test]
async fn github_signed_ping_pushes_and_logs() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let owner = make_user(&fixture).await;
    let bot_id = make_bot(&fixture, owner, &[], Some("g-default")).await;
    let (_channel_id, token, secret) = make_channel(&fixture, bot_id, "github").await;
    let secret = secret.expect("GitHub 通道必须有签名密钥");
    let body = ping_payload();
    let signed = signature(&secret, &body);

    let reply = send!(app, github_request(&token, "ping", &body, Some(&signed)));
    let reply = assert_status!(reply, StatusCode::OK);
    assert_eq!(reply.json(), json!({"ok": true}));

    let calls = fixture.mock.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].target, "group:g-default");
    assert_eq!(calls[0].body["msg_type"], json!(2));

    let source: String = sqlx::query_scalar(
        "SELECT source_msgtype FROM push_logs WHERE owner_user_id = ? \
         ORDER BY id DESC LIMIT 1",
    )
    .bind(owner)
    .fetch_one(&fixture.pool)
    .await
    .expect("查询推送日志失败");
    assert_eq!(source, "ping");
}

#[actix_web::test]
async fn github_rejects_missing_or_bad_signature() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let owner = make_user(&fixture).await;
    let bot_id = make_bot(&fixture, owner, &[], Some("g-default")).await;
    let (_channel_id, token, _secret) = make_channel(&fixture, bot_id, "github").await;
    let body = ping_payload();

    let missing = send!(app, github_request(&token, "ping", &body, None));
    let missing = assert_status!(missing, StatusCode::UNAUTHORIZED);
    assert!(
        missing.json()["error"]
            .as_str()
            .unwrap_or_default()
            .contains("签名")
    );

    let wrong_signature = format!("sha256={}", "0".repeat(64));
    let wrong = send!(
        app,
        github_request(&token, "ping", &body, Some(&wrong_signature))
    );
    let wrong = assert_status!(wrong, StatusCode::UNAUTHORIZED);
    assert_eq!(wrong.json()["error"], json!("签名不匹配"));

    let tampered_signature = signature_bytes("other-secret", b"{}");
    let tampered = send!(
        app,
        github_request(&token, "ping", &body, Some(&tampered_signature))
    );
    assert_status!(tampered, StatusCode::UNAUTHORIZED);
    assert!(fixture.mock.calls().is_empty());
}

#[actix_web::test]
async fn github_arbitrary_event_pushes_and_logs() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let owner = make_user(&fixture).await;
    let bot_id = make_bot(&fixture, owner, &[], Some("g-default")).await;
    let (_channel_id, token, secret) = make_channel(&fixture, bot_id, "github").await;
    let secret = secret.expect("GitHub 通道必须有签名密钥");
    let body = json!({
        "action": "created",
        "deployment": {"environment": "production"},
        "repository": {"full_name": "acme/widgets"},
        "sender": {"login": "octocat"},
    });
    let signed = signature(&secret, &body);

    let reply = send!(
        app,
        github_request(&token, "deployment", &body, Some(&signed))
    );
    let reply = assert_status!(reply, StatusCode::OK);
    assert_eq!(reply.json()["ok"], json!(true));
    assert_eq!(fixture.mock.calls().len(), 1);

    let source: String = sqlx::query_scalar(
        "SELECT source_msgtype FROM push_logs WHERE owner_user_id = ? \
         ORDER BY id DESC LIMIT 1",
    )
    .bind(owner)
    .fetch_one(&fixture.pool)
    .await
    .expect("查询推送日志失败");
    assert_eq!(source, "deployment.created");
}

#[actix_web::test]
async fn github_without_path_token_is_rejected() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let owner = make_user(&fixture).await;
    let bot_id = make_bot(&fixture, owner, &[], Some("g-default")).await;
    make_channel(&fixture, bot_id, "github").await;

    let reply = send!(app, json_request("/webhook/github", &json!({})));
    let reply = assert_status!(reply, StatusCode::NOT_FOUND);
    assert!(
        reply.json()["error"]
            .as_str()
            .unwrap_or_default()
            .contains("webhook/github/{token}")
    );
}

#[actix_web::test]
async fn github_rotate_replaces_token_and_secret() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let owner = make_user(&fixture).await;
    let bot_id = make_bot(&fixture, owner, &[], Some("g-default")).await;
    let (channel_id, old_token, old_secret) = make_channel(&fixture, bot_id, "github").await;
    let old_secret = old_secret.expect("GitHub 通道必须有签名密钥");
    let session = session_for(&fixture, owner).await;

    let rotated = send!(
        app,
        json_request(
            &format!("/api/admin/channels/{channel_id}/rotate"),
            &json!({})
        )
        .insert_header((header::COOKIE, format!("sid={session}")))
    );
    let rotated = assert_status!(rotated, StatusCode::OK).json();
    let new_token = rotated["webhook_token"]
        .as_str()
        .expect("轮换响应缺少 webhook_token")
        .to_string();
    let new_secret = rotated["secret"]
        .as_str()
        .expect("轮换响应缺少 secret")
        .to_string();
    assert_ne!(new_token, old_token);
    assert_ne!(new_secret, old_secret);

    let body = ping_payload();
    let stale = send!(
        app,
        github_request(
            &old_token,
            "ping",
            &body,
            Some(&signature(&old_secret, &body)),
        )
    );
    assert_status!(stale, StatusCode::UNAUTHORIZED);

    let fresh = send!(
        app,
        github_request(
            &new_token,
            "ping",
            &body,
            Some(&signature(&new_secret, &body)),
        )
    );
    assert_status!(fresh, StatusCode::OK);
    assert_eq!(fixture.mock.calls().len(), 1);
}

// --------------------------------------------------------------------------- 队列

#[actix_web::test]
async fn queue_accepts_before_any_send() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup_with_queue(Some(20)).await;
    clear_push_jobs(&fixture.pool).await;
    let app = app!(fixture.state.clone());
    let owner = make_user(&fixture).await;
    let bot_id = make_bot(&fixture, owner, &["u-default"], None).await;
    let (channel_id, token, _) = make_channel(&fixture, bot_id, "dingtalk").await;

    let reply = send!(
        app,
        webhook_request(
            "/webhook/dingtalk",
            &json!({"msgtype": "text", "text": {"content": "入队即确认"}}),
            &token,
        )
    );
    assert_status!(reply, StatusCode::OK);
    assert!(fixture.mock.calls().is_empty(), "入队后不应同步发送");

    let rows: Vec<(Vec<u8>, Option<String>)> = sqlx::query_as(
        "SELECT job, idempotency_key FROM jobs WHERE job_type = 'push' AND status = 'Pending'",
    )
    .fetch_all(&fixture.pool)
    .await
    .expect("查询队列任务失败");
    assert_eq!(rows.len(), 1);
    let job: PushJob = serde_json::from_slice(&rows[0].0).expect("队列任务必须是 PushJob");
    assert_eq!(job.bot_id, bot_id);
    assert_eq!(job.content, "入队即确认");
    let key = rows[0].1.clone().expect("队列任务缺少 idempotency_key");
    assert_eq!(key.len(), 36);
    assert!(
        key.chars()
            .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
    );
    assert_eq!(
        key,
        dedupe_key("dingtalk", channel_id, None, &job.request_id)
    );

    clear_push_jobs(&fixture.pool).await;
}

#[actix_web::test]
async fn queue_duplicate_delivery_is_acked() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup_with_queue(Some(20)).await;
    clear_push_jobs(&fixture.pool).await;
    let app = app!(fixture.state.clone());
    let owner = make_user(&fixture).await;
    let bot_id = make_bot(&fixture, owner, &["u-default"], None).await;
    let (channel_id, token, _) = make_channel(&fixture, bot_id, "dingtalk").await;
    let msgid = format!("{}-dup", fixture.prefix);
    let body = json!({
        "msgtype": "text",
        "text": {"content": "重复"},
        "msgid": msgid,
    });

    let first = send!(app, webhook_request("/webhook/dingtalk", &body, &token));
    assert_status!(first, StatusCode::OK);

    // 同一 msgid 的第二次投递应被队列按幂等键判重并直接确认，不得再次发送。
    let duplicate = send!(app, webhook_request("/webhook/dingtalk", &body, &token));
    let duplicate = assert_status!(duplicate, StatusCode::OK);
    assert_eq!(
        duplicate.json()["errmsg"],
        json!("重复投递，已忽略"),
        "实现缺陷：src/services/queue.rs::is_duplicate_key 用 SQLSTATE 与 \"1062\" 比较，\
         而 sqlx-mysql 的 DatabaseError::code() 返回 \"23000\"，导致判重失败并降级为同步发送"
    );
    assert!(fixture.mock.calls().is_empty());

    let key = dedupe_key("dingtalk", channel_id, Some(&msgid), "request-id-ignored");
    let count: i64 = sqlx::query_scalar(
        "SELECT CAST(COUNT(*) AS SIGNED) FROM jobs \
         WHERE job_type = 'push' AND idempotency_key = ?",
    )
    .bind(&key)
    .fetch_one(&fixture.pool)
    .await
    .expect("统计队列任务失败");
    assert_eq!(count, 1);

    clear_push_jobs(&fixture.pool).await;
}

#[actix_web::test]
async fn queue_dedupe_key_is_scoped_per_channel() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup_with_queue(Some(20)).await;
    clear_push_jobs(&fixture.pool).await;
    let app = app!(fixture.state.clone());
    let owner = make_user(&fixture).await;
    let bot_id = make_bot(&fixture, owner, &["u-default"], None).await;
    // 同一机器人挂两个相同平台的通道：平台的投递 ID 相同也不互相压制。
    let (channel_a, token_a, _) = make_channel(&fixture, bot_id, "dingtalk").await;
    let (channel_b, token_b, _) = make_channel(&fixture, bot_id, "dingtalk").await;
    let msgid = format!("{}-cross", fixture.prefix);
    let body = json!({
        "msgtype": "text",
        "text": {"content": "跨通道去重"},
        "msgid": msgid,
    });

    let first = send!(app, webhook_request("/webhook/dingtalk", &body, &token_a));
    assert_status!(first, StatusCode::OK);
    let second = send!(app, webhook_request("/webhook/dingtalk", &body, &token_b));
    let second = assert_status!(second, StatusCode::OK);
    // 第二条若被误判为重复会返回「重复投递，已忽略」。
    assert_eq!(second.json()["errmsg"], json!("ok"));
    assert!(fixture.mock.calls().is_empty());

    let mut keys: Vec<String> = sqlx::query_scalar(
        "SELECT idempotency_key FROM jobs \
         WHERE job_type = 'push' AND status = 'Pending'",
    )
    .fetch_all(&fixture.pool)
    .await
    .expect("查询队列任务失败")
    .into_iter()
    .map(|key: Option<String>| key.expect("队列任务缺少 idempotency_key"))
    .collect();
    assert_eq!(keys.len(), 2, "两个通道的相同投递 ID 应各自入队");
    let key_a = dedupe_key("dingtalk", channel_a, Some(&msgid), "r");
    let key_b = dedupe_key("dingtalk", channel_b, Some(&msgid), "r");
    assert_ne!(key_a, key_b, "跨通道的幂等键必须包含通道维度");
    keys.sort();
    let mut expected = vec![key_a, key_b];
    expected.sort();
    assert_eq!(keys, expected);

    clear_push_jobs(&fixture.pool).await;
}

#[actix_web::test]
async fn queue_full_asks_sender_to_retry() {
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup_with_queue(Some(0)).await;
    let app = app!(fixture.state.clone());
    let owner = make_user(&fixture).await;
    let bot_id = make_bot(&fixture, owner, &["u-default"], None).await;
    let (_channel_id, token, _) = make_channel(&fixture, bot_id, "dingtalk").await;

    let reply = send!(
        app,
        webhook_request(
            "/webhook/dingtalk",
            &json!({"msgtype": "text", "text": {"content": "积压"}}),
            &token,
        )
    );
    let reply = assert_status!(reply, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(reply.json()["errcode"], json!(503));
    assert!(fixture.mock.calls().is_empty());
}

// --------------------------------------------------------- 长度限制（HTTP 全链路）

#[actix_web::test]
async fn webhook_applies_markdown_length_limit() {
    // 覆盖 test_renderer.py::test_truncation_limits 的 HTTP 侧行为
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let owner = make_user(&fixture).await;
    let bot_id = make_bot(&fixture, owner, &["u-default"], None).await;
    let (_channel_id, token, _) = make_channel(&fixture, bot_id, "wecom").await;
    fixture.apply_settings(json!({"markdown_max_len": 100}));

    let content = "字".repeat(500);
    let reply = send!(
        app,
        webhook_request(
            "/webhook/wecom",
            &json!({"msgtype": "markdown", "markdown": {"content": content}}),
            &token,
        )
    );
    assert_status!(reply, StatusCode::OK);

    let calls = fixture.mock.calls();
    assert_eq!(calls.len(), 1);
    let rendered = calls[0].body["markdown"]["content"]
        .as_str()
        .expect("Markdown 消息缺少 markdown.content");
    assert_eq!(rendered.chars().count(), 100);
    assert!(rendered.ends_with("（内容过长已截断）"));
}

#[actix_web::test]
async fn webhook_applies_text_length_limit() {
    // 覆盖 test_renderer.py 的纯文本长度上限语义
    let _guard = TEST_LOCK.lock().await;
    let fixture = setup().await;
    let app = app!(fixture.state.clone());
    let owner = make_user(&fixture).await;
    let bot_id = make_bot(&fixture, owner, &["u-default"], None).await;
    let (_channel_id, token, _) = make_channel(&fixture, bot_id, "dingtalk").await;
    fixture.apply_settings(json!({"text_max_len": 50}));

    let content = "a".repeat(200);
    let reply = send!(
        app,
        webhook_request(
            "/webhook/dingtalk",
            &json!({"msgtype": "text", "text": {"content": content}}),
            &token,
        )
    );
    assert_status!(reply, StatusCode::OK);

    let calls = fixture.mock.calls();
    assert_eq!(calls.len(), 1);
    let rendered = calls[0].body["content"]
        .as_str()
        .expect("纯文本消息缺少 content");
    assert_eq!(rendered.chars().count(), 50);
    assert!(rendered.ends_with("（内容过长已截断）"));
}

// ---------------------------------------------------------------- Markdown 清洗

#[test]
fn degrades_table_to_list() {
    let content = "指标|值\n|磁盘|90%|\n|CPU|12%|\n";
    assert!(degrade_tables(content).starts_with("指标|值"));

    let table = "|指标|值|\n|---|:---:|\n|磁盘|90%|\n|CPU|12%|";
    assert_eq!(
        degrade_tables(table),
        "- **指标**：磁盘，**值**：90%\n- **指标**：CPU，**值**：12%"
    );
}

#[test]
fn strips_html_and_images() {
    let content = "<font color=\"warning\">警告</font>\n![图](https://img.example.com/a.png)";
    let cleaned = sanitize_markdown(content, None);
    assert!(!cleaned.contains("<font"));
    assert!(cleaned.contains("警告"));
    assert!(cleaned.contains("（图片：图）"));
    assert!(!cleaned.contains("https://img.example.com/a.png"));
}

#[test]
fn truncates_with_suffix() {
    let cleaned = sanitize_markdown(&"a".repeat(100), Some(20));
    assert!(cleaned.ends_with("（内容过长已截断）"));
    assert_eq!(cleaned.chars().count(), 20);
}

#[test]
fn sanitize_text_removes_control_chars_and_blank_lines() {
    let raw = "第一行\x00\n\n\n\n第二行\r\n";
    assert_eq!(sanitize_text(raw, None), "第一行\n\n第二行");
}

// -------------------------------------------------------------- 渲染（QQ 消息体）

#[test]
fn markdown_message_uses_msg_type_2_with_empty_content() {
    let payload = render_qq(&UnifiedMessage::markdown("**磁盘** 90%").with_title("告警"));
    assert_eq!(payload.msg_type, MSG_TYPE_MARKDOWN);
    let body = payload.to_dict();
    assert_eq!(body["msg_type"], json!(2));
    assert_eq!(body["content"], json!(""));
    assert_eq!(
        body["markdown"]["content"],
        json!("### 告警\n\n**磁盘** 90%")
    );
}

#[test]
fn text_message_uses_msg_type_0() {
    let payload = render_qq(&UnifiedMessage::text("内容").with_title("标题"));
    assert_eq!(payload.msg_type, MSG_TYPE_TEXT);
    let body = payload.to_dict();
    assert_eq!(body["msg_type"], json!(0));
    assert_eq!(body["content"], json!("标题\n内容"));
    assert!(body.get("markdown").is_none());
}

#[test]
fn markdown_empty_after_sanitize_falls_back_to_text() {
    let payload = render_qq(&UnifiedMessage::markdown("<div></div>"));
    assert_eq!(payload.msg_type, MSG_TYPE_TEXT);
}

#[test]
fn empty_message_gets_placeholder() {
    let payload = render_qq(&UnifiedMessage::text(""));
    assert_eq!(payload.content, "（消息内容为空）");
}

#[test]
fn truncation_limits() {
    let payload = render_qq_with_limits(&UnifiedMessage::markdown("字".repeat(500)), 100, 2000);
    assert!(payload.markdown.is_some());
    assert_eq!(payload.markdown.as_ref().unwrap().chars().count(), 100);
}

// ------------------------------------------------------------------ 平台适配器

fn parse_platform(platform: &str, payload: &Value) -> Result<UnifiedMessage, AdapterError> {
    parse_event(platform, "", payload)
}

fn parse_event(
    platform: &str,
    event: &str,
    payload: &Value,
) -> Result<UnifiedMessage, AdapterError> {
    match platform {
        "dingtalk" => DingTalkAdapter::new().parse(payload, event),
        "wecom" => WeComAdapter::new().parse(payload, event),
        "feishu" => FeishuAdapter::new().parse(payload, event),
        "github" => GitHubAdapter::new().parse(payload, event),
        other => panic!("未知测试平台：{other}"),
    }
}

fn assert_payload_error(result: Result<UnifiedMessage, AdapterError>) {
    let error = result.expect_err("期望负载错误");
    assert!(
        matches!(error, AdapterError::Payload(_)),
        "期望 Payload 错误，实际 {error:?}"
    );
}

fn assert_ignored(result: Result<UnifiedMessage, AdapterError>) {
    let error = result.expect_err("期望忽略事件");
    assert!(
        matches!(error, AdapterError::Ignored(_)),
        "期望 Ignored 错误，实际 {error:?}"
    );
}

// 钉钉 ---------------------------------------------------------------------

#[test]
fn dingtalk_text_with_mentions() {
    let message = parse_platform(
        "dingtalk",
        &json!({
            "msgtype": "text",
            "text": {"content": "磁盘告警"},
            "at": {"atMobiles": ["user-a"], "isAtAll": false},
        }),
    )
    .expect("解析成功");
    assert_eq!(message.fmt, FMT_TEXT);
    assert_eq!(message.body, "磁盘告警 @user-a");
    assert_eq!(message.mentions, ["user-a"]);
    assert_eq!(message.source_msgtype, "text");
}

#[test]
fn dingtalk_markdown_keeps_title_separate() {
    let message = parse_platform(
        "dingtalk",
        &json!({
            "msgtype": "markdown",
            "markdown": {"title": "告警", "text": "### 磁盘\n> 90%"},
            "at": {"atUserIds": ["user-b"]},
        }),
    )
    .expect("解析成功");
    assert_eq!(message.fmt, FMT_MARKDOWN);
    assert_eq!(message.title.as_deref(), Some("告警"));
    assert!(!message.body.contains("### 告警"));
    assert_eq!(message.mentions, ["user-b"]);
    assert!(message.body.ends_with("@user-b"));
}

#[test]
fn dingtalk_link_and_action_card() {
    let link = parse_platform(
        "dingtalk",
        &json!({
            "msgtype": "link",
            "link": {
                "title": "发布失败",
                "text": "流水线 #12",
                "messageUrl": "https://ci.example.com/12",
                "picUrl": "https://ci.example.com/12.png",
            },
        }),
    )
    .expect("解析成功");
    assert_eq!(link.fmt, FMT_MARKDOWN);
    assert_eq!(link.title.as_deref(), Some("发布失败"));
    assert!(link.body.contains("[查看详情](https://ci.example.com/12)"));
    assert_eq!(link.attachments[0].kind, "image");

    let card = parse_platform(
        "dingtalk",
        &json!({
            "msgtype": "actionCard",
            "actionCard": {
                "title": "审批",
                "text": "请确认",
                "singleTitle": "查看",
                "singleURL": "https://oa.example.com/1",
            },
        }),
    )
    .expect("解析成功");
    assert_eq!(card.fmt, FMT_MARKDOWN);
    assert!(card.body.contains("- [查看](https://oa.example.com/1)"));
}

#[test]
fn dingtalk_feed_card_and_unknown_type() {
    let feed = parse_platform(
        "dingtalk",
        &json!({
            "msgtype": "feedCard",
            "feedCard": {"links": [{"title": "a", "messageURL": "https://a.example.com"}]},
        }),
    )
    .expect("解析成功");
    assert_eq!(feed.fmt, FMT_MARKDOWN);
    assert_eq!(feed.body, "- [a](https://a.example.com)");

    assert_payload_error(parse_platform(
        "dingtalk",
        &json!({"msgtype": "video", "video": {}}),
    ));
}

// 企业微信 -----------------------------------------------------------------

#[test]
fn wecom_text_strips_mention_tags() {
    let message = parse_platform(
        "wecom",
        &json!({
            "msgtype": "text",
            "text": {
                "content": "服务 <@all> 异常 <@zhangsan>",
                "mentioned_list": ["@all", "lisi"],
                "mentioned_mobile_list": ["13800000000"],
            },
        }),
    )
    .expect("解析成功");
    assert_eq!(message.fmt, FMT_TEXT);
    assert!(!message.body.contains("<@"));
    assert!(message.body.starts_with("服务 异常"));
    assert_eq!(
        message.mentions,
        ["所有人", "zhangsan", "lisi", "13800000000"]
    );
    assert_eq!(message.body.matches("@所有人").count(), 1);
}

#[test]
fn wecom_markdown_v2_degrades_tables() {
    let message = parse_platform(
        "wecom",
        &json!({
            "msgtype": "markdown_v2",
            "markdown_v2": {"content": "|指标|值|\n|---|---|\n|CPU|90%|"},
        }),
    )
    .expect("解析成功");
    assert_eq!(message.fmt, FMT_MARKDOWN);
    assert_eq!(message.body, "- **指标**：CPU，**值**：90%");
}

#[test]
fn wecom_news_image_and_template_card() {
    let news = parse_platform(
        "wecom",
        &json!({
            "msgtype": "news",
            "news": {
                "articles": [
                    {"title": "n1", "description": "d1", "url": "https://n1.example.com"}
                ]
            },
        }),
    )
    .expect("解析成功");
    assert!(news.body.contains("- [n1](https://n1.example.com)"));

    let image = parse_platform(
        "wecom",
        &json!({"msgtype": "image", "image": {"media_id": "m-1", "content": ""}}),
    )
    .expect("解析成功");
    assert_eq!(image.fmt, FMT_TEXT);
    assert_eq!(image.body, "[图片]");
    assert_eq!(image.attachments[0].media_id.as_deref(), Some("m-1"));

    let card = parse_platform(
        "wecom",
        &json!({
            "msgtype": "template_card",
            "template_card": {
                "main_title": {"title": "构建", "desc": "成功"},
                "sub_title_text": "分支 main",
            },
        }),
    )
    .expect("解析成功");
    assert_eq!(card.fmt, FMT_MARKDOWN);
    assert_eq!(card.title.as_deref(), Some("构建"));
    assert!(!card.body.contains("### 构建"));
    assert!(card.body.contains("**分支 main**"));
}

#[test]
fn wecom_unknown_type() {
    assert_payload_error(parse_platform(
        "wecom",
        &json!({"msgtype": "video", "video": {"media_id": "x"}}),
    ));
}

// 飞书 ---------------------------------------------------------------------

#[test]
fn feishu_text_replaces_at_tags() {
    let message = parse_platform(
        "feishu",
        &json!({"msg_type": "text", "content": {"text": "hi <at user_id=\"ou_1\">张三</at>"}}),
    )
    .expect("解析成功");
    assert_eq!(message.fmt, FMT_TEXT);
    assert_eq!(message.body, "hi @张三");
    assert_eq!(message.mentions, ["张三"]);
}

#[test]
fn feishu_post_renders_inline_elements() {
    let message = parse_platform(
        "feishu",
        &json!({
            "msg_type": "post",
            "content": {
                "post": {
                    "zh_cn": {
                        "title": "每日报表",
                        "content": [
                            [
                                {"tag": "text", "text": "访问量 "},
                                {"tag": "a", "text": "详情", "href": "https://x.example.com"},
                            ],
                            [{"tag": "md", "text": "**环比 +5%**"}],
                            [{"tag": "hr"}],
                        ],
                    }
                }
            },
        }),
    )
    .expect("解析成功");
    assert_eq!(message.fmt, FMT_MARKDOWN);
    assert_eq!(message.title.as_deref(), Some("每日报表"));
    assert!(
        message
            .body
            .contains("访问量 [详情](https://x.example.com)")
    );
    assert!(message.body.contains("**环比 +5%**"));
    assert!(message.body.contains("---"));
}

#[test]
fn feishu_interactive_card() {
    let message = parse_platform(
        "feishu",
        &json!({
            "msg_type": "interactive",
            "card": {
                "header": {"title": {"tag": "plain_text", "content": "值班提醒"}},
                "elements": [{"tag": "div", "text": {"tag": "lark_md", "content": "**张三**"}}],
            },
        }),
    )
    .expect("解析成功");
    assert_eq!(message.fmt, FMT_MARKDOWN);
    assert_eq!(message.title.as_deref(), Some("值班提醒"));
    assert!(message.body.contains("**张三**"));
    assert!(!message.body.contains("### 值班提醒"));
}

#[test]
fn feishu_share_chat_and_post_media_tags() {
    let share = parse_platform(
        "feishu",
        &json!({"msg_type": "share_chat", "content": {"share_chat_id": "oc_1"}}),
    )
    .expect("解析成功");
    assert_eq!(share.body, "[群聊分享] oc_1");

    let post = parse_platform(
        "feishu",
        &json!({
            "msg_type": "post",
            "content": {
                "post": {
                    "zh_cn": {
                        "content": [
                            [
                                {"tag": "at", "user_id": "ou_1", "user_name": "张三"},
                                {"tag": "img", "image_key": "img_1"},
                            ]
                        ]
                    }
                }
            },
        }),
    )
    .expect("解析成功");
    assert!(post.body.contains("@张三"));
    assert!(post.body.contains("[图片](img_1)"));
}

#[test]
fn feishu_unknown_type() {
    assert_payload_error(parse_platform(
        "feishu",
        &json!({"msg_type": "audio", "content": {}}),
    ));
}

// GitHub -------------------------------------------------------------------

fn github_payload() -> Value {
    json!({
        "repository": {"full_name": "acme/widgets"},
        "sender": {"login": "octocat"},
    })
}

fn github_payload_with(extra: Value) -> Value {
    let mut payload = github_payload();
    if let Value::Object(extra) = extra {
        let object = payload.as_object_mut().expect("GitHub 负载必须是对象");
        for (key, value) in extra {
            object.insert(key, value);
        }
    }
    payload
}

#[test]
fn github_ping() {
    let message = parse_event(
        "github",
        "ping",
        &github_payload_with(json!({
            "zen": "Keep it logically awesome.",
            "hook_id": 42,
        })),
    )
    .expect("解析成功");
    assert_eq!(message.fmt, FMT_MARKDOWN);
    assert!(
        message
            .title
            .as_deref()
            .unwrap_or_default()
            .contains("接入成功")
    );
    assert!(message.body.contains("acme/widgets"));
    assert!(message.body.contains("Keep it logically awesome."));
    assert_eq!(message.source_msgtype, "ping");
}

#[test]
fn github_push_lists_commits_and_compare() {
    let commits = (0..7)
        .map(|index| {
            json!({
                "id": format!("{index:040x}"),
                "message": format!("fix #{index}\n\n细节"),
                "author": {"name": "Alice"},
            })
        })
        .collect::<Vec<_>>();
    let message = parse_event(
        "github",
        "push",
        &github_payload_with(json!({
            "ref": "refs/heads/main",
            "before": "a".repeat(40),
            "after": "b".repeat(40),
            "commits": commits,
            "compare": "https://github.com/acme/widgets/compare/a...b",
        })),
    )
    .expect("解析成功");
    assert_eq!(message.title.as_deref(), Some("acme/widgets 推送 main"));
    assert!(message.body.contains("octocat"));
    assert!(message.body.contains("7 个提交"));
    assert!(message.body.contains("fix #0"));
    assert!(!message.body.contains("fix #5"));
    assert!(message.body.contains("另有 2 条提交"));
    assert!(message.body.contains("[查看对比]"));
    assert_eq!(message.source_msgtype, "push");
}

#[test]
fn github_push_deleted_branch() {
    let message = parse_event(
        "github",
        "push",
        &github_payload_with(json!({
            "ref": "refs/heads/feature",
            "deleted": true,
            "commits": [],
        })),
    )
    .expect("解析成功");
    assert!(
        message
            .title
            .as_deref()
            .unwrap_or_default()
            .contains("删除分支")
    );
    assert!(message.body.contains("feature"));
}

#[test]
fn github_pull_request_merged_uses_merger() {
    let message = parse_event(
        "github",
        "pull_request",
        &github_payload_with(json!({
            "action": "closed",
            "number": 12,
            "pull_request": {
                "number": 12,
                "title": "新增登录",
                "html_url": "https://github.com/acme/widgets/pull/12",
                "merged": true,
                "merged_by": {"login": "maintainer"},
            },
        })),
    )
    .expect("解析成功");
    assert_eq!(message.title.as_deref(), Some("acme/widgets PR #12"));
    assert!(message.body.contains("maintainer"));
    assert!(message.body.contains("合并"));
    assert_eq!(message.source_msgtype, "pull_request.closed");
}

#[test]
fn github_issues_and_release() {
    let issue = parse_event(
        "github",
        "issues",
        &github_payload_with(json!({
            "action": "opened",
            "issue": {
                "number": 7,
                "title": "按钮错位",
                "html_url": "https://github.com/acme/widgets/issues/7",
            },
        })),
    )
    .expect("解析成功");
    assert!(
        issue
            .title
            .as_deref()
            .unwrap_or_default()
            .contains("Issue #7")
    );
    assert!(issue.body.contains("打开"));

    let release = parse_event(
        "github",
        "release",
        &github_payload_with(json!({
            "action": "published",
            "release": {
                "tag_name": "v1.2.0",
                "name": "v1.2.0",
                "html_url": "https://github.com/acme/widgets/releases/v1.2.0",
                "body": "修复若干问题",
            },
        })),
    )
    .expect("解析成功");
    assert!(
        release
            .title
            .as_deref()
            .unwrap_or_default()
            .contains("Release v1.2.0")
    );
    assert!(release.body.contains("修复若干问题"));
    assert_eq!(release.source_msgtype, "release.published");
}

#[test]
fn github_workflow_run_completed_only() {
    let message = parse_event(
        "github",
        "workflow_run",
        &github_payload_with(json!({
            "action": "completed",
            "workflow_run": {
                "name": "CI",
                "conclusion": "failure",
                "head_branch": "main",
                "html_url": "https://github.com/acme/widgets/actions/runs/1",
            },
        })),
    )
    .expect("解析成功");
    assert!(
        message
            .title
            .as_deref()
            .unwrap_or_default()
            .contains("工作流 CI 失败")
    );
    assert!(message.body.contains("main"));

    assert_ignored(parse_event(
        "github",
        "workflow_run",
        &github_payload_with(json!({
            "action": "in_progress",
            "workflow_run": {"name": "CI"},
        })),
    ));
}

#[test]
fn github_workflow_job_status() {
    let message = parse_event(
        "github",
        "workflow_job",
        &github_payload_with(json!({
            "action": "completed",
            "workflow_job": {
                "name": "build",
                "status": "completed",
                "conclusion": "success",
                "head_branch": "main",
                "html_url": "https://github.com/acme/widgets/actions/runs/1/job/2",
            },
        })),
    )
    .expect("解析成功");
    assert!(
        message
            .title
            .as_deref()
            .unwrap_or_default()
            .contains("工作流任务 build 成功")
    );
    assert!(message.body.contains("main"));
    assert_eq!(message.source_msgtype, "workflow_job.completed");

    let running = parse_event(
        "github",
        "workflow_job",
        &github_payload_with(json!({
            "action": "in_progress",
            "workflow_job": {"name": "build", "status": "in_progress"},
        })),
    )
    .expect("解析成功");
    assert!(
        running
            .title
            .as_deref()
            .unwrap_or_default()
            .contains("build 进行中")
    );
}

#[test]
fn github_generic_event_and_missing_header() {
    let message = parse_event(
        "github",
        "deployment",
        &github_payload_with(json!({
            "action": "created",
            "deployment": {
                "environment": "production",
                "html_url": "https://github.com/acme/widgets/deployments/1",
            },
        })),
    )
    .expect("解析成功");
    assert_eq!(message.fmt, FMT_MARKDOWN);
    assert_eq!(message.title.as_deref(), Some("acme/widgets 部署"));
    assert!(message.body.contains("octocat"));
    assert!(message.body.contains("创建"));
    assert!(
        message
            .body
            .contains("[production](https://github.com/acme/widgets/deployments/1)")
    );
    assert_eq!(message.source_msgtype, "deployment.created");

    let unknown = parse_event(
        "github",
        "future_event",
        &github_payload_with(json!({"action": "happened"})),
    )
    .expect("解析成功");
    assert_eq!(unknown.title.as_deref(), Some("acme/widgets future_event"));
    assert!(unknown.body.contains("octocat"));
    assert_eq!(unknown.source_msgtype, "future_event.happened");

    assert_payload_error(parse_platform("github", &github_payload()));
}
