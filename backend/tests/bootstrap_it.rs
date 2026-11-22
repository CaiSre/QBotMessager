//! 启动引导集成测试。
//!
//! 覆盖 `src/bootstrap.rs` 的四个分支：
//! - 凭据齐全时创建超管，并导入默认机器人与三条通道；
//! - 重复执行幂等，不重复写入；
//! - 缺少管理员或 QQ 凭据时相应跳过；
//! - 邮箱已存在时仅在系统没有启用超管的情况下提升角色，且不改密码。
//!
//! 数据库为真实 MySQL（默认 `qbot_test_bootstrap`）。引导逻辑读写的是全局表，
//! 因此用例用进程内互斥锁串行化，并在每个用例开始时清空相关表。

mod common;

use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Duration as StdDuration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE;
use chrono::Utc;
use qbotmessager::auth::passwords::{hash_password_async, verify_password_async};
use qbotmessager::bootstrap;
use qbotmessager::config::Config;
use qbotmessager::crypto::decrypt_secret;
use qbotmessager::db::models::{
    HOOK_TYPE_DINGTALK, HOOK_TYPE_FEISHU, HOOK_TYPE_WECOM, ROLE_SUPER_ADMIN, ROLE_USER,
    STATUS_ACTIVE, STATUS_DISABLED,
};
use qbotmessager::db::queries;
use qbotmessager::db::queries::users::NewUser;
use qbotmessager::services::runtime_settings::RuntimeSettings;
use serde_json::json;
use sqlx::mysql::{MySqlPool, MySqlPoolOptions};

/// 测试管理员密码。
const ADMIN_PASSWORD: &str = "BootstrapPassw0rd!";
/// 既有账号的旧密码。
const OLD_PASSWORD: &str = "OldPassw0rd!";

/// 引导会改写全局表，进程内串行化。
static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
/// 进程内只执行一次迁移，避免并发 DDL 冲突。
static MIGRATED: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();

fn database_url() -> String {
    let url = std::env::var("MYSQL_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| {
            "mysql://qbotmessager:testpw@127.0.0.1:13306/qbot_test_bootstrap".to_string()
        });
    // 库名固定为本套件的库：与其它套件隔离，避免并跑时互相清库。
    common::with_database(&url, "qbot_test_bootstrap")
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

/// 清空引导涉及的表（先子表后父表）。
async fn reset(pool: &MySqlPool) {
    sqlx::query("DELETE FROM channels")
        .execute(pool)
        .await
        .expect("清空 channels 失败");
    sqlx::query("DELETE FROM bot_profiles")
        .execute(pool)
        .await
        .expect("清空 bot_profiles 失败");
    sqlx::query("DELETE FROM users")
        .execute(pool)
        .await
        .expect("清空 users 失败");
}

fn test_config(fernet_key: Option<String>) -> Config {
    Config {
        mysql_url: database_url(),
        app_secret_key: fernet_key,
        app_name: "QBotMessager".to_string(),
        cookie_name: "sid".to_string(),
        bootstrap_admin_email: String::new(),
        bootstrap_admin_password: String::new(),
        qq_appid: String::new(),
        qq_app_secret: String::new(),
        openids: Vec::new(),
        qq_allowed_hosts: vec!["api.bot.qq.com".to_string()],
        db_pool_size: 5,
        db_max_overflow: 5,
        db_pool_timeout: 10,
        push_queue_max: 20,
        trust_proxy: false,
        static_dir: PathBuf::from("./web/out"),
    }
}

fn suffix() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

async fn count(pool: &MySqlPool, table: &str) -> i64 {
    // sqlx 0.9 只接受静态 SQL；表名仅用于选择本文件内的常量语句。
    let sql = match table {
        "users" => "SELECT COUNT(*) FROM users",
        "bot_profiles" => "SELECT COUNT(*) FROM bot_profiles",
        "channels" => "SELECT COUNT(*) FROM channels",
        other => panic!("未登记的表名：{other}"),
    };
    let (total,): (i64,) = sqlx::query_as(sql)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|err| panic!("统计 {table} 失败：{err}"));
    total
}

/// 创建一条既有账号，返回其 id 与密码哈希。
async fn insert_user(pool: &MySqlPool, email: &str, role: &str, status: &str) -> (i64, String) {
    let password_hash = hash_password_async(OLD_PASSWORD)
        .await
        .expect("生成密码哈希失败");
    let id = queries::users::insert(
        pool,
        &NewUser {
            email,
            name: &format!("u{}", suffix()),
            password_hash: Some(&password_hash),
            role,
            status,
            created_at: Utc::now().naive_utc(),
        },
    )
    .await
    .expect("插入测试账号失败");
    (id, password_hash)
}

// --------------------------------------------------------------------------- 用例

/// 凭据齐全：创建超管、写入默认机器人与三条通道，密文可解密。
#[tokio::test]
async fn creates_admin_bot_and_channels() {
    let _guard = TEST_LOCK.lock().await;
    let pool = test_pool().await;
    reset(&pool).await;

    let suffix = suffix();
    let email = format!("Boot{suffix}@Example.COM");
    let normalized = email.trim().to_lowercase();
    let key = URL_SAFE.encode([7u8; 32]);
    let mut config = test_config(Some(key.clone()));
    config.bootstrap_admin_email = email;
    config.bootstrap_admin_password = ADMIN_PASSWORD.to_string();
    config.qq_appid = "102000001".to_string();
    config.qq_app_secret = "bootstrap-app-secret".to_string();
    config.openids = vec!["openid-a".to_string(), "openid-b".to_string()];
    let runtime = RuntimeSettings::new(Some(key.clone()));

    let summary = bootstrap::run(&pool, &config, &runtime)
        .await
        .expect("启动引导失败");

    assert_eq!(summary.admin_created.as_deref(), Some(normalized.as_str()));
    assert!(summary.admin_promoted.is_none());
    assert!(summary.bot_created);

    let user = queries::users::find_by_email(&pool, &normalized)
        .await
        .expect("查询账号失败")
        .expect("未创建超管账号");
    assert_eq!(user.role, ROLE_SUPER_ADMIN);
    assert_eq!(user.status, STATUS_ACTIVE);
    assert_eq!(user.name, format!("boot{suffix}"));
    assert!(
        verify_password_async(
            ADMIN_PASSWORD,
            user.password_hash.as_deref().expect("缺少密码哈希")
        )
        .await,
        "引导写入的密码无法校验"
    );

    let bots = queries::bots::list(&pool, Some(user.id))
        .await
        .expect("查询机器人失败");
    assert_eq!(bots.len(), 1);
    let bot = &bots[0];
    assert_eq!(bot.name, "默认机器人");
    assert_eq!(bot.qq_appid, "102000001");
    assert_eq!(bot.qq_host, runtime.qq_host());
    assert_eq!(bot.default_openids, json!(["openid-a", "openid-b"]));
    assert!(bot.enabled);
    assert!(
        bot.qq_app_secret.starts_with("enc1:"),
        "AppSecret 未加密：{}",
        bot.qq_app_secret
    );
    assert_eq!(
        decrypt_secret(&bot.qq_app_secret, Some(key.as_str())).expect("解密失败"),
        "bootstrap-app-secret"
    );

    let channels = queries::channels::list_for_bot(&pool, bot.id)
        .await
        .expect("查询通道失败");
    assert_eq!(channels.len(), 3);
    let mut hook_types: Vec<&str> = channels.iter().map(|c| c.hook_type.as_str()).collect();
    hook_types.sort_unstable();
    let mut expected = vec![HOOK_TYPE_DINGTALK, HOOK_TYPE_FEISHU, HOOK_TYPE_WECOM];
    expected.sort_unstable();
    assert_eq!(hook_types, expected);
    let tokens: HashSet<&str> = channels.iter().map(|c| c.webhook_token.as_str()).collect();
    assert_eq!(tokens.len(), 3, "通道凭据必须互不相同");
    for channel in &channels {
        assert_eq!(
            channel.webhook_token.len(),
            32,
            "24 字节 token 应为 32 字符"
        );
        assert!(channel.enabled);
        assert_eq!(channel.push_source, "", "默认通道的推送来源应为空");
    }
}

/// 同一配置重复执行：不再写入任何行。
#[tokio::test]
async fn rerun_is_idempotent() {
    let _guard = TEST_LOCK.lock().await;
    let pool = test_pool().await;
    reset(&pool).await;

    let suffix = suffix();
    let email = format!("boot{suffix}@example.com");
    let key = URL_SAFE.encode([8u8; 32]);
    let mut config = test_config(Some(key.clone()));
    config.bootstrap_admin_email = email.clone();
    config.bootstrap_admin_password = ADMIN_PASSWORD.to_string();
    config.qq_appid = "102000002".to_string();
    config.qq_app_secret = "bootstrap-app-secret".to_string();
    let runtime = RuntimeSettings::new(Some(key));

    let first = bootstrap::run(&pool, &config, &runtime)
        .await
        .expect("首次引导失败");
    assert_eq!(first.admin_created.as_deref(), Some(email.as_str()));
    assert!(first.bot_created);

    let second = bootstrap::run(&pool, &config, &runtime)
        .await
        .expect("重复引导失败");
    assert!(second.admin_created.is_none());
    assert!(second.admin_promoted.is_none());
    assert!(!second.bot_created);

    assert_eq!(count(&pool, "users").await, 1);
    assert_eq!(count(&pool, "bot_profiles").await, 1);
    assert_eq!(count(&pool, "channels").await, 3);
}

/// 未配置管理员凭据：不创建账号，也不导入机器人。
#[tokio::test]
async fn skips_without_admin_credentials() {
    let _guard = TEST_LOCK.lock().await;
    let pool = test_pool().await;
    reset(&pool).await;

    let mut config = test_config(None);
    config.qq_appid = "102000003".to_string();
    config.qq_app_secret = "bootstrap-app-secret".to_string();
    let runtime = RuntimeSettings::new(None);

    let summary = bootstrap::run(&pool, &config, &runtime)
        .await
        .expect("启动引导失败");

    assert!(summary.admin_created.is_none());
    assert!(summary.admin_promoted.is_none());
    assert!(!summary.bot_created);
    assert_eq!(count(&pool, "users").await, 0);
    assert_eq!(count(&pool, "bot_profiles").await, 0);
}

/// 有管理员但缺少 QQ 凭据：只创建账号，不导入机器人。
#[tokio::test]
async fn creates_admin_without_qq_credentials() {
    let _guard = TEST_LOCK.lock().await;
    let pool = test_pool().await;
    reset(&pool).await;

    let email = format!("boot{}@example.com", suffix());
    let mut config = test_config(None);
    config.bootstrap_admin_email = email.clone();
    config.bootstrap_admin_password = ADMIN_PASSWORD.to_string();
    let runtime = RuntimeSettings::new(None);

    let summary = bootstrap::run(&pool, &config, &runtime)
        .await
        .expect("启动引导失败");

    assert_eq!(summary.admin_created.as_deref(), Some(email.as_str()));
    assert!(!summary.bot_created);
    assert_eq!(count(&pool, "users").await, 1);
    assert_eq!(count(&pool, "bot_profiles").await, 0);
    assert_eq!(count(&pool, "channels").await, 0);
}

/// 邮箱已存在且系统没有启用超管：提升为超管，保留原密码，并为该账号导入机器人。
#[tokio::test]
async fn promotes_existing_user_without_active_super_admin() {
    let _guard = TEST_LOCK.lock().await;
    let pool = test_pool().await;
    reset(&pool).await;

    let email = format!("boot{}@example.com", suffix());
    let (user_id, original_hash) = insert_user(&pool, &email, ROLE_USER, STATUS_ACTIVE).await;

    let key = URL_SAFE.encode([9u8; 32]);
    let mut config = test_config(Some(key));
    config.bootstrap_admin_email = email.to_uppercase();
    config.bootstrap_admin_password = ADMIN_PASSWORD.to_string();
    config.qq_appid = "102000004".to_string();
    config.qq_app_secret = "bootstrap-app-secret".to_string();
    let runtime = RuntimeSettings::new(None);

    let summary = bootstrap::run(&pool, &config, &runtime)
        .await
        .expect("启动引导失败");

    assert!(summary.admin_created.is_none());
    assert_eq!(summary.admin_promoted.as_deref(), Some(email.as_str()));
    assert!(summary.bot_created);

    let user = queries::users::find_by_id(&pool, user_id)
        .await
        .expect("查询账号失败")
        .expect("账号丢失");
    assert_eq!(user.role, ROLE_SUPER_ADMIN);
    assert_eq!(user.password_hash.as_deref(), Some(original_hash.as_str()));
    assert!(verify_password_async(OLD_PASSWORD, &original_hash).await);
    assert!(!verify_password_async(ADMIN_PASSWORD, &original_hash).await);

    let bots = queries::bots::list(&pool, Some(user_id))
        .await
        .expect("查询机器人失败");
    assert_eq!(bots.len(), 1);
}

/// 已存在其他启用的超管：普通账号保持原角色。
#[tokio::test]
async fn keeps_role_when_another_active_super_admin_exists() {
    let _guard = TEST_LOCK.lock().await;
    let pool = test_pool().await;
    reset(&pool).await;

    let other_email = format!("root{}@example.com", suffix());
    insert_user(&pool, &other_email, ROLE_SUPER_ADMIN, STATUS_ACTIVE).await;
    let email = format!("boot{}@example.com", suffix());
    let (user_id, _) = insert_user(&pool, &email, ROLE_USER, STATUS_ACTIVE).await;

    let mut config = test_config(None);
    config.bootstrap_admin_email = email;
    config.bootstrap_admin_password = ADMIN_PASSWORD.to_string();
    let runtime = RuntimeSettings::new(None);

    let summary = bootstrap::run(&pool, &config, &runtime)
        .await
        .expect("启动引导失败");

    assert!(summary.admin_created.is_none());
    assert!(summary.admin_promoted.is_none());
    let user = queries::users::find_by_id(&pool, user_id)
        .await
        .expect("查询账号失败")
        .expect("账号丢失");
    assert_eq!(user.role, ROLE_USER);
}

/// 唯一的超管已禁用：仍视为「没有可用超管」，提升目标账号。
#[tokio::test]
async fn promotes_when_existing_super_admin_is_disabled() {
    let _guard = TEST_LOCK.lock().await;
    let pool = test_pool().await;
    reset(&pool).await;

    let other_email = format!("root{}@example.com", suffix());
    insert_user(&pool, &other_email, ROLE_SUPER_ADMIN, STATUS_DISABLED).await;
    let email = format!("boot{}@example.com", suffix());
    let (user_id, _) = insert_user(&pool, &email, ROLE_USER, STATUS_ACTIVE).await;

    let mut config = test_config(None);
    config.bootstrap_admin_email = email.clone();
    config.bootstrap_admin_password = ADMIN_PASSWORD.to_string();
    let runtime = RuntimeSettings::new(None);

    let summary = bootstrap::run(&pool, &config, &runtime)
        .await
        .expect("启动引导失败");

    assert_eq!(summary.admin_promoted.as_deref(), Some(email.as_str()));
    let user = queries::users::find_by_id(&pool, user_id)
        .await
        .expect("查询账号失败")
        .expect("账号丢失");
    assert_eq!(user.role, ROLE_SUPER_ADMIN);
}
