//! 数据保留集成测试。
//!
//! 使用真实 MySQL 验证各表按保留天数删除、推送日志预览单独清空，
//! 以及未过期/最近数据不受影响。

mod common;

use std::time::Duration as StdDuration;

use chrono::{Duration, Utc};
use qbotmessager::config::RetentionPolicy;
use qbotmessager::services::retention;
use sqlx::mysql::{MySqlPool, MySqlPoolOptions};

static MIGRATED: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();

fn database_url() -> String {
    let url = std::env::var("MYSQL_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| {
            "mysql://qbotmessager:testpw@127.0.0.1:13306/qbot_test_retention".to_string()
        });
    common::with_database(&url, "qbot_test_retention")
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
        .max_connections(5)
        .acquire_timeout(StdDuration::from_secs(15))
        .connect(&database_url())
        .await
        .expect("连接测试 MySQL 失败（请设置 MYSQL_URL）")
}

async fn count(pool: &MySqlPool, sql: &'static str, value: &str) -> i64 {
    sqlx::query_scalar(sql)
        .bind(value)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|err| panic!("统计失败：{err}"))
}

#[tokio::test]
async fn cleanup_respects_retention_days_and_clears_previews() {
    let pool = test_pool().await;
    let now = Utc::now().naive_utc();
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let email = format!("retention-{suffix}@example.com");
    let audit_target = format!("audit-{suffix}");
    let request_old = format!("push-old-{suffix}");
    let request_recent = format!("push-recent-{suffix}");
    let request_fresh = format!("push-fresh-{suffix}");

    let user_id = sqlx::query(
        "INSERT INTO users (email, name, password_hash, role, status, created_at) \
         VALUES (?, ?, NULL, 'user', 'active', ?)",
    )
    .bind(&email)
    .bind(format!("retention-{suffix}"))
    .bind(now)
    .execute(&pool)
    .await
    .expect("插入测试用户失败")
    .last_insert_id();

    let token_old = format!("{suffix}old");
    let token_revoked = format!("{suffix}revoked");
    let token_active = format!("{suffix}active");
    for (token, expires_at, revoked_at) in [
        (&token_old, now - Duration::days(40), None),
        (
            &token_revoked,
            now + Duration::days(1),
            Some(now - Duration::days(40)),
        ),
        (&token_active, now + Duration::days(1), None),
    ] {
        sqlx::query(
            "INSERT INTO sessions (token_hash, user_id, expires_at, revoked_at, created_at) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(token)
        .bind(user_id)
        .bind(expires_at)
        .bind(revoked_at)
        .bind(now - Duration::days(40))
        .execute(&pool)
        .await
        .expect("插入会话失败");
    }

    sqlx::query(
        "INSERT INTO email_verification_codes \
         (email, purpose, code_hash, expires_at, attempts, created_at) \
         VALUES (?, 'register', 'old', ?, 0, ?), (?, 'register', 'new', ?, 0, ?)",
    )
    .bind(&email)
    .bind(now - Duration::days(10))
    .bind(now - Duration::days(10))
    .bind(&email)
    .bind(now + Duration::days(1))
    .bind(now)
    .execute(&pool)
    .await
    .expect("插入验证码失败");

    sqlx::query(
        "INSERT INTO email_code_guards (email, purpose, updated_at) \
         VALUES (?, 'register', ?), (?, 'reset_password', ?)",
    )
    .bind(&email)
    .bind(now - Duration::days(10))
    .bind(&email)
    .bind(now)
    .execute(&pool)
    .await
    .expect("插入发码守卫失败");

    sqlx::query(
        "INSERT INTO admin_audit_logs (actor_user_id, action, target_id, created_at) \
         VALUES (?, 'test.old', ?, ?), (?, 'test.new', ?, ?)",
    )
    .bind(user_id)
    .bind(&audit_target)
    .bind(now - Duration::days(200))
    .bind(user_id)
    .bind(&audit_target)
    .bind(now)
    .execute(&pool)
    .await
    .expect("插入审计日志失败");

    for (request_id, created_at, preview) in [
        (&request_old, now - Duration::days(100), "old-secret"),
        (&request_recent, now - Duration::days(10), "recent-secret"),
        (&request_fresh, now - Duration::days(1), "fresh-secret"),
    ] {
        sqlx::query(
            "INSERT INTO push_logs \
             (owner_user_id, hook_type, push_source, source_msgtype, target, \
              content_preview, content_len, status, duration_ms, request_id, created_at) \
             VALUES (?, 'github', 'test', 'push', 'openid', ?, ?, 'success', 1, ?, ?)",
        )
        .bind(user_id)
        .bind(preview)
        .bind(preview.len() as i32)
        .bind(request_id)
        .bind(created_at)
        .execute(&pool)
        .await
        .expect("插入推送日志失败");
    }

    let policy = RetentionPolicy {
        sessions_days: 30,
        email_codes_days: 7,
        email_guards_days: 7,
        audit_days: 180,
        push_logs_days: 90,
        push_preview_days: 7,
        interval_hours: 24,
    };
    let report = retention::cleanup_once(&pool, &policy, now)
        .await
        .expect("执行保留清理失败");

    assert!(report.sessions >= 2, "{report:?}");
    assert!(report.email_codes >= 1, "{report:?}");
    assert!(report.email_guards >= 1, "{report:?}");
    assert!(report.audit_logs >= 1, "{report:?}");
    assert!(report.push_logs >= 1, "{report:?}");
    assert!(report.push_previews_cleared >= 1, "{report:?}");

    for (token, expected) in [(&token_old, 0), (&token_revoked, 0), (&token_active, 1)] {
        assert_eq!(
            count(
                &pool,
                "SELECT COUNT(*) FROM sessions WHERE token_hash = ?",
                token
            )
            .await,
            expected,
            "会话 {token} 保留结果不符"
        );
    }

    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) FROM email_verification_codes WHERE email = ?",
            &email
        )
        .await,
        1,
        "只应保留最近的验证码"
    );
    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) FROM email_code_guards WHERE email = ?",
            &email
        )
        .await,
        1,
        "只应保留最近使用的发码守卫"
    );
    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) FROM admin_audit_logs WHERE target_id = ?",
            &audit_target
        )
        .await,
        1,
        "只应保留最近的管理审计日志"
    );
    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) FROM push_logs WHERE request_id = ?",
            &request_old
        )
        .await,
        0,
        "超过保留期的推送日志应删除"
    );
    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) FROM push_logs WHERE request_id = ? AND content_preview = ''",
            &request_recent
        )
        .await,
        1,
        "保留期内但超过预览期的日志应清空预览"
    );
    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) FROM push_logs WHERE request_id = ? AND content_preview = 'fresh-secret'",
            &request_fresh
        )
        .await,
        1,
        "预览保留期内的日志不应清空"
    );

    // 清理幂等：第二次没有可删行，也不影响剩余数据。
    let again = retention::cleanup_once(&pool, &policy, now)
        .await
        .expect("重复执行保留清理失败");
    assert_eq!(again.sessions, 0);
    assert_eq!(again.email_codes, 0);
    assert_eq!(again.email_guards, 0);
    assert_eq!(again.audit_logs, 0);
    assert_eq!(again.push_logs, 0);
    assert_eq!(again.push_previews_cleared, 0);
}
