//! 数据保留：按天数清理过期会话、验证码、审计与推送日志。
//!
//! 由 worker 内的定时任务执行，避免 Web 线程承担批量删除；
//! 每张表按小批次删除并让出执行权，长时间运行的实例也能持续收敛。
//! 天数配置为 0 表示关闭该类数据的清理。

use chrono::{Duration, NaiveDateTime};
use sqlx::MySqlPool;

use crate::config::RetentionPolicy;
use crate::error::AppError;

/// 单批删除行数；批次越小，持有锁的时间越短。
pub const BATCH_SIZE: u64 = 1000;

/// 一次清理的结果。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RetentionReport {
    /// 删除的会话数。
    pub sessions: u64,
    /// 删除的邮箱验证码数。
    pub email_codes: u64,
    /// 删除的发码守卫行数。
    pub email_guards: u64,
    /// 删除的管理审计日志数。
    pub audit_logs: u64,
    /// 删除的推送日志数。
    pub push_logs: u64,
    /// 被清空内容预览的推送日志数。
    pub push_previews_cleared: u64,
}

impl RetentionReport {
    /// 是否发生了任何清理（包括清空内容预览）。
    pub fn is_empty(&self) -> bool {
        self.total() == 0
    }

    /// 清理行数合计。
    pub fn total(&self) -> u64 {
        self.sessions
            + self.email_codes
            + self.email_guards
            + self.audit_logs
            + self.push_logs
            + self.push_previews_cleared
    }
}

/// 执行一次保留清理。
///
/// `now` 由调用方注入，便于测试固定时间；生产传入 UTC 当前时间。
pub async fn cleanup_once(
    pool: &MySqlPool,
    policy: &RetentionPolicy,
    now: NaiveDateTime,
) -> Result<RetentionReport, AppError> {
    let mut report = RetentionReport::default();

    if policy.sessions_days > 0 {
        let cutoff = now - Duration::days(i64::from(policy.sessions_days));
        report.sessions = delete_sessions(pool, cutoff).await?;
    }

    if policy.email_codes_days > 0 {
        let cutoff = now - Duration::days(i64::from(policy.email_codes_days));
        report.email_codes = delete_batches(
            pool,
            "DELETE FROM email_verification_codes WHERE created_at < ? LIMIT ?",
            cutoff,
        )
        .await?;
    }

    if policy.email_guards_days > 0 {
        let cutoff = now - Duration::days(i64::from(policy.email_guards_days));
        report.email_guards = delete_batches(
            pool,
            "DELETE FROM email_code_guards WHERE updated_at < ? LIMIT ?",
            cutoff,
        )
        .await?;
    }

    if policy.audit_days > 0 {
        let cutoff = now - Duration::days(i64::from(policy.audit_days));
        report.audit_logs = delete_batches(
            pool,
            "DELETE FROM admin_audit_logs WHERE created_at < ? LIMIT ?",
            cutoff,
        )
        .await?;
    }

    if policy.push_logs_days > 0 {
        let cutoff = now - Duration::days(i64::from(policy.push_logs_days));
        report.push_logs = delete_batches(
            pool,
            "DELETE FROM push_logs WHERE created_at < ? LIMIT ?",
            cutoff,
        )
        .await?;
    }

    // 日志本身仍在保留期内时，单独清空消息片段，兼顾排查与隐私。
    if policy.push_preview_days > 0 {
        let cutoff = now - Duration::days(i64::from(policy.push_preview_days));
        report.push_previews_cleared = clear_previews(pool, cutoff).await?;
    }

    Ok(report)
}

/// 分批删除已过期或已撤销超过保留期的会话。
async fn delete_sessions(pool: &MySqlPool, cutoff: NaiveDateTime) -> Result<u64, AppError> {
    let mut removed = 0_u64;
    loop {
        let result =
            sqlx::query("DELETE FROM sessions WHERE expires_at < ? OR revoked_at < ? LIMIT ?")
                .bind(cutoff)
                .bind(cutoff)
                .bind(BATCH_SIZE as i64)
                .execute(pool)
                .await?;
        let affected = result.rows_affected();
        removed += affected;
        if affected < BATCH_SIZE {
            return Ok(removed);
        }
        tokio::task::yield_now().await;
    }
}

/// 分批删除，直到没有更多匹配行。
async fn delete_batches(
    pool: &MySqlPool,
    sql: &'static str,
    cutoff: NaiveDateTime,
) -> Result<u64, AppError> {
    let mut removed = 0_u64;
    loop {
        let result = sqlx::query(sql)
            .bind(cutoff)
            .bind(BATCH_SIZE as i64)
            .execute(pool)
            .await?;
        let affected = result.rows_affected();
        removed += affected;
        if affected < BATCH_SIZE {
            return Ok(removed);
        }
        // 大批量清理时给其它数据库操作让路。
        tokio::task::yield_now().await;
    }
}

/// 分批清空过期日志的内容预览。
async fn clear_previews(pool: &MySqlPool, cutoff: NaiveDateTime) -> Result<u64, AppError> {
    let mut cleared = 0_u64;
    loop {
        let result = sqlx::query(
            "UPDATE push_logs SET content_preview = '' \
             WHERE created_at < ? AND content_preview <> '' LIMIT ?",
        )
        .bind(cutoff)
        .bind(BATCH_SIZE as i64)
        .execute(pool)
        .await?;
        let affected = result.rows_affected();
        cleared += affected;
        if affected < BATCH_SIZE {
            return Ok(cleared);
        }
        tokio::task::yield_now().await;
    }
}

/// 启动保留清理循环；策略全部关闭时立即返回。
pub async fn run(pool: MySqlPool, policy: RetentionPolicy) {
    if !policy.enabled() {
        tracing::debug!("数据保留策略全部关闭，跳过清理任务");
        return;
    }

    let interval_hours = policy.interval_hours.max(1);
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(
        u64::from(interval_hours) * 3600,
    ));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        ticker.tick().await;
        match cleanup_once(&pool, &policy, chrono::Utc::now().naive_utc()).await {
            Ok(report) if !report.is_empty() => tracing::info!(
                sessions = report.sessions,
                email_codes = report.email_codes,
                email_guards = report.email_guards,
                audit_logs = report.audit_logs,
                push_logs = report.push_logs,
                push_previews_cleared = report.push_previews_cleared,
                "已清理过期数据"
            ),
            Ok(_) => {}
            Err(err) => tracing::warn!(error = %err, "清理过期数据失败"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_sums_all_cleanup_rows() {
        let report = RetentionReport {
            sessions: 1,
            email_codes: 2,
            email_guards: 3,
            audit_logs: 4,
            push_logs: 5,
            push_previews_cleared: 6,
        };
        assert_eq!(report.total(), 21);
        assert!(!report.is_empty());
    }

    #[test]
    fn preview_only_cleanup_is_not_empty() {
        let report = RetentionReport {
            push_previews_cleared: 1,
            ..Default::default()
        };
        assert!(!report.is_empty());
    }
}
