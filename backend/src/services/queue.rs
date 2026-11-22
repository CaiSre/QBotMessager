//! 推送任务队列：MySQL 队列（apalis + apalis-mysql）与幂等守卫。
//!
//! Webhook 只做校验与入队后立即确认，实际发送由 worker 按频控节奏完成；
//! 队列不可用时上层降级为同步发送（GitHub 不重投，始终走同步回退）。
//!
//! 幂等守卫（原 Redis `saq:sent:{key}`）改为 MySQL 表 `sent_guards`：
//! - key = `{request_id}:{target_label}`；
//! - TTL 900s；用 `INSERT IGNORE` 判首次；读取失败按「未发送」处理；
//! - worker 内定时任务清理过期行。

use std::time::Duration;

use apalis::prelude::{TaskBuilder, TaskSink, TaskSinkError};
use apalis_mysql::MySqlStorage;
use chrono::{Duration as ChronoDuration, NaiveDateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::MySqlPool;

use crate::error::AppError;
use crate::services::push::PushJob;

/// 队列任务类型（apalis 的 `job_type`）。
pub const QUEUE_NAME: &str = "push";

/// 队列积压默认上限。
pub const DEFAULT_MAX_PENDING: usize = 200;
/// 入队超过该秒数仍未开始的任务直接丢弃。
pub const JOB_EXPIRES_SECONDS: u64 = 900;
/// 单个任务的执行上限（秒）。
pub const JOB_TIMEOUT_SECONDS: u64 = 180;
/// 额外重试次数（最多尝试 `JOB_RETRIES + 1` 次）。
pub const JOB_RETRIES: usize = 2;
/// 固定重试间隔（秒）。
pub const JOB_RETRY_DELAY_SECONDS: u64 = 5;
/// 幂等守卫 TTL（秒）。
pub const SENT_GUARD_TTL_SECONDS: u64 = 900;
/// 去重键在 `jobs.idempotency_key` 列中的最大长度（`varchar(36)`）。
pub const DEDUPE_KEY_MAX_LEN: usize = 36;

/// 队列操作错误。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum QueueError {
    /// 积压达到上限。
    #[error("推送队列积压已达 {0}")]
    Full(usize),
    /// 队列后端不可用。
    #[error("推送队列不可用：{0}")]
    Backend(String),
}

/// 推送队列。
pub struct PushQueue {
    /// apalis 的 MySQL 存储；`push_task` 需要 `&mut`，故用互斥锁保护。
    storage: tokio::sync::Mutex<MySqlStorage<PushJob>>,
    pool: MySqlPool,
    max_pending: usize,
}

impl PushQueue {
    /// 连接队列：建表并构造后端。
    pub async fn connect(pool: MySqlPool, max_pending: usize) -> Result<Self, QueueError> {
        MySqlStorage::<()>::setup(&pool)
            .await
            .map_err(|err| QueueError::Backend(err.to_string()))?;

        // 默认队列名取自 `Args` 的类型名，这里统一固定为 `push`，
        // 保证 Web 进程入队与 worker 消费的是同一个队列。
        let config = apalis_mysql::Config::default().queue(QUEUE_NAME);
        let storage = MySqlStorage::<PushJob>::new(&pool).with_config(config);

        Ok(Self {
            storage: tokio::sync::Mutex::new(storage),
            pool,
            max_pending,
        })
    }

    /// 队列使用的数据库连接池。
    pub fn pool(&self) -> &MySqlPool {
        &self.pool
    }

    /// 积压上限。
    pub fn max_pending(&self) -> usize {
        self.max_pending
    }

    /// 当前积压（`status = 'Pending'` 的任务数）。
    pub async fn pending(&self) -> Result<usize, QueueError> {
        let count: i64 = sqlx::query_scalar(
            "SELECT CAST(COUNT(*) AS SIGNED) FROM jobs \
             WHERE job_type = ? AND status = 'Pending'",
        )
        .bind(QUEUE_NAME)
        .fetch_one(&self.pool)
        .await
        .map_err(|err| QueueError::Backend(err.to_string()))?;
        Ok(count.max(0) as usize)
    }

    /// 入队；返回 `false` 表示同一投递仍在队列中（重复投递）。
    pub async fn enqueue(&self, job: PushJob, job_id: &str) -> Result<bool, QueueError> {
        // SAQ 没有排队过期机制：停机后重新拉起时，过旧的推送已无意义，直接丢弃。
        purge_expired_pending(&self.pool)
            .await
            .map_err(|err| QueueError::Backend(err.to_string()))?;

        if self.pending().await? >= self.max_pending {
            return Err(QueueError::Full(self.max_pending));
        }

        // 旧 SAQ 的 key 只约束「排队中/执行中」的任务：推送完成后的重复投递会重新入队，
        // 再由 SentGuard 跳过已成功的目标。MySQL 的 (job_type, idempotency_key) 唯一索引
        // 会把已结束的任务也算进去，所以这里先清掉同一键下已结束的行。
        sqlx::query(
            "DELETE FROM jobs WHERE job_type = ? AND idempotency_key = ? \
             AND status IN ('Done', 'Failed')",
        )
        .bind(QUEUE_NAME)
        .bind(job_id)
        .execute(&self.pool)
        .await
        .map_err(|err| QueueError::Backend(err.to_string()))?;

        // 重试由 worker 的 retry 中间件完成（固定 5 秒、共 3 次尝试），
        // 因此这里把数据库层的最大尝试次数固定为 1，避免中间件耗尽后又被重新取出。
        let task = TaskBuilder::new(job)
            .idempotency_key(job_id)
            .max_attempts(1)
            .build();

        let mut storage = self.storage.lock().await;
        match storage.push_task(task).await {
            Ok(()) => Ok(true),
            // 并发入队时唯一索引冲突：同一投递已经在队列里。
            Err(err) if is_duplicate_key(&err) => Ok(false),
            Err(err) => Err(QueueError::Backend(err.to_string())),
        }
    }
}

/// 删除入队超过 [`JOB_EXPIRES_SECONDS`] 仍未开始的任务。
///
/// 旧实现按 SAQ 任务的 `queued` 时间在执行时判断；MySQL 队列没有该字段，
/// 但 `jobs.run_at` 在入队时写入，等价于排队起始时间。
pub async fn purge_expired_pending(pool: &MySqlPool) -> Result<u64, sqlx::Error> {
    let cutoff = Utc::now().naive_utc() - ChronoDuration::seconds(JOB_EXPIRES_SECONDS as i64);
    let result = sqlx::query(
        "DELETE FROM jobs WHERE job_type = ? AND status IN ('Pending', 'Queued') \
         AND run_at < ?",
    )
    .bind(QUEUE_NAME)
    .bind(cutoff)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// 是否为唯一索引冲突（MySQL 1062）。
fn is_duplicate_key(err: &TaskSinkError<apalis_mysql::Error>) -> bool {
    match err {
        TaskSinkError::PushError(apalis_mysql::Error::Database(sqlx::Error::Database(db_err))) => {
            db_err.is_unique_violation()
        }
        _ => false,
    }
}

/// 记录已成功推送的目标（apalis 至少一次语义下的幂等守卫）。
#[derive(Debug, Clone)]
pub struct SentGuard {
    pool: MySqlPool,
    ttl_seconds: u64,
}

impl SentGuard {
    /// 用默认 TTL 创建。
    pub fn new(pool: MySqlPool) -> Self {
        Self {
            pool,
            ttl_seconds: SENT_GUARD_TTL_SECONDS,
        }
    }

    /// 指定 TTL 创建。
    pub fn with_ttl(pool: MySqlPool, ttl_seconds: u64) -> Self {
        Self { pool, ttl_seconds }
    }

    /// 守卫 TTL。
    pub fn ttl_seconds(&self) -> u64 {
        self.ttl_seconds
    }

    /// 该目标是否已经在上一轮发送成功。
    ///
    /// 与 Redis `EXISTS` 一致：过期行即使尚未被清理也视为未发送。
    pub async fn done(&self, guard_key: &str) -> Result<bool, AppError> {
        let row: Option<(NaiveDateTime,)> =
            sqlx::query_as("SELECT expires_at FROM sent_guards WHERE guard_key = ?")
                .bind(guard_key)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.is_some_and(|(expires_at,)| guard_valid(expires_at, Utc::now().naive_utc())))
    }

    /// 标记该目标已发送成功。
    pub async fn mark(&self, guard_key: &str) -> Result<(), AppError> {
        let now = Utc::now().naive_utc();
        let expires_at = guard_expiry(now, self.ttl_seconds);
        // Redis `SET ... EX` 会刷新 TTL；重复标记（例如读取标记失败后的重发）同样刷新过期时间。
        sqlx::query(
            "INSERT INTO sent_guards (guard_key, expires_at, created_at) VALUES (?, ?, ?) \
             ON DUPLICATE KEY UPDATE expires_at = VALUES(expires_at)",
        )
        .bind(guard_key)
        .bind(expires_at)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// 清理过期行，返回删除数量。
    pub async fn cleanup_expired(&self) -> Result<u64, AppError> {
        let now = Utc::now().naive_utc();
        let result = sqlx::query("DELETE FROM sent_guards WHERE expires_at <= ?")
            .bind(now)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }
}

/// 守卫行是否仍在有效期内。
fn guard_valid(expires_at: NaiveDateTime, now: NaiveDateTime) -> bool {
    expires_at > now
}

/// 计算守卫的过期时间。
fn guard_expiry(now: NaiveDateTime, ttl_seconds: u64) -> NaiveDateTime {
    now + ChronoDuration::seconds(ttl_seconds as i64)
}

/// 计算可放进 `jobs.idempotency_key`（`varchar(36)`）的去重键。
///
/// 规格书原始形态是 `push:<sha256(platform:delivery_id)>`（Redis 无长度限制）；
/// MySQL 列只有 36 字符，这里保留完整 SHA-256 的语义，取十六进制摘要前 36 位。
/// 无 delivery_id 时退化为 `sha256("push:" + request_id)`。
pub fn dedupe_key(platform: &str, delivery_id: Option<&str>, request_id: &str) -> String {
    let raw = match delivery_id {
        Some(delivery_id) => format!("push:{platform}:{delivery_id}"),
        None => format!("push:{request_id}"),
    };
    let digest = Sha256::digest(raw.as_bytes());
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    hex[..DEDUPE_KEY_MAX_LEN].to_string()
}

/// 任务超时。
pub fn job_timeout() -> Duration {
    Duration::from_secs(JOB_TIMEOUT_SECONDS)
}

/// 重试间隔。
pub fn job_retry_delay() -> Duration {
    Duration::from_secs(JOB_RETRY_DELAY_SECONDS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;

    fn at(hours: i64) -> NaiveDateTime {
        NaiveDate::from_ymd_opt(2026, 1, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap()
            + ChronoDuration::hours(hours)
    }

    #[test]
    fn dedupe_key_is_stable_and_fits_column() {
        let key = dedupe_key("github", Some("delivery-1"), "request-a");
        assert_eq!(key.len(), DEDUPE_KEY_MAX_LEN);
        // 相同的平台与投递 ID 必须得到同一个键，与 request_id 无关（平台会重投同一条消息）。
        assert_eq!(key, dedupe_key("github", Some("delivery-1"), "request-b"));
        // 硬编码值锁定摘要算法：sha256("push:github:delivery-1") 的前 36 位。
        assert_eq!(key, "b53f51f012003193e020f3fd7a18e608e2fd");
    }

    #[test]
    fn dedupe_key_distinguishes_platform_and_delivery() {
        assert_ne!(
            dedupe_key("github", Some("same"), "r"),
            dedupe_key("feishu", Some("same"), "r")
        );
        assert_ne!(
            dedupe_key("github", Some("a"), "r"),
            dedupe_key("github", Some("b"), "r")
        );
    }

    #[test]
    fn dedupe_key_falls_back_to_request_id() {
        let key = dedupe_key("dingtalk", None, "request-1");
        assert_eq!(key.len(), DEDUPE_KEY_MAX_LEN);
        assert_eq!(key, dedupe_key("dingtalk", None, "request-1"));
        assert_ne!(key, dedupe_key("dingtalk", None, "request-2"));
    }

    #[test]
    fn sent_guard_hit_and_expiry() {
        let now = at(0);
        let expires_at = guard_expiry(now, SENT_GUARD_TTL_SECONDS);
        // 未到期：命中去重
        assert!(guard_valid(expires_at, now));
        assert!(guard_valid(
            expires_at,
            at(0) + ChronoDuration::seconds(899)
        ));
        // 到期即失效（Redis EXPIRE 语义：不包含过期时刻）
        assert!(!guard_valid(expires_at, expires_at));
        assert!(!guard_valid(
            expires_at,
            expires_at + ChronoDuration::seconds(1)
        ));
        // TTL 为 0 时立即过期
        assert!(!guard_valid(guard_expiry(now, 0), now));
    }
}
