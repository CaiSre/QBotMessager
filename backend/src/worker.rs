//! 推送 worker：apalis + MySQL 队列，按频控节奏执行 Webhook 推送任务。
//!
//! 与 Web 进程共用 [`AppState`]，但必须单进程运行（QQ 频控是机器人账号级）。
//!
//! 设计要点：
//! - 任务超时 180s、重试 2 次（最多 3 次尝试）、固定 5s 重试间隔；
//! - 每分钟同步一次库内设置，让频控参数在 worker 内生效；
//! - 定期清理 `sent_guards` 过期行。
//! - 启动时回收崩溃残留的 worker 注册行与在跑任务。

use std::sync::Arc;
use std::time::Duration;

use apalis::prelude::{Data, Task, WorkerBuilder, WorkerBuilderExt, WorkerContext};
use apalis_mysql::MySqlStorage;
use tokio::task::JoinHandle;
use tower::retry::Policy;

use crate::error::AppError;
use crate::services::push::{PushJob, execute_push};
use crate::services::queue::{
    JOB_RETRIES, QUEUE_NAME, job_retry_delay, job_timeout, purge_expired_pending,
    recover_worker_registration,
};
use crate::state::AppState;

/// worker 并发数：频控由进程内限流器串行化，并发只用于让不同机器人互不阻塞。
pub const WORKER_CONCURRENCY: usize = 8;
/// 设置刷新间隔（秒）。
pub const SETTINGS_REFRESH_SECONDS: u64 = 60;
/// 过期守卫清理间隔（秒）。
pub const SENT_GUARD_CLEANUP_SECONDS: u64 = 300;
/// worker 名称。
pub const WORKER_NAME: &str = "push-worker";

/// worker 错误类型。
pub type WorkerError = Box<dyn std::error::Error + Send + Sync>;

/// worker 任务可提取的共享状态。
pub type WorkerData = Data<Arc<AppState>>;

/// 固定间隔重试策略。
///
/// apalis 自带的 [`apalis::layers::retry::RetryPolicy`] 立即重试；这里固定间隔 5 秒，
/// 这里用 tower 的 `Policy` 返回一个 sleep future 实现同样的语义。
#[derive(Debug, Clone)]
struct FixedDelayRetryPolicy {
    retries: usize,
    delay: Duration,
}

impl FixedDelayRetryPolicy {
    /// 额外重试次数与每次重试前的等待时间。
    fn new(retries: usize, delay: Duration) -> Self {
        Self { retries, delay }
    }
}

impl<T, Res, Err> Policy<Task<T>, Res, Err> for FixedDelayRetryPolicy
where
    T: Clone,
{
    type Future = tokio::time::Sleep;

    fn retry(&mut self, req: &mut Task<T>, result: &mut Result<Res, Err>) -> Option<Self::Future> {
        // 与 apalis 自带策略一致：正在关停时不再重试，避免 5 秒等待拖慢优雅退出。
        if let Some(worker) = req.data().get::<WorkerContext>()
            && worker.is_shutting_down()
        {
            return None;
        }
        if result.is_ok() {
            return None;
        }
        // attempt 在每次执行前自增：第 1 次失败后 attempt = 1。
        // `<= retries` 对应「重试 retries 次」（共 retries + 1 次尝试）。
        if req.attempt() > self.retries {
            return None;
        }
        tracing::warn!(
            attempt = req.attempt(),
            delay_seconds = self.delay.as_secs(),
            "推送任务失败，等待重试"
        );
        Some(tokio::time::sleep(self.delay))
    }

    fn clone_request(&mut self, req: &Task<T>) -> Option<Task<T>> {
        Some(req.clone())
    }
}

/// 启动 worker：建表、注册推送处理器与定时任务，然后运行直到收到关停信号。
pub async fn run(state: Arc<AppState>) -> Result<(), AppError> {
    MySqlStorage::<()>::setup(&state.pool)
        .await
        .map_err(|err| AppError::internal(format!("初始化推送队列表失败：{err}")))?;

    let config = apalis_mysql::Config::default().queue(QUEUE_NAME);
    let heartbeat_seconds = config.heartbeat_interval.as_secs();

    // 崩溃残留的注册行会让 apalis 拒绝注册（WorkerAlreadyExists），worker 随即退出；
    // 先回收旧进程的注册与在跑任务。
    match recover_worker_registration(&state.pool, WORKER_NAME, heartbeat_seconds).await {
        Ok(requeued) => {
            if requeued > 0 {
                tracing::info!(requeued, "已回收崩溃残留的推送任务");
            }
        }
        Err(err) => tracing::warn!(error = %err, "回收崩溃残留的 worker 注册失败"),
    }

    // 服务停摆期间积压的旧任务不应在重启后集中补发。
    if let Err(err) = purge_expired_pending(&state.pool).await {
        tracing::warn!(error = %err, "清理过期的排队推送任务失败");
    }

    let backend = MySqlStorage::<PushJob>::new(&state.pool).with_config(config);

    let settings_task = spawn_settings_refresh(state.clone());
    let cleanup_task = spawn_sent_guard_cleanup(state.clone());

    // 顺序即层级：concurrency 最外层、retry 居中、timeout 最内层，
    // 这样每次尝试各自享有 180 秒上限，且重试不会额外占用并发槽。
    let worker = WorkerBuilder::new(WORKER_NAME)
        .backend(backend)
        .data(state.clone())
        .concurrency(WORKER_CONCURRENCY)
        .retry(FixedDelayRetryPolicy::new(JOB_RETRIES, job_retry_delay()))
        .timeout(job_timeout())
        .build(push_bot_message);

    tracing::info!(
        concurrency = WORKER_CONCURRENCY,
        timeout_seconds = job_timeout().as_secs(),
        retries = JOB_RETRIES,
        "推送 worker 已启动"
    );

    let result = worker.run_until(shutdown_signal()).await;

    // worker 进入优雅停止后会等待在跑任务完成；定时任务没有收尾动作，直接取消。
    settings_task.abort();
    cleanup_task.abort();

    result.map_err(|err| AppError::internal(format!("推送 worker 异常退出：{err}")))
}

/// 推送任务处理器。
pub async fn push_bot_message(job: PushJob, state: WorkerData) -> Result<(), WorkerError> {
    let state = state.0.clone();
    let settings = state.settings().clone();
    let limiter = state.limiters.get(&format!("bot:{}", job.bot_id));

    let outcome = execute_push(
        &state.pool,
        &job,
        &settings,
        &state.qq,
        &limiter,
        Some(&state.sent_guard),
    )
    .await;

    if outcome.is_success() {
        return Ok(());
    }
    let failures = outcome.failed();
    if outcome.retryable {
        // 全部目标都是可重试失败时整体重排；已成功的目标由 SentGuard 跳过，不会重复推送。
        return Err(format!("QQ 推送失败，等待重试：{}", failures.join("；")).into());
    }
    tracing::warn!(
        request_id = %job.request_id,
        failures = ?failures,
        "推送存在不可重试的失败"
    );
    Ok(())
}

/// 每分钟同步库内设置。
pub async fn refresh_runtime_settings(state: WorkerData) -> Result<(), WorkerError> {
    let state = state.0.clone();
    // 先读出副本再在锁外做数据库 IO，避免阻塞 Web 线程的读取。
    let mut next = state.settings().clone();
    if let Err(err) = next.load(&state.pool).await {
        return Err(format!("同步系统设置失败：{err}").into());
    }
    next.apply_side_effects(&state.limiters, &state.login_limiter);
    *state
        .runtime
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = next;
    Ok(())
}

/// 清理 `sent_guards` 中的过期行。
pub async fn cleanup_sent_guards(state: WorkerData) -> Result<(), WorkerError> {
    let state = state.0.clone();
    let removed = state
        .sent_guard
        .cleanup_expired()
        .await
        .map_err(|err| format!("清理推送守卫失败：{err}"))?;
    if removed > 0 {
        tracing::debug!(removed, "已清理过期的推送守卫");
    }
    Ok(())
}

/// 启动设置刷新定时任务（首个 tick 立即执行一次）。
fn spawn_settings_refresh(state: Arc<AppState>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let data = Data(state);
        let mut ticker = tokio::time::interval(Duration::from_secs(SETTINGS_REFRESH_SECONDS));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            if let Err(err) = refresh_runtime_settings(data.clone()).await {
                tracing::warn!(error = %err, "worker 同步系统设置失败");
            }
        }
    })
}

/// 启动过期守卫清理定时任务。
fn spawn_sent_guard_cleanup(state: Arc<AppState>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let data = Data(state);
        let mut ticker = tokio::time::interval(Duration::from_secs(SENT_GUARD_CLEANUP_SECONDS));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            if let Err(err) = cleanup_sent_guards(data.clone()).await {
                tracing::warn!(error = %err, "worker 清理过期推送守卫失败");
            }
        }
    })
}

/// 等待 SIGTERM（类 Unix）或 Ctrl-C。
///
/// `worker.run_until` 收到该信号后会停止拉取新任务，并等待在跑任务完成。
async fn shutdown_signal() -> std::io::Result<()> {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(err) => tracing::warn!(error = %err, "监听 SIGTERM 失败"),
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        result = ctrl_c => result,
        _ = terminate => Ok(()),
    }
}
