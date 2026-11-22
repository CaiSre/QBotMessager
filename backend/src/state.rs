//! 应用共享状态。
//!
//! Actix 各 worker 通过 `web::Data<AppState>` 共享同一份状态；其中数据库连接池、
//! HTTP 客户端与各类限流器都要求单进程、单副本运行（QQ 频控是账号级的）。

use std::sync::{Arc, RwLock, RwLockReadGuard};

use actix_web::HttpRequest;
use sqlx::MySqlPool;

use crate::config::Config;
use crate::services::qq::QqClient;
use crate::services::queue::{PushQueue, SentGuard};
use crate::services::runtime_settings::RuntimeSettings;
use crate::services::throttle::{AttemptLimiter, LimiterRegistry};

/// `X-Forwarded-For` 请求头。
const X_FORWARDED_FOR: &str = "x-forwarded-for";

/// 应用共享状态。
pub struct AppState {
    /// MySQL 连接池。
    pub pool: MySqlPool,
    /// 环境变量配置（不可变）。
    pub config: Arc<Config>,
    /// 数据库内的运行期设置缓存。
    ///
    /// 管理端修改后用写锁更新；服务读取时持读锁，临界区很短。
    pub runtime: Arc<RwLock<RuntimeSettings>>,
    /// 共享的 HTTP 客户端（OAuth / GitHub / 通用出站请求）。
    pub http: reqwest::Client,
    /// QQ 机器人客户端（token 缓存 + 发送）。
    pub qq: QqClient,
    /// 按机器人分配的 QQ 发送限流器。
    pub limiters: LimiterRegistry,
    /// 登录失败限流器。
    pub login_limiter: AttemptLimiter,
    /// 推送队列；`None` 表示未启用，Webhook 走同步发送。
    pub queue: Option<Arc<PushQueue>>,
    /// 推送幂等守卫（代替原 Redis `saq:sent:*`）。
    pub sent_guard: SentGuard,
    /// 版本号，用于 `/healthz` 与 `/readyz`。
    pub version: String,
}

impl AppState {
    /// 构造共享状态。
    pub fn new(
        pool: MySqlPool,
        config: Arc<Config>,
        runtime: RuntimeSettings,
        http: reqwest::Client,
        queue: Option<Arc<PushQueue>>,
    ) -> Self {
        let limiters = LimiterRegistry::new(
            runtime.qq_qps(),
            runtime.qq_qpm(),
            runtime.qq_min_interval_duration(),
        );
        let login_limiter = AttemptLimiter::new(
            runtime.login_max_failures(),
            runtime.login_ip_max_failures(),
            runtime.login_window_seconds(),
        );
        runtime.apply_side_effects(&limiters, &login_limiter);

        Self {
            qq: QqClient::new(http.clone()),
            sent_guard: SentGuard::new(pool.clone()),
            pool,
            config,
            runtime: Arc::new(RwLock::new(runtime)),
            http,
            limiters,
            login_limiter,
            queue,
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    /// 读取运行期设置。
    pub fn settings(&self) -> RwLockReadGuard<'_, RuntimeSettings> {
        self.runtime
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// 客户端 IP。
    ///
    /// `TRUST_PROXY=false`（默认）时取直连对端地址，忽略一切转发头
    /// （等价于旧 `web/proxy.ts` 剥离 `X-Forwarded-*` 的行为）；
    /// `TRUST_PROXY=true` 时取 `X-Forwarded-For` 最右侧一跳，缺失则退回直连地址。
    pub fn client_ip(&self, req: &HttpRequest) -> Option<String> {
        if self.config.trust_proxy
            && let Some(raw) = req
                .headers()
                .get(X_FORWARDED_FOR)
                .and_then(|value| value.to_str().ok())
            && let Some(last) = raw.rsplit(',').next()
        {
            let last = last.trim();
            if !last.is_empty() {
                return Some(last.to_string());
            }
        }
        req.peer_addr().map(|addr| addr.ip().to_string())
    }
}
