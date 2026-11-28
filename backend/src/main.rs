//! QBotMessager 二进制入口。
//!
//! 启动顺序：dotenvy → tracing（读 `RUST_LOG`）→ 安装 rustls ring
//! provider → `Config::from_env` → MySQL 连接池 → `sqlx::migrate!` → 运行期设置
//! → `AppState` → Actix 绑定 `0.0.0.0:${PORT:-3000}` → SIGTERM/SIGINT 优雅关停。
//! worker 退出即进程退出（由容器编排拉起），HTTP 不在无 worker 的状态下独活。
//!
//! `rustls::crypto::ring::default_provider().install_default()` 必须在创建任何
//! HTTP 客户端（reqwest / lettre）之前执行：依赖用的是 reqwest 的
//! `rustls-no-provider`，没有进程级 CryptoProvider 时首次 TLS 握手会运行期 panic。

use std::sync::Arc;
use std::time::Duration;

use actix_web::{App, HttpServer, web};
use qbotmessager::api;
use qbotmessager::config::Config;
use qbotmessager::services::queue::PushQueue;
use qbotmessager::services::runtime_settings::RuntimeSettings;
use qbotmessager::state::AppState;
use qbotmessager::web as site;
use sqlx::mysql::MySqlPoolOptions;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // `.env` 可选；Config::from_env 也会尝试加载，这里提前加载以便日志配置生效。
    let _ = dotenvy::dotenv();
    init_tracing();

    // reqwest 0.13 的 rustls-no-provider 需要进程级 provider，否则首次 TLS 握手 panic。
    if rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
    {
        tracing::debug!("rustls CryptoProvider 已由其他组件安装");
    }

    let config = Config::from_env()?;
    tracing::info!(
        app = %config.app_name,
        version = env!("CARGO_PKG_VERSION"),
        "QBotMessager 后端启动中"
    );

    let pool = MySqlPoolOptions::new()
        .max_connections(config.db_pool_size + config.db_max_overflow)
        .acquire_timeout(Duration::from_secs(config.db_pool_timeout as u64))
        .connect(&config.mysql_url)
        .await?;

    qbotmessager::db::migrator().run(&pool).await?;

    let mut runtime = RuntimeSettings::new(config.app_secret_key.clone());
    runtime.load(&pool).await?;

    // 首次启动引导：初始超级管理员与环境变量中的默认机器人（幂等）。
    let bootstrap = qbotmessager::bootstrap::run(&pool, &config, &runtime).await?;
    if bootstrap.admin_created.is_some()
        || bootstrap.admin_promoted.is_some()
        || bootstrap.bot_created
    {
        tracing::info!(
            admin_created = ?bootstrap.admin_created,
            admin_promoted = ?bootstrap.admin_promoted,
            bot_created = bootstrap.bot_created,
            "启动引导完成"
        );
    }

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .connect_timeout(Duration::from_secs(5))
        .user_agent("qbotmessager")
        .build()?;

    // Web 与 worker 共享同一份 AppState：队列、限流器与运行期设置都只有一份。
    let queue = Arc::new(
        PushQueue::connect(
            pool.clone(),
            config.push_queue_max,
            config.push_queue_max_per_user,
        )
        .await?,
    );
    let state = Arc::new(AppState::new(
        pool,
        Arc::new(config),
        runtime,
        http,
        Some(queue),
    ));

    let port = std::env::var("PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(3000);

    // Actix worker 数：默认按 CPU 核数但在容器内压到最多 2 个以降低内存占用。
    let workers = std::env::var("WORKERS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|count| *count > 0)
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
                .min(2)
        });

    // 任何绑定之前拉起 worker；它自行监听关停信号并等待在跑任务完成。
    let worker_handle = tokio::spawn(qbotmessager::worker::run(state.clone()));

    // worker 退出即进程退出：监督任务持有其 JoinHandle，异常返回（初始化失败、
    // panic、被取消）时记 error 并以非零码退出，交给容器编排
    //（restart: unless-stopped）拉起新进程重连 MySQL 与队列，避免 HTTP 只听
    // 不发、且无日志可观测的半死状态。worker 结束时先经 oneshot 通知关停
    // 等待方，超时与否都不影响这里的退出决策。
    let (worker_done_tx, worker_done_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let outcome = worker_handle.await;
        let _ = worker_done_tx.send(());
        match outcome {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                tracing::error!(error = %err, "推送 worker 已退出，进程跟随退出");
                std::process::exit(1);
            }
            Err(err) => {
                tracing::error!(error = %err, "推送 worker 任务终止，进程跟随退出");
                std::process::exit(1);
            }
        }
    });

    let shared = web::Data::from(state.clone());
    let server = HttpServer::new(move || {
        let shared = shared.clone();
        App::new()
            .wrap(site::SecurityHeaders)
            .app_data(shared)
            .configure(api::configure)
            .configure(site::configure)
    })
    .workers(workers)
    .shutdown_timeout(10)
    .bind(("0.0.0.0", port))?
    .run();

    tracing::info!(address = %format!("0.0.0.0:{port}"), "HTTP 服务已监听");

    let handle = server.handle();
    tokio::spawn(async move {
        shutdown_signal().await;
        handle.stop(true).await;
    });

    server.await?;

    // docker stop_grace_period 为 30s，留 5s 余量等待 worker 收尾：
    // HTTP 已停止收尾后，在这里等监督任务发出 worker 结束通知。
    let mut worker_done_rx = worker_done_rx;
    match tokio::time::timeout(Duration::from_secs(25), &mut worker_done_rx).await {
        Ok(Ok(())) => tracing::info!("推送 worker 已停止"),
        Ok(Err(_lost)) => tracing::warn!("worker 结束通知通道已关闭"),
        Err(_) => tracing::warn!("等待推送 worker 收尾超时（25s），直接退出"),
    }

    tracing::info!("QBotMessager 后端已停止");
    Ok(())
}

/// 初始化 tracing：`RUST_LOG` 优先，缺省 INFO。
fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

/// 等待 SIGINT 或（类 Unix 上的）SIGTERM。
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::warn!(error = %err, "监听 Ctrl-C 失败");
        }
    };

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
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("收到关停信号，正在优雅退出");
}
