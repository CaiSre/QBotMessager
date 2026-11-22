//! 存活与就绪探针（根路径，无 `/api` 前缀）。
//!
//! - `GET /healthz` → 200 `{"status":"ok","version":"<ver>"}`；
//! - `GET /readyz` → `SELECT 1` 检查数据库连接，再检查推送 worker 的注册
//!   心跳是否在新鲜窗口内（无心跳则无人消费队列，推送会无限积压）；
//!   任一失败返回 503，由 Docker HEALTHCHECK 把容器判为 unhealthy。

use actix_web::{HttpResponse, web};
use serde_json::json;

use crate::state::AppState;
use crate::worker::WORKER_NAME;

/// worker 心跳新鲜窗口（秒）＝ 2 × apalis 默认心跳间隔 30s。
const WORKER_HEARTBEAT_FRESH_SECONDS: i64 = 60;

/// 注册探针路由。
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route("/healthz", web::get().to(healthz))
        .route("/readyz", web::get().to(readyz));
}

/// 存活探针。
pub async fn healthz(state: web::Data<AppState>) -> HttpResponse {
    HttpResponse::Ok().json(json!({
        "status": "ok",
        "version": state.version.as_str(),
    }))
}

/// 就绪探针；数据库或推送 worker 不可用时返回 503。
pub async fn readyz(state: web::Data<AppState>) -> HttpResponse {
    match sqlx::query("SELECT 1").execute(&state.pool).await {
        Ok(_) => {}
        Err(err) => {
            tracing::warn!(error = %err, "就绪探针：数据库不可用");
            return HttpResponse::ServiceUnavailable().json(json!({
                "status": "error",
                "detail": "database unavailable",
            }));
        }
    }

    // worker 注册行心跳过期即视为不可用：半死状态下 HTTP 依然应答，
    // 但队列无人消费，必须让编排层看到 unhealthy 才能触发重建。
    let worker_alive: i64 = sqlx::query_scalar(
        "SELECT CAST(COUNT(*) AS SIGNED) FROM workers WHERE id = ? \
         AND last_seen >= NOW() - INTERVAL ? SECOND",
    )
    .bind(WORKER_NAME)
    .bind(WORKER_HEARTBEAT_FRESH_SECONDS)
    .fetch_one(&state.pool)
    .await
    .unwrap_or(0);

    if worker_alive == 0 {
        tracing::warn!(worker = WORKER_NAME, "就绪探针：推送 worker 不可用");
        return HttpResponse::ServiceUnavailable().json(json!({
            "status": "error",
            "detail": "push worker unavailable",
        }));
    }

    HttpResponse::Ok().json(json!({
        "status": "ok",
        "version": state.version.as_str(),
    }))
}
