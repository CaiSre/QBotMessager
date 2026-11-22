//! 存活与就绪探针（根路径，无 `/api` 前缀）。
//!
//! - `GET /healthz` → 200 `{"status":"ok","version":"<ver>"}`；
//! - `GET /readyz` → 做一次 `SELECT 1`，失败返回 503
//!   `{"status":"error","detail":"database unavailable"}`。

use actix_web::{HttpResponse, web};
use serde_json::json;

use crate::state::AppState;

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

/// 就绪探针；数据库不可用时返回 503。
pub async fn readyz(state: web::Data<AppState>) -> HttpResponse {
    match sqlx::query("SELECT 1").execute(&state.pool).await {
        Ok(_) => HttpResponse::Ok().json(json!({
            "status": "ok",
            "version": state.version.as_str(),
        })),
        Err(err) => {
            tracing::warn!(error = %err, "就绪探针：数据库不可用");
            HttpResponse::ServiceUnavailable().json(json!({
                "status": "error",
                "detail": "database unavailable",
            }))
        }
    }
}
