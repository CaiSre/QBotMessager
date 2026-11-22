//! HTTP API。
//!
//! 根路径探针（`/healthz`、`/readyz`）与业务子模块（`auth`、`admin`、`webhook`）
//! 由本模块的 [`configure`] 统一注册，调用方（`main`）无需改动。

pub mod admin;
pub mod auth;
pub mod health;
pub mod webhook;

/// 注册全部 API 路由。
pub fn configure(cfg: &mut actix_web::web::ServiceConfig) {
    health::configure(cfg);
    auth::configure(cfg);
    admin::configure(cfg);
    webhook::configure(cfg);
}
