//! QBotMessager 后端（Rust + Actix Web）。
//!
//! 模块布局见迁移规格书第 1 节。

pub mod adapters;
pub mod api;
pub mod auth;
pub mod bootstrap;
pub mod config;
pub mod crypto;
pub mod db;
pub mod error;
pub mod markdown;
pub mod renderer;
pub mod services;
pub mod state;
pub mod web;
pub mod worker;
