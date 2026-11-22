//! 数据库层：行结构体与 SQL 查询。
//!
//! 落地行结构体（`models`）与内嵌建表脚本；具体 SQL 查询由各 service 直接使用 `sqlx`，
//! 需要复用的查询在后续阶段集中到 `queries`。

pub mod models;
pub mod queries;

pub use models::*;

/// 内嵌的建表脚本（schema 初始化）。
///
/// 记录表使用独立的 `_qbot_migrations`：`PushQueue::connect` 会执行 apalis 自带的
/// 建表脚本并记录在默认的 `_sqlx_migrations`。两者共用同一张记录表时，后运行的
/// 一方会把对方的版本视为「已应用但不在当前集合」，启动直接失败。
///
/// 启动时执行 `migrator().run(&pool)`，失败即退出。
pub fn migrator() -> sqlx::migrate::Migrator {
    let mut migrator = sqlx::migrate!();
    migrator.dangerous_set_table_name("_qbot_migrations");
    migrator
}
