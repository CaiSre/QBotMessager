//! 数据库层：行结构体与 SQL 查询。
//!
//! 本阶段落地行结构体（`models`）与内嵌迁移；具体 SQL 查询由各 service 直接使用 `sqlx`，
//! 需要复用的查询在后续阶段集中到 `queries`。

pub mod models;
pub mod queries;

pub use models::*;

/// 内嵌的数据库迁移。
///
/// 记录表使用独立的 `_qbot_migrations`：`PushQueue::connect` 会执行 apalis 自带的
/// 迁移，而 apalis 使用默认的 `_sqlx_migrations`。两者共用同一张表时，后运行的一方
/// 会把对方的版本视为「已应用但不在当前迁移集」，启动直接失败。
///
/// 启动时执行 `migrator().run(&pool)`，失败即退出（规格书第 9 节）。
pub fn migrator() -> sqlx::migrate::Migrator {
    let mut migrator = sqlx::migrate!();
    migrator.dangerous_set_table_name("_qbot_migrations");
    migrator
}
