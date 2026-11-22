//! 后台写操作审计。
//!
//! 写入语义：
//! `actor` 为空表示系统操作，`target_id` 统一转成字符串，`detail` 存 JSON。
//!
//! 查询按 `id` 倒序分页，支持动作、操作者、目标、关键词与时间区间过滤；
//! 所有条件都通过绑定参数传入（见 [`crate::db::queries::audit`]）。

use chrono::{NaiveDateTime, Utc};
use serde_json::Value;
use sqlx::MySqlPool;

use crate::db::models::AdminAuditLog;
use crate::db::queries::{self, DEFAULT_PAGE_SIZE, normalize_pagination};
use crate::error::AppError;

/// 一条审计记录的入参。
#[derive(Debug, Clone, Default)]
pub struct AuditEntry<'a> {
    /// 操作者用户 ID；系统操作为 `None`。
    pub actor_user_id: Option<i64>,
    /// 动作，例如 `settings.update`。
    pub action: &'a str,
    /// 目标类型，例如 `system_setting`。
    pub target_type: Option<&'a str>,
    /// 目标 ID。
    pub target_id: Option<String>,
    /// 详情（JSON）。
    pub detail: Option<Value>,
    /// 客户端 IP。
    pub ip: Option<&'a str>,
}

/// 审计日志查询条件。
#[derive(Debug, Clone)]
pub struct AuditQuery {
    /// 页码，从 1 开始。
    pub page: i64,
    /// 每页条数。
    pub page_size: i64,
    /// 动作精确匹配。
    pub action: Option<String>,
    /// 操作者。
    pub actor_user_id: Option<i64>,
    /// 目标类型精确匹配。
    pub target_type: Option<String>,
    /// 目标 ID 精确匹配。
    pub target_id: Option<String>,
    /// 关键词（动作 / 目标 / IP 的模糊匹配）。
    pub keyword: Option<String>,
    /// 起始时间（含）。
    pub since: Option<NaiveDateTime>,
    /// 结束时间（不含）。
    pub until: Option<NaiveDateTime>,
}

impl Default for AuditQuery {
    fn default() -> Self {
        Self {
            page: 1,
            page_size: DEFAULT_PAGE_SIZE,
            action: None,
            actor_user_id: None,
            target_type: None,
            target_id: None,
            keyword: None,
            since: None,
            until: None,
        }
    }
}

/// 一页审计日志。
#[derive(Debug, Clone)]
pub struct AuditPage {
    /// 当前页记录。
    pub items: Vec<AdminAuditLog>,
    /// 满足条件的总记录数。
    pub total: i64,
    /// 实际生效的页码（至少 1）。
    pub page: i64,
    /// 实际生效的每页条数（已按上限截断）。
    pub page_size: i64,
}

/// 写入一条审计记录（独立连接）。
pub async fn record_audit(pool: &MySqlPool, entry: AuditEntry<'_>) -> Result<(), AppError> {
    record_audit_on(pool, entry).await
}

/// 在指定执行器（连接池或事务）上写入审计记录。
///
/// 管理端修改账号时需要与业务更新同一事务提交，因此单独暴露该变体。
pub async fn record_audit_on<'e, E>(executor: E, entry: AuditEntry<'_>) -> Result<(), AppError>
where
    E: sqlx::Executor<'e, Database = sqlx::MySql>,
{
    let new_entry = queries::audit::NewAuditLog {
        actor_user_id: entry.actor_user_id,
        action: entry.action,
        target_type: entry.target_type,
        target_id: entry.target_id.as_deref(),
        detail: entry.detail.as_ref(),
        ip: entry.ip,
        created_at: Utc::now().naive_utc(),
    };
    queries::audit::insert(executor, &new_entry).await?;
    Ok(())
}

/// 分页查询审计日志。
pub async fn list_audits(pool: &MySqlPool, query: &AuditQuery) -> Result<AuditPage, AppError> {
    let (page_size, offset) = normalize_pagination(query.page, query.page_size);
    let page = query.page.max(1);

    let filter = queries::audit::AuditFilter {
        action: optional_text(query.action.as_deref()),
        actor_user_id: query.actor_user_id,
        target_type: optional_text(query.target_type.as_deref()),
        target_id: optional_text(query.target_id.as_deref()),
        keyword: optional_text(query.keyword.as_deref()),
        since: query.since,
        until: query.until,
    };

    let total = queries::audit::count(pool, &filter).await?;
    let items = if total == 0 {
        Vec::new()
    } else {
        queries::audit::list(pool, &filter, page_size, offset).await?
    };
    Ok(AuditPage {
        items,
        total,
        page,
        page_size,
    })
}

/// 过滤条件里的空字符串按「不过滤」处理，并去掉首尾空白。
fn optional_text(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_query_is_first_page() {
        let query = AuditQuery::default();
        assert_eq!(query.page, 1);
        assert_eq!(query.page_size, DEFAULT_PAGE_SIZE);
        assert!(query.action.is_none());
        assert!(query.actor_user_id.is_none());
        assert!(query.since.is_none());
    }

    #[test]
    fn empty_filters_are_dropped() {
        assert_eq!(optional_text(None), None);
        assert_eq!(optional_text(Some("")), None);
        assert_eq!(optional_text(Some("   ")), None);
        assert_eq!(optional_text(Some("  user.update ")), Some("user.update"));
    }

    #[test]
    fn pagination_is_clamped() {
        let (page_size, offset) = normalize_pagination(0, 0);
        assert_eq!(page_size, DEFAULT_PAGE_SIZE);
        assert_eq!(offset, 0);

        let (page_size, offset) = normalize_pagination(3, 50);
        assert_eq!(page_size, 50);
        assert_eq!(offset, 100);

        let (page_size, _) = normalize_pagination(1, i64::MAX);
        assert_eq!(page_size, queries::MAX_PAGE_SIZE);
    }
}
