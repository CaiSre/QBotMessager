//! 跨服务复用的参数化 SQL 查询。
//!
//! 按域分模块；行结构体一律复用 [`crate::db::models`] 里的 `FromRow` 结构，
//! 这里不重复定义实体。
//!
//! 约定：
//! - 所有值都通过 `?` 占位符绑定，禁止把外部输入拼进 SQL；
//! - 需要复用的动态过滤条件用 [`sqlx::QueryBuilder`] 组合固定片段与绑定参数；
//! - 查询函数对 `Executor` 泛型，既可直接传 `&MySqlPool`，也可传事务
//!   （`&mut *tx`）以参与调用方的事务。

use chrono::NaiveDateTime;
use serde_json::Value;
use sqlx::{Executor, FromRow, MySql, MySqlPool, QueryBuilder, Row};

use crate::db::models::{
    AdminAuditLog, AuthIdentity, BotProfile, Channel, EmailVerificationCode, InviteCode,
    OAuthProvider, PushLog, Session, SystemSetting, User,
};

/// 默认分页大小（与管理端日志接口一致）。
pub const DEFAULT_PAGE_SIZE: i64 = 20;
/// 单页上限（与管理端日志接口一致）。
pub const MAX_PAGE_SIZE: i64 = 200;

/// 规范化分页参数，返回 `(page_size, offset)`。
///
/// 页码至少为 1；页大小非正数时取默认值，超过上限时截断，
/// 避免调用方传入超大 offset 造成无界扫描。
pub fn normalize_pagination(page: i64, page_size: i64) -> (i64, i64) {
    let page = page.max(1);
    let page_size = if page_size <= 0 {
        DEFAULT_PAGE_SIZE
    } else {
        page_size.min(MAX_PAGE_SIZE)
    };
    let offset = page.saturating_sub(1).saturating_mul(page_size);
    (page_size, offset)
}

/// 构造 `LIKE` 的“包含”模式串，并转义 `%`、`_`、`\`。
///
/// 返回值只作为绑定参数使用，不参与 SQL 拼接。
pub fn like_contains(keyword: &str) -> String {
    let mut pattern = String::with_capacity(keyword.len() + 2);
    pattern.push('%');
    for ch in keyword.chars() {
        match ch {
            '%' | '_' | '\\' => {
                pattern.push('\\');
                pattern.push(ch);
            }
            _ => pattern.push(ch),
        }
    }
    pattern.push('%');
    pattern
}

/// 账号。
pub mod users {
    use super::*;

    /// 新账号的插入参数。
    #[derive(Debug, Clone)]
    pub struct NewUser<'a> {
        /// 邮箱（已规范化为小写）。
        pub email: &'a str,
        /// 用户名。
        pub name: &'a str,
        /// 密码哈希；OAuth 创建的账号为 `None`。
        pub password_hash: Option<&'a str>,
        /// 角色。
        pub role: &'a str,
        /// 状态。
        pub status: &'a str,
        /// 创建时间。
        pub created_at: NaiveDateTime,
    }

    /// 按主键查询。
    pub async fn find_by_id<'e, E>(executor: E, id: i64) -> Result<Option<User>, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        sqlx::query_as::<_, User>(
            "SELECT id, email, name, password_hash, role, status, last_login_at, created_at \
             FROM users WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(executor)
        .await
    }

    /// 按邮箱查询（邮箱库内均为小写）。
    pub async fn find_by_email<'e, E>(executor: E, email: &str) -> Result<Option<User>, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        sqlx::query_as::<_, User>(
            "SELECT id, email, name, password_hash, role, status, last_login_at, created_at \
             FROM users WHERE email = ?",
        )
        .bind(email)
        .fetch_optional(executor)
        .await
    }

    /// 按用户名忽略大小写查询；同名账号理论上可能重复，取最早注册的一个。
    pub async fn find_by_name_ci<'e, E>(
        executor: E,
        name: &str,
    ) -> Result<Option<User>, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        sqlx::query_as::<_, User>(
            "SELECT id, email, name, password_hash, role, status, last_login_at, created_at \
             FROM users WHERE LOWER(name) = ? ORDER BY id LIMIT 1",
        )
        .bind(name.to_lowercase())
        .fetch_optional(executor)
        .await
    }

    /// 邮箱是否已被占用；`exclude_user_id` 用于资料更新时排除自己。
    pub async fn email_taken<'e, E>(
        executor: E,
        email: &str,
        exclude_user_id: Option<i64>,
    ) -> Result<bool, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        let row: Option<(i64,)> = match exclude_user_id {
            Some(user_id) => {
                sqlx::query_as("SELECT id FROM users WHERE email = ? AND id <> ? LIMIT 1")
                    .bind(email)
                    .bind(user_id)
                    .fetch_optional(executor)
                    .await?
            }
            None => {
                sqlx::query_as("SELECT id FROM users WHERE email = ? LIMIT 1")
                    .bind(email)
                    .fetch_optional(executor)
                    .await?
            }
        };
        Ok(row.is_some())
    }

    /// 用户名是否已被占用（忽略大小写）。
    ///
    /// 条件写成 `LOWER(name) = ?`，与库上的函数唯一索引 `uq_users_name_lower` 对齐。
    pub async fn name_taken<'e, E>(
        executor: E,
        name: &str,
        exclude_user_id: Option<i64>,
    ) -> Result<bool, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        let lowered = name.to_lowercase();
        let row: Option<(i64,)> = match exclude_user_id {
            Some(user_id) => {
                sqlx::query_as("SELECT id FROM users WHERE LOWER(name) = ? AND id <> ? LIMIT 1")
                    .bind(&lowered)
                    .bind(user_id)
                    .fetch_optional(executor)
                    .await?
            }
            None => {
                sqlx::query_as("SELECT id FROM users WHERE LOWER(name) = ? LIMIT 1")
                    .bind(&lowered)
                    .fetch_optional(executor)
                    .await?
            }
        };
        Ok(row.is_some())
    }

    /// 全部账号，按注册顺序。
    pub async fn list_all<'e, E>(executor: E) -> Result<Vec<User>, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        sqlx::query_as::<_, User>(
            "SELECT id, email, name, password_hash, role, status, last_login_at, created_at \
             FROM users ORDER BY id",
        )
        .fetch_all(executor)
        .await
    }

    /// 插入账号，返回自增主键。
    pub async fn insert<'e, E>(executor: E, user: &NewUser<'_>) -> Result<i64, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        let result = sqlx::query(
            "INSERT INTO users (email, name, password_hash, role, status, created_at) \
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(user.email)
        .bind(user.name)
        .bind(user.password_hash)
        .bind(user.role)
        .bind(user.status)
        .bind(user.created_at)
        .execute(executor)
        .await?;
        Ok(result.last_insert_id() as i64)
    }

    /// 更新用户名。
    pub async fn update_name<'e, E>(executor: E, id: i64, name: &str) -> Result<u64, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        let result = sqlx::query("UPDATE users SET name = ? WHERE id = ?")
            .bind(name)
            .bind(id)
            .execute(executor)
            .await?;
        Ok(result.rows_affected())
    }

    /// 更新邮箱。
    pub async fn update_email<'e, E>(executor: E, id: i64, email: &str) -> Result<u64, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        let result = sqlx::query("UPDATE users SET email = ? WHERE id = ?")
            .bind(email)
            .bind(id)
            .execute(executor)
            .await?;
        Ok(result.rows_affected())
    }

    /// 更新密码哈希。
    pub async fn update_password_hash<'e, E>(
        executor: E,
        id: i64,
        password_hash: &str,
    ) -> Result<u64, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        let result = sqlx::query("UPDATE users SET password_hash = ? WHERE id = ?")
            .bind(password_hash)
            .bind(id)
            .execute(executor)
            .await?;
        Ok(result.rows_affected())
    }

    /// 管理端修改角色、状态与用户名；`None` 表示该字段保持不变。
    pub async fn update_admin_fields<'e, E>(
        executor: E,
        id: i64,
        role: Option<&str>,
        status: Option<&str>,
        name: Option<&str>,
    ) -> Result<u64, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        let result = sqlx::query(
            "UPDATE users SET role = COALESCE(?, role), status = COALESCE(?, status), \
             name = COALESCE(?, name) WHERE id = ?",
        )
        .bind(role)
        .bind(status)
        .bind(name)
        .bind(id)
        .execute(executor)
        .await?;
        Ok(result.rows_affected())
    }

    /// 锁定全部启用的超管行（按 id 序）并返回 id；须在事务内使用。
    /// 降级检查前的取锁集步骤：并发降级事务按同一顺序竞争同一行集，
    /// 后来者在第一个事务提交、锁释放后重新评估计数。
    pub async fn active_super_admin_ids_for_update<'e, E>(
        executor: E,
    ) -> Result<Vec<i64>, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        sqlx::query_scalar(
            "SELECT id FROM users WHERE role = 'super_admin' AND status = 'active' \
             ORDER BY id FOR UPDATE",
        )
        .fetch_all(executor)
        .await
    }

    /// 除指定账号外仍然启用的超级管理员数量。
    pub async fn count_other_active_super_admins<'e, E>(
        executor: E,
        exclude_user_id: i64,
    ) -> Result<i64, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        sqlx::query_scalar(
            "SELECT CAST(COUNT(*) AS SIGNED) FROM users \
             WHERE role = 'super_admin' AND status = 'active' AND id <> ?",
        )
        .bind(exclude_user_id)
        .fetch_one(executor)
        .await
    }
}

/// 邀请码。
pub mod invites {
    use super::*;

    /// 新邀请码的插入参数。
    #[derive(Debug, Clone)]
    pub struct NewInviteCode<'a> {
        /// 邀请码。
        pub code: &'a str,
        /// 限定邮箱；`None` 表示不限。
        pub email: Option<&'a str>,
        /// 最大可用次数。
        pub max_uses: i32,
        /// 过期时间。
        pub expires_at: Option<NaiveDateTime>,
        /// 创建者。
        pub created_by: Option<i64>,
        /// 创建时间。
        pub created_at: NaiveDateTime,
    }

    /// 按邀请码查询。
    pub async fn find_by_code<'e, E>(
        executor: E,
        code: &str,
    ) -> Result<Option<InviteCode>, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        sqlx::query_as::<_, InviteCode>(
            "SELECT id, code, email, max_uses, used_count, expires_at, revoked_at, created_by, \
             created_at FROM invite_codes WHERE code = ?",
        )
        .bind(code)
        .fetch_optional(executor)
        .await
    }

    /// 原子占用一次名额；返回受影响行数（1 表示占用成功）。
    pub async fn consume_slot<'e, E>(
        executor: E,
        id: i64,
        now: NaiveDateTime,
    ) -> Result<u64, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        let result = sqlx::query(
            "UPDATE invite_codes SET used_count = used_count + 1 \
             WHERE id = ? AND revoked_at IS NULL AND used_count < max_uses \
             AND (expires_at IS NULL OR expires_at > ?)",
        )
        .bind(id)
        .bind(now)
        .execute(executor)
        .await?;
        Ok(result.rows_affected())
    }

    /// 插入邀请码，返回自增主键。
    pub async fn insert<'e, E>(executor: E, invite: &NewInviteCode<'_>) -> Result<i64, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        let result = sqlx::query(
            "INSERT INTO invite_codes (code, email, max_uses, used_count, expires_at, created_by, \
             created_at) VALUES (?, ?, ?, 0, ?, ?, ?)",
        )
        .bind(invite.code)
        .bind(invite.email)
        .bind(invite.max_uses)
        .bind(invite.expires_at)
        .bind(invite.created_by)
        .bind(invite.created_at)
        .execute(executor)
        .await?;
        Ok(result.last_insert_id() as i64)
    }

    /// 全部邀请码，新创建的在前。
    pub async fn list_desc<'e, E>(executor: E) -> Result<Vec<InviteCode>, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        sqlx::query_as::<_, InviteCode>(
            "SELECT id, code, email, max_uses, used_count, expires_at, revoked_at, created_by, \
             created_at FROM invite_codes ORDER BY id DESC",
        )
        .fetch_all(executor)
        .await
    }

    /// 撤销邀请码。
    pub async fn revoke<'e, E>(executor: E, id: i64, now: NaiveDateTime) -> Result<u64, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        let result = sqlx::query("UPDATE invite_codes SET revoked_at = ? WHERE id = ?")
            .bind(now)
            .bind(id)
            .execute(executor)
            .await?;
        Ok(result.rows_affected())
    }
}

/// 机器人配置。
pub mod bots {
    use super::*;

    /// 新机器人配置的插入参数。
    #[derive(Debug, Clone)]
    pub struct NewBotProfile<'a> {
        /// 所属用户。
        pub owner_user_id: i64,
        /// 名称。
        pub name: &'a str,
        /// QQ AppID。
        pub qq_appid: &'a str,
        /// QQ AppSecret（密文）。
        pub qq_app_secret: &'a str,
        /// QQ 接口主机。
        pub qq_host: &'a str,
        /// 默认推送目标（JSON）。
        pub default_openids: &'a Value,
        /// 默认群 openid。
        pub default_group_openid: Option<&'a str>,
        /// 是否启用。
        pub enabled: bool,
        /// 创建时间。
        pub created_at: NaiveDateTime,
    }

    /// 按主键查询。
    pub async fn find_by_id<'e, E>(executor: E, id: i64) -> Result<Option<BotProfile>, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        sqlx::query_as::<_, BotProfile>(
            "SELECT id, owner_user_id, name, qq_appid, qq_app_secret, qq_host, default_openids, \
             default_group_openid, enabled, created_at FROM bot_profiles WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(executor)
        .await
    }

    /// 按主键查询启用的机器人配置（Webhook 用）。
    pub async fn find_enabled_by_id<'e, E>(
        executor: E,
        id: i64,
    ) -> Result<Option<BotProfile>, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        sqlx::query_as::<_, BotProfile>(
            "SELECT id, owner_user_id, name, qq_appid, qq_app_secret, qq_host, default_openids, \
             default_group_openid, enabled, created_at FROM bot_profiles \
             WHERE id = ? AND enabled = TRUE",
        )
        .bind(id)
        .fetch_optional(executor)
        .await
    }

    /// 机器人列表；`owner_user_id` 为 `None` 时返回全部。
    pub async fn list<'e, E>(
        executor: E,
        owner_user_id: Option<i64>,
    ) -> Result<Vec<BotProfile>, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        match owner_user_id {
            Some(owner_user_id) => {
                sqlx::query_as::<_, BotProfile>(
                    "SELECT id, owner_user_id, name, qq_appid, qq_app_secret, qq_host, \
                     default_openids, default_group_openid, enabled, created_at \
                     FROM bot_profiles WHERE owner_user_id = ? ORDER BY id",
                )
                .bind(owner_user_id)
                .fetch_all(executor)
                .await
            }
            None => {
                sqlx::query_as::<_, BotProfile>(
                    "SELECT id, owner_user_id, name, qq_appid, qq_app_secret, qq_host, \
                     default_openids, default_group_openid, enabled, created_at \
                     FROM bot_profiles ORDER BY id",
                )
                .fetch_all(executor)
                .await
            }
        }
    }

    /// 机器人列表与所属用户邮箱；`owner_user_id` 为 `None` 时返回全部。
    pub async fn list_with_owner<'e, E>(
        executor: E,
        owner_user_id: Option<i64>,
    ) -> Result<Vec<(BotProfile, String)>, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        let rows =
            match owner_user_id {
                Some(owner_user_id) => sqlx::query(
                    "SELECT b.id, b.owner_user_id, b.name, b.qq_appid, b.qq_app_secret, b.qq_host, \
                     b.default_openids, b.default_group_openid, b.enabled, b.created_at, u.email \
                     FROM bot_profiles b JOIN users u ON u.id = b.owner_user_id \
                     WHERE b.owner_user_id = ? ORDER BY b.id",
                )
                .bind(owner_user_id)
                .fetch_all(executor)
                .await?,
                None => sqlx::query(
                    "SELECT b.id, b.owner_user_id, b.name, b.qq_appid, b.qq_app_secret, b.qq_host, \
                     b.default_openids, b.default_group_openid, b.enabled, b.created_at, u.email \
                     FROM bot_profiles b JOIN users u ON u.id = b.owner_user_id ORDER BY b.id",
                )
                .fetch_all(executor)
                .await?,
            };
        let mut result = Vec::with_capacity(rows.len());
        for row in rows {
            let bot = BotProfile::from_row(&row)?;
            let email: String = row.try_get("email")?;
            result.push((bot, email));
        }
        Ok(result)
    }

    /// 插入机器人配置，返回自增主键。
    pub async fn insert<'e, E>(executor: E, bot: &NewBotProfile<'_>) -> Result<i64, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        let result = sqlx::query(
            "INSERT INTO bot_profiles (owner_user_id, name, qq_appid, qq_app_secret, qq_host, \
             default_openids, default_group_openid, enabled, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(bot.owner_user_id)
        .bind(bot.name)
        .bind(bot.qq_appid)
        .bind(bot.qq_app_secret)
        .bind(bot.qq_host)
        .bind(bot.default_openids)
        .bind(bot.default_group_openid)
        .bind(bot.enabled)
        .bind(bot.created_at)
        .execute(executor)
        .await?;
        Ok(result.last_insert_id() as i64)
    }

    /// 启停用机器人。
    pub async fn set_enabled<'e, E>(executor: E, id: i64, enabled: bool) -> Result<u64, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        let result = sqlx::query("UPDATE bot_profiles SET enabled = ? WHERE id = ?")
            .bind(enabled)
            .bind(id)
            .execute(executor)
            .await?;
        Ok(result.rows_affected())
    }

    /// 删除机器人配置。
    pub async fn delete<'e, E>(executor: E, id: i64) -> Result<u64, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        let result = sqlx::query("DELETE FROM bot_profiles WHERE id = ?")
            .bind(id)
            .execute(executor)
            .await?;
        Ok(result.rows_affected())
    }
}

/// 钩子类型通道。
pub mod channels {
    use super::*;

    /// 新通道的插入参数。
    #[derive(Debug, Clone)]
    pub struct NewChannel<'a> {
        /// 所属机器人。
        pub bot_profile_id: i64,
        /// 钩子类型。
        pub hook_type: &'a str,
        /// 推送来源（用户自填）。
        pub push_source: &'a str,
        /// Webhook 凭据哈希。
        pub webhook_token_hash: &'a str,
        /// 是否启用。
        pub enabled: bool,
        /// 钩子附加配置（JSON）。
        pub extra: Option<&'a Value>,
        /// 创建时间。
        pub created_at: NaiveDateTime,
    }

    /// 按主键查询。
    pub async fn find_by_id<'e, E>(executor: E, id: i64) -> Result<Option<Channel>, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        sqlx::query_as::<_, Channel>(
            "SELECT id, bot_profile_id, hook_type, push_source, webhook_token_hash, enabled, extra, created_at \
             FROM channels WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(executor)
        .await
    }

    /// 按 webhook token 哈希 + 钩子类型查询启用中的通道（Webhook 鉴权用）。
    pub async fn find_enabled_for_hook_type<'e, E>(
        executor: E,
        hook_type: &str,
        webhook_token_hash: &str,
    ) -> Result<Option<Channel>, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        sqlx::query_as::<_, Channel>(
            "SELECT id, bot_profile_id, hook_type, push_source, webhook_token_hash, enabled, extra, created_at \
             FROM channels WHERE webhook_token_hash = ? AND hook_type = ? AND enabled = TRUE",
        )
        .bind(webhook_token_hash)
        .bind(hook_type)
        .fetch_optional(executor)
        .await
    }

    /// 某个机器人下的全部通道。
    pub async fn list_for_bot<'e, E>(
        executor: E,
        bot_profile_id: i64,
    ) -> Result<Vec<Channel>, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        sqlx::query_as::<_, Channel>(
            "SELECT id, bot_profile_id, hook_type, push_source, webhook_token_hash, enabled, extra, created_at \
             FROM channels WHERE bot_profile_id = ? ORDER BY id",
        )
        .bind(bot_profile_id)
        .fetch_all(executor)
        .await
    }

    /// 通道列表与所属机器人；`owner_user_id` 为 `None` 时返回全部。
    pub async fn list_with_bot<'e, E>(
        executor: E,
        owner_user_id: Option<i64>,
    ) -> Result<Vec<(Channel, BotProfile)>, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        let rows = match owner_user_id {
            Some(owner_user_id) => {
                sqlx::query(
                    "SELECT c.id AS c_id, c.bot_profile_id AS c_bot_profile_id, \
                     c.hook_type AS c_hook_type, c.push_source AS c_push_source, \
                     c.webhook_token_hash AS c_webhook_token_hash, \
                     c.enabled AS c_enabled, c.extra AS c_extra, c.created_at AS c_created_at, \
                     b.id AS b_id, b.owner_user_id AS b_owner_user_id, b.name AS b_name, \
                     b.qq_appid AS b_qq_appid, b.qq_app_secret AS b_qq_app_secret, \
                     b.qq_host AS b_qq_host, b.default_openids AS b_default_openids, \
                     b.default_group_openid AS b_default_group_openid, b.enabled AS b_enabled, \
                     b.created_at AS b_created_at FROM channels c \
                     JOIN bot_profiles b ON b.id = c.bot_profile_id \
                     WHERE b.owner_user_id = ? ORDER BY c.id",
                )
                .bind(owner_user_id)
                .fetch_all(executor)
                .await?
            }
            None => {
                sqlx::query(
                    "SELECT c.id AS c_id, c.bot_profile_id AS c_bot_profile_id, \
                     c.hook_type AS c_hook_type, c.push_source AS c_push_source, \
                     c.webhook_token_hash AS c_webhook_token_hash, \
                     c.enabled AS c_enabled, c.extra AS c_extra, c.created_at AS c_created_at, \
                     b.id AS b_id, b.owner_user_id AS b_owner_user_id, b.name AS b_name, \
                     b.qq_appid AS b_qq_appid, b.qq_app_secret AS b_qq_app_secret, \
                     b.qq_host AS b_qq_host, b.default_openids AS b_default_openids, \
                     b.default_group_openid AS b_default_group_openid, b.enabled AS b_enabled, \
                     b.created_at AS b_created_at FROM channels c \
                     JOIN bot_profiles b ON b.id = c.bot_profile_id ORDER BY c.id",
                )
                .fetch_all(executor)
                .await?
            }
        };
        let mut result = Vec::with_capacity(rows.len());
        for row in rows {
            let channel = Channel {
                id: row.try_get("c_id")?,
                bot_profile_id: row.try_get("c_bot_profile_id")?,
                hook_type: row.try_get("c_hook_type")?,
                push_source: row.try_get("c_push_source")?,
                webhook_token_hash: row.try_get("c_webhook_token_hash")?,
                enabled: row.try_get("c_enabled")?,
                extra: row.try_get("c_extra")?,
                created_at: row.try_get("c_created_at")?,
            };
            let bot = BotProfile {
                id: row.try_get("b_id")?,
                owner_user_id: row.try_get("b_owner_user_id")?,
                name: row.try_get("b_name")?,
                qq_appid: row.try_get("b_qq_appid")?,
                qq_app_secret: row.try_get("b_qq_app_secret")?,
                qq_host: row.try_get("b_qq_host")?,
                default_openids: row.try_get("b_default_openids")?,
                default_group_openid: row.try_get("b_default_group_openid")?,
                enabled: row.try_get("b_enabled")?,
                created_at: row.try_get("b_created_at")?,
            };
            result.push((channel, bot));
        }
        Ok(result)
    }

    /// 插入通道，返回自增主键。
    pub async fn insert<'e, E>(executor: E, channel: &NewChannel<'_>) -> Result<i64, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        let result = sqlx::query(
            "INSERT INTO channels (bot_profile_id, hook_type, push_source, webhook_token_hash, \
             enabled, extra, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(channel.bot_profile_id)
        .bind(channel.hook_type)
        .bind(channel.push_source)
        .bind(channel.webhook_token_hash)
        .bind(channel.enabled)
        .bind(channel.extra)
        .bind(channel.created_at)
        .execute(executor)
        .await?;
        Ok(result.last_insert_id() as i64)
    }

    /// 轮换 webhook token（写入新哈希）。
    pub async fn update_webhook_token_hash<'e, E>(
        executor: E,
        id: i64,
        webhook_token_hash: &str,
    ) -> Result<u64, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        let result = sqlx::query("UPDATE channels SET webhook_token_hash = ? WHERE id = ?")
            .bind(webhook_token_hash)
            .bind(id)
            .execute(executor)
            .await?;
        Ok(result.rows_affected())
    }

    /// 启停用通道。
    pub async fn set_enabled<'e, E>(executor: E, id: i64, enabled: bool) -> Result<u64, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        let result = sqlx::query("UPDATE channels SET enabled = ? WHERE id = ?")
            .bind(enabled)
            .bind(id)
            .execute(executor)
            .await?;
        Ok(result.rows_affected())
    }

    /// 删除通道。
    pub async fn delete<'e, E>(executor: E, id: i64) -> Result<u64, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        let result = sqlx::query("DELETE FROM channels WHERE id = ?")
            .bind(id)
            .execute(executor)
            .await?;
        Ok(result.rows_affected())
    }
}

/// OAuth2 提供方与账号绑定。
pub mod oauth {
    use super::*;

    /// 新 OAuth 绑定的插入参数。
    #[derive(Debug, Clone)]
    pub struct NewAuthIdentity<'a> {
        /// 本地用户。
        pub user_id: i64,
        /// 提供方标识。
        pub provider: &'a str,
        /// 提供方侧用户 ID。
        pub provider_user_id: &'a str,
        /// 提供方侧登录名。
        pub provider_login: Option<&'a str>,
        /// 创建时间。
        pub created_at: NaiveDateTime,
    }

    /// 全部启用的提供方。
    pub async fn list_enabled<'e, E>(executor: E) -> Result<Vec<OAuthProvider>, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        sqlx::query_as::<_, OAuthProvider>(
            "SELECT id, `key`, display_name, client_id, client_secret, authorization_url, \
             token_url, userinfo_url, scopes, email_field, id_field, name_field, enabled, \
             email_verified, created_at FROM oauth_providers WHERE enabled = TRUE ORDER BY id",
        )
        .fetch_all(executor)
        .await
    }

    /// 全部提供方（管理端）。
    pub async fn list_all<'e, E>(executor: E) -> Result<Vec<OAuthProvider>, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        sqlx::query_as::<_, OAuthProvider>(
            "SELECT id, `key`, display_name, client_id, client_secret, authorization_url, \
             token_url, userinfo_url, scopes, email_field, id_field, name_field, enabled, \
             email_verified, created_at FROM oauth_providers ORDER BY id",
        )
        .fetch_all(executor)
        .await
    }

    /// 按标识查询。
    pub async fn find_by_key<'e, E>(
        executor: E,
        key: &str,
    ) -> Result<Option<OAuthProvider>, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        sqlx::query_as::<_, OAuthProvider>(
            "SELECT id, `key`, display_name, client_id, client_secret, authorization_url, \
             token_url, userinfo_url, scopes, email_field, id_field, name_field, enabled, \
             email_verified, created_at FROM oauth_providers WHERE `key` = ?",
        )
        .bind(key)
        .fetch_optional(executor)
        .await
    }

    /// 按标识查询启用中的提供方。
    pub async fn find_enabled_by_key<'e, E>(
        executor: E,
        key: &str,
    ) -> Result<Option<OAuthProvider>, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        sqlx::query_as::<_, OAuthProvider>(
            "SELECT id, `key`, display_name, client_id, client_secret, authorization_url, \
             token_url, userinfo_url, scopes, email_field, id_field, name_field, enabled, \
             email_verified, created_at FROM oauth_providers \
             WHERE `key` = ? AND enabled = TRUE",
        )
        .bind(key)
        .fetch_optional(executor)
        .await
    }

    /// 按 (provider, provider_user_id) 查询账号绑定。
    pub async fn find_identity<'e, E>(
        executor: E,
        provider: &str,
        provider_user_id: &str,
    ) -> Result<Option<AuthIdentity>, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        sqlx::query_as::<_, AuthIdentity>(
            "SELECT id, user_id, provider, provider_user_id, provider_login, created_at \
             FROM auth_identities WHERE provider = ? AND provider_user_id = ?",
        )
        .bind(provider)
        .bind(provider_user_id)
        .fetch_optional(executor)
        .await
    }

    /// 插入账号绑定，返回自增主键。
    pub async fn insert_identity<'e, E>(
        executor: E,
        identity: &NewAuthIdentity<'_>,
    ) -> Result<i64, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        let result = sqlx::query(
            "INSERT INTO auth_identities (user_id, provider, provider_user_id, provider_login, \
             created_at) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(identity.user_id)
        .bind(identity.provider)
        .bind(identity.provider_user_id)
        .bind(identity.provider_login)
        .bind(identity.created_at)
        .execute(executor)
        .await?;
        Ok(result.last_insert_id() as i64)
    }

    /// 按主键查询账号绑定（校验归属时使用）。
    pub async fn find_identity_by_id<'e, E>(
        executor: E,
        id: i64,
    ) -> Result<Option<AuthIdentity>, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        sqlx::query_as::<_, AuthIdentity>(
            "SELECT id, user_id, provider, provider_user_id, provider_login, created_at \
             FROM auth_identities WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(executor)
        .await
    }

    /// 列出用户在全部提供方下的账号绑定。
    pub async fn list_identities_for_user<'e, E>(
        executor: E,
        user_id: i64,
    ) -> Result<Vec<AuthIdentity>, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        sqlx::query_as::<_, AuthIdentity>(
            "SELECT id, user_id, provider, provider_user_id, provider_login, created_at \
             FROM auth_identities WHERE user_id = ? ORDER BY id",
        )
        .bind(user_id)
        .fetch_all(executor)
        .await
    }

    /// 按主键删除账号绑定，返回是否删除了记录。
    pub async fn delete_identity<'e, E>(executor: E, id: i64) -> Result<bool, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        let result = sqlx::query("DELETE FROM auth_identities WHERE id = ?")
            .bind(id)
            .execute(executor)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// 统计用户名下账号绑定的数量（与通行密钥计数同型）。
    pub async fn count_identities_for_user<'e, E>(
        executor: E,
        user_id: i64,
    ) -> Result<i64, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        let (count,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM auth_identities WHERE user_id = ?")
                .bind(user_id)
                .fetch_one(executor)
                .await?;
        Ok(count)
    }
}

/// 会话。
pub mod sessions {
    use super::*;

    /// 新会话的插入参数。
    #[derive(Debug, Clone)]
    pub struct NewSession<'a> {
        /// token 的 SHA-256 十六进制。
        pub token_hash: &'a str,
        /// 所属用户。
        pub user_id: i64,
        /// 客户端 IP。
        pub ip: Option<&'a str>,
        /// 客户端 UA。
        pub user_agent: Option<&'a str>,
        /// 过期时间。
        pub expires_at: NaiveDateTime,
        /// 创建时间。
        pub created_at: NaiveDateTime,
    }

    /// 按 token 哈希查询会话。
    pub async fn find_by_token_hash<'e, E>(
        executor: E,
        token_hash: &str,
    ) -> Result<Option<Session>, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        sqlx::query_as::<_, Session>(
            "SELECT id, token_hash, user_id, ip, user_agent, expires_at, revoked_at, created_at \
             FROM sessions WHERE token_hash = ?",
        )
        .bind(token_hash)
        .fetch_optional(executor)
        .await
    }

    /// 插入会话。
    pub async fn insert<'e, E>(executor: E, session: &NewSession<'_>) -> Result<u64, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        let result = sqlx::query(
            "INSERT INTO sessions (token_hash, user_id, ip, user_agent, expires_at, created_at) \
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(session.token_hash)
        .bind(session.user_id)
        .bind(session.ip)
        .bind(session.user_agent)
        .bind(session.expires_at)
        .bind(session.created_at)
        .execute(executor)
        .await?;
        Ok(result.rows_affected())
    }

    /// 撤销用户的全部会话。
    pub async fn revoke_all<'e, E>(
        executor: E,
        user_id: i64,
        now: NaiveDateTime,
    ) -> Result<u64, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        let result = sqlx::query(
            "UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
        )
        .bind(now)
        .bind(user_id)
        .execute(executor)
        .await?;
        Ok(result.rows_affected())
    }

    /// 撤销用户除指定 token 外的其他会话。
    pub async fn revoke_others<'e, E>(
        executor: E,
        user_id: i64,
        keep_token_hash: &str,
        now: NaiveDateTime,
    ) -> Result<u64, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        let result = sqlx::query(
            "UPDATE sessions SET revoked_at = ? \
             WHERE user_id = ? AND token_hash <> ? AND revoked_at IS NULL",
        )
        .bind(now)
        .bind(user_id)
        .bind(keep_token_hash)
        .execute(executor)
        .await?;
        Ok(result.rows_affected())
    }
}

/// 系统设置。
pub mod settings {
    use super::*;

    /// 按 key 查询。
    pub async fn get<'e, E>(executor: E, key: &str) -> Result<Option<SystemSetting>, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        sqlx::query_as::<_, SystemSetting>(
            "SELECT `key`, `value`, updated_at, created_at FROM system_settings WHERE `key` = ?",
        )
        .bind(key)
        .fetch_optional(executor)
        .await
    }

    /// 按 key 读取字符串值。
    pub async fn get_value<'e, E>(executor: E, key: &str) -> Result<Option<String>, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        sqlx::query_scalar("SELECT `value` FROM system_settings WHERE `key` = ?")
            .bind(key)
            .fetch_optional(executor)
            .await
    }

    /// 全部设置项。
    pub async fn list_all<'e, E>(executor: E) -> Result<Vec<SystemSetting>, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        sqlx::query_as::<_, SystemSetting>(
            "SELECT `key`, `value`, updated_at, created_at FROM system_settings ORDER BY `key`",
        )
        .fetch_all(executor)
        .await
    }

    /// 写入或更新设置项。
    pub async fn upsert<'e, E>(
        executor: E,
        key: &str,
        value: &str,
        now: NaiveDateTime,
    ) -> Result<u64, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        let result = sqlx::query(
            "INSERT INTO system_settings (`key`, `value`, created_at, updated_at) \
             VALUES (?, ?, ?, ?) \
             ON DUPLICATE KEY UPDATE `value` = VALUES(`value`), \
             `updated_at` = VALUES(`updated_at`)",
        )
        .bind(key)
        .bind(value)
        .bind(now)
        .bind(now)
        .execute(executor)
        .await?;
        Ok(result.rows_affected())
    }
}

/// 后台审计日志。
pub mod audit {
    use super::*;

    /// 一条审计记录的插入参数。
    #[derive(Debug, Clone)]
    pub struct NewAuditLog<'a> {
        /// 操作者。
        pub actor_user_id: Option<i64>,
        /// 动作。
        pub action: &'a str,
        /// 目标类型。
        pub target_type: Option<&'a str>,
        /// 目标 ID。
        pub target_id: Option<&'a str>,
        /// 详情（JSON）。
        pub detail: Option<&'a Value>,
        /// 客户端 IP。
        pub ip: Option<&'a str>,
        /// 创建时间。
        pub created_at: NaiveDateTime,
    }

    /// 查询过滤条件；所有字段均为可选。
    #[derive(Debug, Clone, Default)]
    pub struct AuditFilter<'a> {
        /// 动作精确匹配。
        pub action: Option<&'a str>,
        /// 操作者。
        pub actor_user_id: Option<i64>,
        /// 目标类型精确匹配。
        pub target_type: Option<&'a str>,
        /// 目标 ID 精确匹配。
        pub target_id: Option<&'a str>,
        /// 关键词（动作 / 目标 / IP 的模糊匹配）。
        pub keyword: Option<&'a str>,
        /// 起始时间（含）。
        pub since: Option<NaiveDateTime>,
        /// 结束时间（不含）。
        pub until: Option<NaiveDateTime>,
    }

    /// 插入审计记录。
    pub async fn insert<'e, E>(executor: E, entry: &NewAuditLog<'_>) -> Result<u64, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        let result = sqlx::query(
            "INSERT INTO admin_audit_logs (actor_user_id, action, target_type, target_id, detail, \
             ip, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(entry.actor_user_id)
        .bind(entry.action)
        .bind(entry.target_type)
        .bind(entry.target_id)
        .bind(entry.detail)
        .bind(entry.ip)
        .bind(entry.created_at)
        .execute(executor)
        .await?;
        Ok(result.rows_affected())
    }

    /// 追加过滤条件（固定 SQL 片段 + 绑定参数）。
    fn push_filters(qb: &mut QueryBuilder<MySql>, filter: &AuditFilter<'_>) {
        qb.push(" WHERE 1 = 1");
        if let Some(action) = filter.action {
            qb.push(" AND action = ").push_bind(action);
        }
        if let Some(actor_user_id) = filter.actor_user_id {
            qb.push(" AND actor_user_id = ").push_bind(actor_user_id);
        }
        if let Some(target_type) = filter.target_type {
            qb.push(" AND target_type = ").push_bind(target_type);
        }
        if let Some(target_id) = filter.target_id {
            qb.push(" AND target_id = ").push_bind(target_id);
        }
        if let Some(keyword) = filter.keyword {
            let pattern = like_contains(keyword);
            qb.push(" AND (action LIKE ")
                .push_bind(pattern.clone())
                .push(" OR target_type LIKE ")
                .push_bind(pattern.clone())
                .push(" OR target_id LIKE ")
                .push_bind(pattern.clone())
                .push(" OR ip LIKE ")
                .push_bind(pattern)
                .push(")");
        }
        if let Some(since) = filter.since {
            qb.push(" AND created_at >= ").push_bind(since);
        }
        if let Some(until) = filter.until {
            qb.push(" AND created_at < ").push_bind(until);
        }
    }

    /// 统计满足条件的记录数。
    pub async fn count<'e, E>(executor: E, filter: &AuditFilter<'_>) -> Result<i64, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        let mut qb =
            QueryBuilder::<MySql>::new("SELECT CAST(COUNT(*) AS SIGNED) FROM admin_audit_logs");
        push_filters(&mut qb, filter);
        qb.build_query_scalar::<i64>().fetch_one(executor).await
    }

    /// 分页查询审计记录（按 id 倒序）。
    pub async fn list<'e, E>(
        executor: E,
        filter: &AuditFilter<'_>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AdminAuditLog>, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        let mut qb = QueryBuilder::<MySql>::new(
            "SELECT id, actor_user_id, action, target_type, target_id, detail, ip, created_at \
             FROM admin_audit_logs",
        );
        push_filters(&mut qb, filter);
        qb.push(" ORDER BY id DESC LIMIT ")
            .push_bind(limit)
            .push(" OFFSET ")
            .push_bind(offset);
        qb.build_query_as::<AdminAuditLog>()
            .fetch_all(executor)
            .await
    }
}

/// 推送日志。
pub mod push_logs {
    use super::*;

    /// 一条推送日志的插入参数。
    #[derive(Debug, Clone)]
    pub struct NewPushLog<'a> {
        /// 归属用户。
        pub owner_user_id: i64,
        /// 通道。
        pub channel_id: Option<i64>,
        /// 机器人。
        pub bot_profile_id: Option<i64>,
        /// 钩子类型。
        pub hook_type: &'a str,
        /// 推送来源（用户自填）。
        pub push_source: &'a str,
        /// 钩子原始消息类型。
        pub source_msgtype: &'a str,
        /// 推送目标。
        pub target: &'a str,
        /// QQ 消息类型。
        pub qq_msg_type: Option<i32>,
        /// 内容预览。
        pub content_preview: &'a str,
        /// 内容长度。
        pub content_len: i32,
        /// 推送状态。
        pub status: &'a str,
        /// 错误码。
        pub error_code: Option<&'a str>,
        /// 错误信息。
        pub error_message: Option<&'a str>,
        /// 耗时（毫秒）。
        pub duration_ms: f64,
        /// 请求 ID。
        pub request_id: &'a str,
        /// 创建时间。
        pub created_at: NaiveDateTime,
    }

    /// 查询过滤条件；所有字段均为可选。
    #[derive(Debug, Clone, Default)]
    pub struct PushLogFilter<'a> {
        /// 归属用户；`None` 表示不限（超管视角）。
        pub owner_user_id: Option<i64>,
        /// 钩子类型精确匹配。
        pub hook_type: Option<&'a str>,
        /// 状态精确匹配。
        pub status: Option<&'a str>,
        /// 内容关键词。
        pub keyword: Option<&'a str>,
        /// 起始时间（含）。
        pub since: Option<NaiveDateTime>,
        /// 结束时间（不含）。
        pub until: Option<NaiveDateTime>,
    }

    /// 插入推送日志，返回自增主键。
    pub async fn insert<'e, E>(executor: E, log: &NewPushLog<'_>) -> Result<i64, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        let result = sqlx::query(
            "INSERT INTO push_logs (owner_user_id, channel_id, bot_profile_id, hook_type, \
             push_source, source_msgtype, target, qq_msg_type, content_preview, content_len, \
             status, error_code, error_message, duration_ms, request_id, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(log.owner_user_id)
        .bind(log.channel_id)
        .bind(log.bot_profile_id)
        .bind(log.hook_type)
        .bind(log.push_source)
        .bind(log.source_msgtype)
        .bind(log.target)
        .bind(log.qq_msg_type)
        .bind(log.content_preview)
        .bind(log.content_len)
        .bind(log.status)
        .bind(log.error_code)
        .bind(log.error_message)
        .bind(log.duration_ms)
        .bind(log.request_id)
        .bind(log.created_at)
        .execute(executor)
        .await?;
        Ok(result.last_insert_id() as i64)
    }

    /// 追加过滤条件（固定 SQL 片段 + 绑定参数）。
    fn push_filters(qb: &mut QueryBuilder<MySql>, filter: &PushLogFilter<'_>) {
        qb.push(" WHERE 1 = 1");
        if let Some(owner_user_id) = filter.owner_user_id {
            qb.push(" AND p.owner_user_id = ").push_bind(owner_user_id);
        }
        if let Some(hook_type) = filter.hook_type {
            qb.push(" AND p.hook_type = ").push_bind(hook_type);
        }
        if let Some(status) = filter.status {
            qb.push(" AND p.status = ").push_bind(status);
        }
        if let Some(keyword) = filter.keyword {
            qb.push(" AND p.content_preview LIKE ")
                .push_bind(like_contains(keyword));
        }
        if let Some(since) = filter.since {
            qb.push(" AND p.created_at >= ").push_bind(since);
        }
        if let Some(until) = filter.until {
            qb.push(" AND p.created_at < ").push_bind(until);
        }
    }

    /// 统计满足条件的日志数。
    pub async fn count<'e, E>(executor: E, filter: &PushLogFilter<'_>) -> Result<i64, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        let mut qb = QueryBuilder::<MySql>::new("SELECT CAST(COUNT(*) AS SIGNED) FROM push_logs p");
        push_filters(&mut qb, filter);
        qb.build_query_scalar::<i64>().fetch_one(executor).await
    }

    /// 分页查询日志与归属用户邮箱（按 id 倒序）。
    pub async fn list<'e, E>(
        executor: E,
        filter: &PushLogFilter<'_>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<(PushLog, String)>, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        let mut qb = QueryBuilder::<MySql>::new(
            "SELECT p.id, p.owner_user_id, p.channel_id, p.bot_profile_id, p.hook_type, \
             p.push_source, \
             p.source_msgtype, p.target, p.qq_msg_type, p.content_preview, p.content_len, \
             p.status, p.error_code, p.error_message, p.duration_ms, p.request_id, p.created_at, \
             u.email FROM push_logs p JOIN users u ON u.id = p.owner_user_id",
        );
        push_filters(&mut qb, filter);
        qb.push(" ORDER BY p.id DESC LIMIT ")
            .push_bind(limit)
            .push(" OFFSET ")
            .push_bind(offset);
        let rows = qb.build().fetch_all(executor).await?;
        let mut result = Vec::with_capacity(rows.len());
        for row in rows {
            let log = PushLog::from_row(&row)?;
            let email: String = row.try_get("email")?;
            result.push((log, email));
        }
        Ok(result)
    }

    /// 按主键查询。
    pub async fn find_by_id<'e, E>(executor: E, id: i64) -> Result<Option<PushLog>, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        sqlx::query_as::<_, PushLog>(
            "SELECT id, owner_user_id, channel_id, bot_profile_id, hook_type, push_source, \
             source_msgtype, target, qq_msg_type, content_preview, content_len, status, \
             error_code, error_message, duration_ms, request_id, created_at \
             FROM push_logs WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(executor)
        .await
    }

    /// 统计时间区间内的日志数；`status` 为 `None` 时不区分状态。
    pub async fn count_between<'e, E>(
        executor: E,
        owner_user_id: Option<i64>,
        start: NaiveDateTime,
        end: NaiveDateTime,
        status: Option<&str>,
    ) -> Result<i64, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        let mut qb = QueryBuilder::<MySql>::new(
            "SELECT CAST(COUNT(*) AS SIGNED) FROM push_logs p WHERE p.created_at >= ",
        );
        qb.push_bind(start)
            .push(" AND p.created_at < ")
            .push_bind(end);
        if let Some(owner_user_id) = owner_user_id {
            qb.push(" AND p.owner_user_id = ").push_bind(owner_user_id);
        }
        if let Some(status) = status {
            qb.push(" AND p.status = ").push_bind(status);
        }
        qb.build_query_scalar::<i64>().fetch_one(executor).await
    }

    /// 按推送来源统计时间区间内的日志数。
    pub async fn push_source_counts_between<'e, E>(
        executor: E,
        owner_user_id: Option<i64>,
        start: NaiveDateTime,
        end: NaiveDateTime,
    ) -> Result<Vec<(String, i64)>, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        let mut qb = QueryBuilder::<MySql>::new(
            "SELECT p.push_source, CAST(COUNT(*) AS SIGNED) FROM push_logs p \
             WHERE p.created_at >= ",
        );
        qb.push_bind(start)
            .push(" AND p.created_at < ")
            .push_bind(end);
        if let Some(owner_user_id) = owner_user_id {
            qb.push(" AND p.owner_user_id = ").push_bind(owner_user_id);
        }
        qb.push(" GROUP BY p.push_source ORDER BY COUNT(*) DESC");
        qb.build_query_as::<(String, i64)>()
            .fetch_all(executor)
            .await
    }

    /// 最近的失败日志。
    pub async fn recent_failures<'e, E>(
        executor: E,
        owner_user_id: Option<i64>,
        limit: i64,
    ) -> Result<Vec<PushLog>, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        let mut qb = QueryBuilder::<MySql>::new(
            "SELECT p.id, p.owner_user_id, p.channel_id, p.bot_profile_id, p.hook_type, \
             p.push_source, \
             p.source_msgtype, p.target, p.qq_msg_type, p.content_preview, p.content_len, \
             p.status, p.error_code, p.error_message, p.duration_ms, p.request_id, p.created_at \
             FROM push_logs p WHERE p.status = 'failed'",
        );
        if let Some(owner_user_id) = owner_user_id {
            qb.push(" AND p.owner_user_id = ").push_bind(owner_user_id);
        }
        qb.push(" ORDER BY p.id DESC LIMIT ").push_bind(limit);
        qb.build_query_as::<PushLog>().fetch_all(executor).await
    }
}

/// 邮箱验证码。
pub mod email_codes {
    use super::*;

    /// 一条验证码的插入参数。
    #[derive(Debug, Clone)]
    pub struct NewEmailCode<'a> {
        /// 邮箱。
        pub email: &'a str,
        /// 用途。
        pub purpose: &'a str,
        /// 验证码哈希。
        pub code_hash: &'a str,
        /// 过期时间。
        pub expires_at: NaiveDateTime,
        /// 签发 IP。
        pub ip: Option<&'a str>,
        /// 创建时间。
        pub created_at: NaiveDateTime,
    }

    /// 同 (email, purpose) 下最新的未消费记录。
    pub async fn latest_unconsumed<'e, E>(
        executor: E,
        email: &str,
        purpose: &str,
    ) -> Result<Option<EmailVerificationCode>, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        sqlx::query_as::<_, EmailVerificationCode>(
            "SELECT id, email, purpose, code_hash, expires_at, consumed_at, attempts, ip, \
             created_at FROM email_verification_codes \
             WHERE email = ? AND purpose = ? AND consumed_at IS NULL \
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(email)
        .bind(purpose)
        .fetch_optional(executor)
        .await
    }

    /// 统计某时刻之后签发的数量（小时配额）。
    pub async fn count_since<'e, E>(
        executor: E,
        email: &str,
        purpose: &str,
        since: NaiveDateTime,
    ) -> Result<i64, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        sqlx::query_scalar(
            "SELECT CAST(COUNT(*) AS SIGNED) FROM email_verification_codes \
             WHERE email = ? AND purpose = ? AND created_at >= ?",
        )
        .bind(email)
        .bind(purpose)
        .bind(since)
        .fetch_one(executor)
        .await
    }

    /// 把同 (email, purpose) 下未消费的记录全部作废。
    pub async fn consume_all<'e, E>(
        executor: E,
        email: &str,
        purpose: &str,
        now: NaiveDateTime,
    ) -> Result<u64, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        let result = sqlx::query(
            "UPDATE email_verification_codes SET consumed_at = ? \
             WHERE email = ? AND purpose = ? AND consumed_at IS NULL",
        )
        .bind(now)
        .bind(email)
        .bind(purpose)
        .execute(executor)
        .await?;
        Ok(result.rows_affected())
    }

    /// 插入验证码，返回自增主键。
    pub async fn insert<'e, E>(executor: E, code: &NewEmailCode<'_>) -> Result<i64, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        let result = sqlx::query(
            "INSERT INTO email_verification_codes (email, purpose, code_hash, expires_at, \
             attempts, ip, created_at) VALUES (?, ?, ?, ?, 0, ?, ?)",
        )
        .bind(code.email)
        .bind(code.purpose)
        .bind(code.code_hash)
        .bind(code.expires_at)
        .bind(code.ip)
        .bind(code.created_at)
        .execute(executor)
        .await?;
        Ok(result.last_insert_id() as i64)
    }

    /// 更新失败次数；`consumed_at` 为 `Some` 时同时作废。
    pub async fn update_attempts<'e, E>(
        executor: E,
        id: i64,
        attempts: i32,
        consumed_at: Option<NaiveDateTime>,
    ) -> Result<u64, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        let result = sqlx::query(
            "UPDATE email_verification_codes SET attempts = ?, \
             consumed_at = COALESCE(?, consumed_at) WHERE id = ?",
        )
        .bind(attempts)
        .bind(consumed_at)
        .bind(id)
        .execute(executor)
        .await?;
        Ok(result.rows_affected())
    }

    /// 将验证码标记为已消费。
    pub async fn consume<'e, E>(
        executor: E,
        id: i64,
        now: NaiveDateTime,
    ) -> Result<u64, sqlx::Error>
    where
        E: Executor<'e, Database = MySql>,
    {
        let result =
            sqlx::query("UPDATE email_verification_codes SET consumed_at = ? WHERE id = ?")
                .bind(now)
                .bind(id)
                .execute(executor)
                .await?;
        Ok(result.rows_affected())
    }
}

/// Webhook 数据面的组合查询。
pub mod webhooks {
    use super::*;

    /// 按钩子类型与 token 哈希查询启用的通道。
    pub async fn find_enabled_channel(
        pool: &MySqlPool,
        hook_type: &str,
        webhook_token_hash: &str,
    ) -> Result<Option<Channel>, sqlx::Error> {
        channels::find_enabled_for_hook_type(pool, hook_type, webhook_token_hash).await
    }

    /// 按机器人主键查询启用的机器人配置。
    pub async fn find_enabled_bot(
        pool: &MySqlPool,
        bot_profile_id: i64,
    ) -> Result<Option<BotProfile>, sqlx::Error> {
        bots::find_enabled_by_id(pool, bot_profile_id).await
    }

    /// 一次解析出启用的通道与其机器人；任一不可用时返回 `None`。
    pub async fn resolve_enabled(
        pool: &MySqlPool,
        hook_type: &str,
        webhook_token_hash: &str,
    ) -> Result<Option<(Channel, BotProfile)>, sqlx::Error> {
        let Some(channel) = find_enabled_channel(pool, hook_type, webhook_token_hash).await? else {
            return Ok(None);
        };
        let bot = find_enabled_bot(pool, channel.bot_profile_id).await?;
        Ok(bot.map(|bot| (channel, bot)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pagination_defaults_and_clamps() {
        assert_eq!(normalize_pagination(1, 20), (20, 0));
        assert_eq!(normalize_pagination(3, 50), (50, 100));
        // 非法页码与页大小回落到安全值
        assert_eq!(normalize_pagination(0, 0), (DEFAULT_PAGE_SIZE, 0));
        assert_eq!(normalize_pagination(-5, -1), (DEFAULT_PAGE_SIZE, 0));
        // 超过上限时截断
        assert_eq!(normalize_pagination(2, 10_000), (MAX_PAGE_SIZE, 200));
        // 极端页码不会溢出
        assert_eq!(
            normalize_pagination(i64::MAX, MAX_PAGE_SIZE),
            (
                MAX_PAGE_SIZE,
                i64::MAX.saturating_sub(1).saturating_mul(MAX_PAGE_SIZE)
            )
        );
    }

    #[test]
    fn like_contains_escapes_wildcards() {
        assert_eq!(like_contains("abc"), "%abc%");
        assert_eq!(like_contains("50%"), "%50\\%%");
        assert_eq!(like_contains("a_b"), "%a\\_b%");
        assert_eq!(like_contains("a\\b"), "%a\\\\b%");
    }

    #[test]
    fn filters_default_to_none() {
        let filter = audit::AuditFilter::default();
        assert!(filter.action.is_none());
        assert!(filter.actor_user_id.is_none());
        assert!(filter.since.is_none());
        let filter = push_logs::PushLogFilter::default();
        assert!(filter.owner_user_id.is_none());
        assert!(filter.keyword.is_none());
    }
}
