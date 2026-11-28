//! 首次启动引导：初始超级管理员，并把环境变量中的 QQ 凭据导入为默认机器人。
//!
//! 语义：
//! - `BOOTSTRAP_ADMIN_EMAIL` 与 `BOOTSTRAP_ADMIN_PASSWORD` 同时非空才创建；
//! - 邮箱已存在时不改密码；仅当系统没有任何启用的超管时把该账号提升为超管；
//! - 仅当该管理员还没有机器人、且 `QQ_APPID` / `QQ_APP_SECRET` 同时非空时导入机器人
//!   （接入通道需在控制台创建：令牌只存哈希，明文仅在创建时展示一次）。

use chrono::Utc;
use serde_json::json;
use sqlx::MySqlPool;

use crate::auth::passwords::{hash_password_async, verify_password_async};
use crate::config::Config;
use crate::crypto::encrypt_secret;
use crate::db::models::{ROLE_SUPER_ADMIN, STATUS_ACTIVE, User};
use crate::db::queries;
use crate::db::queries::bots::NewBotProfile;
use crate::db::queries::users::NewUser;
use crate::error::AppError;
use crate::services::runtime_settings::RuntimeSettings;
use crate::services::users::{
    is_super_admin, normalize_email, unique_name, validate_email, validate_password,
};

/// 本次引导创建或提升的实体摘要（用于启动日志与测试）。
#[derive(Debug, Default)]
pub struct BootstrapSummary {
    /// 新建的超管邮箱。
    pub admin_created: Option<String>,
    /// 被提升为超管的既有账号邮箱。
    pub admin_promoted: Option<String>,
    /// 是否导入了默认机器人。
    pub bot_created: bool,
}

/// 执行幂等引导。
pub async fn run(
    pool: &MySqlPool,
    config: &Config,
    runtime: &RuntimeSettings,
) -> Result<BootstrapSummary, AppError> {
    let mut summary = BootstrapSummary::default();
    let mut admin: Option<User> = None;

    if !config.bootstrap_admin_email.is_empty() && !config.bootstrap_admin_password.is_empty() {
        let email = normalize_email(&config.bootstrap_admin_email);
        validate_email(&email)?;
        validate_password(&config.bootstrap_admin_password).map_err(|err| {
            AppError::bad_request(format!(
                "BOOTSTRAP_ADMIN_PASSWORD 不符合密码策略：{}",
                err.detail()
            ))
        })?;

        admin = match queries::users::find_by_email(pool, &email).await? {
            Some(user) if is_super_admin(&user) => Some(user),
            Some(user) => {
                let other_admins =
                    queries::users::count_other_active_super_admins(pool, user.id).await?;
                if other_admins > 0 {
                    tracing::warn!(
                        email = %email,
                        "已存在其他启用的超级管理员，跳过角色提升与机器人导入"
                    );
                    None
                } else {
                    // 提升靠邮箱匹配还不够：必须证明持有该账号的密码，
                    // 避免管理员邮箱被抢注后靠重启获得超管权限。
                    let password_matches = match user.password_hash.as_deref() {
                        Some(stored) => {
                            verify_password_async(&config.bootstrap_admin_password, stored).await
                        }
                        None => false,
                    };
                    if !password_matches {
                        tracing::warn!(
                            email = %email,
                            "既有账号的密码与 BOOTSTRAP_ADMIN_PASSWORD 不匹配，跳过角色提升与机器人导入"
                        );
                        None
                    } else {
                        sqlx::query("UPDATE users SET role = ? WHERE id = ?")
                            .bind(ROLE_SUPER_ADMIN)
                            .bind(user.id)
                            .execute(pool)
                            .await?;
                        tracing::warn!(
                            email = %email,
                            "系统中没有可用超级管理员，已将该账号提升为超级管理员"
                        );
                        summary.admin_promoted = Some(email.clone());
                        let mut promoted = user;
                        promoted.role = ROLE_SUPER_ADMIN.to_string();
                        Some(promoted)
                    }
                }
            }
            None => {
                let preferred = email.split('@').next().unwrap_or_default();
                let name = unique_name(pool, preferred).await?;
                let password_hash = hash_password_async(&config.bootstrap_admin_password).await?;
                let id = queries::users::insert(
                    pool,
                    &NewUser {
                        email: &email,
                        name: &name,
                        password_hash: Some(&password_hash),
                        role: ROLE_SUPER_ADMIN,
                        status: STATUS_ACTIVE,
                        created_at: Utc::now().naive_utc(),
                    },
                )
                .await?;
                tracing::info!(email = %email, "已创建初始超级管理员账号");
                summary.admin_created = Some(email.clone());
                Some(
                    queries::users::find_by_id(pool, id)
                        .await?
                        .ok_or_else(|| AppError::internal("创建初始管理员后无法读回账号"))?,
                )
            }
        };
    } else {
        tracing::warn!("未配置 BOOTSTRAP_ADMIN_EMAIL/PASSWORD，系统可能没有超级管理员");
    }

    let Some(admin) = admin else {
        if !config.qq_appid.is_empty() && !config.qq_app_secret.is_empty() {
            tracing::warn!("未配置初始超级管理员，跳过 QQ 机器人导入");
        }
        return Ok(summary);
    };

    let existing_bot: Option<(i64,)> =
        sqlx::query_as("SELECT id FROM bot_profiles WHERE owner_user_id = ? LIMIT 1")
            .bind(admin.id)
            .fetch_optional(pool)
            .await?;
    if existing_bot.is_none() && !config.qq_appid.is_empty() && !config.qq_app_secret.is_empty() {
        let secret = encrypt_secret(&config.qq_app_secret, config.app_secret_key.as_deref());
        let openids = json!(config.openids);
        let now = Utc::now().naive_utc();

        let mut tx = pool.begin().await?;
        queries::bots::insert(
            &mut *tx,
            &NewBotProfile {
                owner_user_id: admin.id,
                name: "默认机器人",
                qq_appid: &config.qq_appid,
                qq_app_secret: &secret,
                qq_host: runtime.qq_host(),
                default_openids: &openids,
                default_group_openid: None,
                enabled: true,
                created_at: now,
            },
        )
        .await?;
        tx.commit().await?;
        tracing::info!("已从环境变量导入默认 QQ 机器人配置；接入通道请在控制台创建");
        summary.bot_created = true;
    }

    Ok(summary)
}
