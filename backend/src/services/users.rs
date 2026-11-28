//! 账号、登录与个人资料业务逻辑。
//!
//! 用户注册 / 资料修改 / 密码与凭据校验：
//! 校验顺序、中文错误信息、HTTP 状态码、唯一性判定（`LOWER(name)`）与事务边界
//! 都不改变。密码哈希统一走 [`crate::auth::passwords`]（PBKDF2 600000 轮，
//! 异步变体内部使用 `spawn_blocking`）。

use chrono::Utc;
use serde_json::json;
use sqlx::MySqlPool;

use crate::auth::passwords::{burn_password_async, hash_password_async, verify_password_async};
use crate::auth::sessions::{create_session, revoke_other_sessions, revoke_user_sessions};
use crate::db::models::{
    InviteCode, ROLE_SUPER_ADMIN, ROLE_USER, ROLES, STATUS_ACTIVE, STATUS_DISABLED, User,
};
use crate::db::queries;
use crate::error::AppError;
use crate::services::email_codes;
use crate::services::mail;
use crate::services::runtime_settings::RuntimeSettings;
use crate::services::throttle::AttemptLimiter;

/// 用户名最大长度。
pub const NAME_MAX: usize = 128;
/// 邮箱最大长度。
pub const EMAIL_MAX: usize = 255;
/// 密码最短长度。
pub const PASSWORD_MIN: usize = 8;
/// 密码最大长度。
pub const PASSWORD_MAX: usize = 256;
/// 登录标识最大长度。
pub const ACCOUNT_MAX: usize = 255;
/// 邀请码最大长度。
pub const INVITE_CODE_MAX: usize = 64;
/// 自动生成用户名时的最大尝试次数，避免异常数据导致死循环。
const MAX_NAME_ATTEMPTS: u32 = 1_000;

/// 注册入参（API 层完成字段提取后传入）。
#[derive(Debug, Clone)]
pub struct RegisterInput<'a> {
    /// 邮箱。
    pub email: &'a str,
    /// 密码（至少 8 位）。
    pub password: &'a str,
    /// 用户名；空串表示按邮箱前缀自动生成。
    pub name: &'a str,
    /// 邀请码。
    pub invite_code: &'a str,
    /// 邮箱验证码；邮件服务配置后必填。
    pub email_code: Option<&'a str>,
}

/// 管理端修改账号的可选字段；`None` 表示保持不变。
#[derive(Debug, Clone, Default)]
pub struct AdminUserPatch<'a> {
    /// 角色。
    pub role: Option<&'a str>,
    /// 状态。
    pub status: Option<&'a str>,
    /// 用户名（会做 `strip`，允许置空）。
    pub name: Option<&'a str>,
}

/// 登录或注册成功后的结果：账号与明文会话 token。
///
/// Cookie 的组装由 API 层用 [`crate::auth::sessions::session_cookie`] 完成。
#[derive(Debug, Clone)]
pub struct AuthSession {
    /// 账号。
    pub user: User,
    /// 明文会话 token（不入库，库内只有 SHA-256）。
    pub token: String,
}

/// 邮箱规范化：去首尾空白并转小写。
pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

/// 邮箱格式校验：本地部分、域名与 TLD 均不含空白与 `@`。
pub fn is_valid_email(email: &str) -> bool {
    let mut parts = email.split('@');
    let Some(local) = parts.next() else {
        return false;
    };
    let Some(domain) = parts.next() else {
        return false;
    };
    if parts.next().is_some() {
        return false;
    }
    if local.is_empty() || local.chars().any(char::is_whitespace) {
        return false;
    }
    if domain.is_empty() || domain.chars().any(char::is_whitespace) {
        return false;
    }
    // 域内必须有点号，且点号前后都至少有一个字符。
    domain
        .char_indices()
        .any(|(index, ch)| ch == '.' && index > 0 && index + 1 < domain.len())
}

/// 校验邮箱格式与长度。
pub fn validate_email(email: &str) -> Result<(), AppError> {
    if email.chars().count() > EMAIL_MAX {
        return Err(AppError::validation(format!("邮箱最长 {EMAIL_MAX} 个字符")));
    }
    if !is_valid_email(email) {
        return Err(AppError::validation("邮箱格式非法"));
    }
    Ok(())
}

/// 校验新密码长度（注册、改密、重置共用）。
pub fn validate_password(password: &str) -> Result<(), AppError> {
    let length = password.chars().count();
    if !(PASSWORD_MIN..=PASSWORD_MAX).contains(&length) {
        return Err(AppError::validation(format!(
            "密码长度需在 {PASSWORD_MIN} 到 {PASSWORD_MAX} 位之间"
        )));
    }
    Ok(())
}

/// 校验个人资料里的用户名：先按原始长度校验上限，再做 `strip` 并要求非空。
pub fn validate_name(raw: &str) -> Result<String, AppError> {
    if raw.chars().count() > NAME_MAX {
        return Err(AppError::validation(format!(
            "用户名最长 {NAME_MAX} 个字符"
        )));
    }
    let name = raw.trim();
    if name.is_empty() {
        return Err(AppError::validation("用户名不能为空"));
    }
    Ok(name.to_string())
}

/// 是否超级管理员（只看角色）。
pub fn is_super_admin(user: &User) -> bool {
    user.role == ROLE_SUPER_ADMIN
}

/// 管理端权限校验：先要求账号启用，再要求超级管理员。
///
/// 需要超管角色。
pub fn require_super_admin(actor: &User) -> Result<(), AppError> {
    if actor.status != STATUS_ACTIVE {
        return Err(AppError::forbidden("账号已停用"));
    }
    if !is_super_admin(actor) {
        return Err(AppError::forbidden("仅超级管理员可操作"));
    }
    Ok(())
}

/// 用户名是否已被占用（忽略大小写）。
pub async fn name_taken(
    pool: &MySqlPool,
    name: &str,
    exclude_user_id: Option<i64>,
) -> Result<bool, AppError> {
    Ok(queries::users::name_taken(pool, name, exclude_user_id).await?)
}

/// 注册时未填用户名：以邮箱前缀为基准，冲突时追加 `-2`、`-3`…
pub async fn unique_name(pool: &MySqlPool, preferred: &str) -> Result<String, AppError> {
    let base: String = preferred.trim().chars().take(NAME_MAX).collect();
    let base = if base.is_empty() {
        "user".to_string()
    } else {
        base
    };
    let mut candidate = base.clone();
    let mut index: u32 = 1;
    while queries::users::name_taken(pool, &candidate, None).await? {
        index = index.saturating_add(1);
        if index > MAX_NAME_ATTEMPTS {
            return Err(AppError::internal("无法生成唯一用户名"));
        }
        candidate = suffixed_name(&base, index);
    }
    Ok(candidate)
}

/// 在长度上限内追加 `-<index>` 后缀。
fn suffixed_name(base: &str, index: u32) -> String {
    let suffix = format!("-{index}");
    let keep = NAME_MAX.saturating_sub(suffix.chars().count());
    let mut name: String = base.chars().take(keep).collect();
    name.push_str(&suffix);
    name
}

/// 校验邀请码是否可用于指定邮箱（不占用名额）。
///
/// 密码注册与 OAuth 首次建号共用，避免两条注册路径对邀请码的校验出现分歧。
pub async fn validate_invite(
    pool: &MySqlPool,
    code: &str,
    email: &str,
) -> Result<InviteCode, AppError> {
    if code.is_empty() || code.chars().count() > INVITE_CODE_MAX {
        return Err(AppError::validation(format!(
            "邀请码长度需在 1 到 {INVITE_CODE_MAX} 个字符之间"
        )));
    }
    let now = Utc::now().naive_utc();
    let Some(invite) = queries::invites::find_by_code(pool, code).await? else {
        return Err(AppError::bad_request("邀请码无效"));
    };
    if invite.revoked_at.is_some() {
        return Err(AppError::bad_request("邀请码已作废"));
    }
    if invite
        .expires_at
        .is_some_and(|expires_at| expires_at <= now)
    {
        return Err(AppError::bad_request("邀请码已过期"));
    }
    if invite.used_count >= invite.max_uses {
        return Err(AppError::bad_request("邀请码已用尽"));
    }
    if let Some(limited_email) = invite.email.as_deref()
        && limited_email.to_lowercase() != email
    {
        return Err(AppError::bad_request("邀请码不适用于该邮箱"));
    }
    Ok(invite)
}

/// 在事务内原子占用一次邀请名额。
pub async fn consume_invite(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    invite_id: i64,
    now: chrono::NaiveDateTime,
) -> Result<(), AppError> {
    let consumed = queries::invites::consume_slot(&mut **tx, invite_id, now).await?;
    if consumed != 1 {
        return Err(AppError::bad_request("邀请码已用尽"));
    }
    Ok(())
}

/// 注册（含邀请码名额占用、唯一性校验与邮箱验证码校验）。
///
/// 事务边界：邀请码名额占用与账号插入同一事务提交；用户名/邮箱唯一索引兜底
/// 并发注册，冲突分别映射为 409。
pub async fn register(
    pool: &MySqlPool,
    settings: &RuntimeSettings,
    input: RegisterInput<'_>,
    ip: Option<&str>,
    user_agent: Option<&str>,
) -> Result<AuthSession, AppError> {
    // 字段校验先于业务开关检查。
    let email = normalize_email(input.email);
    validate_email(&email)?;
    validate_password(input.password)?;
    if input.name.chars().count() > NAME_MAX {
        return Err(AppError::validation(format!(
            "用户名最长 {NAME_MAX} 个字符"
        )));
    }
    if input.invite_code.is_empty() || input.invite_code.chars().count() > INVITE_CODE_MAX {
        return Err(AppError::validation(format!(
            "邀请码长度需在 1 到 {INVITE_CODE_MAX} 个字符之间"
        )));
    }

    if !settings.register_enabled() {
        return Err(AppError::forbidden("注册入口已关闭"));
    }

    let now = Utc::now().naive_utc();
    let invite = validate_invite(pool, input.invite_code, &email).await?;

    if queries::users::email_taken(pool, &email, None).await? {
        return Err(AppError::conflict("该邮箱已注册"));
    }

    let explicit_name = input.name.trim();
    if !explicit_name.is_empty() && name_taken(pool, explicit_name, None).await? {
        return Err(AppError::conflict("该用户名已被使用"));
    }

    if mail::is_configured(settings) {
        let code = input.email_code.unwrap_or("");
        if code.is_empty() {
            return Err(AppError::bad_request("请填写邮箱验证码"));
        }
        if !email_codes::verify_code(pool, &email, email_codes::PURPOSE_REGISTER, code).await? {
            return Err(AppError::bad_request("邮箱验证码错误或已过期"));
        }
    }

    let final_name = if explicit_name.is_empty() {
        let prefix = email.split('@').next().unwrap_or("");
        unique_name(pool, prefix).await?
    } else {
        explicit_name.to_string()
    };

    // PBKDF2 计算不放在事务里，避免长时间占用连接与行锁。
    let password_hash = hash_password_async(input.password).await?;

    let mut tx = pool.begin().await?;
    // 原子占用名额：条件 UPDATE 保证并发注册也不会突破 max_uses。
    consume_invite(&mut tx, invite.id, now).await?;

    let new_user = queries::users::NewUser {
        email: &email,
        name: &final_name,
        password_hash: Some(&password_hash),
        role: ROLE_USER,
        status: STATUS_ACTIVE,
        created_at: now,
    };
    let user_id = match queries::users::insert(&mut *tx, &new_user).await {
        Ok(user_id) => user_id,
        Err(err) => {
            let _ = tx.rollback().await;
            return Err(map_register_duplicate(err));
        }
    };
    tx.commit().await?;

    let user = User {
        id: user_id,
        email,
        name: final_name,
        password_hash: Some(password_hash),
        role: ROLE_USER.to_string(),
        status: STATUS_ACTIVE.to_string(),
        last_login_at: None,
        created_at: now,
    };
    let token = create_session(pool, &user, settings.session_ttl_hours(), ip, user_agent).await?;
    Ok(AuthSession { user, token })
}

/// 校验登录凭据；成功时重置该 (IP, 账号) 的失败计数。
///
/// 顺序：限速检查 → 查账号 → 校验密码 → 检查状态。
pub async fn authenticate(
    pool: &MySqlPool,
    limiter: &AttemptLimiter,
    account: &str,
    password: &str,
    ip: Option<&str>,
) -> Result<User, AppError> {
    let account = account.trim().to_lowercase();
    if account.is_empty() {
        return Err(AppError::validation("请填写用户名或邮箱"));
    }
    if account.chars().count() > ACCOUNT_MAX {
        return Err(AppError::validation(format!(
            "用户名或邮箱最长 {ACCOUNT_MAX} 个字符"
        )));
    }
    if password.is_empty() {
        return Err(AppError::validation("请填写密码"));
    }
    if password.chars().count() > PASSWORD_MAX {
        return Err(AppError::validation(format!(
            "密码最长 {PASSWORD_MAX} 个字符"
        )));
    }

    let wait = limiter.remaining_wait(ip, &account);
    if wait > 0 {
        return Err(AppError::rate_limited(
            format!("尝试过于频繁，请 {wait} 秒后再试"),
            wait,
        ));
    }

    let user = if account.contains('@') {
        queries::users::find_by_email(pool, &account).await?
    } else {
        queries::users::find_by_name_ci(pool, &account).await?
    };
    let Some(user) = user else {
        // 账号不存在时也消耗一次等价 PBKDF2，避免用响应时间枚举已注册账号。
        burn_password_async(password).await;
        limiter.record_failure(ip, &account);
        return Err(AppError::unauthorized("用户名或密码错误"));
    };

    let password_ok = match user.password_hash.as_deref() {
        Some(stored) => verify_password_async(password, stored).await,
        // 仅 OAuth 创建的账号没有密码，按密码错误处理。
        None => false,
    };
    if !password_ok {
        limiter.record_failure(ip, &account);
        return Err(AppError::unauthorized("用户名或密码错误"));
    }
    // 密码正确后才暴露停用状态，避免账号枚举。
    if user.status != STATUS_ACTIVE {
        return Err(AppError::forbidden("账号已停用"));
    }

    limiter.reset(ip, &account);
    Ok(user)
}

/// 登录：校验凭据并创建会话。
pub async fn login(
    pool: &MySqlPool,
    limiter: &AttemptLimiter,
    settings: &RuntimeSettings,
    account: &str,
    password: &str,
    ip: Option<&str>,
    user_agent: Option<&str>,
) -> Result<AuthSession, AppError> {
    let user = authenticate(pool, limiter, account, password, ip).await?;
    let token = create_session(pool, &user, settings.session_ttl_hours(), ip, user_agent).await?;
    Ok(AuthSession { user, token })
}

/// 管理端账号列表（按 id 升序）。
pub async fn list_users(pool: &MySqlPool, actor: &User) -> Result<Vec<User>, AppError> {
    require_super_admin(actor)?;
    Ok(queries::users::list_all(pool).await?)
}

/// 管理端修改账号：角色、状态、用户名；返回更新后的账号。
///
/// 权限与保护规则：不能修改自己的角色/状态；
/// 降级或停用超级管理员时，系统必须仍保留至少一个启用的超级管理员。
pub async fn admin_update_user(
    pool: &MySqlPool,
    actor: &User,
    target_id: i64,
    patch: AdminUserPatch<'_>,
    ip: Option<&str>,
) -> Result<User, AppError> {
    require_super_admin(actor)?;

    // 降级判定涉及「整个启用超管行集」的不变式：并发降级事务若各在
    // 事务外读计数，可交错通过校验把系统降成零超管。这里在事务内先按
    // id 序锁定全部启用超管行，再读目标行并完成其余校验，两个并发降
    // 级在同一行集上串行化，后到者在先者提交后重新评估。
    let mut tx = pool.begin().await?;
    let super_admin_ids = queries::users::active_super_admin_ids_for_update(&mut *tx).await?;

    let Some(mut target) = queries::users::find_by_id(&mut *tx, target_id).await? else {
        return Err(AppError::not_found("用户不存在"));
    };

    if let Some(role) = patch.role {
        if !ROLES.contains(&role) {
            return Err(AppError::bad_request("角色非法"));
        }
        if target.id == actor.id && role != target.role.as_str() {
            return Err(AppError::bad_request("不能修改自己的角色"));
        }
    }
    if let Some(status) = patch.status {
        if status != STATUS_ACTIVE && status != STATUS_DISABLED {
            return Err(AppError::bad_request("状态非法"));
        }
        if target.id == actor.id && status != target.status.as_str() {
            return Err(AppError::bad_request("不能修改自己的账号状态"));
        }
    }

    let demoting = target.role == ROLE_SUPER_ADMIN
        && ((patch.role.is_some() && patch.role != Some(ROLE_SUPER_ADMIN))
            || (patch.status.is_some() && patch.status != Some(STATUS_ACTIVE)));
    if demoting
        && !super_admin_ids
            .iter()
            .any(|&admin_id| admin_id != target.id)
    {
        // 超管行集已在锁内，事务内的评估没有 TOCTOU 窗口。
        return Err(AppError::bad_request("系统至少需要一个启用的超级管理员"));
    }

    // 空串视为不修改：与 `COALESCE(?, name)` 语义一致，传 None 时保留原用户名。
    let new_name = patch
        .name
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    if let Some(name) = new_name.as_deref()
        && queries::users::name_taken(&mut *tx, name, Some(target.id)).await?
    {
        return Err(AppError::conflict("该用户名已被使用"));
    }
    queries::users::update_admin_fields(
        &mut *tx,
        target.id,
        patch.role,
        patch.status,
        new_name.as_deref(),
    )
    .await
    .map_err(map_name_duplicate)?;

    let detail = json!({ "role": patch.role, "status": patch.status });
    crate::services::audit::record_audit_on(
        &mut *tx,
        crate::services::audit::AuditEntry {
            actor_user_id: Some(actor.id),
            action: "user.update",
            target_type: Some("user"),
            target_id: Some(target.id.to_string()),
            detail: Some(detail),
            ip,
        },
    )
    .await?;
    tx.commit().await.map_err(map_name_duplicate)?;

    if let Some(role) = patch.role {
        target.role = role.to_string();
    }
    if let Some(status) = patch.status {
        target.status = status.to_string();
    }
    if let Some(name) = new_name {
        target.name = name;
    }
    Ok(target)
}

/// 个人资料：修改用户名。
pub async fn update_profile_name(
    pool: &MySqlPool,
    user: &User,
    name: &str,
) -> Result<User, AppError> {
    let name = validate_name(name)?;
    if name_taken(pool, &name, Some(user.id)).await? {
        return Err(AppError::conflict("该用户名已被使用"));
    }
    queries::users::update_name(pool, user.id, &name)
        .await
        .map_err(map_name_duplicate)?;

    let mut updated = user.clone();
    updated.name = name;
    Ok(updated)
}

/// 敏感操作当前密码校验的限速键；与登录失败计数分开，避免互相锁死。
fn step_up_key(user: &User) -> String {
    format!("stepup:{}", user.email)
}

/// 校验当前密码，并按 (来源地址, 账号) 限速。
///
/// 用于修改邮箱、修改密码与 step-up 验证；无密码账号返回引导信息，
/// 同时消耗一次等价 PBKDF2，避免按响应时间判断账号是否设置过密码。
pub async fn verify_current_password(
    limiter: &AttemptLimiter,
    ip: Option<&str>,
    user: &User,
    password: &str,
) -> Result<(), AppError> {
    let key = step_up_key(user);
    let wait = limiter.remaining_wait(ip, &key);
    if wait > 0 {
        return Err(AppError::rate_limited(
            format!("验证过于频繁，请 {wait} 秒后再试"),
            wait,
        ));
    }

    let Some(stored) = user.password_hash.as_deref() else {
        burn_password_async(password).await;
        return Err(AppError::bad_request(
            "该账号未设置密码，请先设置密码或重新登录验证身份",
        ));
    };
    if !verify_password_async(password, stored).await {
        limiter.record_failure(ip, &key);
        return Err(AppError::bad_request("当前密码错误"));
    }
    limiter.reset(ip, &key);
    Ok(())
}

/// 个人资料：修改邮箱。
///
/// 账号已有密码时必须校验当前密码与新地址验证码；无密码账号（仅 OAuth 创建）
/// 没有可验凭据，不允许直接改邮箱，须先通过「设置密码」流程补齐密码。
/// 成功后吊销其他会话，避免凭据泄露时旧设备仍以新邮箱维持登录。
#[allow(clippy::too_many_arguments)]
pub async fn update_profile_email(
    pool: &MySqlPool,
    limiter: &AttemptLimiter,
    user: &User,
    email: &str,
    current_password: &str,
    email_code: &str,
    keep_token: &str,
    ip: Option<&str>,
) -> Result<User, AppError> {
    let email = normalize_email(email);
    validate_email(&email)?;

    verify_current_password(limiter, ip, user, current_password).await?;
    if email == user.email {
        return Ok(user.clone());
    }
    if queries::users::email_taken(pool, &email, Some(user.id)).await? {
        return Err(AppError::conflict("该邮箱已被使用"));
    }
    if email_code.is_empty() {
        return Err(AppError::bad_request("请填写邮箱验证码"));
    }
    if !email_codes::verify_code(pool, &email, email_codes::PURPOSE_CHANGE_EMAIL, email_code)
        .await?
    {
        return Err(AppError::bad_request("邮箱验证码错误或已过期"));
    }

    queries::users::update_email(pool, user.id, &email)
        .await
        .map_err(map_email_duplicate)?;
    revoke_other_sessions(pool, user.id, keep_token).await?;

    let mut updated = user.clone();
    updated.email = email;
    Ok(updated)
}

/// 修改密码（个人中心）。
///
/// - 已有密码：必须验证当前密码，且新密码不能与当前密码相同；
/// - 无密码且邮件已配置：必须提供 `set_password` 邮箱验证码；
/// - 成功后撤销除当前会话外的其他会话。
#[allow(clippy::too_many_arguments)]
pub async fn change_password(
    pool: &MySqlPool,
    limiter: &AttemptLimiter,
    settings: &RuntimeSettings,
    user: &User,
    current_password: &str,
    new_password: &str,
    email_code: &str,
    keep_token: &str,
    ip: Option<&str>,
) -> Result<(), AppError> {
    validate_password(new_password)?;

    if let Some(stored) = user.password_hash.as_deref() {
        verify_current_password(limiter, ip, user, current_password).await?;
        if verify_password_async(new_password, stored).await {
            return Err(AppError::bad_request("新密码不能与当前密码相同"));
        }
    } else if mail::is_configured(settings) {
        if email_code.is_empty() {
            return Err(AppError::bad_request("请填写邮箱验证码"));
        }
        if !email_codes::verify_code(
            pool,
            &user.email,
            email_codes::PURPOSE_SET_PASSWORD,
            email_code,
        )
        .await?
        {
            return Err(AppError::bad_request("邮箱验证码错误或已过期"));
        }
    }

    let password_hash = hash_password_async(new_password).await?;
    queries::users::update_password_hash(pool, user.id, &password_hash).await?;
    revoke_other_sessions(pool, user.id, keep_token).await?;
    Ok(())
}

/// 通过邮箱验证码重置密码；成功后撤销该用户的全部会话。
pub async fn reset_password(
    pool: &MySqlPool,
    settings: &RuntimeSettings,
    email: &str,
    code: &str,
    new_password: &str,
) -> Result<(), AppError> {
    let email = normalize_email(email);
    validate_email(&email)?;
    validate_password(new_password)?;

    if !mail::is_configured(settings) {
        // 邮件服务未配置返回 503；错误类型里只有 DatabaseBusy 映射 503，
        // 这里沿用该变体以保证状态码与响应体一致。
        return Err(AppError::database_busy("邮件服务未配置"));
    }

    let Some(user) = queries::users::find_by_email(pool, &email).await? else {
        return Err(AppError::bad_request("验证码错误或已过期"));
    };
    if user.status != STATUS_ACTIVE {
        return Err(AppError::bad_request("验证码错误或已过期"));
    }
    if !email_codes::verify_code(pool, &email, email_codes::PURPOSE_RESET_PASSWORD, code).await? {
        return Err(AppError::bad_request("验证码错误或已过期"));
    }

    let password_hash = hash_password_async(new_password).await?;
    queries::users::update_password_hash(pool, user.id, &password_hash).await?;
    revoke_user_sessions(pool, user.id).await?;
    Ok(())
}

/// 唯一索引冲突的分类。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DuplicateKey {
    /// 用户名唯一索引。
    Name,
    /// 其他（邮箱唯一索引兜底）。
    Email,
}

/// 识别 MySQL 1062（唯一索引冲突）。
///
/// MySQL 8 的错误信息形如
/// `Duplicate entry 'x' for key 'users.uq_users_name_lower'`；
/// 按索引名判定，不匹配时按邮箱兜底。
fn duplicate_key(err: &sqlx::Error) -> Option<DuplicateKey> {
    let sqlx::Error::Database(db_err) = err else {
        return None;
    };
    if db_err.code().as_deref() != Some("1062") {
        return None;
    }
    let message = db_err.message().to_ascii_lowercase();
    // 未匹配到已知索引名时按邮箱兜底，与下方注册映射的判定顺序一致。
    if message.contains("uq_users_name_lower") {
        Some(DuplicateKey::Name)
    } else {
        Some(DuplicateKey::Email)
    }
}

/// 注册时的冲突映射：用户名优先判断，其余按邮箱已注册。
fn map_register_duplicate(err: sqlx::Error) -> AppError {
    match duplicate_key(&err) {
        Some(DuplicateKey::Name) => AppError::conflict("该用户名已被使用"),
        Some(DuplicateKey::Email) => AppError::conflict("该邮箱已注册"),
        None => AppError::from(err),
    }
}

/// 用户名更新的冲突映射。
fn map_name_duplicate(err: sqlx::Error) -> AppError {
    if duplicate_key(&err).is_some() {
        AppError::conflict("该用户名已被使用")
    } else {
        AppError::from(err)
    }
}

/// 邮箱更新的冲突映射。
fn map_email_duplicate(err: sqlx::Error) -> AppError {
    if duplicate_key(&err).is_some() {
        AppError::conflict("该邮箱已被使用")
    } else {
        AppError::from(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_user(role: &str, status: &str) -> User {
        User {
            id: 1,
            email: "alice@example.com".to_string(),
            name: "alice".to_string(),
            password_hash: None,
            role: role.to_string(),
            status: status.to_string(),
            last_login_at: None,
            created_at: Utc::now().naive_utc(),
        }
    }

    #[test]
    fn normalize_email_trims_and_lowercases() {
        assert_eq!(normalize_email("  Alice@Example.COM "), "alice@example.com");
        assert_eq!(normalize_email(""), "");
    }

    #[test]
    fn email_format_rejects_bad_addresses() {
        for valid in [
            "bob@example.com",
            "a.b+c@sub.example.com",
            "user.name@example.org",
            "a@.b.c",
        ] {
            assert!(is_valid_email(valid), "{valid} 应被接受");
        }
        for invalid in [
            "",
            "a",
            "a@b",
            "a@b.",
            "a@.b",
            "@b.co",
            "a b@example.com",
            "a@b co",
            "a@@b.co",
            "bob@example.com\nx",
        ] {
            assert!(!is_valid_email(invalid), "{invalid} 应被拒绝");
        }
    }

    #[test]
    fn validate_email_reports_chinese_message() {
        assert_eq!(
            validate_email("not-an-email").unwrap_err().detail(),
            "邮箱格式非法"
        );
        let too_long = format!("{}@example.com", "a".repeat(EMAIL_MAX));
        assert_eq!(
            validate_email(&too_long).unwrap_err().detail(),
            "邮箱最长 255 个字符"
        );
        assert!(validate_email("alice@example.com").is_ok());
    }

    #[test]
    fn password_length_boundaries() {
        assert!(validate_password("12345678").is_ok());
        assert!(validate_password(&"x".repeat(PASSWORD_MAX)).is_ok());
        assert!(validate_password("1234567").is_err());
        assert!(validate_password(&"x".repeat(PASSWORD_MAX + 1)).is_err());
        // 按字符计数
        assert!(validate_password(&"密".repeat(PASSWORD_MIN)).is_ok());
    }

    #[test]
    fn name_validation_trims_and_caps() {
        assert_eq!(validate_name("  alice  ").unwrap(), "alice");
        assert_eq!(validate_name("   ").unwrap_err().detail(), "用户名不能为空");
        assert_eq!(validate_name("").unwrap_err().detail(), "用户名不能为空");
        let too_long = "a".repeat(NAME_MAX + 1);
        assert!(validate_name(&too_long).is_err());
        assert_eq!(
            validate_name(&"a".repeat(NAME_MAX)).unwrap().len(),
            NAME_MAX
        );
    }

    #[test]
    fn suffixed_name_keeps_total_length() {
        assert_eq!(suffixed_name("alice", 2), "alice-2");
        assert_eq!(suffixed_name("alice", 10), "alice-10");
        let base = "x".repeat(NAME_MAX);
        let candidate = suffixed_name(&base, 2);
        assert_eq!(candidate.chars().count(), NAME_MAX);
        assert!(candidate.ends_with("-2"));
        let candidate = suffixed_name(&base, 1_000);
        assert_eq!(candidate.chars().count(), NAME_MAX);
        assert!(candidate.ends_with("-1000"));
    }

    #[test]
    fn super_admin_requires_role_and_active_status() {
        let admin = sample_user(ROLE_SUPER_ADMIN, STATUS_ACTIVE);
        assert!(is_super_admin(&admin));
        assert!(require_super_admin(&admin).is_ok());

        let disabled = sample_user(ROLE_SUPER_ADMIN, STATUS_DISABLED);
        assert_eq!(
            require_super_admin(&disabled).unwrap_err().detail(),
            "账号已停用"
        );

        let normal = sample_user(ROLE_USER, STATUS_ACTIVE);
        assert!(!is_super_admin(&normal));
        assert_eq!(
            require_super_admin(&normal).unwrap_err().detail(),
            "仅超级管理员可操作"
        );
    }
}
