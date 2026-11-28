//! 认证相关能力。
//!
//! - `passwords`：PBKDF2 密码哈希（已实现）；
//! - `sessions`：会话创建/校验/撤销/过期与 Cookie（契约）；
//! - `oauth`：OAuth2 授权码流程；
//! - `passkey`：WebAuthn 注册与断言。

pub mod oauth;
pub mod passkey;
pub mod passwords;
pub mod sessions;

pub use passwords::{
    ALGORITHM, DEFAULT_ROUNDS, hash_password, hash_password_async, hash_password_with,
    verify_password, verify_password_async,
};
pub use sessions::{
    STEP_UP_WINDOW_MINUTES, USER_AGENT_MAX, clear_session_cookie, create_session, hash_token,
    is_session_valid, mark_verified, new_session_token, resolve_session, revoke_other_sessions,
    revoke_session, revoke_user_sessions, session_cookie, step_up_valid, verified_at,
};
