//! 业务服务层。
//!
//! - `runtime_settings`：`system_settings` 的内存缓存与一次性环境变量导入（已实现）；
//! - `throttle`：进程内 QPS/QPM 与登录失败限速（已实现）；
//! - `qq` / `mail` / `email_codes` / `users` / `audit` / `push` / `queue`
//!   为契约层：类型与签名已固定，函数体在后续阶段实现。

pub mod audit;
pub mod email_codes;
pub mod http;
pub mod mail;
pub mod push;
pub mod qq;
pub mod queue;
pub mod retention;
pub mod runtime_settings;
pub mod throttle;
pub mod users;

pub use push::{PushJob, PushOutcome};
pub use qq::{QqClient, QqError, QqTarget};
pub use queue::{PushQueue, QueueError, SentGuard};
pub use runtime_settings::{
    RuntimeSettings, SettingGroup, SettingItem, SettingKind, SettingSource, SettingSpec,
    SettingValue,
};
pub use throttle::{AttemptLimiter, LimiterRegistry, RateLimiter};
