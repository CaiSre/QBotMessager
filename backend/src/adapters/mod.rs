//! 钩子适配器：钉钉 / 企业微信 / 飞书 / GitHub。
//!
//! [`base`] 固定共享 trait 与统一消息结构，四个子模块各自实现对应钩子类型的负载解析；
//! 钩子注册表在 API 阶段加入。

pub mod base;
pub mod dingtalk;
pub mod feishu;
pub mod github;
pub mod wecom;

pub use base::{
    Adapter, AdapterError, Attachment, FMT_MARKDOWN, FMT_TEXT, IgnoredEvent, PayloadError,
    UnifiedMessage,
};
pub use dingtalk::DingTalkAdapter;
pub use feishu::FeishuAdapter;
pub use github::GitHubAdapter;
pub use wecom::WeComAdapter;
