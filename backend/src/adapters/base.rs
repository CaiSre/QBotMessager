//! 钩子适配器：负载 → 统一消息模型。
//!
//! 四个钩子类型（钉钉 / 企业微信 / 飞书 / GitHub）的适配器在后续阶段实现本模块的
//! [`Adapter`] trait。统一消息结构复用 `renderer` 中的定义，避免两份模型漂移。

pub use crate::renderer::{Attachment, FMT_MARKDOWN, FMT_TEXT, UnifiedMessage};

use serde_json::Value;

/// 负载非法或消息类型不受支持。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct PayloadError(pub String);

impl PayloadError {
    /// 构造错误。
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

/// 事件合法但不在订阅范围内；调用方应按成功确认并跳过推送。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct IgnoredEvent(pub String);

impl IgnoredEvent {
    /// 构造忽略事件。
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

/// 适配器错误。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AdapterError {
    /// 负载非法或不支持。
    #[error(transparent)]
    Payload(#[from] PayloadError),
    /// 合法但无需推送的事件。
    #[error(transparent)]
    Ignored(#[from] IgnoredEvent),
}

impl AdapterError {
    /// 构造负载错误。
    pub fn payload(message: impl Into<String>) -> Self {
        Self::Payload(PayloadError::new(message))
    }

    /// 构造忽略事件。
    pub fn ignored(message: impl Into<String>) -> Self {
        Self::Ignored(IgnoredEvent::new(message))
    }

    /// 是否为应静默确认的忽略事件。
    pub fn is_ignored(&self) -> bool {
        matches!(self, Self::Ignored(_))
    }
}

/// 钩子适配器。
///
/// `parse` 读取钩子原始 webhook JSON，返回统一消息；`event` 为钩子事件类型
/// （GitHub 用 `X-GitHub-Event`，其余钩子类型传空串）。
pub trait Adapter: Send + Sync {
    /// 钩子类型标识（`dingtalk` / `wecom` / `feishu` / `github`）。
    fn hook_type(&self) -> &'static str;

    /// 解析原始负载。
    fn parse(&self, payload: &Value, event: &str) -> Result<UnifiedMessage, AdapterError>;
}

/// 把 JSON 值渲染为展示用文本：字符串原样、其余按 JSON 字面量。
///
/// 布尔与 null 在提及列表 / 标题编号里极少出现，渲染成 `true` / `null`
/// 是合理降级，保持与 JSON 负载一致的文本形式。
pub fn value_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

/// JSON 值是否非空（字符串看长度，数组和对象看元素数）。
pub fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64().is_some_and(|value| value != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
    }
}
