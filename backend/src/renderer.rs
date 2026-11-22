//! 统一消息 → QQ 机器人消息体。
//!
//! QQ 约束（https://bot.q.qq.com/wiki/develop/api-v2/server-inter/message/type/markdown.html）：
//! - msg_type=0 纯文本（content），msg_type=2 Markdown（markdown.content）
//! - 两者互斥：传 markdown 时 content 必须为空字符串
//!
//! 语义与 Python `server/renderer.py` 一致。

use serde::Serialize;

use crate::markdown::{sanitize_markdown, sanitize_text};

/// 纯文本格式。
pub const FMT_TEXT: &str = "text";
/// Markdown 格式。
pub const FMT_MARKDOWN: &str = "markdown";

/// 纯文本消息类型。
pub const MSG_TYPE_TEXT: i32 = 0;
/// Markdown 消息类型。
pub const MSG_TYPE_MARKDOWN: i32 = 2;

/// Markdown 默认长度上限。
pub const DEFAULT_MARKDOWN_MAX_LEN: usize = 4000;
/// 纯文本默认长度上限。
pub const DEFAULT_TEXT_MAX_LEN: usize = 2000;

const EMPTY_PLACEHOLDER: &str = "（消息内容为空）";

/// 平台负载归一后的附件。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Attachment {
    /// 附件类型：image / file / voice / link。
    pub kind: String,
    /// 附件地址。
    pub url: Option<String>,
    /// 附件标题。
    pub title: Option<String>,
    /// 平台侧媒体 ID。
    pub media_id: Option<String>,
}

/// 平台负载归一后的统一消息。
#[derive(Debug, Clone, PartialEq)]
pub struct UnifiedMessage {
    /// 消息格式：`text` 或 `markdown`。
    pub fmt: String,
    /// 标题（可能为空）。
    pub title: Option<String>,
    /// 正文。
    pub body: String,
    /// 被提及的用户。
    pub mentions: Vec<String>,
    /// 附件。
    pub attachments: Vec<Attachment>,
    /// 平台原始消息类型。
    pub source_msgtype: String,
    /// 平台原始附加信息。
    pub meta: serde_json::Map<String, serde_json::Value>,
}

impl Default for UnifiedMessage {
    fn default() -> Self {
        Self {
            fmt: FMT_TEXT.to_string(),
            title: None,
            body: String::new(),
            mentions: Vec::new(),
            attachments: Vec::new(),
            source_msgtype: String::new(),
            meta: serde_json::Map::new(),
        }
    }
}

impl UnifiedMessage {
    /// 构造纯文本消息。
    pub fn text(body: impl Into<String>) -> Self {
        Self {
            body: body.into(),
            ..Self::default()
        }
    }

    /// 构造 Markdown 消息。
    pub fn markdown(body: impl Into<String>) -> Self {
        Self {
            fmt: FMT_MARKDOWN.to_string(),
            body: body.into(),
            ..Self::default()
        }
    }

    /// 设置标题。
    pub fn with_title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }
}

/// QQ 消息体（渲染结果）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QqPayload {
    /// 消息类型：0 纯文本 / 2 Markdown。
    pub msg_type: i32,
    /// 纯文本内容（Markdown 消息时为空串）。
    pub content: String,
    /// Markdown 内容（纯文本消息时为 `None`）。
    pub markdown: Option<String>,
}

impl QqPayload {
    /// 消息正文（按类型取 markdown 或 content）。
    pub fn text(&self) -> &str {
        match self.msg_type {
            MSG_TYPE_MARKDOWN => self.markdown.as_deref().unwrap_or_default(),
            _ => &self.content,
        }
    }

    /// 转成 QQ 接口的请求体。
    ///
    /// Markdown 时 `content` 必须是空串；纯文本时不带 `markdown` 字段。
    pub fn to_dict(&self) -> serde_json::Value {
        if self.msg_type == MSG_TYPE_MARKDOWN {
            serde_json::json!({
                "msg_type": MSG_TYPE_MARKDOWN,
                "markdown": { "content": self.markdown.clone().unwrap_or_default() },
                "content": "",
                "msg_id": "",
                "msg_seq": 1,
            })
        } else {
            serde_json::json!({
                "msg_type": MSG_TYPE_TEXT,
                "content": self.content,
                "msg_id": "",
                "msg_seq": 1,
            })
        }
    }
}

/// QQ 请求体的可序列化形式（保持字段顺序）。
#[derive(Debug, Clone, Serialize)]
pub struct QqRequestBody {
    /// 消息类型。
    pub msg_type: i32,
    /// Markdown 内容体（纯文本消息缺省）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub markdown: Option<MarkdownBody>,
    /// 纯文本内容。
    pub content: String,
    /// 消息 ID（发送时留空）。
    pub msg_id: String,
    /// 消息序号。
    pub msg_seq: i32,
}

/// Markdown 内容体。
#[derive(Debug, Clone, Serialize)]
pub struct MarkdownBody {
    /// Markdown 文本。
    pub content: String,
}

/// 把统一消息渲染为 QQ 消息体（默认长度上限）。
pub fn render_qq(message: &UnifiedMessage) -> QqPayload {
    render_qq_with_limits(message, DEFAULT_MARKDOWN_MAX_LEN, DEFAULT_TEXT_MAX_LEN)
}

/// 把统一消息渲染为 QQ 消息体。
pub fn render_qq_with_limits(
    message: &UnifiedMessage,
    markdown_max_len: usize,
    text_max_len: usize,
) -> QqPayload {
    let title = message
        .title
        .as_deref()
        .unwrap_or_default()
        .trim()
        .to_string();
    let body = message.body.as_str();

    if message.fmt == FMT_MARKDOWN {
        let mut parts: Vec<String> = Vec::new();
        if !title.is_empty() {
            parts.push(format!("### {title}"));
        }
        let cleaned = sanitize_markdown(body, Some(markdown_max_len));
        if !cleaned.is_empty() {
            parts.push(cleaned);
        }
        let markdown = parts.join("\n\n").trim().to_string();
        if !markdown.is_empty() {
            return QqPayload {
                msg_type: MSG_TYPE_MARKDOWN,
                content: String::new(),
                markdown: Some(markdown),
            };
        }
        // Markdown 清洗后为空 → 回退纯文本
        let joined = [title.as_str(), body]
            .iter()
            .filter(|part| !part.is_empty())
            .copied()
            .collect::<Vec<&str>>()
            .join(" ");
        let fallback = sanitize_text(&joined, Some(text_max_len));
        return QqPayload {
            msg_type: MSG_TYPE_TEXT,
            content: if fallback.is_empty() {
                EMPTY_PLACEHOLDER.to_string()
            } else {
                fallback
            },
            markdown: None,
        };
    }

    let mut cleaned_text = sanitize_text(body, Some(text_max_len));
    if !title.is_empty() {
        cleaned_text = if cleaned_text.is_empty() {
            title.clone()
        } else {
            format!("{title}\n{cleaned_text}").trim().to_string()
        };
    }
    QqPayload {
        msg_type: MSG_TYPE_TEXT,
        content: if cleaned_text.is_empty() {
            EMPTY_PLACEHOLDER.to_string()
        } else {
            cleaned_text
        },
        markdown: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markdown_message_uses_msg_type_2_with_empty_content() {
        let payload = render_qq(&UnifiedMessage::markdown("**磁盘** 90%").with_title("告警"));
        assert_eq!(payload.msg_type, MSG_TYPE_MARKDOWN);
        let body = payload.to_dict();
        assert_eq!(body["msg_type"], 2);
        assert_eq!(body["content"], "");
        assert_eq!(body["markdown"]["content"], "### 告警\n\n**磁盘** 90%");
    }

    #[test]
    fn text_message_uses_msg_type_0() {
        let payload = render_qq(&UnifiedMessage::text("内容").with_title("标题"));
        assert_eq!(payload.msg_type, MSG_TYPE_TEXT);
        let body = payload.to_dict();
        assert_eq!(body["msg_type"], 0);
        assert_eq!(body["content"], "标题\n内容");
        assert!(body.get("markdown").is_none());
    }

    #[test]
    fn markdown_empty_after_sanitize_falls_back_to_text() {
        let payload = render_qq(&UnifiedMessage::markdown("<div></div>"));
        assert_eq!(payload.msg_type, MSG_TYPE_TEXT);
    }

    #[test]
    fn empty_message_gets_placeholder() {
        let payload = render_qq(&UnifiedMessage::text(""));
        assert_eq!(payload.content, "（消息内容为空）");
    }

    #[test]
    fn truncation_limits() {
        let payload = render_qq_with_limits(
            &UnifiedMessage::markdown("字".repeat(500)),
            100,
            DEFAULT_TEXT_MAX_LEN,
        );
        assert!(payload.markdown.is_some());
        assert_eq!(payload.markdown.as_ref().unwrap().chars().count(), 100);
    }

    #[test]
    fn to_dict_shape_matches_qq_api() {
        let payload = render_qq(&UnifiedMessage::text("hi"));
        let body = payload.to_dict();
        assert_eq!(body["msg_id"], "");
        assert_eq!(body["msg_seq"], 1);

        let payload = render_qq(&UnifiedMessage::markdown("hi"));
        let body = payload.to_dict();
        assert_eq!(body["msg_type"], 2);
        assert_eq!(body["markdown"]["content"], "hi");
    }

    #[test]
    fn markdown_without_title_has_no_heading() {
        let payload = render_qq(&UnifiedMessage::markdown("正文"));
        assert_eq!(payload.markdown.as_deref(), Some("正文"));
    }
}
