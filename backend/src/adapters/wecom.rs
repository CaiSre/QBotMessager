//! 企业微信「消息推送」负载解析。
//!
//! 协议与 `server/adapters/wecom.py` 一一对应；正文中的 `<@all>` / `<@userid>`
//! 会被解析为提及并从正文移除。

use std::sync::OnceLock;

use regex::Regex;
use serde_json::{Map, Value};

use crate::markdown::degrade_tables;

use super::base::{Adapter, AdapterError, Attachment, FMT_MARKDOWN, FMT_TEXT, UnifiedMessage};

/// 企业微信适配器。
#[derive(Debug, Default, Clone, Copy)]
pub struct WeComAdapter;

impl WeComAdapter {
    /// 构造适配器。
    pub fn new() -> Self {
        Self
    }
}

impl Adapter for WeComAdapter {
    fn platform(&self) -> &'static str {
        "wecom"
    }

    fn parse(&self, payload: &Value, _event: &str) -> Result<UnifiedMessage, AdapterError> {
        let Some(payload) = payload.as_object() else {
            return Err(AdapterError::payload("负载必须是 JSON 对象"));
        };
        let Some(raw_type) = first_truthy(payload, &["msgtype", "type"]) else {
            return Err(AdapterError::payload("缺少 msgtype"));
        };
        let Some(msgtype) = raw_type.as_str() else {
            return Err(AdapterError::payload(format!(
                "不支持的企业微信消息类型：{}",
                value_text(raw_type)
            )));
        };
        match msgtype {
            "text" => text_message(payload),
            "markdown" => markdown_message(payload),
            "markdown_v2" => markdown_v2_message(payload),
            "news" => news_message(payload),
            "image" => Ok(media_message(payload, "image", "image", "[图片]")),
            "file" => Ok(media_message(payload, "file", "file", "[文件]")),
            "voice" => Ok(media_message(payload, "voice", "voice", "[语音]")),
            "template_card" => template_card_message(payload),
            other => Err(AdapterError::payload(format!(
                "不支持的企业微信消息类型：{other}"
            ))),
        }
    }
}

fn font_tag_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)</?font[^>]*>").expect("font 标签正则"))
}

fn mention_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"<@(all|[A-Za-z0-9_\-]+)>").expect("企微提及正则"))
}

fn double_space_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[ \t]{2,}").expect("连续空白正则"))
}

fn text_message(payload: &Map<String, Value>) -> Result<UnifiedMessage, AdapterError> {
    let text = object(payload.get("text"));
    let raw = stripped_field(text, "content");

    let without_mentions = mention_regex().replace_all(&raw, "");
    let collapsed = double_space_regex().replace_all(&without_mentions, " ");
    let cleaned = collapsed.trim().to_string();
    if cleaned.is_empty() {
        return Err(AdapterError::payload("text.content 不能为空"));
    }

    let mut mentions: Vec<String> = Vec::new();
    for captures in mention_regex().captures_iter(&raw) {
        let matched = &captures[1];
        let name = if matched == "all" {
            "所有人"
        } else {
            matched
        };
        if !mentions.iter().any(|existing| existing == name) {
            mentions.push(name.to_string());
        }
    }
    if let Some(values) = text
        .and_then(|map| map.get("mentioned_list"))
        .and_then(Value::as_array)
    {
        for value in values {
            let raw_id = if truthy(value) {
                value_text(value)
            } else {
                String::new()
            };
            let user_id = raw_id.trim();
            if user_id.is_empty() {
                continue;
            }
            let name = if user_id.to_lowercase() == "@all" {
                "所有人".to_string()
            } else {
                user_id.to_string()
            };
            if !mentions.contains(&name) {
                mentions.push(name);
            }
        }
    }
    if let Some(values) = text
        .and_then(|map| map.get("mentioned_mobile_list"))
        .and_then(Value::as_array)
    {
        for value in values {
            let raw_mobile = if truthy(value) {
                value_text(value)
            } else {
                String::new()
            };
            let mobile = raw_mobile.trim();
            if !mobile.is_empty() && !mentions.iter().any(|existing| existing == mobile) {
                mentions.push(mobile.to_string());
            }
        }
    }

    let body = if mentions.is_empty() {
        cleaned
    } else {
        let tags: Vec<String> = mentions.iter().map(|name| format!("@{name}")).collect();
        format!("{cleaned} {}", tags.join(" "))
    };
    Ok(UnifiedMessage {
        fmt: FMT_TEXT.to_string(),
        body,
        mentions,
        source_msgtype: "text".to_string(),
        ..UnifiedMessage::default()
    })
}

fn markdown_message(payload: &Map<String, Value>) -> Result<UnifiedMessage, AdapterError> {
    let content = stripped_field(object(payload.get("markdown")), "content");
    if content.is_empty() {
        return Err(AdapterError::payload("markdown.content 不能为空"));
    }
    let body = font_tag_regex().replace_all(&content, "").into_owned();
    Ok(UnifiedMessage {
        fmt: FMT_MARKDOWN.to_string(),
        body,
        source_msgtype: "markdown".to_string(),
        ..UnifiedMessage::default()
    })
}

fn markdown_v2_message(payload: &Map<String, Value>) -> Result<UnifiedMessage, AdapterError> {
    let content = stripped_field(object(payload.get("markdown_v2")), "content");
    if content.is_empty() {
        return Err(AdapterError::payload("markdown_v2.content 不能为空"));
    }
    Ok(UnifiedMessage {
        fmt: FMT_MARKDOWN.to_string(),
        body: degrade_tables(&content),
        source_msgtype: "markdown_v2".to_string(),
        ..UnifiedMessage::default()
    })
}

fn news_message(payload: &Map<String, Value>) -> Result<UnifiedMessage, AdapterError> {
    let mut parts: Vec<String> = Vec::new();
    if let Some(articles) = object(payload.get("news"))
        .and_then(|map| map.get("articles"))
        .and_then(Value::as_array)
    {
        for article in articles {
            let article = article.as_object();
            let title = stripped_field(article, "title");
            let url = stripped_field(article, "url");
            let description = stripped_field(article, "description");
            if !title.is_empty() && !url.is_empty() {
                parts.push(format!("- [{title}]({url})"));
            } else if !title.is_empty() {
                parts.push(format!("- {title}"));
            }
            if !description.is_empty() {
                parts.push(format!("  {description}"));
            }
        }
    }
    if parts.is_empty() {
        return Err(AdapterError::payload("news.articles 为空"));
    }
    Ok(UnifiedMessage {
        fmt: FMT_MARKDOWN.to_string(),
        body: parts.join("\n"),
        source_msgtype: "news".to_string(),
        ..UnifiedMessage::default()
    })
}

fn media_message(
    payload: &Map<String, Value>,
    key: &str,
    kind: &str,
    placeholder: &str,
) -> UnifiedMessage {
    let node = object(payload.get(key));
    let media_id = stripped_field(node, "media_id");
    let content = stripped_field(node, "content");
    let body = if content.is_empty() {
        placeholder.to_string()
    } else {
        content
    };
    UnifiedMessage {
        fmt: FMT_TEXT.to_string(),
        body,
        attachments: vec![Attachment {
            kind: kind.to_string(),
            media_id: non_empty(media_id),
            ..Attachment::default()
        }],
        source_msgtype: kind.to_string(),
        ..UnifiedMessage::default()
    }
}

fn template_card_message(payload: &Map<String, Value>) -> Result<UnifiedMessage, AdapterError> {
    let card = object(payload.get("template_card"));
    let main_title = object(card.and_then(|map| map.get("main_title")));
    let title = stripped_field(main_title, "title");
    let desc = stripped_field(main_title, "desc");

    let mut parts: Vec<String> = Vec::new();
    if !desc.is_empty() {
        parts.push(desc);
    }
    let sub_title = stripped_field(card, "sub_title_text");
    if !sub_title.is_empty() {
        parts.push(format!("**{sub_title}**"));
    }
    if let Some(elements) = card
        .and_then(|map| map.get("elements"))
        .and_then(Value::as_array)
    {
        for element in elements {
            let extracted = extract_card_text(element);
            if !extracted.is_empty() {
                parts.push(extracted);
            }
        }
    }
    if parts.is_empty() && title.is_empty() {
        return Err(AdapterError::payload("template_card 内容为空"));
    }
    Ok(UnifiedMessage {
        fmt: FMT_MARKDOWN.to_string(),
        title: non_empty(title),
        body: parts.join("\n\n"),
        source_msgtype: "template_card".to_string(),
        ..UnifiedMessage::default()
    })
}

/// 递归抽取模板卡片里的可读文本。
fn extract_card_text(node: &Value) -> String {
    match node {
        Value::String(text) => text.trim().to_string(),
        Value::Array(items) => {
            let parts: Vec<String> = items
                .iter()
                .map(extract_card_text)
                .filter(|part| !part.is_empty())
                .collect();
            parts.join("\n")
        }
        Value::Object(map) => {
            let mut parts: Vec<String> = Vec::new();
            for key in ["title", "desc", "content", "text", "value", "url", "key"] {
                let Some(value) = map.get(key) else {
                    continue;
                };
                match value {
                    Value::String(text) => {
                        let text = text.trim();
                        if !text.is_empty() {
                            parts.push(text.to_string());
                        }
                    }
                    Value::Object(_) | Value::Array(_) => {
                        let nested = extract_card_text(value);
                        if !nested.is_empty() {
                            parts.push(nested);
                        }
                    }
                    _ => {}
                }
            }
            parts.join("\n")
        }
        _ => String::new(),
    }
}

fn object(value: Option<&Value>) -> Option<&Map<String, Value>> {
    value.and_then(Value::as_object)
}

fn stripped_field(map: Option<&Map<String, Value>>, key: &str) -> String {
    map.and_then(|map| map.get(key))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn non_empty(text: String) -> Option<String> {
    if text.is_empty() { None } else { Some(text) }
}

fn first_truthy<'a>(map: &'a Map<String, Value>, keys: &[&str]) -> Option<&'a Value> {
    keys.iter()
        .filter_map(|key| map.get(*key))
        .find(|value| truthy(value))
}

fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().is_some_and(|value| value != 0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
    }
}

/// 近似 Python `str(value)`，用于提及列表。
fn value_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        Value::Null => "None".to_string(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn parse(payload: serde_json::Value) -> Result<UnifiedMessage, AdapterError> {
        WeComAdapter::new().parse(&payload, "")
    }

    #[test]
    fn text_strips_mention_tags_and_dedupes_lists() {
        let message = parse(json!({
            "msgtype": "text",
            "text": {
                "content": "告警 <@all> 请处理  <@zhangsan> 磁盘 <@zhangsan>",
                "mentioned_list": ["@all", "lisi", "lisi"],
                "mentioned_mobile_list": ["13800000000", "13800000000"]
            }
        }))
        .expect("解析成功");
        assert_eq!(message.fmt, FMT_TEXT);
        assert_eq!(
            message.body,
            "告警 请处理 磁盘 @所有人 @zhangsan @lisi @13800000000"
        );
        assert_eq!(
            message.mentions,
            ["所有人", "zhangsan", "lisi", "13800000000"]
        );
        assert_eq!(message.source_msgtype, "text");
    }

    #[test]
    fn markdown_removes_font_tags() {
        let message = parse(json!({
            "msgtype": "markdown",
            "markdown": {"content": "<font color=\"warning\">磁盘告警</font> **90%**"}
        }))
        .expect("解析成功");
        assert_eq!(message.fmt, FMT_MARKDOWN);
        assert_eq!(message.body, "磁盘告警 **90%**");
        assert_eq!(message.source_msgtype, "markdown");
    }

    #[test]
    fn markdown_v2_degrades_tables_like_python() {
        let message = parse(json!({
            "type": "markdown_v2",
            "markdown_v2": {"content": "|指标|值|\n|---|:---:|\n|磁盘|90%|"}
        }))
        .expect("解析成功");
        assert_eq!(message.body, "- **指标**：磁盘，**值**：90%");
        assert_eq!(message.source_msgtype, "markdown_v2");
    }

    #[test]
    fn news_renders_articles_and_descriptions() {
        let message = parse(json!({
            "msgtype": "news",
            "news": {"articles": [
                {"title": "发布", "url": "https://example.com/1", "description": "第一行"},
                {"title": "无链接"}
            ]}
        }))
        .expect("解析成功");
        assert_eq!(
            message.body,
            "- [发布](https://example.com/1)\n  第一行\n- 无链接"
        );
        assert_eq!(message.source_msgtype, "news");
    }

    #[test]
    fn media_messages_keep_placeholder_and_attachment() {
        let image = parse(json!({
            "msgtype": "image",
            "image": {"media_id": "MEDIA_1", "content": ""}
        }))
        .expect("解析成功");
        assert_eq!(image.body, "[图片]");
        assert_eq!(
            image.attachments,
            [Attachment {
                kind: "image".to_string(),
                media_id: Some("MEDIA_1".to_string()),
                ..Attachment::default()
            }]
        );

        let voice =
            parse(json!({"msgtype": "voice", "voice": {"content": "语音转写"}})).expect("解析成功");
        assert_eq!(voice.body, "语音转写");
        assert_eq!(voice.attachments[0].media_id, None);
        assert_eq!(voice.source_msgtype, "voice");
    }

    #[test]
    fn template_card_extracts_nested_text() {
        let message = parse(json!({
            "msgtype": "template_card",
            "template_card": {
                "main_title": {"title": "构建通知", "desc": "仓库 A"},
                "sub_title_text": "详情",
                "elements": [
                    {"title": "分支", "value": "main"},
                    {"content": {"title": "子项", "value": "1"}}
                ]
            }
        }))
        .expect("解析成功");
        assert_eq!(message.title.as_deref(), Some("构建通知"));
        assert_eq!(message.body, "仓库 A\n\n**详情**\n\n分支\nmain\n\n子项\n1");
        assert_eq!(message.source_msgtype, "template_card");
    }

    #[test]
    fn invalid_payloads_are_rejected() {
        assert_eq!(
            parse(json!({"msgtype": "video"})).unwrap_err().to_string(),
            "不支持的企业微信消息类型：video"
        );
        assert_eq!(
            parse(json!({"msgtype": "text", "text": {"content": "<@all>"}}))
                .unwrap_err()
                .to_string(),
            "text.content 不能为空"
        );
        assert_eq!(
            parse(json!({"msgtype": "news", "news": {"articles": []}}))
                .unwrap_err()
                .to_string(),
            "news.articles 为空"
        );
    }
}
