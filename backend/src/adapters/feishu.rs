//! 飞书自定义机器人负载解析。
//!
//! 正文中的 `<at user_id="x">名字</at>` 会被解析为提及并替换成 `@名字`。

use std::sync::OnceLock;

use regex::{Captures, Regex};
use serde_json::{Map, Value};

use super::base::{
    Adapter, AdapterError, Attachment, FMT_MARKDOWN, FMT_TEXT, UnifiedMessage, truthy, value_text,
};

/// 飞书适配器。
#[derive(Debug, Default, Clone, Copy)]
pub struct FeishuAdapter;

impl FeishuAdapter {
    /// 构造适配器。
    pub fn new() -> Self {
        Self
    }
}

impl Adapter for FeishuAdapter {
    fn platform(&self) -> &'static str {
        "feishu"
    }

    fn parse(&self, payload: &Value, _event: &str) -> Result<UnifiedMessage, AdapterError> {
        let Some(payload) = payload.as_object() else {
            return Err(AdapterError::payload("负载必须是 JSON 对象"));
        };
        let Some(raw_type) = first_truthy(payload, &["msg_type", "msgtype"]) else {
            return Err(AdapterError::payload("缺少 msg_type"));
        };
        let Some(msg_type) = raw_type.as_str() else {
            return Err(AdapterError::payload(format!(
                "不支持的飞书消息类型：{}",
                value_text(raw_type)
            )));
        };
        match msg_type {
            "text" => text_message(payload),
            "post" => post_message(payload),
            "image" => Ok(image_message(payload)),
            "file" => Ok(file_message(payload)),
            "share_chat" => Ok(share_chat_message(payload)),
            "interactive" => interactive_message(payload),
            other => Err(AdapterError::payload(format!(
                "不支持的飞书消息类型：{other}"
            ))),
        }
    }
}

fn at_tag_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?s)<at user_id="([^"]*)"\s*>(.*?)</at>"#).expect("飞书 at 正则")
    })
}

fn text_message(payload: &Map<String, Value>) -> Result<UnifiedMessage, AdapterError> {
    let text = stripped_field(object(payload.get("content")), "text");
    if text.is_empty() {
        return Err(AdapterError::payload("content.text 不能为空"));
    }
    let mut mentions: Vec<String> = Vec::new();
    for captures in at_tag_regex().captures_iter(&text) {
        let user_id = &captures[1];
        let name = captures[2].trim();
        mentions.push(if name.is_empty() {
            user_id.to_string()
        } else {
            name.to_string()
        });
    }
    let body = at_tag_regex()
        .replace_all(&text, |captures: &Captures| {
            let user_id = &captures[1];
            let name = captures[2].trim();
            if name.is_empty() {
                format!("@{user_id}")
            } else {
                format!("@{name}")
            }
        })
        .into_owned();
    Ok(UnifiedMessage {
        fmt: FMT_TEXT.to_string(),
        body,
        mentions,
        source_msgtype: "text".to_string(),
        ..UnifiedMessage::default()
    })
}

fn post_message(payload: &Map<String, Value>) -> Result<UnifiedMessage, AdapterError> {
    let content = object(payload.get("content"));
    let post = object(content.and_then(|map| map.get("post")));
    let locale = non_empty_object(post.and_then(|map| map.get("zh_cn")))
        .or_else(|| non_empty_object(post.and_then(|map| map.get("en_us"))));

    let title = locale
        .and_then(|map| map.get("title"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_string();
    let mut lines: Vec<String> = Vec::new();
    if let Some(paragraphs) = locale
        .and_then(|map| map.get("content"))
        .and_then(Value::as_array)
    {
        for paragraph in paragraphs {
            let line = render_paragraph(paragraph).trim().to_string();
            if !line.is_empty() {
                lines.push(line);
            }
        }
    }
    if lines.is_empty() && title.is_empty() {
        return Err(AdapterError::payload("post 内容为空"));
    }
    Ok(UnifiedMessage {
        fmt: FMT_MARKDOWN.to_string(),
        title: non_empty(title),
        body: lines.join("\n"),
        source_msgtype: "post".to_string(),
        ..UnifiedMessage::default()
    })
}

fn image_message(payload: &Map<String, Value>) -> UnifiedMessage {
    let image_key = stripped_field(object(payload.get("content")), "image_key");
    UnifiedMessage {
        fmt: FMT_TEXT.to_string(),
        body: "[图片]".to_string(),
        attachments: vec![Attachment {
            kind: "image".to_string(),
            media_id: non_empty(image_key),
            ..Attachment::default()
        }],
        source_msgtype: "image".to_string(),
        ..UnifiedMessage::default()
    }
}

fn file_message(payload: &Map<String, Value>) -> UnifiedMessage {
    let file_key = stripped_field(object(payload.get("content")), "file_key");
    UnifiedMessage {
        fmt: FMT_TEXT.to_string(),
        body: "[文件]".to_string(),
        attachments: vec![Attachment {
            kind: "file".to_string(),
            media_id: non_empty(file_key),
            ..Attachment::default()
        }],
        source_msgtype: "file".to_string(),
        ..UnifiedMessage::default()
    }
}

fn share_chat_message(payload: &Map<String, Value>) -> UnifiedMessage {
    let chat_id = stripped_field(object(payload.get("content")), "share_chat_id");
    let body = if chat_id.is_empty() {
        "[群聊分享]".to_string()
    } else {
        format!("[群聊分享] {chat_id}")
    };
    UnifiedMessage {
        fmt: FMT_TEXT.to_string(),
        body,
        source_msgtype: "share_chat".to_string(),
        ..UnifiedMessage::default()
    }
}

fn interactive_message(payload: &Map<String, Value>) -> Result<UnifiedMessage, AdapterError> {
    let content = object(payload.get("content"));
    // 自定义机器人卡片消息的 card 位于请求体顶层；空的卡片对象继续回退。
    let card = non_empty_object(payload.get("card"))
        .or_else(|| non_empty_object(content.and_then(|map| map.get("card"))))
        .or(content);

    let mut title: Option<String> = None;
    let header = object(card.and_then(|map| map.get("header")));
    match header.and_then(|map| map.get("title")) {
        Some(Value::Object(title_map)) => {
            let raw = first_truthy_str(title_map, &["content", "text"]).unwrap_or_default();
            let trimmed = raw.trim();
            if !trimmed.is_empty() {
                title = Some(trimmed.to_string());
            }
        }
        Some(Value::String(text)) => {
            let trimmed = text.trim();
            if !trimmed.is_empty() {
                title = Some(trimmed.to_string());
            }
        }
        _ => {}
    }

    let mut parts: Vec<String> = Vec::new();
    if let Some(elements) = card
        .and_then(|map| map.get("elements"))
        .and_then(Value::as_array)
    {
        for element in elements {
            let rendered = render_card_element(element);
            if !rendered.is_empty() {
                parts.push(rendered);
            }
        }
    }
    if parts.is_empty() && title.is_none() {
        return Err(AdapterError::payload("interactive 卡片内容为空"));
    }
    Ok(UnifiedMessage {
        fmt: FMT_MARKDOWN.to_string(),
        title,
        body: parts.join("\n\n"),
        source_msgtype: "interactive".to_string(),
        ..UnifiedMessage::default()
    })
}

fn render_paragraph(paragraph: &Value) -> String {
    match paragraph {
        Value::String(text) => text.trim().to_string(),
        Value::Array(items) => {
            let rendered: String = items.iter().map(render_paragraph).collect();
            rendered.trim().to_string()
        }
        Value::Object(map) => {
            let tag = map.get("tag").and_then(Value::as_str).unwrap_or("");
            match tag {
                "text" => map
                    .get("text")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                "a" => {
                    let text = field_trim(map, "text");
                    let href = field_trim(map, "href");
                    if !text.is_empty() && !href.is_empty() {
                        format!("[{text}]({href})")
                    } else if !text.is_empty() {
                        text
                    } else {
                        href
                    }
                }
                "at" => {
                    let user_id = field_trim(map, "user_id");
                    let name = match map.get("user_name").and_then(Value::as_str) {
                        Some(name) if !name.is_empty() => name.trim().to_string(),
                        _ => user_id,
                    };
                    if name.is_empty() {
                        String::new()
                    } else {
                        format!("@{name}")
                    }
                }
                "img" => {
                    let key = field_trim(map, "image_key");
                    if key.is_empty() {
                        "[图片]".to_string()
                    } else {
                        format!("[图片]({key})")
                    }
                }
                "md" => {
                    let md_text = map
                        .get("md")
                        .and_then(Value::as_object)
                        .and_then(|md| md.get("text"))
                        .and_then(Value::as_str)
                        .filter(|text| !text.is_empty());
                    md_text
                        .or_else(|| map.get("text").and_then(Value::as_str))
                        .unwrap_or_default()
                        .trim()
                        .to_string()
                }
                "hr" => "---".to_string(),
                _ => String::new(),
            }
        }
        _ => String::new(),
    }
}

fn render_card_element(element: &Value) -> String {
    match element {
        Value::String(text) => text.trim().to_string(),
        Value::Object(map) => {
            let tag = map.get("tag").and_then(Value::as_str).unwrap_or("");
            match tag {
                "markdown" => first_truthy_value(map, &["content", "text"])
                    .map(value_text)
                    .unwrap_or_default()
                    .trim()
                    .to_string(),
                "hr" => "---".to_string(),
                "div" => match map.get("text").filter(|value| truthy(value)) {
                    Some(Value::Object(text_map)) => {
                        first_truthy_value(text_map, &["content", "text"])
                            .map(value_text)
                            .unwrap_or_default()
                            .trim()
                            .to_string()
                    }
                    Some(value) => value_text(value).trim().to_string(),
                    None => String::new(),
                },
                "note" => {
                    let mut parts: Vec<String> = Vec::new();
                    if let Some(elements) = map.get("elements").and_then(Value::as_array) {
                        for item in elements {
                            let rendered = render_card_element(item);
                            if !rendered.is_empty() {
                                parts.push(rendered);
                            }
                        }
                    }
                    parts.join("\n")
                }
                _ => String::new(),
            }
        }
        _ => String::new(),
    }
}

fn object(value: Option<&Value>) -> Option<&Map<String, Value>> {
    value.and_then(Value::as_object)
}

fn non_empty_object(value: Option<&Value>) -> Option<&Map<String, Value>> {
    value
        .and_then(Value::as_object)
        .filter(|map| !map.is_empty())
}

fn stripped_field(map: Option<&Map<String, Value>>, key: &str) -> String {
    map.and_then(|map| map.get(key))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn field_trim(map: &Map<String, Value>, key: &str) -> String {
    map.get(key)
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

fn first_truthy_value<'a>(map: &'a Map<String, Value>, keys: &[&str]) -> Option<&'a Value> {
    keys.iter()
        .filter_map(|key| map.get(*key))
        .find(|value| truthy(value))
}

fn first_truthy_str<'a>(map: &'a Map<String, Value>, keys: &[&str]) -> Option<&'a str> {
    first_truthy_value(map, keys).and_then(Value::as_str)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn parse(payload: serde_json::Value) -> Result<UnifiedMessage, AdapterError> {
        FeishuAdapter::new().parse(&payload, "")
    }

    #[test]
    fn text_replaces_at_tags_and_collects_names() {
        let message = parse(json!({
            "msg_type": "text",
            "content": {"text": "<at user_id=\"ou_1\">张三</at> 你好 <at user_id=\"ou_2\"></at>"}
        }))
        .expect("解析成功");
        assert_eq!(message.fmt, FMT_TEXT);
        assert_eq!(message.body, "@张三 你好 @ou_2");
        assert_eq!(message.mentions, ["张三", "ou_2"]);
        assert_eq!(message.source_msgtype, "text");
    }

    #[test]
    fn post_renders_zh_cn_paragraphs() {
        let message = parse(json!({
            "msg_type": "post",
            "content": {"post": {"zh_cn": {
                "title": " 构建完成 ",
                "content": [
                    [
                        {"tag": "text", "text": "分支 "},
                        {"tag": "a", "text": "main", "href": "https://example.com/b"},
                        {"tag": "text", "text": " 完成"}
                    ],
                    [
                        {"tag": "at", "user_id": "ou_1", "user_name": "张三"},
                        {"tag": "text", "text": " 请查看"}
                    ],
                    [
                        {"tag": "img", "image_key": "img_1"},
                        {"tag": "hr"}
                    ]
                ]
            }}}
        }))
        .expect("解析成功");
        assert_eq!(message.fmt, FMT_MARKDOWN);
        assert_eq!(message.title.as_deref(), Some("构建完成"));
        assert_eq!(
            message.body,
            "分支 [main](https://example.com/b) 完成\n@张三 请查看\n[图片](img_1)---"
        );
        assert_eq!(message.source_msgtype, "post");
    }

    #[test]
    fn post_falls_back_to_en_us_when_zh_cn_is_empty() {
        let message = parse(json!({
            "msg_type": "post",
            "content": {"post": {
                "zh_cn": {},
                "en_us": {"title": "Build", "content": [[{"tag": "text", "text": "done"}]]}
            }}
        }))
        .expect("解析成功");
        assert_eq!(message.title.as_deref(), Some("Build"));
        assert_eq!(message.body, "done");
    }

    #[test]
    fn media_and_share_chat_messages() {
        let image = parse(json!({
            "msg_type": "image",
            "content": {"image_key": "img_1"}
        }))
        .expect("解析成功");
        assert_eq!(image.body, "[图片]");
        assert_eq!(
            image.attachments,
            [Attachment {
                kind: "image".to_string(),
                media_id: Some("img_1".to_string()),
                ..Attachment::default()
            }]
        );

        let file =
            parse(json!({"msgtype": "file", "content": {"file_key": "file_1"}})).expect("解析成功");
        assert_eq!(file.body, "[文件]");
        assert_eq!(file.attachments[0].kind, "file");

        let share = parse(json!({
            "msg_type": "share_chat",
            "content": {"share_chat_id": "oc_1"}
        }))
        .expect("解析成功");
        assert_eq!(share.body, "[群聊分享] oc_1");
        assert_eq!(share.source_msgtype, "share_chat");
    }

    #[test]
    fn interactive_card_uses_top_level_card() {
        let message = parse(json!({
            "msg_type": "interactive",
            "card": {
                "header": {"title": {"content": "发布通知", "text": ""}},
                "elements": [
                    {"tag": "markdown", "content": "**版本** 1.0"},
                    {"tag": "hr"},
                    {"tag": "div", "text": {"content": "详情"}},
                    {"tag": "note", "elements": [
                        {"tag": "plain_text", "content": "忽略"},
                        {"tag": "markdown", "content": "备注"}
                    ]}
                ]
            }
        }))
        .expect("解析成功");
        assert_eq!(message.title.as_deref(), Some("发布通知"));
        assert_eq!(message.body, "**版本** 1.0\n\n---\n\n详情\n\n备注");
        assert_eq!(message.source_msgtype, "interactive");
    }

    #[test]
    fn invalid_payloads_are_rejected() {
        assert_eq!(
            parse(json!({"msg_type": "audio"})).unwrap_err().to_string(),
            "不支持的飞书消息类型：audio"
        );
        assert_eq!(
            parse(json!({"msg_type": "text", "content": {"text": "  "}}))
                .unwrap_err()
                .to_string(),
            "content.text 不能为空"
        );
        assert_eq!(
            parse(json!({"msg_type": "interactive", "card": {}}))
                .unwrap_err()
                .to_string(),
            "interactive 卡片内容为空"
        );
        assert_eq!(
            parse(json!({"content": {"text": "x"}}))
                .unwrap_err()
                .to_string(),
            "缺少 msg_type"
        );
    }
}
