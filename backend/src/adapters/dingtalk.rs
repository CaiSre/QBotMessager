//! 钉钉自定义机器人负载解析。
//!
//! @ 信息位于请求体顶层 `at` 对象中。

use serde_json::{Map, Value};

use super::base::{
    Adapter, AdapterError, Attachment, FMT_MARKDOWN, FMT_TEXT, UnifiedMessage, truthy, value_text,
};

/// 钉钉适配器。
#[derive(Debug, Default, Clone, Copy)]
pub struct DingTalkAdapter;

impl DingTalkAdapter {
    /// 构造适配器。
    pub fn new() -> Self {
        Self
    }
}

impl Adapter for DingTalkAdapter {
    fn platform(&self) -> &'static str {
        "dingtalk"
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
                "不支持的钉钉消息类型：{}",
                value_text(raw_type)
            )));
        };
        match msgtype {
            "text" => text_message(payload),
            "markdown" => markdown_message(payload),
            "link" => link_message(payload),
            "actionCard" => action_card_message(payload),
            "feedCard" => feed_card_message(payload),
            other => Err(AdapterError::payload(format!(
                "不支持的钉钉消息类型：{other}"
            ))),
        }
    }
}

fn text_message(payload: &Map<String, Value>) -> Result<UnifiedMessage, AdapterError> {
    let content = stripped_field(object(payload.get("text")), "content");
    if content.is_empty() {
        return Err(AdapterError::payload("text.content 不能为空"));
    }
    let mentions = at_mentions(payload.get("at"));
    let body = with_mentions(&content, &mentions);
    Ok(UnifiedMessage {
        fmt: FMT_TEXT.to_string(),
        body,
        mentions,
        source_msgtype: "text".to_string(),
        ..UnifiedMessage::default()
    })
}

fn markdown_message(payload: &Map<String, Value>) -> Result<UnifiedMessage, AdapterError> {
    let md = object(payload.get("markdown"));
    let title = stripped_field(md, "title");
    let content = stripped_field(md, "text");
    if content.is_empty() {
        return Err(AdapterError::payload("markdown.text 不能为空"));
    }
    let mentions = at_mentions(payload.get("at"));
    let body = with_mentions(&content, &mentions);
    Ok(UnifiedMessage {
        fmt: FMT_MARKDOWN.to_string(),
        title: non_empty(title),
        body,
        mentions,
        source_msgtype: "markdown".to_string(),
        ..UnifiedMessage::default()
    })
}

fn link_message(payload: &Map<String, Value>) -> Result<UnifiedMessage, AdapterError> {
    let link = object(payload.get("link"));
    let title = stripped_field(link, "title");
    let text = stripped_field(link, "text");
    let message_url = stripped_field(link, "messageUrl");
    let pic_url = stripped_field(link, "picUrl");

    let mut parts: Vec<String> = Vec::new();
    if !text.is_empty() {
        parts.push(text);
    }
    if !message_url.is_empty() {
        parts.push(format!("[查看详情]({message_url})"));
    }
    if parts.is_empty() && title.is_empty() {
        return Err(AdapterError::payload("link 消息内容为空"));
    }

    let attachments = if pic_url.is_empty() {
        Vec::new()
    } else {
        vec![Attachment {
            kind: "image".to_string(),
            url: Some(pic_url),
            ..Attachment::default()
        }]
    };
    Ok(UnifiedMessage {
        fmt: FMT_MARKDOWN.to_string(),
        title: non_empty(title),
        body: parts.join("\n\n"),
        attachments,
        source_msgtype: "link".to_string(),
        ..UnifiedMessage::default()
    })
}

fn action_card_message(payload: &Map<String, Value>) -> Result<UnifiedMessage, AdapterError> {
    let card = object(payload.get("actionCard"));
    let title = stripped_field(card, "title");
    let text = stripped_field(card, "text");

    let mut parts: Vec<String> = Vec::new();
    if !text.is_empty() {
        parts.push(text);
    }
    let single_title = stripped_field(card, "singleTitle");
    let single_url = stripped_field(card, "singleURL");
    if !single_title.is_empty() && !single_url.is_empty() {
        parts.push(format!("- [{single_title}]({single_url})"));
    }
    if let Some(buttons) = card
        .and_then(|map| map.get("btns"))
        .and_then(Value::as_array)
    {
        for button in buttons {
            let button = button.as_object();
            let button_title = stripped_field(button, "title");
            let button_url = stripped_field(button, "actionURL");
            if !button_title.is_empty() && !button_url.is_empty() {
                parts.push(format!("- [{button_title}]({button_url})"));
            } else if !button_title.is_empty() {
                parts.push(format!("- {button_title}"));
            }
        }
    }
    if parts.is_empty() && title.is_empty() {
        return Err(AdapterError::payload("actionCard 消息内容为空"));
    }
    Ok(UnifiedMessage {
        fmt: FMT_MARKDOWN.to_string(),
        title: non_empty(title),
        body: parts.join("\n\n"),
        source_msgtype: "actionCard".to_string(),
        ..UnifiedMessage::default()
    })
}

fn feed_card_message(payload: &Map<String, Value>) -> Result<UnifiedMessage, AdapterError> {
    let card = object(payload.get("feedCard"));
    let mut parts: Vec<String> = Vec::new();
    if let Some(links) = card
        .and_then(|map| map.get("links"))
        .and_then(Value::as_array)
    {
        for link in links {
            let link = link.as_object();
            let item_title = stripped_field(link, "title");
            let item_url = stripped_field(link, "messageURL");
            if !item_title.is_empty() && !item_url.is_empty() {
                parts.push(format!("- [{item_title}]({item_url})"));
            } else if !item_title.is_empty() {
                parts.push(format!("- {item_title}"));
            }
        }
    }
    if parts.is_empty() {
        return Err(AdapterError::payload("feedCard 消息内容为空"));
    }
    Ok(UnifiedMessage {
        fmt: FMT_MARKDOWN.to_string(),
        body: parts.join("\n"),
        source_msgtype: "feedCard".to_string(),
        ..UnifiedMessage::default()
    })
}

/// 钉钉的 @ 信息位于请求体顶层 `at` 对象中。
fn at_mentions(at: Option<&Value>) -> Vec<String> {
    let Some(at) = at.and_then(Value::as_object) else {
        return Vec::new();
    };
    let mut mentions: Vec<String> = Vec::new();
    if at.get("isAtAll").is_some_and(truthy) {
        mentions.push("所有人".to_string());
    }
    for key in ["atUserIds", "atMobiles"] {
        let Some(values) = at.get(key).and_then(Value::as_array) else {
            continue;
        };
        for value in values {
            if truthy(value) {
                mentions.push(value_text(value));
            }
        }
    }
    mentions
}

fn with_mentions(content: &str, mentions: &[String]) -> String {
    if mentions.is_empty() {
        return content.to_string();
    }
    let tags: Vec<String> = mentions.iter().map(|name| format!("@{name}")).collect();
    format!("{content} {}", tags.join(" "))
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn parse(payload: serde_json::Value) -> Result<UnifiedMessage, AdapterError> {
        DingTalkAdapter::new().parse(&payload, "")
    }

    #[test]
    fn text_appends_mentions_in_payload_order() {
        let message = parse(json!({
            "msgtype": "text",
            "text": {"content": "  磁盘告警  "},
            "at": {"isAtAll": true, "atUserIds": ["u1"], "atMobiles": ["13800000000"]}
        }))
        .expect("解析成功");
        assert_eq!(message.fmt, FMT_TEXT);
        assert_eq!(message.title, None);
        assert_eq!(message.body, "磁盘告警 @所有人 @u1 @13800000000");
        assert_eq!(message.mentions, ["所有人", "u1", "13800000000"]);
        assert_eq!(message.source_msgtype, "text");
    }

    #[test]
    fn type_field_is_fallback_and_markdown_keeps_title() {
        let message = parse(json!({
            "type": "markdown",
            "markdown": {"title": " 标题 ", "text": " **正文** "}
        }))
        .expect("解析成功");
        assert_eq!(message.fmt, FMT_MARKDOWN);
        assert_eq!(message.title.as_deref(), Some("标题"));
        assert_eq!(message.body, "**正文**");
        assert_eq!(message.source_msgtype, "markdown");
    }

    #[test]
    fn link_builds_detail_link_and_image_attachment() {
        let message = parse(json!({
            "msgtype": "link",
            "link": {
                "title": "构建失败",
                "text": "查看详情",
                "messageUrl": "https://example.com/build/1",
                "picUrl": "https://example.com/a.png"
            }
        }))
        .expect("解析成功");
        assert_eq!(message.fmt, FMT_MARKDOWN);
        assert_eq!(message.title.as_deref(), Some("构建失败"));
        assert_eq!(
            message.body,
            "查看详情\n\n[查看详情](https://example.com/build/1)"
        );
        assert_eq!(
            message.attachments,
            [Attachment {
                kind: "image".to_string(),
                url: Some("https://example.com/a.png".to_string()),
                title: None,
                media_id: None,
            }]
        );
    }

    #[test]
    fn action_card_renders_single_button_and_btns() {
        let message = parse(json!({
            "msgtype": "actionCard",
            "actionCard": {
                "title": "发布申请",
                "text": "请审批",
                "singleTitle": "查看",
                "singleURL": "https://example.com/a",
                "btns": [
                    {"title": "同意", "actionURL": "https://example.com/yes"},
                    {"title": "备注"}
                ]
            }
        }))
        .expect("解析成功");
        assert_eq!(
            message.body,
            "请审批\n\n- [查看](https://example.com/a)\n\n- [同意](https://example.com/yes)\n\n- 备注"
        );
        assert_eq!(message.source_msgtype, "actionCard");
    }

    #[test]
    fn feed_card_joins_links_with_single_newline() {
        let message = parse(json!({
            "msgtype": "feedCard",
            "feedCard": {
                "links": [
                    {"title": "一", "messageURL": "https://example.com/1"},
                    {"title": "二"}
                ]
            }
        }))
        .expect("解析成功");
        assert_eq!(message.body, "- [一](https://example.com/1)\n- 二");
        assert_eq!(message.title, None);
        assert_eq!(message.source_msgtype, "feedCard");
    }

    #[test]
    fn unsupported_and_invalid_payloads_are_rejected() {
        let error = parse(json!({"msgtype": "image"})).expect_err("不支持的类型");
        assert_eq!(error.to_string(), "不支持的钉钉消息类型：image");

        let error = parse(json!({"text": {"content": "x"}})).expect_err("缺少类型");
        assert_eq!(error.to_string(), "缺少 msgtype");

        let error = parse(json!([1, 2])).expect_err("非对象负载");
        assert_eq!(error.to_string(), "负载必须是 JSON 对象");

        let error =
            parse(json!({"msgtype": "text", "text": {"content": " "}})).expect_err("空内容");
        assert_eq!(error.to_string(), "text.content 不能为空");
    }
}
