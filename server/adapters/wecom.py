"""企业微信「消息推送」负载解析。

官方文档：https://developer.work.weixin.qq.com/document/path/91770
"""

from __future__ import annotations

import re

from server.adapters.base import (
    FMT_MARKDOWN,
    FMT_TEXT,
    Attachment,
    PayloadError,
    UnifiedMessage,
)
from server.markdown import degrade_tables

_FONT_TAG = re.compile(r"</?font[^>]*>", re.IGNORECASE)
_MENTION = re.compile(r"<@(all|[A-Za-z0-9_\-]+)>")


class WeComAdapter:
    platform = "wecom"

    def parse(self, payload: dict) -> UnifiedMessage:
        if not isinstance(payload, dict):
            raise PayloadError("负载必须是 JSON 对象")
        msgtype = payload.get("msgtype") or payload.get("type")
        if not msgtype:
            raise PayloadError("缺少 msgtype")
        handler = {
            "text": self._text,
            "markdown": self._markdown,
            "markdown_v2": self._markdown_v2,
            "news": self._news,
            "image": self._image,
            "file": self._file,
            "voice": self._voice,
            "template_card": self._template_card,
        }.get(msgtype)
        if handler is None:
            raise PayloadError(f"不支持的企业微信消息类型：{msgtype}")
        return handler(payload)

    # -- 各类型 -------------------------------------------------------------

    def _text(self, payload: dict) -> UnifiedMessage:
        text = payload.get("text") or {}
        raw = (text.get("content") or "").strip()
        cleaned = re.sub(r"[ \t]{2,}", " ", _MENTION.sub("", raw)).strip()
        if not cleaned:
            raise PayloadError("text.content 不能为空")
        mentions: list[str] = []
        for match in _MENTION.findall(raw):
            name = "所有人" if match == "all" else match
            if name not in mentions:
                mentions.append(name)
        for userid in text.get("mentioned_list") or []:
            uid = str(userid or "").strip()
            if not uid:
                continue
            name = "所有人" if uid.lower() == "@all" else uid
            if name not in mentions:
                mentions.append(name)
        for mobile in text.get("mentioned_mobile_list") or []:
            value = str(mobile or "").strip()
            if value and value not in mentions:
                mentions.append(value)
        body = cleaned
        if mentions:
            body = f"{body} " + " ".join(f"@{m}" for m in mentions)
        return UnifiedMessage(
            fmt=FMT_TEXT, body=body, mentions=mentions, source_msgtype="text"
        )

    def _markdown(self, payload: dict) -> UnifiedMessage:
        md = payload.get("markdown") or {}
        content = (md.get("content") or "").strip()
        if not content:
            raise PayloadError("markdown.content 不能为空")
        content = _FONT_TAG.sub("", content)
        return UnifiedMessage(
            fmt=FMT_MARKDOWN, body=content, source_msgtype="markdown"
        )

    def _markdown_v2(self, payload: dict) -> UnifiedMessage:
        md = payload.get("markdown_v2") or {}
        content = (md.get("content") or "").strip()
        if not content:
            raise PayloadError("markdown_v2.content 不能为空")
        return UnifiedMessage(
            fmt=FMT_MARKDOWN,
            body=degrade_tables(content),
            source_msgtype="markdown_v2",
        )

    def _news(self, payload: dict) -> UnifiedMessage:
        news = payload.get("news") or {}
        articles = news.get("articles") or []
        parts: list[str] = []
        for article in articles:
            title = (article.get("title") or "").strip()
            url = (article.get("url") or "").strip()
            description = (article.get("description") or "").strip()
            if title and url:
                parts.append(f"- [{title}]({url})")
            elif title:
                parts.append(f"- {title}")
            if description:
                parts.append(f"  {description}")
        if not parts:
            raise PayloadError("news.articles 为空")
        return UnifiedMessage(
            fmt=FMT_MARKDOWN, body="\n".join(parts), source_msgtype="news"
        )

    def _image(self, payload: dict) -> UnifiedMessage:
        image = payload.get("image") or {}
        media_id = (image.get("media_id") or "").strip()
        content = (image.get("content") or "").strip()
        body = content or "[图片]"
        return UnifiedMessage(
            fmt=FMT_TEXT,
            body=body,
            attachments=[Attachment(kind="image", media_id=media_id or None)],
            source_msgtype="image",
        )

    def _file(self, payload: dict) -> UnifiedMessage:
        file = payload.get("file") or {}
        media_id = (file.get("media_id") or "").strip()
        content = (file.get("content") or "").strip()
        body = content or "[文件]"
        return UnifiedMessage(
            fmt=FMT_TEXT,
            body=body,
            attachments=[Attachment(kind="file", media_id=media_id or None)],
            source_msgtype="file",
        )

    def _voice(self, payload: dict) -> UnifiedMessage:
        voice = payload.get("voice") or {}
        media_id = (voice.get("media_id") or "").strip()
        content = (voice.get("content") or "").strip()
        body = content or "[语音]"
        return UnifiedMessage(
            fmt=FMT_TEXT,
            body=body,
            attachments=[Attachment(kind="voice", media_id=media_id or None)],
            source_msgtype="voice",
        )

    def _template_card(self, payload: dict) -> UnifiedMessage:
        card = payload.get("template_card") or {}
        parts: list[str] = []
        main_title = card.get("main_title") or {}
        title = (main_title.get("title") or "").strip()
        desc = (main_title.get("desc") or "").strip()
        if desc:
            parts.append(desc)
        sub_title = (card.get("sub_title_text") or "").strip()
        if sub_title:
            parts.append(f"**{sub_title}**")
        for element in card.get("elements") or []:
            extracted = _extract_card_text(element)
            if extracted:
                parts.append(extracted)
        if not parts and not title:
            raise PayloadError("template_card 内容为空")
        return UnifiedMessage(
            fmt=FMT_MARKDOWN,
            title=title or None,
            body="\n\n".join(parts),
            source_msgtype="template_card",
        )


def _extract_card_text(node: object) -> str:
    """递归抽取模板卡片里的可读文本。"""
    if isinstance(node, str):
        return node.strip()
    if isinstance(node, list):
        parts = [p for p in (_extract_card_text(item) for item in node) if p]
        return "\n".join(parts)
    if not isinstance(node, dict):
        return ""
    parts: list[str] = []
    for key in ("title", "desc", "content", "text", "value", "url", "key"):
        value = node.get(key)
        if isinstance(value, str) and value.strip():
            parts.append(value.strip())
        elif isinstance(value, (dict, list)):
            nested = _extract_card_text(value)
            if nested:
                parts.append(nested)
    return "\n".join(parts)
