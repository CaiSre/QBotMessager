"""飞书自定义机器人负载解析。

官方文档：https://open.feishu.cn/document/client-docs/bot-v3/add-custom-bot
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

_AT_TAG = re.compile(r'<at user_id="([^"]*)"\s*>(.*?)</at>', re.DOTALL)


class FeishuAdapter:
    platform = "feishu"

    def parse(self, payload: dict) -> UnifiedMessage:
        if not isinstance(payload, dict):
            raise PayloadError("负载必须是 JSON 对象")
        msg_type = payload.get("msg_type") or payload.get("msgtype")
        if not msg_type:
            raise PayloadError("缺少 msg_type")
        handler = {
            "text": self._text,
            "post": self._post,
            "image": self._image,
            "file": self._file,
            "share_chat": self._share_chat,
            "interactive": self._interactive,
        }.get(msg_type)
        if handler is None:
            raise PayloadError(f"不支持的飞书消息类型：{msg_type}")
        return handler(payload)

    # -- 各类型 -------------------------------------------------------------

    def _text(self, payload: dict) -> UnifiedMessage:
        content = payload.get("content") or {}
        text = (content.get("text") or "").strip()
        if not text:
            raise PayloadError("content.text 不能为空")
        mentions: list[str] = []
        for user_id, name in _AT_TAG.findall(text):
            mentions.append(name.strip() or user_id)
        body = _AT_TAG.sub(lambda m: f"@{m.group(2).strip() or m.group(1)}", text)
        return UnifiedMessage(
            fmt=FMT_TEXT, body=body, mentions=mentions, source_msgtype="text"
        )

    def _post(self, payload: dict) -> UnifiedMessage:
        content = payload.get("content") or {}
        post = content.get("post") or {}
        locale_block = post.get("zh_cn") or post.get("en_us") or {}
        title = (locale_block.get("title") or "").strip() or None
        lines: list[str] = []
        for paragraph in locale_block.get("content") or []:
            line = self._render_paragraph(paragraph).strip()
            if line:
                lines.append(line)
        if not lines and not title:
            raise PayloadError("post 内容为空")
        return UnifiedMessage(
            fmt=FMT_MARKDOWN,
            title=title,
            body="\n".join(lines),
            source_msgtype="post",
        )

    def _image(self, payload: dict) -> UnifiedMessage:
        content = payload.get("content") or {}
        image_key = (content.get("image_key") or "").strip()
        return UnifiedMessage(
            fmt=FMT_TEXT,
            body="[图片]",
            attachments=[Attachment(kind="image", media_id=image_key or None)],
            source_msgtype="image",
        )

    def _file(self, payload: dict) -> UnifiedMessage:
        content = payload.get("content") or {}
        file_key = (content.get("file_key") or "").strip()
        return UnifiedMessage(
            fmt=FMT_TEXT,
            body="[文件]",
            attachments=[Attachment(kind="file", media_id=file_key or None)],
            source_msgtype="file",
        )

    def _share_chat(self, payload: dict) -> UnifiedMessage:
        content = payload.get("content") or {}
        chat_id = (content.get("share_chat_id") or "").strip()
        return UnifiedMessage(
            fmt=FMT_TEXT,
            body="[群聊分享]" + (f" {chat_id}" if chat_id else ""),
            source_msgtype="share_chat",
        )

    def _interactive(self, payload: dict) -> UnifiedMessage:
        content = payload.get("content") or {}
        # 自定义机器人卡片消息的 card 位于请求体顶层
        card = payload.get("card") or content.get("card") or content
        parts: list[str] = []
        title = None
        header = card.get("header") or {}
        header_title = header.get("title") or {}
        if isinstance(header_title, dict):
            title = (header_title.get("content") or header_title.get("text") or "").strip() or None
        elif isinstance(header_title, str):
            title = header_title.strip() or None
        for element in card.get("elements") or []:
            rendered = self._render_card_element(element)
            if rendered:
                parts.append(rendered)
        if not parts and not title:
            raise PayloadError("interactive 卡片内容为空")
        return UnifiedMessage(
            fmt=FMT_MARKDOWN,
            title=title,
            body="\n\n".join(parts),
            source_msgtype="interactive",
        )

    # -- 工具 ---------------------------------------------------------------

    @staticmethod
    def _render_paragraph(paragraph: object) -> str:
        if isinstance(paragraph, str):
            return paragraph.strip()
        if isinstance(paragraph, (list, tuple)):
            # 飞书 post 的每个段落是「行内元素列表」
            return "".join(FeishuAdapter._render_paragraph(item) for item in paragraph).strip()
        if not isinstance(paragraph, dict):
            return ""
        tag = paragraph.get("tag")
        if tag == "text":
            # 行内元素之间靠原文空格分隔，这里不裁剪，整行在外层 strip
            return paragraph.get("text") or ""
        if tag == "a":
            text = (paragraph.get("text") or "").strip()
            href = (paragraph.get("href") or "").strip()
            if text and href:
                return f"[{text}]({href})"
            return text or href
        if tag == "at":
            user_id = (paragraph.get("user_id") or "").strip()
            name = (paragraph.get("user_name") or user_id).strip()
            return f"@{name}" if name else ""
        if tag == "img":
            key = (paragraph.get("image_key") or "").strip()
            return "[图片]" + (f"({key})" if key else "")
        if tag == "md":
            md = paragraph.get("md") or {}
            text = md.get("text") if isinstance(md, dict) else None
            return (text or paragraph.get("text") or "").strip()
        if tag == "hr":
            return "---"
        return ""

    @classmethod
    def _render_card_element(cls, element: object) -> str:
        if isinstance(element, str):
            return element.strip()
        if not isinstance(element, dict):
            return ""
        tag = element.get("tag")
        if tag == "markdown":
            md = element.get("content") or element.get("text") or ""
            return str(md).strip()
        if tag == "hr":
            return "---"
        if tag == "div":
            text = element.get("text") or {}
            if isinstance(text, dict):
                content = text.get("content") or text.get("text") or ""
                return str(content).strip()
            return str(text).strip()
        if tag == "note":
            elements = element.get("elements") or []
            parts = [cls._render_card_element(item) for item in elements]
            return "\n".join(p for p in parts if p)
        return ""
