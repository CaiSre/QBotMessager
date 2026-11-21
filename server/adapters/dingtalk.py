"""钉钉自定义机器人负载解析。

官方文档：https://open.dingtalk.com/document/development/robot-message-type
"""

from __future__ import annotations

from server.adapters.base import (
    FMT_MARKDOWN,
    FMT_TEXT,
    Attachment,
    PayloadError,
    UnifiedMessage,
)

_AT_KEYS = ("atMobiles", "atUserIds", "isAtAll")


class DingTalkAdapter:
    platform = "dingtalk"

    def parse(self, payload: dict, *, event: str = "") -> UnifiedMessage:
        if not isinstance(payload, dict):
            raise PayloadError("负载必须是 JSON 对象")
        msgtype = payload.get("msgtype") or payload.get("type")
        if not msgtype:
            raise PayloadError("缺少 msgtype")
        handler = {
            "text": self._text,
            "markdown": self._markdown,
            "link": self._link,
            "actionCard": self._action_card,
            "feedCard": self._feed_card,
        }.get(msgtype)
        if handler is None:
            raise PayloadError(f"不支持的钉钉消息类型：{msgtype}")
        return handler(payload)

    # -- 各类型 -------------------------------------------------------------

    def _text(self, payload: dict) -> UnifiedMessage:
        text = payload.get("text") or {}
        content = (text.get("content") or "").strip()
        if not content:
            raise PayloadError("text.content 不能为空")
        mentions = self._mentions(payload.get("at"))
        body = content
        if mentions:
            body = content + " " + " ".join(f"@{m}" for m in mentions)
        return UnifiedMessage(
            fmt=FMT_TEXT,
            body=body,
            mentions=mentions,
            source_msgtype="text",
        )

    def _markdown(self, payload: dict) -> UnifiedMessage:
        md = payload.get("markdown") or {}
        title = (md.get("title") or "").strip() or None
        content = (md.get("text") or "").strip()
        if not content:
            raise PayloadError("markdown.text 不能为空")
        mentions = self._mentions(payload.get("at"))
        body = content
        if mentions:
            body = content + " " + " ".join(f"@{m}" for m in mentions)
        return UnifiedMessage(
            fmt=FMT_MARKDOWN,
            title=title,
            body=body,
            mentions=mentions,
            source_msgtype="markdown",
        )

    def _link(self, payload: dict) -> UnifiedMessage:
        link = payload.get("link") or {}
        title = (link.get("title") or "").strip()
        text = (link.get("text") or "").strip()
        message_url = (link.get("messageUrl") or "").strip()
        pic_url = (link.get("picUrl") or "").strip()
        parts: list[str] = []
        if text:
            parts.append(text)
        if message_url:
            parts.append(f"[查看详情]({message_url})")
        if not parts and not title:
            raise PayloadError("link 消息内容为空")
        attachments = [Attachment(kind="image", url=pic_url)] if pic_url else []
        return UnifiedMessage(
            fmt=FMT_MARKDOWN,
            title=title or None,
            body="\n\n".join(parts),
            attachments=attachments,
            source_msgtype="link",
        )

    def _action_card(self, payload: dict) -> UnifiedMessage:
        card = payload.get("actionCard") or {}
        title = (card.get("title") or "").strip()
        text = (card.get("text") or "").strip()
        parts: list[str] = []
        if text:
            parts.append(text)
        single_title = (card.get("singleTitle") or "").strip()
        single_url = (card.get("singleURL") or "").strip()
        if single_title and single_url:
            parts.append(f"- [{single_title}]({single_url})")
        for btn in card.get("btns") or []:
            btn_title = (btn.get("title") or "").strip()
            btn_url = (btn.get("actionURL") or "").strip()
            if btn_title and btn_url:
                parts.append(f"- [{btn_title}]({btn_url})")
            elif btn_title:
                parts.append(f"- {btn_title}")
        if not parts and not title:
            raise PayloadError("actionCard 消息内容为空")
        return UnifiedMessage(
            fmt=FMT_MARKDOWN,
            title=title or None,
            body="\n\n".join(parts),
            source_msgtype="actionCard",
        )

    def _feed_card(self, payload: dict) -> UnifiedMessage:
        card = payload.get("feedCard") or {}
        links = card.get("links") or []
        parts: list[str] = []
        for item in links:
            item_title = (item.get("title") or "").strip()
            item_url = (item.get("messageURL") or "").strip()
            if item_title and item_url:
                parts.append(f"- [{item_title}]({item_url})")
            elif item_title:
                parts.append(f"- {item_title}")
        if not parts:
            raise PayloadError("feedCard 消息内容为空")
        return UnifiedMessage(
            fmt=FMT_MARKDOWN,
            body="\n".join(parts),
            source_msgtype="feedCard",
        )

    # -- 工具 ---------------------------------------------------------------

    @staticmethod
    def _mentions(at: dict | None) -> list[str]:
        """钉钉的 @ 信息位于请求体顶层 `at` 对象中。"""
        if not isinstance(at, dict):
            return []
        mentions: list[str] = []
        if at.get("isAtAll"):
            mentions.append("所有人")
        for key in ("atUserIds", "atMobiles"):
            for value in at.get(key) or []:
                if value:
                    mentions.append(str(value))
        return mentions
