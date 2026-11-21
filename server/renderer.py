"""统一消息 → QQ 机器人消息体。

QQ 约束（https://bot.q.qq.com/wiki/develop/api-v2/server-inter/message/type/markdown.html）：
- msg_type=0 纯文本（content），msg_type=2 Markdown（markdown.content）
- 两者互斥：传 markdown 时 content 必须为空字符串
"""

from __future__ import annotations

from dataclasses import dataclass

from server.adapters.base import FMT_MARKDOWN, UnifiedMessage
from server.markdown import sanitize_markdown, sanitize_text

MSG_TYPE_TEXT = 0
MSG_TYPE_MARKDOWN = 2

_EMPTY_PLACEHOLDER = "（消息内容为空）"


@dataclass
class QqPayload:
    msg_type: int
    content: str
    markdown: str | None = None

    def to_dict(self) -> dict:
        if self.msg_type == MSG_TYPE_MARKDOWN:
            return {
                "msg_type": MSG_TYPE_MARKDOWN,
                "markdown": {"content": self.markdown or ""},
                "content": "",
                "msg_id": "",
                "msg_seq": 1,
            }
        return {
            "msg_type": MSG_TYPE_TEXT,
            "content": self.content,
            "msg_id": "",
            "msg_seq": 1,
        }

    @property
    def text(self) -> str:
        return self.markdown if self.msg_type == MSG_TYPE_MARKDOWN else self.content


def render_qq(
    message: UnifiedMessage,
    *,
    markdown_max_len: int = 4000,
    text_max_len: int = 2000,
) -> QqPayload:
    """把统一消息渲染为 QQ 消息体。"""
    title = (message.title or "").strip()
    body = message.body or ""

    if message.fmt == FMT_MARKDOWN:
        parts = []
        if title:
            parts.append(f"### {title}")
        cleaned = sanitize_markdown(body, max_len=markdown_max_len)
        if cleaned:
            parts.append(cleaned)
        markdown = "\n\n".join(parts).strip()
        if markdown:
            return QqPayload(msg_type=MSG_TYPE_MARKDOWN, content="", markdown=markdown)
        # Markdown 清洗后为空 → 回退纯文本
        fallback = sanitize_text(" ".join(p for p in (title, body) if p), max_len=text_max_len)
        return QqPayload(
            msg_type=MSG_TYPE_TEXT,
            content=fallback or _EMPTY_PLACEHOLDER,
        )

    cleaned_text = sanitize_text(body, max_len=text_max_len)
    if title:
        cleaned_text = f"{title}\n{cleaned_text}".strip() if cleaned_text else title
    return QqPayload(
        msg_type=MSG_TYPE_TEXT,
        content=cleaned_text or _EMPTY_PLACEHOLDER,
    )
