"""统一消息 → QQ 消息体。"""

from __future__ import annotations

from server.adapters.base import FMT_MARKDOWN, FMT_TEXT, UnifiedMessage
from server.renderer import MSG_TYPE_MARKDOWN, MSG_TYPE_TEXT, QqPayload, render_qq


def test_markdown_message_uses_msg_type_2_with_empty_content() -> None:
    payload = render_qq(
        UnifiedMessage(fmt=FMT_MARKDOWN, title="告警", body="**磁盘** 90%")
    )
    assert isinstance(payload, QqPayload)
    assert payload.msg_type == MSG_TYPE_MARKDOWN
    body = payload.to_dict()
    assert body["msg_type"] == 2
    assert body["content"] == ""
    assert body["markdown"]["content"] == "### 告警\n\n**磁盘** 90%"


def test_text_message_uses_msg_type_0() -> None:
    payload = render_qq(UnifiedMessage(fmt=FMT_TEXT, title="标题", body="内容"))
    assert payload.msg_type == MSG_TYPE_TEXT
    body = payload.to_dict()
    assert body["msg_type"] == 0
    assert body["content"] == "标题\n内容"
    assert "markdown" not in body


def test_markdown_empty_after_sanitize_falls_back_to_text() -> None:
    payload = render_qq(UnifiedMessage(fmt=FMT_MARKDOWN, body="<div></div>"))
    assert payload.msg_type == MSG_TYPE_TEXT


def test_empty_message_gets_placeholder() -> None:
    payload = render_qq(UnifiedMessage(fmt=FMT_TEXT, body=""))
    assert payload.content == "（消息内容为空）"


def test_truncation_limits() -> None:
    payload = render_qq(
        UnifiedMessage(fmt=FMT_MARKDOWN, body="字" * 500),
        markdown_max_len=100,
    )
    assert payload.markdown is not None
    assert len(payload.markdown) == 100
