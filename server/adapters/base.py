"""平台负载 → 统一消息模型。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

FMT_TEXT = "text"
FMT_MARKDOWN = "markdown"


class PayloadError(ValueError):
    """负载非法或消息类型不受支持。"""


@dataclass
class Attachment:
    kind: str  # image / file / voice / link
    url: str | None = None
    title: str | None = None
    media_id: str | None = None


@dataclass
class UnifiedMessage:
    """三个平台归一后的消息。"""

    fmt: str = FMT_TEXT
    title: str | None = None
    body: str = ""
    mentions: list[str] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
    source_msgtype: str = ""
    meta: dict = field(default_factory=dict)

    @property
    def is_empty(self) -> bool:
        return not self.body.strip() and not self.attachments and not self.title


class Adapter(Protocol):
    platform: str

    def parse(self, payload: dict) -> UnifiedMessage: ...
