"""平台适配器：钉钉 / 企业微信 / 飞书 / GitHub。"""

from __future__ import annotations

from server.adapters.base import Adapter
from server.adapters.dingtalk import DingTalkAdapter
from server.adapters.feishu import FeishuAdapter
from server.adapters.github import GitHubAdapter
from server.adapters.wecom import WeComAdapter

__all__ = [
    "Adapter",
    "DingTalkAdapter",
    "FeishuAdapter",
    "GitHubAdapter",
    "WeComAdapter",
    "get_adapter",
]


_ADAPTERS: dict[str, Adapter] = {
    "dingtalk": DingTalkAdapter(),
    "wecom": WeComAdapter(),
    "feishu": FeishuAdapter(),
    "github": GitHubAdapter(),
}


def get_adapter(platform: str) -> Adapter:
    try:
        return _ADAPTERS[platform]
    except KeyError as exc:  # pragma: no cover - 由路由层保证
        raise KeyError(f"未知平台：{platform}") from exc
