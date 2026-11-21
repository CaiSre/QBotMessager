"""三平台负载解析。"""

from __future__ import annotations

import pytest

from server.adapters import get_adapter
from server.adapters.base import FMT_MARKDOWN, FMT_TEXT, PayloadError


def parse(platform: str, payload: dict):
    return get_adapter(platform).parse(payload)


# ------------------------------------------------------------------- 钉钉


def test_dingtalk_text_with_mentions() -> None:
    message = parse(
        "dingtalk",
        {
            "msgtype": "text",
            "text": {"content": "磁盘告警"},
            "at": {"atMobiles": ["user-a"], "isAtAll": False},
        },
    )
    assert message.fmt == FMT_TEXT
    assert message.body == "磁盘告警 @user-a"
    assert message.mentions == ["user-a"]
    assert message.source_msgtype == "text"


def test_dingtalk_markdown_keeps_title_separate() -> None:
    message = parse(
        "dingtalk",
        {
            "msgtype": "markdown",
            "markdown": {"title": "告警", "text": "### 磁盘\n> 90%"},
            "at": {"atUserIds": ["user-b"]},
        },
    )
    assert message.fmt == FMT_MARKDOWN
    assert message.title == "告警"
    assert "### 告警" not in message.body
    assert message.mentions == ["user-b"]
    assert message.body.endswith("@user-b")


def test_dingtalk_link_and_action_card() -> None:
    link = parse(
        "dingtalk",
        {
            "msgtype": "link",
            "link": {
                "title": "发布失败",
                "text": "流水线 #12",
                "messageUrl": "https://ci.example.com/12",
                "picUrl": "https://ci.example.com/12.png",
            },
        },
    )
    assert link.fmt == FMT_MARKDOWN
    assert link.title == "发布失败"
    assert "[查看详情](https://ci.example.com/12)" in link.body
    assert link.attachments[0].kind == "image"

    card = parse(
        "dingtalk",
        {
            "msgtype": "actionCard",
            "actionCard": {
                "title": "审批",
                "text": "请确认",
                "singleTitle": "查看",
                "singleURL": "https://oa.example.com/1",
            },
        },
    )
    assert card.fmt == FMT_MARKDOWN
    assert "- [查看](https://oa.example.com/1)" in card.body


def test_dingtalk_feed_card_and_unknown_type() -> None:
    feed = parse(
        "dingtalk",
        {
            "msgtype": "feedCard",
            "feedCard": {"links": [{"title": "a", "messageURL": "https://a.example.com"}]},
        },
    )
    assert feed.fmt == FMT_MARKDOWN
    assert feed.body == "- [a](https://a.example.com)"

    with pytest.raises(PayloadError):
        parse("dingtalk", {"msgtype": "video", "video": {}})


# --------------------------------------------------------------- 企业微信


def test_wecom_text_strips_mention_tags() -> None:
    message = parse(
        "wecom",
        {
            "msgtype": "text",
            "text": {
                "content": "服务 <@all> 异常 <@zhangsan>",
                "mentioned_list": ["@all", "lisi"],
                "mentioned_mobile_list": ["13800000000"],
            },
        },
    )
    assert message.fmt == FMT_TEXT
    assert "<@" not in message.body
    assert message.body.startswith("服务 异常")
    assert message.mentions == ["所有人", "zhangsan", "lisi", "13800000000"]
    assert message.body.count("@所有人") == 1


def test_wecom_markdown_v2_degrades_tables() -> None:
    message = parse(
        "wecom",
        {
            "msgtype": "markdown_v2",
            "markdown_v2": {"content": "|指标|值|\n|---|---|\n|CPU|90%|"},
        },
    )
    assert message.fmt == FMT_MARKDOWN
    assert message.body == "- **指标**：CPU，**值**：90%"


def test_wecom_news_image_and_template_card() -> None:
    news = parse(
        "wecom",
        {
            "msgtype": "news",
            "news": {
                "articles": [
                    {"title": "n1", "description": "d1", "url": "https://n1.example.com"}
                ]
            },
        },
    )
    assert "- [n1](https://n1.example.com)" in news.body

    image = parse(
        "wecom", {"msgtype": "image", "image": {"media_id": "m-1", "content": ""}}
    )
    assert image.fmt == FMT_TEXT
    assert image.body == "[图片]"
    assert image.attachments[0].media_id == "m-1"

    card = parse(
        "wecom",
        {
            "msgtype": "template_card",
            "template_card": {
                "main_title": {"title": "构建", "desc": "成功"},
                "sub_title_text": "分支 main",
            },
        },
    )
    assert card.fmt == FMT_MARKDOWN
    assert card.title == "构建"
    assert "### 构建" not in card.body
    assert "**分支 main**" in card.body


def test_wecom_unknown_type() -> None:
    with pytest.raises(PayloadError):
        parse("wecom", {"msgtype": "video", "video": {"media_id": "x"}})


# ------------------------------------------------------------------ 飞书


def test_feishu_text_replaces_at_tags() -> None:
    message = parse(
        "feishu",
        {"msg_type": "text", "content": {"text": 'hi <at user_id="ou_1">张三</at>'}},
    )
    assert message.fmt == FMT_TEXT
    assert message.body == "hi @张三"
    assert message.mentions == ["张三"]


def test_feishu_post_renders_inline_elements() -> None:
    message = parse(
        "feishu",
        {
            "msg_type": "post",
            "content": {
                "post": {
                    "zh_cn": {
                        "title": "每日报表",
                        "content": [
                            [
                                {"tag": "text", "text": "访问量 "},
                                {"tag": "a", "text": "详情", "href": "https://x.example.com"},
                            ],
                            [{"tag": "md", "text": "**环比 +5%**"}],
                            [{"tag": "hr"}],
                        ],
                    }
                }
            },
        },
    )
    assert message.fmt == FMT_MARKDOWN
    assert message.title == "每日报表"
    assert "访问量 [详情](https://x.example.com)" in message.body
    assert "**环比 +5%**" in message.body
    assert "---" in message.body


def test_feishu_interactive_card() -> None:
    message = parse(
        "feishu",
        {
            "msg_type": "interactive",
            "card": {
                "header": {"title": {"tag": "plain_text", "content": "值班提醒"}},
                "elements": [{"tag": "div", "text": {"tag": "lark_md", "content": "**张三**"}}],
            },
        },
    )
    assert message.fmt == FMT_MARKDOWN
    assert message.title == "值班提醒"
    assert "**张三**" in message.body
    assert "### 值班提醒" not in message.body


def test_feishu_share_chat_and_post_media_tags() -> None:
    share = parse(
        "feishu", {"msg_type": "share_chat", "content": {"share_chat_id": "oc_1"}}
    )
    assert share.body == "[群聊分享] oc_1"

    post = parse(
        "feishu",
        {
            "msg_type": "post",
            "content": {
                "post": {
                    "zh_cn": {
                        "content": [
                            [
                                {"tag": "at", "user_id": "ou_1", "user_name": "张三"},
                                {"tag": "img", "image_key": "img_1"},
                            ]
                        ]
                    }
                }
            },
        },
    )
    assert "@张三" in post.body
    assert "[图片](img_1)" in post.body


def test_feishu_unknown_type() -> None:
    with pytest.raises(PayloadError):
        parse("feishu", {"msg_type": "audio", "content": {}})
