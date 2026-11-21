"""三平台负载解析。"""

from __future__ import annotations

import pytest

from server.adapters import get_adapter
from server.adapters.base import FMT_MARKDOWN, FMT_TEXT, IgnoredEvent, PayloadError


def parse(platform: str, payload: dict):
    return get_adapter(platform).parse(payload)


def parse_event(platform: str, event: str, payload: dict):
    return get_adapter(platform).parse(payload, event=event)


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


# ------------------------------------------------------------------- GitHub


def _github_payload(**overrides):
    payload = {
        "repository": {"full_name": "acme/widgets"},
        "sender": {"login": "octocat"},
    }
    payload.update(overrides)
    return payload


def test_github_ping() -> None:
    message = parse_event(
        "github",
        "ping",
        _github_payload(zen="Keep it logically awesome.", hook_id=42),
    )
    assert message.fmt == FMT_MARKDOWN
    assert "接入成功" in message.title
    assert "acme/widgets" in message.body
    assert "Keep it logically awesome." in message.body
    assert message.source_msgtype == "ping"


def test_github_push_lists_commits_and_compare() -> None:
    commits = [
        {
            "id": f"{i:040x}",
            "message": f"fix #{i}\n\n细节",
            "author": {"name": "Alice"},
        }
        for i in range(7)
    ]
    message = parse_event(
        "github",
        "push",
        _github_payload(
            ref="refs/heads/main",
            before="a" * 40,
            after="b" * 40,
            commits=commits,
            compare="https://github.com/acme/widgets/compare/a...b",
        ),
    )
    assert message.title == "acme/widgets 推送 main"
    assert "octocat" in message.body
    assert "7 个提交" in message.body
    assert "fix #0" in message.body
    assert "fix #5" not in message.body
    assert "另有 2 条提交" in message.body
    assert "[查看对比]" in message.body
    assert message.source_msgtype == "push"


def test_github_push_deleted_branch() -> None:
    message = parse_event(
        "github",
        "push",
        _github_payload(ref="refs/heads/feature", deleted=True, commits=[]),
    )
    assert "删除分支" in message.title
    assert "feature" in message.body


def test_github_pull_request_merged_uses_merger() -> None:
    message = parse_event(
        "github",
        "pull_request",
        _github_payload(
            action="closed",
            number=12,
            pull_request={
                "number": 12,
                "title": "新增登录",
                "html_url": "https://github.com/acme/widgets/pull/12",
                "merged": True,
                "merged_by": {"login": "maintainer"},
            },
        ),
    )
    assert message.title == "acme/widgets PR #12"
    assert "maintainer" in message.body
    assert "合并" in message.body
    assert message.source_msgtype == "pull_request.closed"


def test_github_issues_and_release() -> None:
    issue = parse_event(
        "github",
        "issues",
        _github_payload(
            action="opened",
            issue={
                "number": 7,
                "title": "按钮错位",
                "html_url": "https://github.com/acme/widgets/issues/7",
            },
        ),
    )
    assert "Issue #7" in issue.title
    assert "打开" in issue.body

    release = parse_event(
        "github",
        "release",
        _github_payload(
            action="published",
            release={
                "tag_name": "v1.2.0",
                "name": "v1.2.0",
                "html_url": "https://github.com/acme/widgets/releases/v1.2.0",
                "body": "修复若干问题",
            },
        ),
    )
    assert "Release v1.2.0" in release.title
    assert "修复若干问题" in release.body
    assert release.source_msgtype == "release.published"


def test_github_workflow_run_completed_only() -> None:
    message = parse_event(
        "github",
        "workflow_run",
        _github_payload(
            action="completed",
            workflow_run={
                "name": "CI",
                "conclusion": "failure",
                "head_branch": "main",
                "html_url": "https://github.com/acme/widgets/actions/runs/1",
            },
        ),
    )
    assert "工作流 CI 失败" in message.title
    assert "main" in message.body

    with pytest.raises(IgnoredEvent):
        parse_event(
            "github",
            "workflow_run",
            _github_payload(action="in_progress", workflow_run={"name": "CI"}),
        )


def test_github_workflow_job_status() -> None:
    message = parse_event(
        "github",
        "workflow_job",
        _github_payload(
            action="completed",
            workflow_job={
                "name": "build",
                "status": "completed",
                "conclusion": "success",
                "head_branch": "main",
                "html_url": "https://github.com/acme/widgets/actions/runs/1/job/2",
            },
        ),
    )
    assert "工作流任务 build 成功" in message.title
    assert "main" in message.body
    assert message.source_msgtype == "workflow_job.completed"

    running = parse_event(
        "github",
        "workflow_job",
        _github_payload(
            action="in_progress",
            workflow_job={"name": "build", "status": "in_progress"},
        ),
    )
    assert "build 进行中" in running.title


def test_github_generic_event_and_missing_header() -> None:
    message = parse_event(
        "github",
        "deployment",
        _github_payload(
            action="created",
            deployment={
                "environment": "production",
                "html_url": "https://github.com/acme/widgets/deployments/1",
            },
        ),
    )
    assert message.fmt == FMT_MARKDOWN
    assert message.title == "acme/widgets 部署"
    assert "octocat" in message.body
    assert "创建" in message.body
    assert "[production](https://github.com/acme/widgets/deployments/1)" in message.body
    assert message.source_msgtype == "deployment.created"

    unknown = parse_event("github", "future_event", _github_payload(action="happened"))
    assert unknown.title == "acme/widgets future_event"
    assert "octocat" in unknown.body
    assert unknown.source_msgtype == "future_event.happened"

    with pytest.raises(PayloadError):
        get_adapter("github").parse(_github_payload())
