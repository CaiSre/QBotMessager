"""Webhook 数据面：鉴权、目标优先级、QQ 消息体与推送日志。"""

from __future__ import annotations

import hashlib
import hmac
import json

from fastapi.testclient import TestClient

import pytest

from tests.conftest import StubQqClient, create_bot, create_channel


def _post(client: TestClient, platform: str, token: str, payload: dict, **kwargs):
    return client.post(
        f"/webhook/{platform}",
        json=payload,
        headers={"X-Webhook-Token": token},
        **kwargs,
    )


def test_text_pushes_to_default_openid(admin: TestClient, qq: StubQqClient) -> None:
    bot_id = create_bot(admin, openids=["u-default"])
    channel = create_channel(admin, bot_id, "dingtalk")

    response = _post(
        admin,
        "dingtalk",
        channel["webhook_token"],
        {"msgtype": "text", "text": {"content": "磁盘告警"}},
    )
    assert response.status_code == 200
    assert response.json() == {"errcode": 0, "errmsg": "ok"}

    assert len(qq.calls) == 1
    call = qq.calls[0]
    assert call["target"] == "user:u-default"
    assert call["payload"] == {
        "msg_type": 0,
        "content": "磁盘告警",
        "msg_id": "",
        "msg_seq": 1,
    }


def test_markdown_uses_msg_type_2(admin: TestClient, qq: StubQqClient) -> None:
    bot_id = create_bot(admin, group="g-default")
    channel = create_channel(admin, bot_id, "wecom")

    response = _post(
        admin,
        "wecom",
        channel["webhook_token"],
        {"msgtype": "markdown", "markdown": {"content": "**服务** 异常"}},
    )
    assert response.status_code == 200
    payload = qq.calls[0]["payload"]
    assert qq.calls[0]["target"] == "group:g-default"
    assert payload["msg_type"] == 2
    assert payload["content"] == ""
    assert payload["markdown"]["content"] == "**服务** 异常"


def test_request_target_overrides_default(admin: TestClient, qq: StubQqClient) -> None:
    bot_id = create_bot(admin, openids=["u-default"])
    channel = create_channel(admin, bot_id, "dingtalk")

    _post(
        admin,
        "dingtalk",
        channel["webhook_token"],
        {"msgtype": "text", "text": {"content": "a"}, "openid": "u-body"},
    )
    _post(
        admin,
        "dingtalk",
        channel["webhook_token"],
        {
            "msgtype": "text",
            "text": {"content": "b"},
            "openid": "u-body",
            "group_openid": "g-body",
        },
    )
    assert [call["target"] for call in qq.calls] == ["user:u-body", "group:g-body"]


def test_push_logs_recorded(admin: TestClient, qq: StubQqClient) -> None:
    bot_id = create_bot(admin, openids=["u-default"])
    channel = create_channel(admin, bot_id, "feishu")

    response = _post(
        admin,
        "feishu",
        channel["webhook_token"],
        {"msg_type": "text", "content": {"text": "上线通知"}},
    )
    assert response.status_code == 200
    assert response.json() == {"code": 0, "msg": "success", "data": {}}

    logs = admin.get("/api/admin/logs").json()
    assert logs["total"] == 1
    item = logs["items"][0]
    assert item["platform"] == "feishu"
    assert item["status"] == "success"
    assert item["owner_email"] == "admin@example.com"
    assert item["target"] == "user:u-default"
    assert "上线通知" in item["content_preview"]


def test_failure_returns_502_and_logs_error(
    admin: TestClient, qq: StubQqClient
) -> None:
    bot_id = create_bot(admin, openids=["u-default"])
    channel = create_channel(admin, bot_id, "dingtalk")
    qq.fail_targets["user:u-default"] = ("50012", "机器人已被移除")

    response = _post(
        admin,
        "dingtalk",
        channel["webhook_token"],
        {"msgtype": "text", "text": {"content": "x"}},
    )
    assert response.status_code == 502
    assert "机器人已被移除" in response.json()["errmsg"]

    failed = admin.get("/api/admin/logs", params={"status": "failed"}).json()
    assert failed["total"] == 1
    assert failed["items"][0]["error_code"] == "50012"


def test_rejects_bad_token_platform_and_body(admin: TestClient, qq: StubQqClient) -> None:
    bot_id = create_bot(admin, openids=["u-default"])
    channel = create_channel(admin, bot_id, "dingtalk")

    assert _post(admin, "dingtalk", "bad-token", {"msgtype": "text"}).status_code == 401
    assert (
        admin.post("/webhook/unknown", json={}, headers={"X-Webhook-Token": "x"}).status_code
        == 404
    )

    not_json = admin.post(
        "/webhook/dingtalk",
        content=b"not-json",
        headers={"X-Webhook-Token": channel["webhook_token"]},
    )
    assert not_json.status_code == 400

    oversize = admin.post(
        "/webhook/dingtalk",
        content=b'{"a":"' + b"x" * 70000 + b'"}',
        headers={"X-Webhook-Token": channel["webhook_token"]},
    )
    assert oversize.status_code == 413

    unknown_type = _post(
        admin,
        "dingtalk",
        channel["webhook_token"],
        {"msgtype": "video", "video": {}},
    )
    assert unknown_type.status_code == 400
    assert qq.calls == []


def test_authorization_bearer_token_accepted(
    admin: TestClient, qq: StubQqClient
) -> None:
    bot_id = create_bot(admin, openids=["u-bearer"])
    channel = create_channel(admin, bot_id, "dingtalk")

    response = admin.post(
        "/webhook/dingtalk",
        json={"msgtype": "text", "text": {"content": "bearer"}},
        headers={"Authorization": f"Bearer {channel['webhook_token']}"},
    )
    assert response.status_code == 200
    assert len(qq.calls) == 1

    wrong_scheme = admin.post(
        "/webhook/dingtalk",
        json={"msgtype": "text", "text": {"content": "basic"}},
        headers={"Authorization": f"Basic {channel['webhook_token']}"},
    )
    assert wrong_scheme.status_code == 401


def test_query_token_rejected_by_default(
    admin: TestClient, qq: StubQqClient
) -> None:
    bot_id = create_bot(admin, openids=["u-query"])
    channel = create_channel(admin, bot_id, "dingtalk")

    response = admin.post(
        f"/webhook/dingtalk?token={channel['webhook_token']}",
        json={"msgtype": "text", "text": {"content": "query"}},
    )
    assert response.status_code == 401, response.text
    assert qq.calls == []


def test_query_token_allowed_when_enabled(
    admin: TestClient, qq: StubQqClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    from server.main import app

    bot_id = create_bot(admin, openids=["u-query"])
    channel = create_channel(admin, bot_id, "dingtalk")

    monkeypatch.setattr(app.state.settings, "webhook_allow_query_token", True)
    response = admin.post(
        f"/webhook/dingtalk?token={channel['webhook_token']}",
        json={"msgtype": "text", "text": {"content": "query"}},
    )
    assert response.status_code == 200, response.text
    assert len(qq.calls) == 1


def test_missing_target_returns_400(admin: TestClient, qq: StubQqClient) -> None:
    bot_id = create_bot(admin)
    channel = create_channel(admin, bot_id, "dingtalk")

    response = _post(
        admin,
        "dingtalk",
        channel["webhook_token"],
        {"msgtype": "text", "text": {"content": "x"}},
    )
    assert response.status_code == 400
    assert "默认目标" in response.json()["errmsg"]


# ------------------------------------------------------------------- GitHub


def _github_post(
    client: TestClient,
    token: str,
    secret: str | None,
    event: str,
    payload: dict,
    *,
    signature: str | None = None,
):
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    if signature is None and secret is not None:
        signature = "sha256=" + hmac.new(
            secret.encode("utf-8"), body, hashlib.sha256
        ).hexdigest()
    headers = {"X-GitHub-Event": event, "Content-Type": "application/json"}
    if signature:
        headers["X-Hub-Signature-256"] = signature
    return client.post(f"/webhook/github/{token}", content=body, headers=headers)


def _ping_payload() -> dict:
    return {
        "zen": "Keep it logically awesome.",
        "hook_id": 1,
        "repository": {"full_name": "acme/widgets"},
        "sender": {"login": "octocat"},
    }


def test_github_signed_ping_pushes_and_logs(
    admin: TestClient, qq: StubQqClient
) -> None:
    bot_id = create_bot(admin, group="g-default")
    channel = create_channel(admin, bot_id, "github")

    response = _github_post(
        admin, channel["webhook_token"], channel["secret"], "ping", _ping_payload()
    )
    assert response.status_code == 200, response.text
    assert response.json() == {"ok": True}
    assert len(qq.calls) == 1
    assert qq.calls[0]["target"] == "group:g-default"
    assert qq.calls[0]["payload"]["msg_type"] == 2

    logs = admin.get("/api/admin/logs").json()
    assert logs["total"] == 1
    assert logs["items"][0]["platform"] == "github"
    assert logs["items"][0]["source_msgtype"] == "ping"


def test_github_rejects_missing_or_bad_signature(
    admin: TestClient, qq: StubQqClient
) -> None:
    bot_id = create_bot(admin, group="g-default")
    channel = create_channel(admin, bot_id, "github")

    missing = _github_post(
        admin, channel["webhook_token"], None, "ping", _ping_payload()
    )
    assert missing.status_code == 401
    assert "签名" in missing.json()["error"]

    wrong = _github_post(
        admin,
        channel["webhook_token"],
        None,
        "ping",
        _ping_payload(),
        signature="sha256=" + "0" * 64,
    )
    assert wrong.status_code == 401
    assert wrong.json()["error"] == "签名不匹配"

    tampered = _github_post(
        admin,
        channel["webhook_token"],
        channel["secret"],
        "ping",
        _ping_payload(),
        signature=(
            "sha256="
            + hmac.new(b"other-secret", b"{}", hashlib.sha256).hexdigest()
        ),
    )
    assert tampered.status_code == 401
    assert qq.calls == []


def test_github_arbitrary_event_pushes_and_logs(
    admin: TestClient, qq: StubQqClient
) -> None:
    bot_id = create_bot(admin, group="g-default")
    channel = create_channel(admin, bot_id, "github")

    response = _github_post(
        admin,
        channel["webhook_token"],
        channel["secret"],
        "deployment",
        {
            "action": "created",
            "deployment": {"environment": "production"},
            "repository": {"full_name": "acme/widgets"},
            "sender": {"login": "octocat"},
        },
    )
    assert response.status_code == 200
    assert response.json()["ok"] is True
    assert len(qq.calls) == 1

    logs = admin.get("/api/admin/logs").json()
    assert logs["items"][0]["source_msgtype"] == "deployment.created"


def test_github_without_path_token_is_rejected(
    admin: TestClient, qq: StubQqClient
) -> None:
    bot_id = create_bot(admin, group="g-default")
    create_channel(admin, bot_id, "github")

    response = admin.post("/webhook/github", json={})
    assert response.status_code == 404
    assert "webhook/github/{token}" in response.json()["error"]


def test_github_rotate_replaces_token_and_secret(
    admin: TestClient, qq: StubQqClient
) -> None:
    bot_id = create_bot(admin, group="g-default")
    channel = create_channel(admin, bot_id, "github")

    rotated = admin.post(f"/api/admin/channels/{channel['id']}/rotate").json()
    assert rotated["webhook_token"] != channel["webhook_token"]
    assert rotated["secret"] and rotated["secret"] != channel["secret"]

    stale = _github_post(
        admin,
        channel["webhook_token"],
        channel["secret"],
        "ping",
        _ping_payload(),
    )
    assert stale.status_code == 401

    fresh = _github_post(
        admin,
        rotated["webhook_token"],
        rotated["secret"],
        "ping",
        _ping_payload(),
    )
    assert fresh.status_code == 200
    assert len(qq.calls) == 1


class _FakeQueue:
    """模拟 PushQueue：记录入队内容，可切换重复投递与队列已满。"""

    def __init__(self) -> None:
        self.jobs: list[tuple[object, str]] = []
        self.duplicate = False
        self.full = False

    async def enqueue(self, job, *, job_id: str) -> bool:
        from server.services.queue import QueueFull

        if self.full:
            raise QueueFull("full")
        self.jobs.append((job, job_id))
        return not self.duplicate


def _with_queue(admin: TestClient, fake: _FakeQueue):
    original = admin.app.state.push_queue
    admin.app.state.push_queue = fake
    return original


def test_queue_accepts_before_any_send(admin: TestClient, qq: StubQqClient) -> None:
    from server.services.push import PushJob

    bot_id = create_bot(admin, openids=["u-default"])
    channel = create_channel(admin, bot_id, "dingtalk")
    fake = _FakeQueue()
    original = _with_queue(admin, fake)
    try:
        response = _post(
            admin,
            "dingtalk",
            channel["webhook_token"],
            {"msgtype": "text", "text": {"content": "入队即确认"}},
        )
    finally:
        admin.app.state.push_queue = original

    assert response.status_code == 200
    assert qq.calls == []
    assert len(fake.jobs) == 1
    job, job_id = fake.jobs[0]
    assert isinstance(job, PushJob)
    assert job.bot_id == bot_id
    assert job.content == "入队即确认"
    assert job_id.startswith("push:")


def test_queue_duplicate_delivery_is_acked(admin: TestClient, qq: StubQqClient) -> None:
    bot_id = create_bot(admin, openids=["u-default"])
    channel = create_channel(admin, bot_id, "dingtalk")
    fake = _FakeQueue()
    fake.duplicate = True
    original = _with_queue(admin, fake)
    try:
        response = _post(
            admin,
            "dingtalk",
            channel["webhook_token"],
            {"msgtype": "text", "text": {"content": "重复"}},
        )
    finally:
        admin.app.state.push_queue = original

    assert response.status_code == 200
    assert response.json()["errmsg"] == "重复投递，已忽略"
    assert qq.calls == []


def test_queue_full_asks_sender_to_retry(admin: TestClient, qq: StubQqClient) -> None:
    bot_id = create_bot(admin, openids=["u-default"])
    channel = create_channel(admin, bot_id, "dingtalk")
    fake = _FakeQueue()
    fake.full = True
    original = _with_queue(admin, fake)
    try:
        response = _post(
            admin,
            "dingtalk",
            channel["webhook_token"],
            {"msgtype": "text", "text": {"content": "积压"}},
        )
    finally:
        admin.app.state.push_queue = original

    assert response.status_code == 503
    assert response.json()["errcode"] == 503
    assert qq.calls == []
