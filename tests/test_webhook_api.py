"""Webhook 数据面：鉴权、目标优先级、QQ 消息体与推送日志。"""

from __future__ import annotations

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
