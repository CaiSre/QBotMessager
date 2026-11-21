"""QQ 客户端：token 缓存、路径、错误分类。"""

from __future__ import annotations

import json

import httpx2 as httpx
import pytest

from server.renderer import QqPayload
from server.services.qq import QqClient, QqError, QqTarget

HOST = "https://qq.example.com"


def make_client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_reuses_token_and_targets_user_and_group() -> None:
    token_calls = 0
    sent: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal token_calls
        if request.url.path == "/app/getAppAccessToken":
            token_calls += 1
            assert json.loads(request.content) == {"appId": "app-1", "clientSecret": "sec"}
            return httpx.Response(200, json={"access_token": "TOKEN", "expires_in": 7200})
        sent.append(
            {
                "path": request.url.path,
                "auth": request.headers["Authorization"],
                "body": json.loads(request.content),
            }
        )
        return httpx.Response(200, json={"id": "m-1"})

    async with make_client(handler) as http:
        qq = QqClient(http)
        payload = QqPayload(msg_type=2, content="", markdown="### 标题")
        await qq.send(
            key="bot:1",
            host=HOST,
            app_id="app-1",
            app_secret="sec",
            target=QqTarget(openid="u-1"),
            payload=payload,
        )
        await qq.send(
            key="bot:1",
            host=HOST,
            app_id="app-1",
            app_secret="sec",
            target=QqTarget(group_openid="g-1"),
            payload=payload,
        )

    assert token_calls == 1
    assert sent[0]["path"] == "/v2/users/u-1/messages"
    assert sent[1]["path"] == "/v2/groups/g-1/messages"
    assert sent[0]["auth"] == "QQBot TOKEN"
    assert sent[0]["body"] == {
        "msg_type": 2,
        "markdown": {"content": "### 标题"},
        "content": "",
        "msg_id": "",
        "msg_seq": 1,
    }


async def test_refreshes_token_once_on_401() -> None:
    token_calls = 0
    send_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal token_calls, send_calls
        if request.url.path == "/app/getAppAccessToken":
            token_calls += 1
            return httpx.Response(
                200, json={"access_token": f"TOKEN-{token_calls}", "expires_in": 7200}
            )
        send_calls += 1
        if send_calls == 1:
            return httpx.Response(401, json={"code": 11244, "message": "invalid token"})
        assert request.headers["Authorization"] == "QQBot TOKEN-2"
        return httpx.Response(200, json={"id": "m-2"})

    async with make_client(handler) as http:
        qq = QqClient(http)
        result = await qq.send(
            key="bot:1",
            host=HOST,
            app_id="app-1",
            app_secret="sec",
            target=QqTarget(openid="u-1"),
            payload=QqPayload(msg_type=0, content="hi"),
        )

    assert result == {"id": "m-2"}
    assert token_calls == 2


async def test_duplicate_is_treated_as_success() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/app/getAppAccessToken":
            return httpx.Response(200, json={"access_token": "T", "expires_in": 7200})
        return httpx.Response(400, json={"code": 40054005, "message": "msg duplicate"})

    async with make_client(handler) as http:
        qq = QqClient(http)
        result = await qq.send(
            key="bot:1",
            host=HOST,
            app_id="app-1",
            app_secret="sec",
            target=QqTarget(openid="u-1"),
            payload=QqPayload(msg_type=0, content="hi"),
        )

    assert result["code"] == 40054005


async def test_rate_limit_error_is_retryable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/app/getAppAccessToken":
            return httpx.Response(200, json={"access_token": "T", "expires_in": 7200})
        return httpx.Response(429, json={"code": 40034100, "message": "too many requests"})

    async with make_client(handler) as http:
        qq = QqClient(http)
        with pytest.raises(QqError) as excinfo:
            await qq.send(
                key="bot:1",
                host=HOST,
                app_id="app-1",
                app_secret="sec",
                target=QqTarget(openid="u-1"),
                payload=QqPayload(msg_type=0, content="hi"),
                max_retries=0,
            )

    assert excinfo.value.code == "40034100"
    assert excinfo.value.retryable is True


async def test_token_failure_surfaces_as_qq_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="unavailable")

    async with make_client(handler) as http:
        qq = QqClient(http)
        with pytest.raises(QqError) as excinfo:
            await qq.send(
                key="bot:1",
                host=HOST,
                app_id="app-1",
                app_secret="sec",
                target=QqTarget(openid="u-1"),
                payload=QqPayload(msg_type=0, content="hi"),
            )

    assert excinfo.value.code == "token_http_503"
    assert excinfo.value.retryable is True
