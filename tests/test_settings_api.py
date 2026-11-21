"""系统设置：目录返回、校验、持久化与即时生效。"""

from __future__ import annotations

import sqlite3

from fastapi.testclient import TestClient

from server.config import Settings
from server.services.runtime_settings import RuntimeSettings
from tests.conftest import ADMIN_EMAIL, create_bot, create_channel


def _items(payload: dict) -> dict[str, dict]:
    return {
        item["key"]: item
        for group in payload["groups"]
        for item in group["items"]
    }


def test_settings_catalog_and_env_seed(admin: TestClient) -> None:
    payload = admin.get("/api/admin/settings").json()
    items = _items(payload)
    assert "qq_qps" in items and items["qq_qps"]["kind"] == "int"
    assert "log_level" in items and items["log_level"]["options"][0] == "DEBUG"
    # conftest 中的 PUBLIC_BASE_URL 应在首次启动时导入数据库
    assert items["public_base_url"]["value"] == "http://testserver"
    assert items["public_base_url"]["source"] == "environment"


def test_settings_patch_persists_and_returns(admin: TestClient, db_path) -> None:
    response = admin.patch(
        "/api/admin/settings",
        json={"qq_qps": 9, "log_level": "DEBUG", "webhook_allow_query_token": True},
    )
    assert response.status_code == 200, response.text
    items = _items(response.json())
    assert items["qq_qps"]["value"] == 9
    assert items["log_level"]["value"] == "DEBUG"
    assert items["webhook_allow_query_token"]["value"] is True
    assert items["qq_qps"]["source"] == "database"

    with sqlite3.connect(db_path) as con:
        row = con.execute(
            "SELECT value FROM system_settings WHERE key = ?", ("qq_qps",)
        ).fetchone()
    assert row[0] == "9"


async def test_settings_reload_from_database(admin: TestClient) -> None:
    assert (
        admin.patch("/api/admin/settings", json={"qq_qps": 9}).status_code == 200
    )

    from server.db.session import get_session_factory

    runtime = RuntimeSettings(Settings())
    async with get_session_factory()() as db:
        await runtime.load(db)
    assert runtime.qq_qps == 9


def test_settings_reject_invalid_values(admin: TestClient) -> None:
    cases = (
        {"qq_qps": 0},
        {"log_level": "TRACE"},
        {"session_ttl_hours": "abc"},
        {"unknown_key": 1},
        {"qq_min_interval": 61},
        {"rp_name": "x" * 129},
    )
    for body in cases:
        response = admin.patch("/api/admin/settings", json=body)
        assert response.status_code == 400, (body, response.text)


def test_login_limiter_applies_immediately(admin: TestClient) -> None:
    response = admin.patch(
        "/api/admin/settings",
        json={"login_max_failures": 1, "login_window_seconds": 60},
    )
    assert response.status_code == 200, response.text

    admin.post("/api/auth/logout")
    first = admin.post(
        "/api/auth/login", json={"email": ADMIN_EMAIL, "password": "wrong-pass"}
    )
    assert first.status_code == 401
    second = admin.post(
        "/api/auth/login", json={"email": ADMIN_EMAIL, "password": "wrong-pass"}
    )
    assert second.status_code == 429


def test_public_base_url_applies_immediately(admin: TestClient) -> None:
    bot_id = create_bot(admin)
    create_channel(admin, bot_id)

    response = admin.patch(
        "/api/admin/settings", json={"public_base_url": "https://push.example.com/"}
    )
    assert response.status_code == 200, response.text

    channels = admin.get("/api/admin/channels").json()
    assert channels[0]["webhook_url"].startswith(
        "https://push.example.com/webhook/"
    )
