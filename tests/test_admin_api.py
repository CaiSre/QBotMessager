"""管理台回归：加密型环境配置的密文不得被空更新清空。"""

from __future__ import annotations

import sqlite3
from datetime import date, datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi.testclient import TestClient

import pytest

from server.db.crypto import decrypt_secret
from tests.conftest import APP_SECRET_KEY

SECRET_VALUE = "top-secret-value"


def _env_row(db_path, key: str):
    with sqlite3.connect(db_path) as con:
        return con.execute(
            "SELECT value, value_enc, is_secret FROM env_configs WHERE key = ?", (key,)
        ).fetchone()


def _create_secret(admin: TestClient, key: str = "API_TOKEN") -> int:
    response = admin.post(
        "/api/admin/env-configs",
        json={
            "key": key,
            "value": SECRET_VALUE,
            "is_secret": True,
            "description": "初始描述",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def test_secret_survives_description_only_patch(admin: TestClient, db_path) -> None:
    config_id = _create_secret(admin)

    response = admin.patch(
        f"/api/admin/env-configs/{config_id}",
        json={"is_secret": True, "description": "只改描述"},
    )
    assert response.status_code == 200, response.text

    value, value_enc, is_secret = _env_row(db_path, "API_TOKEN")
    assert is_secret == 1
    assert value_enc, "密文被清空了"
    assert decrypt_secret(value_enc, APP_SECRET_KEY) == SECRET_VALUE


def test_secret_survives_repeated_patches(admin: TestClient, db_path) -> None:
    config_id = _create_secret(admin)
    for _ in range(3):
        response = admin.patch(
            f"/api/admin/env-configs/{config_id}",
            json={"is_secret": True, "description": "改描述"},
        )
        assert response.status_code == 200, response.text

    _, value_enc, _ = _env_row(db_path, "API_TOKEN")
    assert decrypt_secret(value_enc, APP_SECRET_KEY) == SECRET_VALUE


def test_new_secret_value_overwrites_ciphertext(admin: TestClient, db_path) -> None:
    config_id = _create_secret(admin)

    response = admin.patch(
        f"/api/admin/env-configs/{config_id}",
        json={"is_secret": True, "value": "rotated-value"},
    )
    assert response.status_code == 200, response.text

    _, value_enc, _ = _env_row(db_path, "API_TOKEN")
    assert decrypt_secret(value_enc, APP_SECRET_KEY) == "rotated-value"


def test_switching_to_plaintext_keeps_value(admin: TestClient, db_path) -> None:
    config_id = _create_secret(admin)

    response = admin.patch(
        f"/api/admin/env-configs/{config_id}", json={"is_secret": False}
    )
    assert response.status_code == 200, response.text

    value, value_enc, is_secret = _env_row(db_path, "API_TOKEN")
    assert is_secret == 0
    assert value_enc is None
    assert value == SECRET_VALUE


def test_switching_plaintext_to_secret_keeps_value(admin: TestClient, db_path) -> None:
    created = admin.post(
        "/api/admin/env-configs",
        json={"key": "PLAIN_KEY", "value": "plain-value", "is_secret": False},
    )
    assert created.status_code == 201, created.text

    response = admin.patch(
        f"/api/admin/env-configs/{created.json()['id']}", json={"is_secret": True}
    )
    assert response.status_code == 200, response.text

    value, value_enc, is_secret = _env_row(db_path, "PLAIN_KEY")
    assert is_secret == 1
    assert value is None
    assert decrypt_secret(value_enc, APP_SECRET_KEY) == "plain-value"


def test_local_midnight_uses_configured_timezone() -> None:
    from server.api.admin import _local_midnight_utc

    tz = timezone(timedelta(hours=8))
    assert _local_midnight_utc(date(2026, 11, 21), tz) == datetime(
        2026, 11, 20, 16, 0, tzinfo=timezone.utc
    )


def test_settings_tz_uses_configured_zone() -> None:
    from server.config import Settings

    try:
        ZoneInfo("Asia/Shanghai")
    except ZoneInfoNotFoundError:
        pytest.skip("本机缺少 IANA 时区库")
    assert Settings(timezone="Asia/Shanghai").tz.key == "Asia/Shanghai"


def test_settings_tz_falls_back_on_unknown_zone() -> None:
    from server.config import Settings

    # 名称非法时退回本机时区，不抛异常
    assert Settings(timezone="Not/AZone").tz is not None


def _insert_push_log(db_path, created_at: datetime, request_id: str) -> None:
    with sqlite3.connect(db_path) as con:
        con.execute(
            "INSERT INTO push_logs (owner_user_id, platform, source_msgtype, target,"
            " content_preview, content_len, status, duration_ms, request_id, created_at)"
            " VALUES (1, 'dingtalk', 'text', 'user:u', 'x', 1, 'success', 1, ?, ?)",
            (request_id, created_at.strftime("%Y-%m-%d %H:%M:%S.%f")),
        )
        con.commit()


def test_stats_today_follows_configured_timezone(
    admin: TestClient, db_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from server.config import Settings

    # 用固定偏移代替具名时区，避免依赖本机是否装了 IANA 时区库
    tz = timezone(timedelta(hours=-8))
    monkeypatch.setattr(Settings, "tz", property(lambda self: tz))

    now = datetime.now(timezone.utc)
    local_day = now.astimezone(tz).date()
    local_midnight = datetime(
        local_day.year, local_day.month, local_day.day, tzinfo=tz
    ).astimezone(timezone.utc)

    # 本地昨天、本地今天的边界各插一条
    _insert_push_log(db_path, local_midnight - timedelta(seconds=1), "before")
    _insert_push_log(db_path, local_midnight + timedelta(seconds=1), "after")

    stats = admin.get("/api/admin/stats").json()
    assert stats["today"]["total"] == 1
    trend = stats["trend"]
    assert len(trend) == 7
    days = [date.fromisoformat(item["date"]) for item in trend]
    assert days == [days[-1] - timedelta(days=offset) for offset in range(6, -1, -1)]
