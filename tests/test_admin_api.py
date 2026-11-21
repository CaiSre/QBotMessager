"""管理台统计与系统设置相关回归。"""

from __future__ import annotations

import sqlite3
from datetime import date, datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi.testclient import TestClient

import pytest


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
    from server.services.runtime_settings import RuntimeSettings

    # 用固定偏移代替具名时区，避免依赖本机是否装了 IANA 时区库
    tz = timezone(timedelta(hours=-8))
    monkeypatch.setattr(RuntimeSettings, "tz", property(lambda self: tz))

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


_BOT_BODY = {"name": "白名单机器人", "qq_appid": "102000002", "qq_app_secret": "s"}


def test_create_bot_accepts_allowlisted_qq_host(admin: TestClient) -> None:
    response = admin.post(
        "/api/admin/bot-profiles",
        json={**_BOT_BODY, "qq_host": "https://api.bot.qq.com"},
    )
    assert response.status_code == 201, response.text


def test_create_bot_rejects_qq_host_outside_allowlist(admin: TestClient) -> None:
    response = admin.post(
        "/api/admin/bot-profiles",
        json={**_BOT_BODY, "qq_host": "https://169.254.169.254"},
    )
    assert response.status_code == 422, response.text
