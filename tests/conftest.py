"""测试公共夹具：临时 SQLite + 引导管理员 + 打桩的 QQ 客户端。"""

from __future__ import annotations

import base64
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from server.services.qq import QqError

ADMIN_EMAIL = "admin@example.com"
ADMIN_PASSWORD = "TestAdmin2026"

# 固定的 Fernet 主密钥（仅测试用）
APP_SECRET_KEY = base64.urlsafe_b64encode(b"1" * 32).decode()


class StubQqClient:
    """记录发送请求的假客户端；可按目标注入失败。"""

    def __init__(self) -> None:
        self.calls: list[dict] = []
        self.fail_targets: dict[str, tuple[str, str]] = {}
        self.closed = False

    async def aclose(self) -> None:
        self.closed = True

    async def send(
        self,
        *,
        key: str,
        host: str,
        app_id: str,
        app_secret: str,
        target,
        payload,
    ) -> dict:
        self.calls.append(
            {
                "key": key,
                "host": host,
                "app_id": app_id,
                "app_secret": app_secret,
                "target": target.to_db_value(),
                "payload": payload.to_dict(),
            }
        )
        failure = self.fail_targets.get(target.to_db_value())
        if failure is not None:
            raise QqError(*failure)
        return {"id": "msg-stub"}


@pytest.fixture()
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "test.db"


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch, db_path: Path):
    monkeypatch.setenv("MYSQL_URL", f"sqlite+aiosqlite:///{db_path.as_posix()}")
    monkeypatch.setenv("APP_SECRET_KEY", APP_SECRET_KEY)
    monkeypatch.setenv("BOOTSTRAP_ADMIN_EMAIL", ADMIN_EMAIL)
    monkeypatch.setenv("BOOTSTRAP_ADMIN_PASSWORD", ADMIN_PASSWORD)
    monkeypatch.setenv("REGISTER_ENABLED", "false")
    monkeypatch.setenv("PUBLIC_BASE_URL", "http://testserver")
    # 覆盖仓库 .env，避免把真实凭据带进测试
    monkeypatch.setenv("QQ_APPID", "")
    monkeypatch.setenv("QQ_APP_SECRET", "")
    monkeypatch.setenv("OPENID", "")
    # 默认不启用邮件验证码；需要时由各用例通过管理接口配置
    monkeypatch.setenv("SMTP_HOST", "")
    monkeypatch.setenv("SMTP_USERNAME", "")
    monkeypatch.setenv("SMTP_PASSWORD", "")
    monkeypatch.setenv("SMTP_FROM", "")

    from sqlalchemy import create_engine

    from server.db import models  # noqa: F401 - 注册全部表
    from server.db.base import Base

    sync_engine = create_engine(f"sqlite:///{db_path.as_posix()}")
    Base.metadata.create_all(sync_engine)
    sync_engine.dispose()

    from server.config import reset_settings_cache

    reset_settings_cache()
    yield
    reset_settings_cache()


@pytest.fixture()
def qq(monkeypatch: pytest.MonkeyPatch) -> StubQqClient:
    from server import main as main_module

    stub = StubQqClient()
    monkeypatch.setattr(main_module, "QqClient", lambda client: stub)
    return stub


@pytest.fixture()
def client(qq: StubQqClient) -> TestClient:
    from server.main import app

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture()
def admin(client: TestClient) -> TestClient:
    response = client.post(
        "/api/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}
    )
    assert response.status_code == 200, response.text
    return client


def create_bot(client: TestClient, *, openids: list[str] | None = None, group: str | None = None) -> int:
    response = client.post(
        "/api/admin/bot-profiles",
        json={
            "name": "测试机器人",
            "qq_appid": "102000001",
            "qq_app_secret": "secret-value",
            "default_openids": openids or [],
            "default_group_openid": group,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def create_channel(client: TestClient, bot_id: int, platform: str = "dingtalk") -> dict:
    response = client.post(
        "/api/admin/channels",
        json={"platform": platform, "bot_profile_id": bot_id},
    )
    assert response.status_code == 201, response.text
    return response.json()
