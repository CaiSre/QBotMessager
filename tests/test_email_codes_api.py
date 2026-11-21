"""SMTP 设置与邮箱验证码：注册、找回密码、OAuth 账号设密。"""

from __future__ import annotations

import re
import sqlite3

import pytest
from fastapi.testclient import TestClient

from server.auth.passwords import hash_password
from tests.conftest import ADMIN_EMAIL, ADMIN_PASSWORD


class Outbox:
    def __init__(self) -> None:
        self.messages: list[dict] = []

    async def __call__(self, settings, *, to, subject, text, html=None) -> None:
        self.messages.append(
            {"to": to, "subject": subject, "text": text, "html": html}
        )

    def latest_code(self) -> str:
        assert self.messages, "没有发送任何邮件"
        text = self.messages[-1]["text"]
        match = re.search(r"(?<!\d)(\d{6})(?!\d)", text)
        if match is None:
            raise AssertionError(f"邮件中未找到验证码：{text}")
        return match.group(1)


@pytest.fixture()
def outbox(monkeypatch: pytest.MonkeyPatch) -> Outbox:
    from server.api import auth as auth_module

    box = Outbox()
    monkeypatch.setattr(auth_module, "send_mail", box)
    return box


def _items(payload: dict) -> dict[str, dict]:
    return {
        item["key"]: item
        for group in payload["groups"]
        for item in group["items"]
    }


def _configure_mail(admin: TestClient) -> None:
    response = admin.patch(
        "/api/admin/settings",
        json={
            "smtp_host": "smtp.example.com",
            "smtp_from": "noreply@example.com",
            "smtp_security": "none",
            "register_enabled": True,
        },
    )
    assert response.status_code == 200, response.text


def _insert_user(db_path, email: str, password: str, *, with_password: bool = True) -> int:
    with sqlite3.connect(db_path) as con:
        cursor = con.execute(
            "INSERT INTO users (email, name, password_hash, role, status, created_at)"
            " VALUES (?, ?, ?, 'user', 'active', CURRENT_TIMESTAMP)",
            (email, email.split("@")[0], hash_password(password) if with_password else None),
        )
        con.commit()
        return int(cursor.lastrowid)


def _logout(client: TestClient) -> None:
    client.post("/api/auth/logout")


def test_smtp_password_is_encrypted_and_never_returned(
    admin: TestClient, db_path, outbox: Outbox
) -> None:
    response = admin.patch(
        "/api/admin/settings",
        json={"smtp_password": "smtp-secret-value"},
    )
    assert response.status_code == 200, response.text
    items = _items(response.json())
    assert items["smtp_password"]["value"] == ""
    assert items["smtp_password"]["has_value"] is True

    with sqlite3.connect(db_path) as con:
        stored = con.execute(
            "SELECT value FROM system_settings WHERE key = 'smtp_password'"
        ).fetchone()[0]
        audit = con.execute(
            "SELECT detail FROM admin_audit_logs WHERE action = 'settings.update'"
            " ORDER BY id DESC LIMIT 1"
        ).fetchone()[0]
    assert stored.startswith("enc1:")
    assert "smtp-secret-value" not in stored
    # 审计日志同样不能落明文
    assert "smtp-secret-value" not in str(audit)


def test_smtp_not_configured_keeps_registration_working(
    admin: TestClient, client: TestClient
) -> None:
    meta = client.get("/api/auth/providers").json()
    assert meta["email_code_enabled"] is False
    response = client.post(
        "/api/auth/email-code",
        json={"email": "new@example.com", "purpose": "register"},
    )
    assert response.status_code == 503


def test_register_requires_email_code(admin: TestClient, outbox: Outbox) -> None:
    invite = _create_invite(admin)
    _configure_mail(admin)
    _logout(admin)

    meta = admin.get("/api/auth/providers").json()
    assert meta["email_code_enabled"] is True

    sent = admin.post(
        "/api/auth/email-code",
        json={"email": "new@example.com", "purpose": "register"},
    )
    assert sent.status_code == 200, sent.text
    code = outbox.latest_code()
    message = outbox.messages[-1]
    assert message["to"] == "new@example.com"
    assert message["subject"] == "QBotMessager 验证码"
    assert code in message["html"]
    assert "font-weight:700" in message["html"]

    payload = {
        "email": "new@example.com",
        "password": "new-password-1",
        "invite_code": invite,
    }
    missing = admin.post("/api/auth/register", json=payload)
    assert missing.status_code == 400
    assert "验证码" in missing.text

    wrong = admin.post("/api/auth/register", json={**payload, "email_code": "000000"})
    assert wrong.status_code == 400

    ok = admin.post("/api/auth/register", json={**payload, "email_code": code})
    assert ok.status_code == 200, ok.text
    assert admin.get("/api/auth/providers").json()["email_code_enabled"] is True


def test_email_code_cooldown(
    admin: TestClient, db_path, outbox: Outbox
) -> None:
    _insert_user(db_path, "someone@example.com", "old-password-1")
    _configure_mail(admin)
    _logout(admin)
    body = {"email": "someone@example.com", "purpose": "reset_password"}
    assert admin.post("/api/auth/email-code", json=body).status_code == 200
    second = admin.post("/api/auth/email-code", json=body)
    assert second.status_code == 429


def test_reset_password_with_code(admin: TestClient, db_path, outbox: Outbox) -> None:
    _insert_user(db_path, "forget@example.com", "old-password-1")
    _configure_mail(admin)
    _logout(admin)

    requested = admin.post(
        "/api/auth/email-code",
        json={"email": "forget@example.com", "purpose": "reset_password"},
    )
    assert requested.status_code == 200, requested.text
    code = outbox.latest_code()

    bad = admin.post(
        "/api/auth/password/reset",
        json={
            "email": "forget@example.com",
            "code": "999999",
            "new_password": "new-password-1",
        },
    )
    assert bad.status_code == 400

    # 错误尝试后仍可用正确验证码重置（未达尝试上限）
    ok = admin.post(
        "/api/auth/password/reset",
        json={
            "email": "forget@example.com",
            "code": code,
            "new_password": "new-password-1",
        },
    )
    assert ok.status_code == 200, ok.text

    assert (
        admin.post(
            "/api/auth/login",
            json={"email": "forget@example.com", "password": "old-password-1"},
        ).status_code
        == 401
    )
    assert (
        admin.post(
            "/api/auth/login",
            json={"email": "forget@example.com", "password": "new-password-1"},
        ).status_code
        == 200
    )


def test_oauth_account_set_password_requires_code(
    admin: TestClient, db_path, outbox: Outbox
) -> None:
    _configure_mail(admin)
    # 模拟 OAuth 创建、尚未设置密码的账号
    with sqlite3.connect(db_path) as con:
        con.execute(
            "UPDATE users SET password_hash = NULL WHERE email = ?", (ADMIN_EMAIL,)
        )
        con.commit()

    without_code = admin.patch(
        "/api/auth/me/password",
        json={"new_password": "oauth-password-1"},
    )
    assert without_code.status_code == 400
    assert "验证码" in without_code.text

    requested = admin.post("/api/auth/me/password-code")
    assert requested.status_code == 200, requested.text
    assert outbox.messages[-1]["to"] == ADMIN_EMAIL
    code = outbox.latest_code()

    with_code = admin.patch(
        "/api/auth/me/password",
        json={
            "new_password": "oauth-password-1",
            "email_code": code,
        },
    )
    assert with_code.status_code == 200, with_code.text

    _logout(admin)
    assert (
        admin.post(
            "/api/auth/login",
            json={"email": ADMIN_EMAIL, "password": "oauth-password-1"},
        ).status_code
        == 200
    )


def _create_invite(admin: TestClient) -> str:
    response = admin.post(
        "/api/admin/invites",
        json={"email": "new@example.com", "max_uses": 1},
    )
    assert response.status_code == 201, response.text
    return response.json()["code"]
