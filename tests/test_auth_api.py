"""认证与权限：登录、注册开关、邀请码、角色与用户隔离。"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from server.auth.passwords import hash_password
from tests.conftest import ADMIN_EMAIL, ADMIN_PASSWORD, create_bot

USER_PASSWORD = "MemberPass2026"
T2_PASSWORD = "Tenant2Pass2026"


def _register(client: TestClient, code: str, email: str) -> object:
    return client.post(
        "/api/auth/register",
        json={"email": email, "invite_code": code, "password": USER_PASSWORD},
    )


def _login(client: TestClient, email: str, password: str) -> None:
    client.post("/api/auth/logout")
    response = client.post("/api/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text


def _insert_user(db_path, email: str, password: str, role: str = "user") -> int:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")
    with sqlite3.connect(db_path) as con:
        con.execute(
            "INSERT INTO users (email, name, password_hash, role, status, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (email, email.split("@")[0], hash_password(password), role, "active", now),
        )
        user_id = con.execute("SELECT last_insert_rowid()").fetchone()[0]
        con.commit()
    return user_id


def test_requires_login(client: TestClient) -> None:
    assert client.get("/api/admin/bot-profiles").status_code == 401
    assert client.get("/api/auth/me").status_code == 401


def test_login_and_logout(client: TestClient) -> None:
    bad = client.post(
        "/api/auth/login", json={"email": ADMIN_EMAIL, "password": "wrong-pass"}
    )
    assert bad.status_code == 401

    response = client.post(
        "/api/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}
    )
    assert response.status_code == 200
    assert "sid" in response.cookies or "sid" in client.cookies

    me = client.get("/api/auth/me")
    assert me.status_code == 200
    assert me.json()["role"] == "super_admin"
    assert "tenant" not in me.json()

    assert client.post("/api/auth/logout").status_code == 200
    assert client.get("/api/auth/me").status_code == 401


def test_register_disabled_by_default(client: TestClient) -> None:
    response = client.post(
        "/api/auth/register",
        json={"email": "someone@example.com", "invite_code": "x", "password": USER_PASSWORD},
    )
    assert response.status_code == 403


def test_invite_register_and_user_scope(admin: TestClient) -> None:
    assert (
        admin.patch("/api/admin/settings", json={"register_enabled": True}).status_code
        == 200
    )
    invite = admin.post(
        "/api/admin/invites", json={"max_uses": 1, "expires_in_days": 7}
    )
    assert invite.status_code == 201, invite.text
    assert "role" not in invite.json()
    code = invite.json()["code"]

    created = _register(admin, code, "user@example.com")
    assert created.status_code == 200, created.text
    assert created.json()["role"] == "user"

    # 当前 Cookie 已换成新用户：只能管理自己的资源
    assert admin.get("/api/admin/bot-profiles").json() == []
    own_bot = admin.post(
        "/api/admin/bot-profiles",
        json={"name": "x", "qq_appid": "1", "qq_app_secret": "s"},
    )
    assert own_bot.status_code == 201, own_bot.text
    assert admin.get("/api/admin/bot-profiles").json()[0]["owner_email"] == "user@example.com"

    # 超管专属接口对普通用户不可用
    assert admin.get("/api/admin/users").status_code == 403
    assert admin.patch("/api/admin/settings", json={"register_enabled": False}).status_code == 403
    assert admin.get("/api/admin/invites").status_code == 403
    assert admin.get("/api/admin/oauth-providers").status_code == 403
    assert admin.get("/api/admin/stats").json()["scope"] == "mine"

    # 重新以管理员登录后，同一邀请码已用尽
    _login(admin, ADMIN_EMAIL, ADMIN_PASSWORD)
    reused = _register(admin, code, "other@example.com")
    assert reused.status_code == 400
    assert "用尽" in reused.json()["detail"]


def test_expired_invite_rejected(admin: TestClient, db_path) -> None:
    admin.patch("/api/admin/settings", json={"register_enabled": True})
    invite = admin.post("/api/admin/invites", json={"max_uses": 1}).json()
    past = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S.%f")
    with sqlite3.connect(db_path) as con:
        con.execute("UPDATE invite_codes SET expires_at = ? WHERE code = ?", (past, invite["code"]))
        con.commit()

    response = _register(admin, invite["code"], "late@example.com")
    assert response.status_code == 400
    assert "过期" in response.json()["detail"]


def test_cross_user_resources_isolated(admin: TestClient, db_path) -> None:
    admin_bot = create_bot(admin)

    _insert_user(db_path, "t2@example.com", T2_PASSWORD)
    _login(admin, "t2@example.com", T2_PASSWORD)

    assert admin.get("/api/admin/bot-profiles").json() == []
    assert admin.patch(f"/api/admin/bot-profiles/{admin_bot}", json={"name": "hijack"}).status_code == 404
    assert admin.delete(f"/api/admin/bot-profiles/{admin_bot}").status_code == 404

    own_bot = create_bot(admin)
    own_logs = admin.get("/api/admin/logs").json()
    assert own_logs["items"] == []

    # 超管可见全部用户资源
    _login(admin, ADMIN_EMAIL, ADMIN_PASSWORD)
    rows = admin.get("/api/admin/bot-profiles").json()
    assert {row["id"] for row in rows} == {admin_bot, own_bot}
    assert {row["owner_email"] for row in rows} == {ADMIN_EMAIL, "t2@example.com"}
    assert admin.get("/api/admin/stats").json()["scope"] == "all"


def test_super_admin_cannot_change_own_role_or_status(admin: TestClient) -> None:
    me = admin.get("/api/auth/me").json()
    role = admin.patch(f"/api/admin/users/{me['id']}", json={"role": "user"})
    assert role.status_code == 400
    assert "不能修改自己的角色" in role.json()["detail"]
    disabled = admin.patch(f"/api/admin/users/{me['id']}", json={"status": "disabled"})
    assert disabled.status_code == 400
    assert "不能修改自己的账号状态" in disabled.json()["detail"]
