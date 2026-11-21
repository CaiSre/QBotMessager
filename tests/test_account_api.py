"""个人中心：用户名、邮箱与密码修改。"""

from __future__ import annotations

import hashlib
import sqlite3
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from server.auth.passwords import hash_password
from tests.conftest import ADMIN_EMAIL, ADMIN_PASSWORD

NEW_PASSWORD = "new-password-123"
OAUTH_PASSWORD = "{{SECRET_q7mz2d1k}}"


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _fmt(value: datetime) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S.%f")


def _insert_user(
    db_path, email: str, password_hash: str | None, name: str | None = None
) -> int:
    with sqlite3.connect(db_path) as con:
        con.execute(
            "INSERT INTO users (email, name, password_hash, role, status, created_at)"
            " VALUES (?, ?, ?, 'user', 'active', ?)",
            (email, name or email.split("@")[0], password_hash, _fmt(_now_utc())),
        )
        user_id = con.execute("SELECT last_insert_rowid()").fetchone()[0]
        con.commit()
    return user_id


def _insert_session(db_path, user_id: int, token: str) -> None:
    with sqlite3.connect(db_path) as con:
        con.execute(
            "INSERT INTO sessions (token_hash, user_id, expires_at, created_at)"
            " VALUES (?, ?, ?, ?)",
            (
                hashlib.sha256(token.encode("utf-8")).hexdigest(),
                user_id,
                _fmt(_now_utc() + timedelta(hours=1)),
                _fmt(_now_utc()),
            ),
        )
        con.commit()


def _login(client: TestClient, email: str, password: str):
    client.post("/api/auth/logout")
    return client.post("/api/auth/login", json={"account": email, "password": password})


def test_update_name(admin: TestClient) -> None:
    response = admin.patch("/api/auth/me/name", json={"name": "  新名字  "})
    assert response.status_code == 200, response.text
    assert response.json()["name"] == "新名字"
    assert admin.get("/api/auth/me").json()["name"] == "新名字"

    blank = admin.patch("/api/auth/me/name", json={"name": "   "})
    assert blank.status_code == 422


def test_update_name_conflict(admin: TestClient, db_path) -> None:
    _insert_user(db_path, "other@example.com", hash_password("other-pass-1"), "taken")

    # 唯一性忽略大小写
    for candidate in ("taken", "TAKEN", " taken "):
        response = admin.patch("/api/auth/me/name", json={"name": candidate})
        assert response.status_code == 409, response.text
        assert "已被使用" in response.json()["detail"]
    assert admin.get("/api/auth/me").json()["name"] == "admin"

    # 改为自身当前用户名（大小写不同）不受限
    own = admin.patch("/api/auth/me/name", json={"name": "ADMIN"})
    assert own.status_code == 200, own.text
    assert own.json()["name"] == "ADMIN"


def test_update_email_requires_current_password(admin: TestClient) -> None:
    wrong = admin.patch(
        "/api/auth/me/email",
        json={"email": "new-admin@example.com", "current_password": "wrong-pass"},
    )
    assert wrong.status_code == 400
    assert admin.get("/api/auth/me").json()["email"] == ADMIN_EMAIL

    ok = admin.patch(
        "/api/auth/me/email",
        json={"email": "New-Admin@Example.com", "current_password": ADMIN_PASSWORD},
    )
    assert ok.status_code == 200, ok.text
    assert ok.json()["email"] == "new-admin@example.com"

    # 新邮箱可登录，旧邮箱失效
    assert _login(admin, "new-admin@example.com", ADMIN_PASSWORD).status_code == 200
    assert _login(admin, ADMIN_EMAIL, ADMIN_PASSWORD).status_code == 401


def test_update_email_conflict(admin: TestClient, db_path) -> None:
    _insert_user(db_path, "taken@example.com", hash_password("{{SECRET_zz91k2qv}}"))
    response = admin.patch(
        "/api/auth/me/email",
        json={"email": "taken@example.com", "current_password": ADMIN_PASSWORD},
    )
    assert response.status_code == 409
    assert "已被使用" in response.json()["detail"]


def test_update_password_revokes_other_sessions(admin: TestClient, db_path) -> None:
    user_id = admin.get("/api/auth/me").json()["id"]
    _insert_session(db_path, user_id, "another-device-token")

    wrong = admin.patch(
        "/api/auth/me/password",
        json={"current_password": "wrong-pass", "new_password": NEW_PASSWORD},
    )
    assert wrong.status_code == 400

    same = admin.patch(
        "/api/auth/me/password",
        json={"current_password": ADMIN_PASSWORD, "new_password": ADMIN_PASSWORD},
    )
    assert same.status_code == 400

    ok = admin.patch(
        "/api/auth/me/password",
        json={"current_password": ADMIN_PASSWORD, "new_password": NEW_PASSWORD},
    )
    assert ok.status_code == 200, ok.text

    # 当前会话保留，其他设备被注销
    assert admin.get("/api/auth/me").status_code == 200
    with sqlite3.connect(db_path) as con:
        revoked = con.execute(
            "SELECT revoked_at FROM sessions WHERE token_hash = ?",
            (hashlib.sha256(b"another-device-token").hexdigest(),),
        ).fetchone()[0]
    assert revoked is not None

    assert _login(admin, ADMIN_EMAIL, ADMIN_PASSWORD).status_code == 401
    assert _login(admin, ADMIN_EMAIL, NEW_PASSWORD).status_code == 200


def test_oauth_account_sets_password(admin: TestClient, db_path) -> None:
    user_id = admin.get("/api/auth/me").json()["id"]
    # 模拟 OAuth 创建、未设置密码的账号
    with sqlite3.connect(db_path) as con:
        con.execute("UPDATE users SET password_hash = NULL WHERE id = ?", (user_id,))
        con.commit()

    assert admin.get("/api/auth/me").json()["has_password"] is False

    # 没有旧密码，直接设置新密码
    response = admin.patch("/api/auth/me/password", json={"new_password": OAUTH_PASSWORD})
    assert response.status_code == 200, response.text
    assert admin.get("/api/auth/me").json()["has_password"] is True

    assert _login(admin, ADMIN_EMAIL, OAUTH_PASSWORD).status_code == 200
