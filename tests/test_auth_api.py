"""认证与权限：登录、注册开关、邀请码、角色与用户隔离。"""

from __future__ import annotations

import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

import pytest

from server.auth.passwords import hash_password
from tests.conftest import ADMIN_EMAIL, ADMIN_PASSWORD, create_bot

USER_PASSWORD = "MemberPass2026"
T2_PASSWORD = "Tenant2Pass2026"


def _register(
    client: TestClient, code: str, email: str, name: str | None = None
) -> object:
    body = {"email": email, "invite_code": code, "password": USER_PASSWORD}
    if name is not None:
        body["name"] = name
    return client.post("/api/auth/register", json=body)


def _login(client: TestClient, email: str, password: str) -> None:
    client.post("/api/auth/logout")
    response = client.post("/api/auth/login", json={"account": email, "password": password})
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
        "/api/auth/login", json={"account": ADMIN_EMAIL, "password": "wrong-pass"}
    )
    assert bad.status_code == 401

    response = client.post(
        "/api/auth/login", json={"account": ADMIN_EMAIL, "password": ADMIN_PASSWORD}
    )
    assert response.status_code == 200
    assert "sid" in response.cookies or "sid" in client.cookies

    me = client.get("/api/auth/me")
    assert me.status_code == 200
    assert me.json()["role"] == "super_admin"
    assert "tenant" not in me.json()

    assert client.post("/api/auth/logout").status_code == 200
    assert client.get("/api/auth/me").status_code == 401


def test_login_with_username(client: TestClient) -> None:
    # 引导管理员的用户名取邮箱前缀
    response = client.post(
        "/api/auth/login", json={"account": "admin", "password": ADMIN_PASSWORD}
    )
    assert response.status_code == 200, response.text
    assert response.json()["name"] == "admin"

    wrong = client.post(
        "/api/auth/login", json={"account": "admin", "password": "wrong-pass"}
    )
    assert wrong.status_code == 401


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


def test_register_rejects_duplicate_username(admin: TestClient, db_path) -> None:
    admin.patch("/api/admin/settings", json={"register_enabled": True})
    code = admin.post("/api/admin/invites", json={"max_uses": 2}).json()["code"]

    first = _register(admin, code, "first@example.com", name="Unique")
    assert first.status_code == 200, first.text

    # 大小写不敏感，且失败时不消耗邀请码
    second = _register(admin, code, "second@example.com", name="unique")
    assert second.status_code == 409, second.text
    assert "已被使用" in second.json()["detail"]
    with sqlite3.connect(db_path) as con:
        used = con.execute(
            "SELECT used_count FROM invite_codes WHERE code = ?", (code,)
        ).fetchone()[0]
    assert used == 1


def test_register_generates_unique_default_username(
    admin: TestClient, db_path
) -> None:
    admin.patch("/api/admin/settings", json={"register_enabled": True})
    code = admin.post("/api/admin/invites", json={"max_uses": 1}).json()["code"]
    # 已有用户名 dup，新注册未填用户名时以邮箱前缀为基准追加后缀
    _insert_user(db_path, "dup@other.test", USER_PASSWORD)

    created = _register(admin, code, "dup@example.com")
    assert created.status_code == 200, created.text
    assert created.json()["name"] == "dup-2"


def test_admin_update_username_unique(admin: TestClient, db_path) -> None:
    target_id = _insert_user(db_path, "target@example.com", T2_PASSWORD)

    dup = admin.patch(f"/api/admin/users/{target_id}", json={"name": "ADMIN"})
    assert dup.status_code == 409, dup.text
    assert "已被使用" in dup.json()["detail"]

    ok = admin.patch(f"/api/admin/users/{target_id}", json={"name": "renamed"})
    assert ok.status_code == 200, ok.text


def test_database_enforces_unique_username(db_path) -> None:
    # 绕过接口直接写入：唯一索引在数据库层同样忽略大小写
    _insert_user(db_path, "db-a@example.com", USER_PASSWORD)
    with pytest.raises(sqlite3.IntegrityError):
        _insert_user(db_path, "DB-A@example.com", USER_PASSWORD)


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


def test_login_failures_are_rate_limited(client: TestClient) -> None:
    for _ in range(5):
        bad = client.post(
            "/api/auth/login",
            json={"account": "nobody@example.com", "password": "wrong-pass"},
        )
        assert bad.status_code == 401, bad.text

    blocked = client.post(
        "/api/auth/login",
        json={"account": "nobody@example.com", "password": "wrong-pass"},
    )
    assert blocked.status_code == 429, blocked.text
    assert int(blocked.headers["Retry-After"]) > 0


def test_successful_login_clears_account_counter(client: TestClient) -> None:
    for _ in range(4):
        bad = client.post(
            "/api/auth/login",
            json={"account": ADMIN_EMAIL, "password": "wrong-pass"},
        )
        assert bad.status_code == 401, bad.text

    ok = client.post(
        "/api/auth/login", json={"account": ADMIN_EMAIL, "password": ADMIN_PASSWORD}
    )
    assert ok.status_code == 200, ok.text

    # 计数已清空，又能再错 5 次
    for _ in range(5):
        bad = client.post(
            "/api/auth/login",
            json={"account": ADMIN_EMAIL, "password": "wrong-pass"},
        )
        assert bad.status_code == 401, bad.text


def test_session_cookie_is_secure_on_https(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    from server.main import app

    assert "Secure" not in client.post(
        "/api/auth/login", json={"account": ADMIN_EMAIL, "password": ADMIN_PASSWORD}
    ).headers["set-cookie"]

    monkeypatch.setattr(app.state.settings, "public_base_url", "https://example.com")
    response = client.post(
        "/api/auth/login", json={"account": ADMIN_EMAIL, "password": ADMIN_PASSWORD}
    )
    assert response.status_code == 200, response.text
    assert "Secure" in response.headers["set-cookie"]


def test_invite_max_uses_never_exceeded(admin: TestClient, db_path) -> None:
    admin.patch("/api/admin/settings", json={"register_enabled": True})
    code = admin.post("/api/admin/invites", json={"max_uses": 1}).json()["code"]

    barrier = threading.Barrier(4)

    def register(index: int):
        barrier.wait()
        return _register(admin, code, f"racer{index}@example.com")

    with ThreadPoolExecutor(max_workers=4) as pool:
        responses = list(pool.map(register, range(4)))

    codes = sorted(response.status_code for response in responses)
    assert codes == [200, 400, 400, 400], codes

    with sqlite3.connect(db_path) as con:
        used = con.execute(
            "SELECT used_count FROM invite_codes WHERE code = ?", (code,)
        ).fetchone()[0]
        users = con.execute(
            "SELECT COUNT(*) FROM users WHERE email LIKE 'racer%@example.com'"
        ).fetchone()[0]
    assert used == 1
    assert users == 1


def test_passkey_register_stores_device_type_value(
    admin: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    from types import SimpleNamespace

    from webauthn.helpers.structs import CredentialDeviceType

    import server.auth.passkey as passkey_flow

    def fake_verify_registration(**_kwargs):
        return SimpleNamespace(
            credential_id=b"cred-1",
            credential_public_key=b"public-key",
            sign_count=0,
            aaguid="00000000-0000-0000-0000-000000000000",
            credential_device_type=CredentialDeviceType.SINGLE_DEVICE,
            credential_backed_up=False,
        )

    monkeypatch.setattr(
        passkey_flow, "verify_registration_response", fake_verify_registration
    )

    begin = admin.post("/api/auth/passkey/register/begin")
    assert begin.status_code == 200, begin.text

    finish = admin.post(
        "/api/auth/passkey/register/finish",
        json={"credential": {"id": "cred-1", "response": {"transports": ["internal"]}}},
    )
    assert finish.status_code == 200, finish.text

    rows = admin.get("/api/auth/passkey").json()
    assert len(rows) == 1
    # webauthn 3.x 的枚举 str() 是 "CredentialDeviceType.SINGLE_DEVICE"，超出库内 32 字符
    assert rows[0]["device_type"] == "single_device"
    assert len(rows[0]["device_type"]) <= 32
