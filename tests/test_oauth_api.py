"""OAuth2 登录回归：Client Secret 不回写明文、未验证邮箱不得接管本地账号。"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from server.auth.passwords import hash_password
from tests.conftest import ADMIN_EMAIL, ADMIN_PASSWORD

CLIENT_SECRET = "demo-client-secret"
VICTIM_EMAIL = "victim@example.com"
VICTIM_PASSWORD = "{{SECRET_ow3n1wmx}}"


class FakeResponse:
    def __init__(self, payload: dict) -> None:
        self._payload = payload
        self.status_code = 200
        self.text = json.dumps(payload, ensure_ascii=False)

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return self._payload


class FakeProviderHttp:
    """打桩的提供方客户端：换 token 与拉 userinfo 都返回固定数据。"""

    def __init__(self, *, email: str, email_verified: bool) -> None:
        self.email = email
        self.email_verified = email_verified
        self.token_requests: list[dict] = []

    async def post(self, url, data=None, headers=None, **kwargs) -> FakeResponse:
        self.token_requests.append(dict(data or {}))
        return FakeResponse({"access_token": "demo-access-token", "token_type": "bearer"})

    async def get(self, url, headers=None, **kwargs) -> FakeResponse:
        return FakeResponse(
            {
                "id": "ext-user-1",
                "login": "demo-user",
                "email": self.email,
                "email_verified": self.email_verified,
            }
        )

    async def aclose(self) -> None:
        return None


def _create_provider(
    client: TestClient, *, email_verified: bool = False, key: str = "demo"
) -> None:
    response = client.post(
        "/api/admin/oauth-providers",
        json={
            "key": key,
            "display_name": "演示提供方",
            "client_id": "demo-client-id",
            "client_secret": CLIENT_SECRET,
            "authorization_url": "https://demo.example.com/authorize",
            "token_url": "https://demo.example.com/token",
            "userinfo_url": "https://demo.example.com/userinfo",
            "email_verified": email_verified,
        },
    )
    assert response.status_code == 201, response.text


def _install_provider_http(email: str, *, email_verified: bool) -> FakeProviderHttp:
    from server.main import app

    fake = FakeProviderHttp(email=email, email_verified=email_verified)
    app.state.httpx = fake
    return fake


def _run_oauth(client: TestClient, provider_key: str = "demo"):
    start = client.get(f"/api/auth/oauth/{provider_key}/start", follow_redirects=False)
    assert start.status_code == 302, start.text
    state = client.cookies.get("oauth_state")
    assert state, "缺少 oauth_state cookie"
    return client.get(
        f"/api/auth/oauth/{provider_key}/callback",
        params={"code": "demo-code", "state": state},
        follow_redirects=False,
    )


def _stored_client_secret(db_path) -> str:
    with sqlite3.connect(db_path) as con:
        row = con.execute(
            "SELECT client_secret FROM oauth_providers WHERE key = 'demo'"
        ).fetchone()
    assert row is not None
    return row[0]


def _insert_user(db_path, email: str, password: str) -> int:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")
    with sqlite3.connect(db_path) as con:
        con.execute(
            "INSERT INTO users (email, name, password_hash, role, status, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (email, email.split("@")[0], hash_password(password), "user", "active", now),
        )
        user_id = con.execute("SELECT last_insert_rowid()").fetchone()[0]
        con.commit()
    return user_id


def test_client_secret_stays_encrypted_after_oauth_login(
    admin: TestClient, db_path
) -> None:
    admin.patch("/api/admin/settings", json={"register_enabled": True})
    _create_provider(admin)
    fake = _install_provider_http("new-user@example.com", email_verified=True)

    callback = _run_oauth(admin)
    assert callback.status_code == 302, callback.text

    # 换 token 用的是解密后的明文，但不能把明文写回库里
    assert fake.token_requests[0]["client_secret"] == CLIENT_SECRET
    stored = _stored_client_secret(db_path)
    assert stored.startswith("enc1:"), stored
    assert CLIENT_SECRET not in stored


def test_untrusted_provider_cannot_take_over_local_account(
    admin: TestClient, db_path
) -> None:
    _insert_user(db_path, VICTIM_EMAIL, VICTIM_PASSWORD)
    _create_provider(admin, email_verified=False)
    _install_provider_http(VICTIM_EMAIL, email_verified=False)

    callback = _run_oauth(admin)
    assert callback.status_code == 409, callback.text
    assert "未验证邮箱" in callback.json()["detail"]

    # 本地账号没有被关联出去
    with sqlite3.connect(db_path) as con:
        identities = con.execute(
            "SELECT COUNT(*) FROM auth_identities WHERE provider = 'demo'"
        ).fetchone()[0]
    assert identities == 0


def test_trusted_provider_links_local_account(admin: TestClient, db_path) -> None:
    user_id = _insert_user(db_path, VICTIM_EMAIL, VICTIM_PASSWORD)
    _create_provider(admin, email_verified=True)
    _install_provider_http(VICTIM_EMAIL, email_verified=False)

    callback = _run_oauth(admin)
    assert callback.status_code == 302, callback.text

    with sqlite3.connect(db_path) as con:
        row = con.execute(
            "SELECT user_id FROM auth_identities WHERE provider = 'demo'"
        ).fetchone()
    assert row is not None
    assert row[0] == user_id


def test_github_preset_trusts_emails(admin: TestClient) -> None:
    _create_provider(admin)
    response = admin.post(
        "/api/admin/oauth-providers",
        json={
            "key": "github",
            "display_name": "GitHub",
            "client_id": "gh-client-id",
            "client_secret": CLIENT_SECRET,
            "use_github_preset": True,
        },
    )
    assert response.status_code == 201, response.text

    providers = admin.get("/api/admin/oauth-providers").json()
    github = next(item for item in providers if item["key"] == "github")
    assert github["email_verified"] is True

    # 自定义提供方默认不信任邮箱
    demo = next(item for item in providers if item["key"] == "demo")
    assert demo["email_verified"] is False


def test_admin_password_still_works(admin: TestClient) -> None:
    # 未验证邮箱的提供方不得影响密码登录
    response = admin.post(
        "/api/auth/login",
        json={"account": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
    )
    assert response.status_code == 200, response.text
