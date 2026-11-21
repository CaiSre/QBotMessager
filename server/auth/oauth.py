"""通用 OAuth2 授权码流程（GitHub 等）。

不引入 authlib：授权码换 token、拉 userinfo 都用 httpx 直接完成。
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from urllib.parse import urlencode

import httpx2 as httpx

from server.db.models import OAuthProvider


GITHUB_PRESET = {
    "key": "github",
    "display_name": "GitHub",
    "authorization_url": "https://github.com/login/oauth/authorize",
    "token_url": "https://github.com/login/oauth/access_token",
    "userinfo_url": "https://api.github.com/user",
    "scopes": "read:user user:email",
    "email_field": "email",
    "id_field": "id",
    "name_field": "login",
}

GITHUB_EMAILS_URL = "https://api.github.com/user/emails"


@dataclass
class OAuthProfile:
    provider_user_id: str
    login: str
    email: str | None
    name: str | None


def new_state() -> str:
    return secrets.token_urlsafe(24)


def build_authorize_url(provider: OAuthProvider, *, redirect_uri: str, state: str) -> str:
    params = {
        "client_id": provider.client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "state": state,
    }
    if provider.scopes:
        params["scope"] = provider.scopes
    return f"{provider.authorization_url}?{urlencode(params)}"


async def exchange_code(
    client: httpx.AsyncClient, provider: OAuthProvider, *, code: str, redirect_uri: str
) -> dict:
    resp = await client.post(
        provider.token_url,
        data={
            "client_id": provider.client_id,
            "client_secret": provider.client_secret,
            "code": code,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        },
        headers={"Accept": "application/json"},
    )
    resp.raise_for_status()
    data = resp.json()
    if not isinstance(data, dict):
        raise ValueError("token 响应格式非法")
    token = data.get("access_token")
    if not token:
        raise ValueError(f"换取 token 失败：{data.get('error_description') or data}")
    return data


async def fetch_profile(
    client: httpx.AsyncClient, provider: OAuthProvider, *, access_token: str
) -> OAuthProfile:
    resp = await client.get(
        provider.userinfo_url,
        headers={
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
            "User-Agent": "qbotmessager",
        },
    )
    resp.raise_for_status()
    data = resp.json()
    if not isinstance(data, dict):
        raise ValueError("userinfo 响应格式非法")

    raw_id = data.get(provider.id_field)
    if raw_id is None:
        raise ValueError(f"userinfo 缺少字段 {provider.id_field}")

    email = data.get(provider.email_field)
    if not email and provider.key == "github":
        # GitHub 的 email 可能是私有的，需要单独拉取主邮箱
        try:
            emails = await client.get(
                GITHUB_EMAILS_URL,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json",
                    "User-Agent": "qbotmessager",
                },
            )
            if emails.status_code == 200:
                items = emails.json()
                primary = next(
                    (e for e in items if isinstance(e, dict) and e.get("primary")),
                    None,
                )
                if primary:
                    email = primary.get("email")
        except (httpx.HTTPError, ValueError):
            email = None

    return OAuthProfile(
        provider_user_id=str(raw_id),
        login=str(data.get("login") or data.get(provider.name_field) or raw_id),
        email=email,
        name=data.get(provider.name_field) or data.get("name"),
    )
