"""QQ 机器人 HTTP 客户端：token 缓存、消息发送、错误分类与重试。

发送逻辑沿用 send_message.py 已验证的路径与请求头约定，扩展为异步 + msg_type=2。
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

import httpx2 as httpx

from server.renderer import QqPayload

logger = logging.getLogger(__name__)

DEFAULT_HOST = "https://api.bot.qq.com"
_TOKEN_REFRESH_AHEAD = 60  # 提前 60s 刷新

ERR_RATE_LIMIT = 40034100  # 主动消息超频
ERR_DUPLICATE = 40054005  # 消息去重
ERR_ACCESS_TOKEN_INVALID = 401


class QqError(RuntimeError):
    """QQ 推送失败，携带可展示的错误码与错误信息。"""

    def __init__(self, code: str, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable


@dataclass
class QqTarget:
    openid: str | None = None
    group_openid: str | None = None

    def path(self) -> str:
        if self.group_openid:
            return f"/v2/groups/{self.group_openid}/messages"
        if self.openid:
            return f"/v2/users/{self.openid}/messages"
        raise ValueError("推送目标为空")

    def label(self) -> str:
        return f"group:{self.group_openid}" if self.group_openid else f"user:{self.openid}"

    def to_db_value(self) -> str:
        return self.label()


class QqClient:
    """按 (bot_profile_id) 缓存 access_token 的异步客户端。"""

    def __init__(self, client: httpx.AsyncClient) -> None:
        self._client = client
        self._tokens: dict[str, tuple[str, float]] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    async def aclose(self) -> None:
        await self._client.aclose()

    def _lock(self, key: str) -> asyncio.Lock:
        lock = self._locks.get(key)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[key] = lock
        return lock

    async def get_access_token(
        self,
        *,
        key: str,
        host: str,
        app_id: str,
        app_secret: str,
        force: bool = False,
    ) -> str:
        now = time.monotonic()
        cached = self._tokens.get(key)
        if cached and not force and cached[1] > now:
            return cached[0]

        async with self._lock(key):
            now = time.monotonic()
            cached = self._tokens.get(key)
            if cached and not force and cached[1] > now:
                return cached[0]
            try:
                resp = await self._client.post(
                    f"{host}/app/getAppAccessToken",
                    json={"appId": app_id, "clientSecret": app_secret},
                )
            except httpx.HTTPError as exc:
                raise QqError("token_network", f"获取 access_token 网络错误：{exc}", retryable=True) from exc
            if resp.status_code != 200:
                raise QqError(
                    f"token_http_{resp.status_code}",
                    f"获取 access_token 失败：HTTP {resp.status_code}",
                    retryable=resp.status_code >= 500,
                )
            data = resp.json()
            token = data.get("access_token")
            if not token:
                raise QqError("token_missing", f"获取 access_token 失败：{data}")
            expires_in = int(data.get("expires_in") or 7200)
            expires_at = time.monotonic() + max(1, expires_in - _TOKEN_REFRESH_AHEAD)
            self._tokens[key] = (token, expires_at)
            return token

    def invalidate(self, key: str) -> None:
        self._tokens.pop(key, None)

    async def send(
        self,
        *,
        key: str,
        host: str,
        app_id: str,
        app_secret: str,
        target: QqTarget,
        payload: QqPayload,
        max_retries: int = 3,
        before_attempt: Callable[[], Awaitable[None]] | None = None,
    ) -> dict:
        """发送消息；401 刷新 token 重试一次，5xx/网络错误退避重试。

        before_attempt 在每次实际请求（含重试）前调用，用于重新获取频控许可。
        """
        attempt = 0
        token_refreshed = False
        backoff = 0.5
        while True:
            if before_attempt is not None:
                await before_attempt()
            token = await self.get_access_token(
                key=key, host=host, app_id=app_id, app_secret=app_secret
            )
            try:
                resp = await self._client.post(
                    f"{host}{target.path()}",
                    headers={"Authorization": f"QQBot {token}"},
                    json=payload.to_dict(),
                )
            except httpx.HTTPError as exc:
                attempt += 1
                if attempt > max_retries:
                    raise QqError("network", f"推送网络错误：{exc}", retryable=True) from exc
                await asyncio.sleep(backoff)
                backoff *= 2
                continue

            if resp.status_code == 200:
                return _safe_json(resp)

            if resp.status_code == ERR_ACCESS_TOKEN_INVALID and not token_refreshed:
                token_refreshed = True
                self.invalidate(key)
                continue

            body = _safe_json(resp)
            code = _extract_code(body) or f"http_{resp.status_code}"

            if code == ERR_DUPLICATE:
                logger.info("QQ 返回消息去重（视为成功）：%s", body)
                return body

            rate_limited = code == ERR_RATE_LIMIT or str(code) == str(ERR_RATE_LIMIT)
            retryable = resp.status_code >= 500 or rate_limited
            if retryable and attempt < max_retries:
                attempt += 1
                delay = _retry_after(resp)
                if delay is None:
                    delay = backoff
                if rate_limited:
                    delay = max(delay, 2.0)
                await asyncio.sleep(delay)
                backoff = min(backoff * 2, 8.0)
                continue

            raise QqError(
                str(code), _extract_message(body) or f"HTTP {resp.status_code}", retryable=retryable
            )


def _retry_after(resp: httpx.Response) -> float | None:
    """读取 Retry-After（秒）；无法解析或过长时忽略。"""
    raw = resp.headers.get("Retry-After", "").strip()
    if not raw:
        return None
    try:
        value = float(raw)
    except ValueError:
        return None
    return min(max(value, 0.0), 30.0)


def _safe_json(resp: httpx.Response) -> dict:
    try:
        data = resp.json()
        return data if isinstance(data, dict) else {"data": data}
    except ValueError:
        return {"raw": resp.text[:500]}


def _extract_code(body: dict) -> object | None:
    for key in ("code", "err_code", "errcode"):
        if key in body:
            return body[key]
    return None


def _extract_message(body: dict) -> str:
    for key in ("message", "msg", "errmsg"):
        value = body.get(key)
        if isinstance(value, str) and value:
            return value
    return ""
