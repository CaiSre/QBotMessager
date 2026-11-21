"""Webhook 数据面：钉钉 / 企业微信 / 飞书 / GitHub → QQ 机器人。"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
import uuid

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.adapters import get_adapter
from server.adapters.base import IgnoredEvent, PayloadError, UnifiedMessage
from server.db.crypto import decrypt_secret
from server.db.models import PLATFORM_GITHUB, PLATFORMS, BotProfile, Channel, PushLog
from server.db.session import get_session_factory
from server.renderer import QqPayload, render_qq
from server.services.qq import QqClient, QqError, QqTarget

logger = logging.getLogger(__name__)

router = APIRouter()


def ack(platform: str, *, errcode: int = 0, errmsg: str = "ok") -> dict:
    if platform == PLATFORM_GITHUB:
        return {"ok": True} if errcode == 0 else {"ok": False, "error": errmsg}
    if platform == "feishu":
        data = {} if errcode == 0 else {"error": errmsg}
        return {"code": errcode, "msg": "success" if errcode == 0 else errmsg, "data": data}
    return {"errcode": errcode, "errmsg": errmsg}


def _json(platform: str, status_code: int, **kwargs) -> JSONResponse:
    return JSONResponse(ack(platform, **kwargs), status_code=status_code)


async def _read_body(request: Request, limit: int) -> bytes | None:
    """按上限读取请求体，超限返回 None。

    先看 Content-Length 直接拒绝，再流式读取并累计长度，避免把超大请求体整个收进内存。
    """
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        return None
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > limit:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


def _verify_github_signature(
    channel: Channel, request: Request, raw: bytes, settings
) -> tuple[int, str | None]:
    """校验 X-Hub-Signature-256；返回 (状态码, 错误信息)，通过时错误信息为 None。"""
    stored = ((channel.extra or {}).get("secret_cipher") or "").strip()
    if not stored:
        return 401, "通道未配置签名密钥"
    try:
        secret = decrypt_secret(stored, settings.app_secret_key)
    except Exception:  # noqa: BLE001 - 密钥不匹配时统一报配置错误
        return 502, "签名密钥无法解密，请检查 APP_SECRET_KEY"

    header = request.headers.get("X-Hub-Signature-256", "").strip()
    if not header.startswith("sha256="):
        return 401, "缺少 X-Hub-Signature-256 签名"
    expected = "sha256=" + hmac.new(
        secret.encode("utf-8"), raw, hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, header):
        return 401, "签名不匹配"
    return 0, None


@router.post("/webhook/{platform}")
async def receive_webhook(platform: str, request: Request) -> JSONResponse:
    if platform not in PLATFORMS:
        return _json(platform, 404, errcode=404, errmsg=f"未知平台：{platform}")
    if platform == PLATFORM_GITHUB:
        return _json(
            platform,
            404,
            errcode=404,
            errmsg="GitHub 通道请使用 /webhook/github/{token}",
        )
    return await _receive(request, platform)


@router.post("/webhook/github/{token}")
async def receive_github_webhook(token: str, request: Request) -> JSONResponse:
    return await _receive(request, PLATFORM_GITHUB, path_token=token)


async def _receive(
    request: Request, platform: str, *, path_token: str | None = None
) -> JSONResponse:
    settings = request.app.state.settings
    limit = (
        settings.github_max_body_bytes
        if platform == PLATFORM_GITHUB
        else settings.max_body_bytes
    )
    raw = await _read_body(request, limit)
    if raw is None:
        return _json(platform, 413, errcode=413, errmsg="请求体过大")

    token = (path_token or "").strip()
    if not token:
        scheme, _, credentials = request.headers.get("Authorization", "").partition(" ")
        bearer = credentials.strip() if scheme.lower() == "bearer" else ""
        token = request.headers.get("X-Webhook-Token") or bearer or ""
        if not token and settings.webhook_allow_query_token:
            # 查询参数会落进访问日志，默认不开放
            token = request.query_params.get("token") or ""
    if not token:
        return _json(platform, 401, errcode=401, errmsg="缺少 webhook token")

    async with get_session_factory()() as db:
        channel = (
            await db.execute(
                select(Channel).where(
                    Channel.webhook_token == token,
                    Channel.platform == platform,
                    Channel.enabled.is_(True),
                )
            )
        ).scalar_one_or_none()
        if channel is None:
            return _json(platform, 401, errcode=401, errmsg="token 无效或通道已停用")

        if platform == PLATFORM_GITHUB:
            status_code, error = _verify_github_signature(channel, request, raw, settings)
            if error:
                return _json(platform, status_code, errcode=status_code, errmsg=error)

        try:
            payload = json.loads(raw.decode("utf-8") or "{}")
        except (UnicodeDecodeError, ValueError):
            return _json(platform, 400, errcode=400, errmsg="请求体不是合法 JSON")

        bot = (
            await db.execute(
                select(BotProfile).where(
                    BotProfile.id == channel.bot_profile_id,
                    BotProfile.enabled.is_(True),
                )
            )
        ).scalar_one_or_none()
        if bot is None:
            return _json(platform, 502, errcode=502, errmsg="机器人配置不可用")

        event = (
            request.headers.get("X-GitHub-Event", "")
            if platform == PLATFORM_GITHUB
            else ""
        )
        try:
            message = get_adapter(platform).parse(payload, event=event)
        except IgnoredEvent as exc:
            # 未订阅的事件按成功确认，避免 GitHub 判定投递失败并重试
            return _json(platform, 200, errmsg=str(exc))
        except PayloadError as exc:
            return _json(platform, 400, errcode=400, errmsg=str(exc))

        targets = _resolve_targets(payload, bot)
        if not targets:
            return _json(platform, 400, errcode=400, errmsg="未指定推送目标且机器人未配置默认目标")

        try:
            app_secret = decrypt_secret(bot.qq_app_secret, settings.app_secret_key)
        except Exception:  # noqa: BLE001 - 密钥不匹配时统一报配置错误
            return _json(platform, 502, errcode=502, errmsg="机器人密钥无法解密，请检查 APP_SECRET_KEY")

        qq_payload = render_qq(
            message,
            markdown_max_len=settings.markdown_max_len,
            text_max_len=settings.text_max_len,
        )

        client: QqClient = request.app.state.qq_client
        # 频控按机器人 AppID 计算，每个机器人各用一份窗口
        limiter = request.app.state.limiters.get(f"bot:{bot.id}")
        request_id = uuid.uuid4().hex
        results = await _push_all(
            db,
            settings=settings,
            client=client,
            limiter=limiter,
            bot=bot,
            channel=channel,
            app_secret=app_secret,
            qq_payload=qq_payload,
            message=message,
            targets=targets,
            request_id=request_id,
        )

    failures = [r for r in results if r]
    if not failures:
        return _json(platform, 200)
    if len(failures) == len(results):
        return _json(platform, 502, errcode=502, errmsg=failures[0])
    return _json(platform, 502, errcode=502, errmsg=f"部分目标推送失败：{failures[0]}")


def _resolve_targets(payload: dict, bot: BotProfile) -> list[QqTarget]:
    """请求体优先，缺省用该用户机器人的默认目标。"""
    if isinstance(payload, dict):
        group_openid = (payload.get("group_openid") or "").strip()
        if group_openid:
            return [QqTarget(group_openid=group_openid)]
        openid = (payload.get("openid") or "").strip()
        if openid:
            return [QqTarget(openid=openid)]
    group_default = (bot.default_group_openid or "").strip()
    if group_default:
        return [QqTarget(group_openid=group_default)]
    return [QqTarget(openid=oid) for oid in (bot.default_openids or []) if oid]


async def _push_all(
    db: AsyncSession,
    *,
    settings,
    client: QqClient,
    limiter,
    bot: BotProfile,
    channel: Channel,
    app_secret: str,
    qq_payload: QqPayload,
    message: UnifiedMessage,
    targets: list[QqTarget],
    request_id: str,
) -> list[str | None]:
    """逐个目标串行发送并落推送日志；返回每个目标的错误信息（None 表示成功）。"""
    errors: list[str | None] = []
    for target in targets:
        started = time.perf_counter()
        error: str | None = None
        error_code: str | None = None
        try:
            await limiter.acquire()
            await client.send(
                key=f"bot:{bot.id}",
                host=bot.qq_host or settings.qq_host,
                app_id=bot.qq_appid,
                app_secret=app_secret,
                target=target,
                payload=qq_payload,
            )
        except QqError as exc:
            error, error_code = exc.message, exc.code
            logger.warning("QQ 推送失败 [%s] %s: %s", target.label(), exc.code, exc.message)
        except Exception as exc:  # noqa: BLE001 - 记录后按失败处理，避免中断其他目标
            error, error_code = str(exc), "unexpected"
            logger.exception("QQ 推送异常 [%s]", target.label())

        duration_ms = (time.perf_counter() - started) * 1000
        db.add(
            PushLog(
                owner_user_id=bot.owner_user_id,
                channel_id=channel.id,
                bot_profile_id=bot.id,
                platform=channel.platform,
                source_msgtype=message.source_msgtype or "unknown",
                target=target.to_db_value(),
                qq_msg_type=qq_payload.msg_type,
                content_preview=qq_payload.text[:200],
                content_len=len(qq_payload.text),
                status="success" if error is None else "failed",
                error_code=error_code,
                error_message=error,
                duration_ms=round(duration_ms, 2),
                request_id=request_id,
            )
        )
        errors.append(error)

    await db.commit()
    return errors
