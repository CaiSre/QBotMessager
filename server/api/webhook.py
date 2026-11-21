"""Webhook 数据面：钉钉 / 企业微信 / 飞书 / GitHub → QQ 机器人。"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import uuid

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select

from server.adapters import get_adapter
from server.adapters.base import IgnoredEvent, PayloadError
from server.db.crypto import decrypt_secret
from server.db.models import PLATFORM_GITHUB, PLATFORMS, BotProfile, Channel
from server.db.session import get_session_factory
from server.renderer import render_qq
from server.services.push import PushJob, execute_push
from server.services.qq import QqTarget
from server.services.queue import PushQueue, QueueFull

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
            decrypt_secret(bot.qq_app_secret, settings.app_secret_key)
        except Exception:  # noqa: BLE001 - 密钥不匹配时统一报配置错误
            return _json(platform, 502, errcode=502, errmsg="机器人密钥无法解密，请检查 APP_SECRET_KEY")

        # 推送所需字段在会话关闭前取出，避免出站 HTTP 期间一直占用数据库连接
        channel_id = channel.id
        channel_platform = channel.platform
        bot_id = bot.id
        owner_user_id = bot.owner_user_id
        bot_host = bot.qq_host
        bot_appid = bot.qq_appid
        bot_secret_cipher = bot.qq_app_secret
        request_id = uuid.uuid4().hex

    qq_payload = render_qq(
        message,
        markdown_max_len=settings.markdown_max_len,
        text_max_len=settings.text_max_len,
    )
    job = PushJob(
        request_id=request_id,
        platform=channel_platform,
        channel_id=channel_id,
        bot_id=bot_id,
        owner_user_id=owner_user_id,
        bot_host=bot_host,
        bot_appid=bot_appid,
        # 只传密文，worker 用环境变量里的主密钥解密，避免明文落到 Redis
        app_secret_cipher=bot_secret_cipher,
        source_msgtype=message.source_msgtype or "unknown",
        msg_type=qq_payload.msg_type,
        content=qq_payload.content,
        markdown=qq_payload.markdown,
        targets=tuple(targets),
    )

    queue: PushQueue | None = getattr(request.app.state, "push_queue", None)
    if queue is not None:
        try:
            queued = await queue.enqueue(job, job_id=_job_id(platform, request, payload, request_id))
        except QueueFull:
            logger.warning("推送队列积压，拒绝入队（request_id=%s）", request_id)
            # 其他平台会对失败的投递重试；GitHub 不会，改走下面的同步发送，避免事件丢失
            if platform != PLATFORM_GITHUB:
                return _json(platform, 503, errcode=503, errmsg="推送队列繁忙，请稍后重试")
        except Exception:  # noqa: BLE001 - Redis 异常时降级为同步发送，避免丢消息
            logger.exception("推送队列不可用，改为同步发送（request_id=%s）", request_id)
        else:
            if not queued:
                # 平台重试投递同一条消息时直接确认，避免重复推送
                return _json(platform, 200, errmsg="重复投递，已忽略")
            return _json(platform, 200)

    # 未配置 Redis：同步发送，行为与引入队列前一致
    outcome = await execute_push(
        job,
        settings=settings,
        client=request.app.state.qq_client,
        limiter=request.app.state.limiters.get(f"bot:{bot_id}"),
    )
    failures = outcome.failed
    if not failures:
        return _json(platform, 200)
    if len(failures) == len(outcome.errors):
        return _json(platform, 502, errcode=502, errmsg=failures[0])
    return _json(platform, 502, errcode=502, errmsg=f"部分目标推送失败：{failures[0]}")


MAX_FANOUT = 50
MAX_TARGET_LEN = 128


def _resolve_targets(payload: dict, bot: BotProfile) -> list[QqTarget]:
    """请求体优先，缺省用该用户机器人的默认目标。"""
    if isinstance(payload, dict):
        group_openid = (payload.get("group_openid") or "").strip()
        if group_openid:
            return [QqTarget(group_openid=group_openid)] if len(group_openid) <= MAX_TARGET_LEN else []
        openid = (payload.get("openid") or "").strip()
        if openid:
            return [QqTarget(openid=openid)] if len(openid) <= MAX_TARGET_LEN else []
    group_default = (bot.default_group_openid or "").strip()
    if group_default:
        return [QqTarget(group_openid=group_default)]
    return [
        QqTarget(openid=oid)
        for oid in (bot.default_openids or [])[:MAX_FANOUT]
        if oid
    ]


def _job_id(platform: str, request: Request, payload: object, request_id: str) -> str:
    """任务去重键：平台会重投同一条消息，重复入队只会推送一次。

    平台提供的投递 ID 先做哈希，避免超长或含特殊字符的 ID 直接成为 Redis 键。
    """
    delivery = _delivery_id(platform, request, payload)
    if not delivery:
        return f"push:{request_id}"
    digest = hashlib.sha256(f"{platform}:{delivery}".encode("utf-8")).hexdigest()
    return f"push:{digest}"


def _delivery_id(platform: str, request: Request, payload: object) -> str | None:
    if platform == PLATFORM_GITHUB:
        return request.headers.get("X-GitHub-Delivery") or None
    if not isinstance(payload, dict):
        return None
    if platform == "feishu":
        header = payload.get("header")
        if isinstance(header, dict):
            return header.get("event_id") or None
        return None
    for key in ("msgid", "msg_id"):
        value = payload.get(key)
        if isinstance(value, str) and value:
            return value
    return None
