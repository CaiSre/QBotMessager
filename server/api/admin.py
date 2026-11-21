"""中台管理接口（需登录；普通用户仅限自己的资源，超级管理员可见全部）。"""

from __future__ import annotations

import secrets
from datetime import date, datetime, timedelta, timezone
from typing import Any

from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import Select, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from server.auth.deps import current_user, is_super_admin, require_super_admin
from server.auth.oauth import GITHUB_PRESET
from server.auth.passwords import hash_password
from server.config import Settings, get_settings as load_settings
from server.db.crypto import decrypt_secret, encrypt_secret, mask_secret
from server.db.models import (
    PLATFORM_GITHUB,
    PLATFORMS,
    ROLE_SUPER_ADMIN,
    ROLE_USER,
    ROLES,
    STATUS_ACTIVE,
    STATUS_DISABLED,
    BotProfile,
    Channel,
    InviteCode,
    OAuthProvider,
    PushLog,
    User,
)
from server.db.session import get_session
from server.services.audit import record_audit
from server.services.runtime_settings import SPECS, RuntimeSettings
from server.services.users import name_taken

router = APIRouter(prefix="/api/admin")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _local_midnight_utc(day: date, tz) -> datetime:
    """本地时区某一天零点的 UTC 时刻。"""
    return datetime(day.year, day.month, day.day, tzinfo=tz).astimezone(timezone.utc)


def generate_token() -> str:
    return secrets.token_urlsafe(24)


# ------------------------------------------------------------------- 机器人配置


@router.get("/bot-profiles")
async def list_bots(
    user: User = Depends(current_user), db: AsyncSession = Depends(get_session)
) -> list[dict]:
    stmt = select(BotProfile, User.email).join(User, BotProfile.owner_user_id == User.id)
    if not is_super_admin(user):
        stmt = stmt.where(BotProfile.owner_user_id == user.id)
    rows = (await db.execute(stmt.order_by(BotProfile.id))).all()
    return [
        {
            "id": row.id,
            "owner_user_id": row.owner_user_id,
            "owner_email": owner_email,
            "name": row.name,
            "qq_appid": row.qq_appid,
            "qq_app_secret_masked": mask_secret(row.qq_app_secret),
            "has_secret": bool(row.qq_app_secret),
            "qq_host": row.qq_host,
            "default_openids": row.default_openids or [],
            "default_group_openid": row.default_group_openid,
            "enabled": row.enabled,
        }
        for row, owner_email in rows
    ]


MAX_DEFAULT_TARGETS = 50
MAX_TARGET_LEN = 128


def _validate_qq_host(value: str | None) -> str | None:
    """只允许 https 且主机在白名单内，避免把请求打到内网或任意地址。"""
    if value is None:
        return None
    value = value.strip().rstrip("/")
    if not value:
        return "https://api.bot.qq.com"
    parts = urlsplit(value)
    if parts.scheme != "https" or not parts.hostname:
        raise ValueError("QQ 接口地址必须是以 https:// 开头的完整地址")
    if parts.username or parts.password:
        raise ValueError("QQ 接口地址不能包含用户信息")
    if parts.query or parts.fragment:
        raise ValueError("QQ 接口地址不能包含查询参数或锚点")
    allowed = {
        item.strip().lower()
        for item in load_settings().qq_allowed_hosts.split(",")
        if item.strip()
    }
    if parts.hostname.lower() not in allowed:
        raise ValueError("QQ 接口地址不在允许的主机列表中")
    return value


def _validate_openids(value: list[str] | None) -> list[str] | None:
    if value is None:
        return None
    if len(value) > MAX_DEFAULT_TARGETS:
        raise ValueError(f"默认目标最多 {MAX_DEFAULT_TARGETS} 个")
    out: list[str] = []
    for item in value:
        item = item.strip()
        if not item:
            continue
        if len(item) > MAX_TARGET_LEN:
            raise ValueError(f"单个 openid 最长 {MAX_TARGET_LEN} 个字符")
        out.append(item)
    return out


class BotIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    qq_appid: str = Field(min_length=1, max_length=128)
    qq_app_secret: str = Field(min_length=1, max_length=512)
    qq_host: str = "https://api.bot.qq.com"
    default_openids: list[str] = Field(default_factory=list)
    default_group_openid: str | None = Field(default=None, max_length=MAX_TARGET_LEN)
    enabled: bool = True

    _qq_host = field_validator("qq_host")(_validate_qq_host)
    _openids = field_validator("default_openids")(_validate_openids)


class BotPatch(BaseModel):
    name: str | None = Field(default=None, max_length=128)
    qq_appid: str | None = Field(default=None, max_length=128)
    qq_app_secret: str | None = Field(default=None, max_length=512)
    qq_host: str | None = None
    default_openids: list[str] | None = None
    default_group_openid: str | None = Field(default=None, max_length=MAX_TARGET_LEN)
    enabled: bool | None = None

    _qq_host = field_validator("qq_host")(_validate_qq_host)
    _openids = field_validator("default_openids")(_validate_openids)


@router.post("/bot-profiles", status_code=status.HTTP_201_CREATED)
async def create_bot(
    data: BotIn,
    request: Request,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_session),
) -> dict:
    settings: Settings = request.app.state.settings
    bot = BotProfile(
        owner_user_id=user.id,
        name=data.name,
        qq_appid=data.qq_appid,
        qq_app_secret=encrypt_secret(data.qq_app_secret, settings.app_secret_key),
        qq_host=data.qq_host,
        default_openids=data.default_openids,
        default_group_openid=data.default_group_openid or None,
        enabled=data.enabled,
    )
    db.add(bot)
    await db.flush()
    await record_audit(
        db,
        actor=user,
        action="bot.create",
        target_type="bot_profile",
        target_id=bot.id,
        detail={"name": bot.name, "appid": bot.qq_appid},
        ip=_client_ip(request),
    )
    await db.commit()
    return {"id": bot.id}


async def _get_owned_bot(db: AsyncSession, user: User, bot_id: int) -> BotProfile:
    bot = await db.get(BotProfile, bot_id)
    if bot is None or (bot.owner_user_id != user.id and not is_super_admin(user)):
        raise HTTPException(status_code=404, detail="机器人配置不存在")
    return bot


@router.patch("/bot-profiles/{bot_id}")
async def patch_bot(
    bot_id: int,
    data: BotPatch,
    request: Request,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_session),
) -> dict:
    settings: Settings = request.app.state.settings
    bot = await _get_owned_bot(db, user, bot_id)
    payload = data.model_dump(exclude_unset=True)
    if "qq_app_secret" in payload and payload["qq_app_secret"]:
        payload["qq_app_secret"] = encrypt_secret(payload["qq_app_secret"], settings.app_secret_key)
    for key, value in payload.items():
        if key == "default_group_openid":
            value = value or None
        setattr(bot, key, value)
    await record_audit(
        db,
        actor=user,
        action="bot.update",
        target_type="bot_profile",
        target_id=bot.id,
        detail={"fields": sorted(k for k in payload if k != "qq_app_secret")},
        ip=_client_ip(request),
    )
    await db.commit()
    return {"id": bot.id}


@router.delete("/bot-profiles/{bot_id}")
async def delete_bot(
    bot_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_session),
) -> dict:
    bot = await _get_owned_bot(db, user, bot_id)
    channels = (
        (await db.execute(select(Channel).where(Channel.bot_profile_id == bot.id)))
        .scalars()
        .all()
    )
    for channel in channels:
        await db.delete(channel)
    await db.delete(bot)
    await record_audit(
        db,
        actor=user,
        action="bot.delete",
        target_type="bot_profile",
        target_id=bot_id,
        ip=_client_ip(request),
    )
    await db.commit()
    return {"ok": True}


# ------------------------------------------------------------------------- 通道


def _webhook_path(platform: str) -> str:
    return f"/webhook/{platform}"


def _webhook_base(request: Request, settings: Settings) -> str:
    if settings.public_base_url:
        return settings.public_base_url.rstrip("/")
    return str(request.base_url).rstrip("/")


async def _get_owned_channel(db: AsyncSession, user: User, channel_id: int) -> Channel:
    channel = await db.get(Channel, channel_id)
    bot = await db.get(BotProfile, channel.bot_profile_id) if channel is not None else None
    if channel is None or bot is None or (
        bot.owner_user_id != user.id and not is_super_admin(user)
    ):
        raise HTTPException(status_code=404, detail="通道不存在")
    return channel


@router.get("/channels")
async def list_channels(
    request: Request,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_session),
) -> list[dict]:
    settings: Settings = request.app.state.settings
    base = _webhook_base(request, settings)
    stmt = (
        select(Channel, User.id, User.email)
        .join(BotProfile, Channel.bot_profile_id == BotProfile.id)
        .join(User, BotProfile.owner_user_id == User.id)
    )
    if not is_super_admin(user):
        stmt = stmt.where(BotProfile.owner_user_id == user.id)
    rows = (await db.execute(stmt.order_by(Channel.id))).all()
    return [
        {
            "id": row.id,
            "owner_user_id": owner_user_id,
            "owner_email": owner_email,
            "platform": row.platform,
            "bot_profile_id": row.bot_profile_id,
            "webhook_token": row.webhook_token,
            "webhook_url": (
                f"{base}/webhook/github/{row.webhook_token}"
                if row.platform == PLATFORM_GITHUB
                else f"{base}{_webhook_path(row.platform)}"
            ),
            "has_secret": bool((row.extra or {}).get("secret_cipher")),
            "enabled": row.enabled,
        }
        for row, owner_user_id, owner_email in rows
    ]


class ChannelIn(BaseModel):
    platform: str
    bot_profile_id: int
    enabled: bool = True
    # GitHub 通道的签名密钥；留空时由服务端生成，仅在创建响应中返回一次
    secret: str | None = None


@router.post("/channels", status_code=status.HTTP_201_CREATED)
async def create_channel(
    data: ChannelIn,
    request: Request,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_session),
) -> dict:
    if data.platform not in PLATFORMS:
        raise HTTPException(status_code=400, detail="平台不受支持")
    await _get_owned_bot(db, user, data.bot_profile_id)

    settings: Settings = request.app.state.settings
    extra: dict | None = None
    secret_plain: str | None = None
    if data.platform == PLATFORM_GITHUB:
        secret_plain = (data.secret or "").strip() or secrets.token_urlsafe(32)
        extra = {"secret_cipher": encrypt_secret(secret_plain, settings.app_secret_key)}

    channel = Channel(
        bot_profile_id=data.bot_profile_id,
        platform=data.platform,
        webhook_token=generate_token(),
        enabled=data.enabled,
        extra=extra,
    )
    db.add(channel)
    await db.flush()
    await record_audit(
        db,
        actor=user,
        action="channel.create",
        target_type="channel",
        target_id=channel.id,
        detail={"platform": channel.platform},
        ip=_client_ip(request),
    )
    await db.commit()

    result: dict[str, Any] = {"id": channel.id, "webhook_token": channel.webhook_token}
    if secret_plain is not None:
        base = _webhook_base(request, settings)
        result["webhook_url"] = f"{base}/webhook/github/{channel.webhook_token}"
        result["secret"] = secret_plain
    return result


class ChannelPatch(BaseModel):
    enabled: bool | None = None
    bot_profile_id: int | None = None


@router.patch("/channels/{channel_id}")
async def patch_channel(
    channel_id: int,
    data: ChannelPatch,
    request: Request,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_session),
) -> dict:
    channel = await _get_owned_channel(db, user, channel_id)
    if data.bot_profile_id is not None:
        await _get_owned_bot(db, user, data.bot_profile_id)
        channel.bot_profile_id = data.bot_profile_id
    if data.enabled is not None:
        channel.enabled = data.enabled
    await record_audit(
        db,
        actor=user,
        action="channel.update",
        target_type="channel",
        target_id=channel.id,
        ip=_client_ip(request),
    )
    await db.commit()
    return {"id": channel.id, "enabled": channel.enabled}


@router.post("/channels/{channel_id}/rotate")
async def rotate_channel_token(
    channel_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_session),
) -> dict:
    channel = await _get_owned_channel(db, user, channel_id)
    settings: Settings = request.app.state.settings
    channel.webhook_token = generate_token()
    result: dict[str, Any] = {"id": channel.id, "webhook_token": channel.webhook_token}
    if channel.platform == PLATFORM_GITHUB:
        # GitHub 不支持自定义请求头，URL token 与签名密钥需同时轮换
        secret_plain = secrets.token_urlsafe(32)
        extra = dict(channel.extra or {})
        extra["secret_cipher"] = encrypt_secret(secret_plain, settings.app_secret_key)
        channel.extra = extra
        result["webhook_url"] = (
            f"{_webhook_base(request, settings)}/webhook/github/{channel.webhook_token}"
        )
        result["secret"] = secret_plain
    await record_audit(
        db,
        actor=user,
        action="channel.rotate_token",
        target_type="channel",
        target_id=channel.id,
        ip=_client_ip(request),
    )
    await db.commit()
    return result


@router.delete("/channels/{channel_id}")
async def delete_channel(
    channel_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_session),
) -> dict:
    channel = await _get_owned_channel(db, user, channel_id)
    await db.delete(channel)
    await record_audit(
        db,
        actor=user,
        action="channel.delete",
        target_type="channel",
        target_id=channel_id,
        ip=_client_ip(request),
    )
    await db.commit()
    return {"ok": True}


# ------------------------------------------------------------------------- 日志


@router.get("/logs")
async def list_logs(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=200),
    platform: str | None = None,
    status_filter: str | None = Query(None, alias="status"),
    keyword: str | None = None,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_session),
) -> dict:
    conditions = [] if is_super_admin(user) else [PushLog.owner_user_id == user.id]
    if platform:
        conditions.append(PushLog.platform == platform)
    if status_filter:
        conditions.append(PushLog.status == status_filter)
    if keyword:
        conditions.append(PushLog.content_preview.contains(keyword))

    total = (
        await db.execute(select(func.count()).select_from(PushLog).where(*conditions))
    ).scalar_one()
    rows = (
        await db.execute(
            select(PushLog, User.email)
            .join(User, PushLog.owner_user_id == User.id)
            .where(*conditions)
            .order_by(PushLog.id.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
    ).all()
    return {
        "total": int(total),
        "page": page,
        "page_size": page_size,
        "items": [
            {
                "id": row.id,
                "owner_user_id": row.owner_user_id,
                "owner_email": owner_email,
                "platform": row.platform,
                "source_msgtype": row.source_msgtype,
                "target": row.target,
                "qq_msg_type": row.qq_msg_type,
                "content_preview": row.content_preview,
                "content_len": row.content_len,
                "status": row.status,
                "error_code": row.error_code,
                "error_message": row.error_message,
                "duration_ms": row.duration_ms,
                "request_id": row.request_id,
                "created_at": row.created_at.isoformat() if row.created_at else None,
            }
            for row, owner_email in rows
        ],
    }


@router.get("/logs/{log_id}")
async def get_log(
    log_id: int,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_session),
) -> dict:
    row = await db.get(PushLog, log_id)
    if row is None or (row.owner_user_id != user.id and not is_super_admin(user)):
        raise HTTPException(status_code=404, detail="日志不存在")
    owner = await db.get(User, row.owner_user_id)
    return {
        "id": row.id,
        "owner_user_id": row.owner_user_id,
        "owner_email": owner.email if owner else None,
        "platform": row.platform,
        "source_msgtype": row.source_msgtype,
        "target": row.target,
        "qq_msg_type": row.qq_msg_type,
        "content_preview": row.content_preview,
        "content_len": row.content_len,
        "status": row.status,
        "error_code": row.error_code,
        "error_message": row.error_message,
        "duration_ms": row.duration_ms,
        "request_id": row.request_id,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


# ------------------------------------------------------------------------- 用户


@router.get("/users")
async def list_users(
    user: User = Depends(require_super_admin), db: AsyncSession = Depends(get_session)
) -> list[dict]:
    rows = (
        (await db.execute(select(User).order_by(User.id))).scalars().all()
    )
    return [
        {
            "id": row.id,
            "email": row.email,
            "name": row.name,
            "role": row.role,
            "status": row.status,
            "last_login_at": row.last_login_at.isoformat() if row.last_login_at else None,
        }
        for row in rows
    ]


class UserPatch(BaseModel):
    role: str | None = None
    status: str | None = None
    name: str | None = Field(default=None, max_length=128)


@router.patch("/users/{user_id}")
async def patch_user(
    user_id: int,
    data: UserPatch,
    request: Request,
    user: User = Depends(require_super_admin),
    db: AsyncSession = Depends(get_session),
) -> dict:
    target = await db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="用户不存在")
    if data.role is not None:
        if data.role not in ROLES:
            raise HTTPException(status_code=400, detail="角色非法")
        if target.id == user.id and data.role != target.role:
            raise HTTPException(status_code=400, detail="不能修改自己的角色")
    if data.status is not None:
        if data.status not in (STATUS_ACTIVE, STATUS_DISABLED):
            raise HTTPException(status_code=400, detail="状态非法")
        if target.id == user.id and data.status != target.status:
            raise HTTPException(status_code=400, detail="不能修改自己的账号状态")
    demoting = target.role == ROLE_SUPER_ADMIN and (
        (data.role is not None and data.role != ROLE_SUPER_ADMIN)
        or (data.status is not None and data.status != STATUS_ACTIVE)
    )
    if demoting:
        remaining = (
            await db.execute(
                select(func.count())
                .select_from(User)
                .where(
                    User.role == ROLE_SUPER_ADMIN,
                    User.status == STATUS_ACTIVE,
                    User.id != target.id,
                )
            )
        ).scalar_one()
        if remaining == 0:
            raise HTTPException(status_code=400, detail="系统至少需要一个启用的超级管理员")
    if data.role is not None:
        target.role = data.role
    if data.status is not None:
        target.status = data.status
    if data.name is not None:
        new_name = data.name.strip()
        if new_name and await name_taken(db, new_name, exclude_user_id=target.id):
            raise HTTPException(status_code=409, detail="该用户名已被使用")
        target.name = new_name
    await record_audit(
        db,
        actor=user,
        action="user.update",
        target_type="user",
        target_id=target.id,
        detail={"role": data.role, "status": data.status},
        ip=_client_ip(request),
    )
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(status_code=409, detail="该用户名已被使用") from exc
    return {"id": target.id}


class InviteIn(BaseModel):
    email: str | None = None
    max_uses: int = Field(default=1, ge=1, le=100)
    expires_in_days: int = Field(default=7, ge=1, le=365)


@router.get("/invites")
async def list_invites(
    user: User = Depends(require_super_admin), db: AsyncSession = Depends(get_session)
) -> list[dict]:
    rows = (
        (await db.execute(select(InviteCode).order_by(InviteCode.id.desc())))
        .scalars()
        .all()
    )
    return [
        {
            "id": row.id,
            "code": row.code,
            "email": row.email,
            "max_uses": row.max_uses,
            "used_count": row.used_count,
            "expires_at": row.expires_at.isoformat() if row.expires_at else None,
            "revoked": row.revoked_at is not None,
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }
        for row in rows
    ]


@router.post("/invites", status_code=status.HTTP_201_CREATED)
async def create_invite(
    data: InviteIn,
    request: Request,
    user: User = Depends(require_super_admin),
    db: AsyncSession = Depends(get_session),
) -> dict:
    invite = InviteCode(
        code=secrets.token_urlsafe(16),
        email=data.email.lower() if data.email else None,
        max_uses=data.max_uses,
        expires_at=_now() + timedelta(days=data.expires_in_days),
        created_by=user.id,
    )
    db.add(invite)
    await record_audit(
        db,
        actor=user,
        action="invite.create",
        target_type="invite",
        target_id=invite.code,
        detail={"max_uses": data.max_uses},
        ip=_client_ip(request),
    )
    await db.commit()
    return {"id": invite.id, "code": invite.code, "expires_at": invite.expires_at.isoformat()}


@router.delete("/invites/{invite_id}")
async def revoke_invite(
    invite_id: int,
    request: Request,
    user: User = Depends(require_super_admin),
    db: AsyncSession = Depends(get_session),
) -> dict:
    invite = await db.get(InviteCode, invite_id)
    if invite is None:
        raise HTTPException(status_code=404, detail="邀请码不存在")
    invite.revoked_at = _now()
    await record_audit(
        db,
        actor=user,
        action="invite.revoke",
        target_type="invite",
        target_id=invite.id,
        ip=_client_ip(request),
    )
    await db.commit()
    return {"ok": True}


# --------------------------------------------------------------------- 安全设置


@router.get("/oauth-providers")
async def list_oauth_providers(
    user: User = Depends(require_super_admin), db: AsyncSession = Depends(get_session)
) -> list[dict]:
    rows = (
        (await db.execute(select(OAuthProvider).order_by(OAuthProvider.id)))
        .scalars()
        .all()
    )
    return [
        {
            "id": row.id,
            "key": row.key,
            "display_name": row.display_name,
            "client_id": row.client_id,
            "client_secret_masked": mask_secret(row.client_secret),
            "authorization_url": row.authorization_url,
            "token_url": row.token_url,
            "userinfo_url": row.userinfo_url,
            "scopes": row.scopes,
            "email_field": row.email_field,
            "id_field": row.id_field,
            "name_field": row.name_field,
            "enabled": row.enabled,
            "email_verified": row.email_verified,
        }
        for row in rows
    ]


class OAuthIn(BaseModel):
    key: str = Field(min_length=1, max_length=64)
    display_name: str = Field(min_length=1, max_length=128)
    client_id: str = Field(min_length=1, max_length=255)
    client_secret: str = Field(min_length=1, max_length=512)
    authorization_url: str = ""
    token_url: str = ""
    userinfo_url: str = ""
    scopes: str = ""
    email_field: str = "email"
    id_field: str = "id"
    name_field: str = "name"
    enabled: bool = True
    # 提供方是否已验证邮箱所有权；不可信时不会自动关联同邮箱的本地账号
    email_verified: bool = False
    use_github_preset: bool = False


class OAuthPatch(BaseModel):
    display_name: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    authorization_url: str | None = None
    token_url: str | None = None
    userinfo_url: str | None = None
    scopes: str | None = None
    email_field: str | None = None
    id_field: str | None = None
    name_field: str | None = None
    enabled: bool | None = None
    email_verified: bool | None = None


def _require_https(url: str) -> None:
    if not (url.startswith("https://") or url.startswith("http://localhost") or url.startswith("http://127.0.0.1")):
        raise HTTPException(status_code=400, detail="提供方 URL 必须为 https（本地开发可用 localhost）")


@router.post("/oauth-providers", status_code=status.HTTP_201_CREATED)
async def create_oauth_provider(
    data: OAuthIn,
    request: Request,
    user: User = Depends(require_super_admin),
    db: AsyncSession = Depends(get_session),
) -> dict:
    settings: Settings = request.app.state.settings
    payload = data.model_dump()
    explicit = data.model_dump(exclude_unset=True)
    if data.use_github_preset and data.key == "github":
        for key, value in GITHUB_PRESET.items():
            if key in ("key", "display_name", "email_verified"):
                continue
            if not payload.get(key):
                payload[key] = value
        # GitHub 只返回已验证邮箱，预设直接信任；用户显式关闭时保留关闭
        if "email_verified" not in explicit:
            payload["email_verified"] = True
    for field in ("authorization_url", "token_url", "userinfo_url"):
        if not payload[field]:
            raise HTTPException(status_code=400, detail=f"{field} 不能为空")
        _require_https(payload[field])
    exists = (
        await db.execute(
            select(OAuthProvider.id).where(OAuthProvider.key == data.key)
        )
    ).scalar_one_or_none()
    if exists is not None:
        raise HTTPException(status_code=409, detail="提供方已存在")
    row = OAuthProvider(
        key=data.key,
        display_name=data.display_name,
        client_id=data.client_id,
        client_secret=encrypt_secret(data.client_secret, settings.app_secret_key),
        authorization_url=payload["authorization_url"],
        token_url=payload["token_url"],
        userinfo_url=payload["userinfo_url"],
        scopes=payload["scopes"],
        email_field=payload["email_field"],
        id_field=payload["id_field"],
        name_field=payload["name_field"],
        enabled=data.enabled,
        email_verified=payload["email_verified"],
    )
    db.add(row)
    await record_audit(
        db,
        actor=user,
        action="oauth.create",
        target_type="oauth_provider",
        target_id=row.key,
        ip=_client_ip(request),
    )
    await db.commit()
    return {"id": row.id, "key": row.key}


@router.patch("/oauth-providers/{provider_id}")
async def patch_oauth_provider(
    provider_id: int,
    data: OAuthPatch,
    request: Request,
    user: User = Depends(require_super_admin),
    db: AsyncSession = Depends(get_session),
) -> dict:
    settings: Settings = request.app.state.settings
    row = await db.get(OAuthProvider, provider_id)
    if row is None:
        raise HTTPException(status_code=404, detail="提供方不存在")
    payload = data.model_dump(exclude_unset=True)
    if payload.get("client_secret"):
        payload["client_secret"] = encrypt_secret(payload["client_secret"], settings.app_secret_key)
    for field in ("authorization_url", "token_url", "userinfo_url"):
        if payload.get(field):
            _require_https(payload[field])
    for key, value in payload.items():
        setattr(row, key, value)
    await record_audit(
        db,
        actor=user,
        action="oauth.update",
        target_type="oauth_provider",
        target_id=row.key,
        detail={"fields": sorted(k for k in payload if k != "client_secret")},
        ip=_client_ip(request),
    )
    await db.commit()
    return {"id": row.id}


@router.delete("/oauth-providers/{provider_id}")
async def delete_oauth_provider(
    provider_id: int,
    request: Request,
    user: User = Depends(require_super_admin),
    db: AsyncSession = Depends(get_session),
) -> dict:
    row = await db.get(OAuthProvider, provider_id)
    if row is None:
        raise HTTPException(status_code=404, detail="提供方不存在")
    key = row.key
    await db.delete(row)
    await record_audit(
        db,
        actor=user,
        action="oauth.delete",
        target_type="oauth_provider",
        target_id=key,
        ip=_client_ip(request),
    )
    await db.commit()
    return {"ok": True}


def _settings_payload(request: Request, runtime: RuntimeSettings) -> dict:
    base: Settings = request.app.state.base_settings
    return {
        "register_enabled": bool(runtime.register_enabled),
        # 兼容安全设置页的来源提示
        "register_enabled_source": (
            "database" if runtime.source_of("register_enabled") == "database" else "env"
        ),
        "env_default": base.register_enabled,
        "groups": runtime.describe_groups(),
    }


@router.get("/settings")
async def get_settings(
    request: Request,
    user: User = Depends(require_super_admin),
) -> dict:
    return _settings_payload(request, request.app.state.settings)


@router.patch("/settings")
async def patch_settings(
    data: dict[str, Any],
    request: Request,
    user: User = Depends(require_super_admin),
    db: AsyncSession = Depends(get_session),
) -> dict:
    runtime: RuntimeSettings = request.app.state.settings
    try:
        values = runtime.validate(data)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    if not values:
        return _settings_payload(request, runtime)

    await runtime.persist(db, values)
    await record_audit(
        db,
        actor=user,
        action="settings.update",
        target_type="system_setting",
        detail={
            "values": {
                key: "******" if SPECS[key].secret else str(value)
                for key, value in values.items()
            }
        },
        ip=_client_ip(request),
    )
    await db.commit()
    runtime.apply(values)
    runtime.apply_side_effects(request.app)
    return _settings_payload(request, runtime)


# ------------------------------------------------------------------------- 统计


@router.get("/stats")
async def get_stats(
    request: Request,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_session),
) -> dict:
    settings: Settings = request.app.state.settings
    now = _now()
    # 「今天」按业务时区（默认本机时区）切分，而不是按 UTC 零点
    tz = settings.tz
    today = now.astimezone(tz).date()
    start = _local_midnight_utc(today, tz)
    end = _local_midnight_utc(today + timedelta(days=1), tz)
    scope_conditions = [] if is_super_admin(user) else [PushLog.owner_user_id == user.id]
    total_today = (
        await db.execute(
            select(func.count())
            .select_from(PushLog)
            .where(
                *scope_conditions,
                PushLog.created_at >= start,
                PushLog.created_at < end,
            )
        )
    ).scalar_one()
    success_today = (
        await db.execute(
            select(func.count())
            .select_from(PushLog)
            .where(
                *scope_conditions,
                PushLog.created_at >= start,
                PushLog.created_at < end,
                PushLog.status == "success",
            )
        )
    ).scalar_one()
    recent_failures = (
        (
            await db.execute(
                select(PushLog)
                .where(*scope_conditions, PushLog.status == "failed")
                .order_by(PushLog.id.desc())
                .limit(5)
            )
        )
        .scalars()
        .all()
    )
    by_platform = (
        await db.execute(
            select(PushLog.platform, func.count())
            .where(
                *scope_conditions,
                PushLog.created_at >= start,
                PushLog.created_at < end,
            )
            .group_by(PushLog.platform)
        )
    ).all()

    days: list[dict] = []
    for offset in range(6, -1, -1):
        day = today - timedelta(days=offset)
        day_start = _local_midnight_utc(day, tz)
        day_end = _local_midnight_utc(day + timedelta(days=1), tz)
        count = (
            await db.execute(
                select(func.count())
                .select_from(PushLog)
                .where(
                    *scope_conditions,
                    PushLog.created_at >= day_start,
                    PushLog.created_at < day_end,
                )
            )
        ).scalar_one()
        days.append({"date": day.isoformat(), "count": int(count)})

    return {
        "scope": "all" if is_super_admin(user) else "mine",
        "today": {"total": int(total_today), "success": int(success_today)},
        "success_rate": round(success_today / total_today, 4) if total_today else 0.0,
        "by_platform": [{"platform": p, "count": int(c)} for p, c in by_platform],
        "trend": days,
        "recent_failures": [
            {
                "id": row.id,
                "platform": row.platform,
                "target": row.target,
                "error_code": row.error_code,
                "error_message": row.error_message,
                "created_at": row.created_at.isoformat() if row.created_at else None,
            }
            for row in recent_failures
        ],
    }
