"""认证接口：邮箱密码、邀请码注册、OAuth2、通行密钥 Passkey。"""

from __future__ import annotations

import logging
import re
import secrets
from datetime import datetime, timezone
from typing import Literal
from urllib.parse import urlsplit

import httpx2 as httpx
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from server.auth import oauth as oauth_flow
from server.auth import passkey as passkey_flow
from server.auth.deps import current_user, get_session_token
from server.auth.passwords import (
    burn_password_async,
    hash_password_async,
    verify_password_async,
)
from server.auth.sessions import (
    create_session,
    revoke_other_sessions,
    revoke_session,
    revoke_user_sessions,
)
from server.config import Settings
from server.db.crypto import decrypt_secret
from server.db.models import (
    ROLE_USER,
    STATUS_ACTIVE,
    AuthIdentity,
    InviteCode,
    OAuthProvider,
    SystemSetting,
    User,
    WebAuthnCredential,
)
from server.db.session import get_session
from server.services.email_codes import (
    PURPOSE_LABELS,
    PURPOSE_REGISTER,
    PURPOSE_RESET_PASSWORD,
    PURPOSE_SET_PASSWORD,
    CodeQuotaExceeded,
    CodeTooFrequent,
    discard_latest,
    issue_code,
    verify_code,
)
from server.services.mail import (
    MailNotConfigured,
    MailSendError,
    is_configured as mail_configured,
    render_code_email,
    send_mail,
)
from server.services.throttle import AttemptLimiter
from server.services.users import name_taken, unique_name

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/auth")

OAUTH_STATE_COOKIE = "oauth_state"
OAUTH_PROVIDER_COOKIE = "oauth_provider"
PASSKEY_CHALLENGE_COOKIE = "webauthn_challenge"
PASSKEY_USER_COOKIE = "webauthn_user"


# --------------------------------------------------------------------------- 模型


_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class _EmailModel(BaseModel):
    email: str = Field(min_length=3, max_length=255)

    @field_validator("email")
    @classmethod
    def _validate_email(cls, value: str) -> str:
        value = value.strip().lower()
        if not _EMAIL_RE.match(value):
            raise ValueError("邮箱格式非法")
        return value


class LoginIn(BaseModel):
    # 登录标识：用户名或邮箱
    account: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=1, max_length=256)

    @field_validator("account")
    @classmethod
    def _strip_identifier(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("请填写用户名或邮箱")
        return value


class RegisterIn(_EmailModel):
    invite_code: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=8, max_length=256)
    name: str = Field(default="", max_length=128)
    email_code: str = Field(default="", max_length=12)


class EmailCodeIn(_EmailModel):
    purpose: Literal["register", "reset_password"]


class PasswordResetIn(_EmailModel):
    code: str = Field(min_length=4, max_length=12)
    new_password: str = Field(min_length=8, max_length=256)


class PasskeyFinishIn(BaseModel):
    credential: dict


class NameIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)

    @field_validator("name")
    @classmethod
    def _strip_name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("用户名不能为空")
        return value


class EmailChangeIn(_EmailModel):
    # 账号已有密码时必须校验；仅 OAuth 创建的账号没有密码可验
    current_password: str = Field(default="", max_length=256)


class PasswordChangeIn(BaseModel):
    current_password: str = Field(default="", max_length=256)
    new_password: str = Field(min_length=8, max_length=256)
    email_code: str = Field(default="", max_length=12)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _is_aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


async def registration_enabled(db: AsyncSession, settings: Settings) -> bool:
    """环境变量是基线，system_settings 可覆盖。"""
    row = await db.get(SystemSetting, "register_enabled")
    if row is not None:
        return row.value.strip().lower() in ("1", "true", "yes", "on")
    return settings.register_enabled


def _set_session_cookie(response: Response, settings: Settings, token: str) -> None:
    response.set_cookie(
        settings.cookie_name,
        token,
        max_age=settings.session_ttl_hours * 3600,
        httponly=True,
        samesite="lax",
        secure=settings.secure_cookies,
        path="/",
    )


def _origin(request: Request, settings: Settings) -> str:
    if settings.public_base_url:
        return settings.public_base_url.rstrip("/")
    return f"{request.url.scheme}://{request.url.netloc}"


def _rp_id(request: Request, settings: Settings) -> str:
    if settings.rp_id:
        return settings.rp_id
    # 反向代理（Next 把 /api/* 转发到 127.0.0.1:8000）会改写 Host，
    # rp.id 必须与浏览器地址栏的域名一致，故优先取对外访问地址。
    if settings.public_base_url:
        host = urlsplit(settings.public_base_url).hostname
        if host:
            return host
    return request.url.hostname or "localhost"


def _code_response(settings: Settings) -> dict:
    return {
        "ok": True,
        "expires_in": settings.email_code_ttl_minutes * 60,
        "resend_after": settings.email_code_resend_seconds,
    }


async def _send_code(
    settings: Settings,
    db: AsyncSession,
    *,
    email: str,
    purpose: str,
    ip: str | None,
) -> dict:
    try:
        code = await issue_code(
            db,
            email=email,
            purpose=purpose,
            ttl_minutes=settings.email_code_ttl_minutes,
            resend_seconds=settings.email_code_resend_seconds,
            hourly_limit=settings.email_code_hourly_limit,
            ip=ip,
        )
    except CodeTooFrequent as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"发送过于频繁，请 {exc.retry_after} 秒后再试",
            headers={"Retry-After": str(exc.retry_after)},
        ) from exc
    except CodeQuotaExceeded as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="发送次数过多，请稍后再试",
            headers={"Retry-After": str(exc.retry_after)},
        ) from exc

    subject, text, html = render_code_email(
        code=code,
        purpose_label=PURPOSE_LABELS[purpose],
        ttl_minutes=settings.email_code_ttl_minutes,
    )
    try:
        await send_mail(settings, to=email, subject=subject, text=text, html=html)
    except (MailNotConfigured, MailSendError) as exc:
        logger.warning("验证码邮件发送失败（%s）", purpose)
        await discard_latest(db, email=email, purpose=purpose)
        if isinstance(exc, MailNotConfigured):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="邮件服务未配置",
            ) from exc
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="验证码邮件发送失败，请稍后重试",
        ) from exc
    return _code_response(settings)


def _user_payload(user: User) -> dict:
    return {
        "id": user.id,
        "email": user.email,
        "name": user.name,
        "role": user.role,
        "status": user.status,
        "has_password": user.password_hash is not None,
    }


# --------------------------------------------------------------------- 元信息 / 会话


@router.get("/providers")
async def list_providers(
    request: Request,
    db: AsyncSession = Depends(get_session),
) -> dict:
    settings: Settings = request.app.state.settings
    providers = (
        (
            await db.execute(
                select(OAuthProvider).where(OAuthProvider.enabled.is_(True))
            )
        )
        .scalars()
        .all()
    )
    return {
        "registration_enabled": await registration_enabled(db, settings),
        "password_enabled": True,
        "passkey_enabled": True,
        "email_code_enabled": mail_configured(settings),
        "rp_id": _rp_id(request, settings),
        "oauth_providers": [
            {"key": p.key, "display_name": p.display_name} for p in providers
        ],
    }


@router.get("/me")
async def me(user: User = Depends(current_user), db: AsyncSession = Depends(get_session)) -> dict:
    payload = _user_payload(user)
    passkeys = (
        await db.execute(
            select(func.count(WebAuthnCredential.id)).where(
                WebAuthnCredential.user_id == user.id
            )
        )
    ).scalar_one()
    payload["passkey_count"] = int(passkeys)
    return payload


# ---------------------------------------------------------------------- 个人资料


@router.patch("/me/name")
async def update_name(
    data: NameIn,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_session),
) -> dict:
    if await name_taken(db, data.name, exclude_user_id=user.id):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="该用户名已被使用")
    user.name = data.name
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="该用户名已被使用"
        ) from exc
    return _user_payload(user)


@router.patch("/me/email")
async def update_email(
    data: EmailChangeIn,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_session),
) -> dict:
    # 没有邮件验证通道，改邮箱以当前密码作为身份确认
    if user.password_hash is not None and not await verify_password_async(
        data.current_password, user.password_hash
    ):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="当前密码错误")
    if data.email == user.email:
        return _user_payload(user)
    exists = (
        await db.execute(
            select(User.id).where(User.email == data.email, User.id != user.id)
        )
    ).scalar_one_or_none()
    if exists is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="该邮箱已被使用")
    user.email = data.email
    await db.commit()
    return _user_payload(user)


@router.patch("/me/password")
async def update_password(
    data: PasswordChangeIn,
    request: Request,
    token: str = Depends(get_session_token),
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_session),
) -> dict:
    settings: Settings = request.app.state.settings
    if user.password_hash is not None:
        if not await verify_password_async(data.current_password, user.password_hash):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="当前密码错误")
        if await verify_password_async(data.new_password, user.password_hash):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="新密码不能与当前密码相同"
            )
    elif mail_configured(settings):
        # 仅 OAuth 创建的账号没有密码；配置邮件后需先验证邮箱归属
        if not data.email_code:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="请填写邮箱验证码"
            )
        if not await verify_code(
            db,
            email=user.email,
            purpose=PURPOSE_SET_PASSWORD,
            code=data.email_code,
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="邮箱验证码错误或已过期"
            )
    user.password_hash = await hash_password_async(data.new_password)
    await db.commit()
    await revoke_other_sessions(db, user.id, keep_token=token)
    return {"ok": True}


@router.post("/me/password-code")
async def request_password_code(
    request: Request,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_session),
) -> dict:
    settings: Settings = request.app.state.settings
    if not mail_configured(settings):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="邮件服务未配置"
        )
    if user.password_hash is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="账号已有密码，请直接修改密码",
        )
    return await _send_code(
        settings,
        db,
        email=user.email,
        purpose=PURPOSE_SET_PASSWORD,
        ip=request.client.host if request.client else None,
    )


@router.post("/email-code")
async def request_email_code(
    data: EmailCodeIn,
    request: Request,
    db: AsyncSession = Depends(get_session),
) -> dict:
    settings: Settings = request.app.state.settings
    if not mail_configured(settings):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="邮件服务未配置"
        )
    email = data.email.lower()
    if data.purpose == PURPOSE_REGISTER:
        if not await registration_enabled(db, settings):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="注册入口已关闭"
            )
        exists = (
            await db.execute(select(User.id).where(User.email == email))
        ).scalar_one_or_none()
        # 邮箱已注册时不发信，但返回相同结果，避免枚举账号
        if exists is not None:
            return _code_response(settings)
    else:
        user = (
            await db.execute(select(User).where(User.email == email))
        ).scalar_one_or_none()
        if user is None or user.status != STATUS_ACTIVE:
            return _code_response(settings)
    return await _send_code(
        settings,
        db,
        email=email,
        purpose=data.purpose,
        ip=request.client.host if request.client else None,
    )


@router.post("/password/reset")
async def reset_password(
    data: PasswordResetIn,
    request: Request,
    db: AsyncSession = Depends(get_session),
) -> dict:
    settings: Settings = request.app.state.settings
    if not mail_configured(settings):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="邮件服务未配置"
        )
    email = data.email.lower()
    user = (
        await db.execute(select(User).where(User.email == email))
    ).scalar_one_or_none()
    if user is None or user.status != STATUS_ACTIVE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="验证码错误或已过期"
        )
    if not await verify_code(
        db, email=email, purpose=PURPOSE_RESET_PASSWORD, code=data.code
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="验证码错误或已过期"
        )
    user.password_hash = await hash_password_async(data.new_password)
    await db.commit()
    # 密码重置后所有旧会话立即失效
    await revoke_user_sessions(db, user.id)
    return {"ok": True}


@router.post("/login")
async def login(
    data: LoginIn,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_session),
) -> dict:
    settings: Settings = request.app.state.settings
    limiter: AttemptLimiter = request.app.state.login_limiter
    ip = request.client.host if request.client else None
    account = data.account.strip()
    account_key = account.lower()

    wait = await limiter.remaining_wait(ip, account_key)
    if wait > 0:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"尝试过于频繁，请 {wait} 秒后再试",
            headers={"Retry-After": str(wait)},
        )

    # 含 @ 的按邮箱查，否则按用户名查（用户名理论上可重复，取最早注册的账号）
    if "@" in account:
        query = select(User).where(User.email == account_key)
    else:
        query = select(User).where(func.lower(User.name) == account_key).order_by(User.id)
    user = (await db.execute(query)).scalars().first()
    if user is None:
        # 账号不存在时也走一次等价 PBKDF2，避免用响应时间枚举已注册账号
        await burn_password_async(data.password)
        await limiter.record_failure(ip, account_key)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="用户名或密码错误"
        )
    if not await verify_password_async(data.password, user.password_hash):
        await limiter.record_failure(ip, account_key)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="用户名或密码错误"
        )
    if user.status != STATUS_ACTIVE:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="账号已停用")

    await limiter.reset(ip, account_key)
    token = await create_session(
        db,
        user,
        ttl_hours=settings.session_ttl_hours,
        ip=ip,
        user_agent=request.headers.get("user-agent"),
    )
    _set_session_cookie(response, settings, token)
    return _user_payload(user)


@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_session),
) -> dict:
    settings: Settings = request.app.state.settings
    await revoke_session(db, request.cookies.get(settings.cookie_name, ""))
    response.delete_cookie(settings.cookie_name, path="/")
    return {"ok": True}


@router.post("/register")
async def register(
    data: RegisterIn,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_session),
) -> dict:
    settings: Settings = request.app.state.settings
    if not await registration_enabled(db, settings):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="注册入口已关闭")

    invite = (
        await db.execute(select(InviteCode).where(InviteCode.code == data.invite_code))
    ).scalar_one_or_none()
    if invite is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="邀请码无效")
    expires_at = _is_aware(invite.expires_at)
    if invite.revoked_at is not None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="邀请码已作废")
    if expires_at is not None and expires_at <= _now():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="邀请码已过期")
    email = data.email.lower()
    if invite.email and invite.email.lower() != email:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="邀请码不适用于该邮箱")

    exists = (
        await db.execute(select(User.id).where(User.email == email))
    ).scalar_one_or_none()
    if exists is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="该邮箱已注册")

    name = data.name.strip()
    if name and await name_taken(db, name):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="该用户名已被使用")

    if mail_configured(settings):
        if not data.email_code:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="请填写邮箱验证码"
            )
        if not await verify_code(
            db, email=email, purpose=PURPOSE_REGISTER, code=data.email_code
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="邮箱验证码错误或已过期"
            )

    # 原子占用名额：条件 UPDATE 保证并发注册也不会突破 max_uses
    consumed = await db.execute(
        update(InviteCode)
        .where(
            InviteCode.id == invite.id,
            InviteCode.revoked_at.is_(None),
            InviteCode.used_count < InviteCode.max_uses,
            or_(
                InviteCode.expires_at.is_(None),
                InviteCode.expires_at > _now(),
            ),
        )
        .values(used_count=InviteCode.used_count + 1)
        # 不让 ORM 在 Python 侧重算条件（库里读回的 naive 时间与会话时间无法直接比较）
        .execution_options(synchronize_session=False)
    )
    if consumed.rowcount != 1:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="邀请码已用尽")
    await db.refresh(invite)

    user = User(
        email=email,
        name=name or await unique_name(db, email.split("@")[0]),
        password_hash=await hash_password_async(data.password),
        role=ROLE_USER,
        status=STATUS_ACTIVE,
    )
    db.add(user)
    try:
        await db.flush()
    except IntegrityError as exc:
        # 并发注册时应用层查重可能同时通过，由数据库唯一索引兜底
        await db.rollback()
        detail = (
            "该用户名已被使用"
            if "name" in str(exc.orig).lower()
            else "该邮箱已注册"
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=detail
        ) from exc

    token = await create_session(
        db,
        user,
        ttl_hours=settings.session_ttl_hours,
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    _set_session_cookie(response, settings, token)
    return _user_payload(user)


# ----------------------------------------------------------------------- OAuth2


@router.get("/oauth/{provider_key}/start")
async def oauth_start(
    provider_key: str,
    request: Request,
    db: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    settings: Settings = request.app.state.settings
    provider = (
        await db.execute(
            select(OAuthProvider).where(
                OAuthProvider.key == provider_key, OAuthProvider.enabled.is_(True)
            )
        )
    ).scalar_one_or_none()
    if provider is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="提供方不存在或未启用")

    try:
        # 只做一次可解密性校验：解密结果不写回 ORM 实体，否则随后的提交会把明文写进库
        decrypt_secret(provider.client_secret, settings.app_secret_key)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail="提供方密钥无法解密") from exc

    state = oauth_flow.new_state()
    redirect_uri = f"{_origin(request, settings)}/api/auth/oauth/{provider.key}/callback"
    url = oauth_flow.build_authorize_url(provider, redirect_uri=redirect_uri, state=state)
    response = RedirectResponse(url, status_code=status.HTTP_302_FOUND)
    response.set_cookie(
        OAUTH_STATE_COOKIE,
        state,
        max_age=600,
        httponly=True,
        samesite="lax",
        secure=settings.secure_cookies,
        path="/",
    )
    response.set_cookie(
        OAUTH_PROVIDER_COOKIE,
        provider.key,
        max_age=600,
        httponly=True,
        samesite="lax",
        secure=settings.secure_cookies,
        path="/",
    )
    return response


@router.get("/oauth/{provider_key}/callback")
async def oauth_callback(
    provider_key: str,
    request: Request,
    code: str = "",
    state: str = "",
    db: AsyncSession = Depends(get_session),
):
    settings: Settings = request.app.state.settings
    expected_state = request.cookies.get(OAUTH_STATE_COOKIE, "")
    expected_provider = request.cookies.get(OAUTH_PROVIDER_COOKIE, "")
    if (
        not state
        or not expected_state
        or not secrets.compare_digest(state, expected_state)
        or expected_provider != provider_key
    ):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="OAuth state 校验失败")
    if not code:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="缺少授权码")

    provider = (
        await db.execute(
            select(OAuthProvider).where(
                OAuthProvider.key == provider_key, OAuthProvider.enabled.is_(True)
            )
        )
    ).scalar_one_or_none()
    if provider is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="提供方不存在或未启用")
    try:
        # 解密结果放在局部变量里：写回 provider 会让随后的提交把明文密钥写进库
        client_secret = decrypt_secret(provider.client_secret, settings.app_secret_key)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail="提供方密钥无法解密") from exc

    redirect_uri = f"{_origin(request, settings)}/api/auth/oauth/{provider.key}/callback"
    client: httpx.AsyncClient = request.app.state.httpx
    try:
        token_data = await oauth_flow.exchange_code(
            client,
            provider,
            code=code,
            redirect_uri=redirect_uri,
            client_secret=client_secret,
        )
        profile = await oauth_flow.fetch_profile(
            client, provider, access_token=token_data["access_token"]
        )
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("OAuth 回调失败：%s", exc)
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=f"OAuth 登录失败：{exc}") from exc

    identity = (
        await db.execute(
            select(AuthIdentity).where(
                AuthIdentity.provider == provider.key,
                AuthIdentity.provider_user_id == profile.provider_user_id,
            )
        )
    ).scalar_one_or_none()
    if identity is not None:
        user = await db.get(User, identity.user_id)
    else:
        user = None
        if profile.email:
            user = (
                await db.execute(select(User).where(User.email == profile.email.lower()))
            ).scalar_one_or_none()
        if user is not None:
            # 已有本地账号：只有提供方邮箱可信时才自动关联，否则会被冒名登录接管账号
            if not (provider.email_verified or profile.email_verified):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="该邮箱已存在本地账号，但提供方未验证邮箱，无法自动关联；请改用密码登录",
                )
        else:
            if not await registration_enabled(db, settings):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="未找到关联账号，且注册入口已关闭，请联系管理员邀请",
                )
            if not profile.email:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="提供方未返回邮箱，无法创建账号",
                )
            user = User(
                email=profile.email.lower(),
                name=await unique_name(
                    db,
                    profile.name
                    or profile.login
                    or profile.email.split("@")[0],
                ),
                password_hash=None,
                role=ROLE_USER,
                status=STATUS_ACTIVE,
            )
            db.add(user)
            await db.flush()
        db.add(
            AuthIdentity(
                user_id=user.id,
                provider=provider.key,
                provider_user_id=profile.provider_user_id,
                provider_login=profile.login,
            )
        )

    if user is None or user.status != STATUS_ACTIVE:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="账号不可用")

    token = await create_session(
        db,
        user,
        ttl_hours=settings.session_ttl_hours,
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    response = RedirectResponse("/", status_code=status.HTTP_302_FOUND)
    _set_session_cookie(response, settings, token)
    response.delete_cookie(OAUTH_STATE_COOKIE, path="/")
    response.delete_cookie(OAUTH_PROVIDER_COOKIE, path="/")
    return response


# ---------------------------------------------------------------------- Passkey


@router.get("/passkey")
async def list_passkeys(
    user: User = Depends(current_user), db: AsyncSession = Depends(get_session)
) -> list[dict]:
    rows = (
        (
            await db.execute(
                select(WebAuthnCredential)
                .where(WebAuthnCredential.user_id == user.id)
                .order_by(WebAuthnCredential.id)
            )
        )
        .scalars()
        .all()
    )
    return [
        {
            "id": row.id,
            "label": row.label,
            "device_type": row.device_type,
            "backed_up": row.backed_up,
            "created_at": row.created_at.isoformat() if row.created_at else None,
            "last_used_at": row.last_used_at.isoformat() if row.last_used_at else None,
        }
        for row in rows
    ]


@router.post("/passkey/register/begin")
async def passkey_register_begin(
    request: Request,
    user: User = Depends(current_user),
) -> dict:
    settings: Settings = request.app.state.settings
    challenge = secrets.token_bytes(32)
    options = passkey_flow.registration_options(
        rp_id=_rp_id(request, settings),
        rp_name=settings.rp_name,
        user_id=user.id,
        user_name=user.email,
        challenge=challenge,
    )
    response = Response(
        content=options, media_type="application/json"
    )
    response.set_cookie(
        PASSKEY_CHALLENGE_COOKIE,
        passkey_flow.b64url_encode(challenge),
        max_age=300,
        httponly=True,
        samesite="lax",
        secure=settings.secure_cookies,
        path="/",
    )
    response.set_cookie(
        PASSKEY_USER_COOKIE,
        str(user.id),
        max_age=300,
        httponly=True,
        samesite="lax",
        secure=settings.secure_cookies,
        path="/",
    )
    return response


@router.post("/passkey/register/finish")
async def passkey_register_finish(
    data: PasskeyFinishIn,
    request: Request,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_session),
) -> dict:
    settings: Settings = request.app.state.settings
    raw_challenge = request.cookies.get(PASSKEY_CHALLENGE_COOKIE, "")
    cookie_user = request.cookies.get(PASSKEY_USER_COOKIE, "")
    if not raw_challenge or cookie_user != str(user.id):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="注册会话已过期，请重试")
    try:
        result = passkey_flow.verify_registration(
            credential=data.credential,
            challenge=passkey_flow.b64url_decode(raw_challenge),
            rp_id=_rp_id(request, settings),
            origin=_origin(request, settings),
        )
    except Exception as exc:  # noqa: BLE001 - 校验失败统一返回 400
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Passkey 校验失败：{exc}") from exc

    exists = (
        await db.execute(
            select(WebAuthnCredential.id).where(
                WebAuthnCredential.credential_id == result.credential_id
            )
        )
    ).scalar_one_or_none()
    if exists is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="该 Passkey 已绑定")

    transports = data.credential.get("response", {}).get("transports") or []
    label = (data.credential.get("label") or "通行密钥")[:64]
    db.add(
        WebAuthnCredential(
            user_id=user.id,
            credential_id=result.credential_id,
            public_key=result.public_key,
            sign_count=result.sign_count,
            aaguid=result.aaguid,
            transports=transports or None,
            device_type=result.device_type,
            backed_up=result.backed_up,
            label=label,
        )
    )
    await db.commit()
    response = Response(
        content='{"ok":true}', media_type="application/json"
    )
    response.delete_cookie(PASSKEY_CHALLENGE_COOKIE, path="/")
    response.delete_cookie(PASSKEY_USER_COOKIE, path="/")
    return response


@router.delete("/passkey/{credential_id}")
async def delete_passkey(
    credential_id: int,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_session),
) -> dict:
    row = await db.get(WebAuthnCredential, credential_id)
    if row is None or row.user_id != user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="凭证不存在")
    await db.delete(row)
    await db.commit()
    return {"ok": True}


@router.post("/passkey/login/begin")
async def passkey_login_begin(request: Request) -> Response:
    settings: Settings = request.app.state.settings
    challenge = secrets.token_bytes(32)
    options = passkey_flow.authentication_options(
        rp_id=_rp_id(request, settings), challenge=challenge, credential_ids=[]
    )
    response = Response(content=options, media_type="application/json")
    response.set_cookie(
        PASSKEY_CHALLENGE_COOKIE,
        passkey_flow.b64url_encode(challenge),
        max_age=300,
        httponly=True,
        samesite="lax",
        secure=settings.secure_cookies,
        path="/",
    )
    return response


@router.post("/passkey/login/finish")
async def passkey_login_finish(
    data: PasskeyFinishIn,
    request: Request,
    db: AsyncSession = Depends(get_session),
) -> Response:
    settings: Settings = request.app.state.settings
    raw_challenge = request.cookies.get(PASSKEY_CHALLENGE_COOKIE, "")
    if not raw_challenge:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="登录会话已过期，请重试")

    raw_id = data.credential.get("id") or data.credential.get("rawId") or ""
    try:
        credential_id = passkey_flow.b64url_decode(raw_id)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="凭证格式非法") from exc

    record = (
        await db.execute(
            select(WebAuthnCredential).where(WebAuthnCredential.credential_id == credential_id)
        )
    ).scalar_one_or_none()
    if record is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="该 Passkey 未绑定")

    try:
        result = passkey_flow.verify_authentication(
            credential=data.credential,
            challenge=passkey_flow.b64url_decode(raw_challenge),
            rp_id=_rp_id(request, settings),
            origin=_origin(request, settings),
            public_key=record.public_key,
            current_sign_count=record.sign_count,
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Passkey 校验失败：{exc}") from exc

    user = await db.get(User, record.user_id)
    if user is None or user.status != STATUS_ACTIVE:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="账号不可用")

    record.sign_count = result.new_sign_count
    record.last_used_at = _now()
    if result.device_type:
        record.device_type = result.device_type
    record.backed_up = result.backed_up

    token = await create_session(
        db,
        user,
        ttl_hours=settings.session_ttl_hours,
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    response = Response(content='{"ok":true}', media_type="application/json")
    _set_session_cookie(response, settings, token)
    response.delete_cookie(PASSKEY_CHALLENGE_COOKIE, path="/")
    return response
