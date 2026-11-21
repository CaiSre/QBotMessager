"""认证接口：邮箱密码、邀请码注册、OAuth2、通行密钥 Passkey。"""

from __future__ import annotations

import logging
import re
import secrets
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx2 as httpx
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from server.auth import oauth as oauth_flow
from server.auth import passkey as passkey_flow
from server.auth.deps import current_user
from server.auth.passwords import burn_password, hash_password, verify_password
from server.auth.sessions import create_session, revoke_session
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
from server.services.throttle import AttemptLimiter

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


class LoginIn(_EmailModel):
    password: str = Field(min_length=1, max_length=256)


class RegisterIn(_EmailModel):
    invite_code: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=8, max_length=256)
    name: str = Field(default="", max_length=128)


class PasskeyFinishIn(BaseModel):
    credential: dict


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


def _user_payload(user: User) -> dict:
    return {
        "id": user.id,
        "email": user.email,
        "name": user.name,
        "role": user.role,
        "status": user.status,
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
    account = data.email.lower()

    wait = await limiter.remaining_wait(ip, account)
    if wait > 0:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"尝试过于频繁，请 {wait} 秒后再试",
            headers={"Retry-After": str(wait)},
        )

    user = (
        await db.execute(select(User).where(User.email == account))
    ).scalar_one_or_none()
    if user is None:
        # 账号不存在时也走一次等价 PBKDF2，避免用响应时间枚举已注册邮箱
        burn_password(data.password)
        await limiter.record_failure(ip, account)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="邮箱或密码错误")
    if not verify_password(data.password, user.password_hash):
        await limiter.record_failure(ip, account)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="邮箱或密码错误")
    if user.status != STATUS_ACTIVE:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="账号已停用")

    await limiter.reset(ip, account)
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
        name=data.name or email.split("@")[0],
        password_hash=hash_password(data.password),
        role=ROLE_USER,
        status=STATUS_ACTIVE,
    )
    db.add(user)
    await db.flush()

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
                name=profile.name or profile.login,
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
