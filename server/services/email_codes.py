"""邮箱验证码的签发与校验。

验证码只保存 PBKDF2 哈希；同一邮箱同一用途同时只有最新一条有效，
过期、尝试次数用尽或校验成功后立即作废。
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from server.auth.passwords import hash_password, verify_password
from server.db.models import EmailVerificationCode

PURPOSE_REGISTER = "register"
PURPOSE_RESET_PASSWORD = "reset_password"
PURPOSE_SET_PASSWORD = "set_password"

PURPOSE_LABELS = {
    PURPOSE_REGISTER: "注册账号",
    PURPOSE_RESET_PASSWORD: "重置密码",
    PURPOSE_SET_PASSWORD: "设置登录密码",
}

MAX_ATTEMPTS = 5


class CodeTooFrequent(RuntimeError):
    def __init__(self, retry_after: int) -> None:
        super().__init__("请求过于频繁")
        self.retry_after = retry_after


class CodeQuotaExceeded(RuntimeError):
    def __init__(self, retry_after: int) -> None:
        super().__init__("发送次数已达上限")
        self.retry_after = retry_after


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def generate_code() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


async def issue_code(
    db: AsyncSession,
    *,
    email: str,
    purpose: str,
    ttl_minutes: int,
    resend_seconds: int,
    hourly_limit: int,
    ip: str | None = None,
) -> str:
    """签发验证码；过频或超量时抛 CodeTooFrequent / CodeQuotaExceeded。"""
    now = _now()
    latest = (
        await db.execute(
            select(EmailVerificationCode)
            .where(
                EmailVerificationCode.email == email,
                EmailVerificationCode.purpose == purpose,
                EmailVerificationCode.consumed_at.is_(None),
            )
            .order_by(EmailVerificationCode.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if latest is not None:
        wait = int(
            (_aware(latest.created_at) + timedelta(seconds=resend_seconds) - now).total_seconds()
        )
        if wait > 0:
            raise CodeTooFrequent(wait)

    since = now - timedelta(hours=1)
    sent = (
        await db.execute(
            select(func.count(EmailVerificationCode.id)).where(
                EmailVerificationCode.email == email,
                EmailVerificationCode.purpose == purpose,
                EmailVerificationCode.created_at >= since,
            )
        )
    ).scalar_one()
    if sent >= hourly_limit:
        raise CodeQuotaExceeded(resend_seconds)

    # 新码签发后旧码立即失效
    await db.execute(
        update(EmailVerificationCode)
        .where(
            EmailVerificationCode.email == email,
            EmailVerificationCode.purpose == purpose,
            EmailVerificationCode.consumed_at.is_(None),
        )
        .values(consumed_at=now)
    )

    code = generate_code()
    db.add(
        EmailVerificationCode(
            email=email,
            purpose=purpose,
            code_hash=hash_password(code),
            expires_at=now + timedelta(minutes=ttl_minutes),
            ip=ip,
        )
    )
    await db.commit()
    return code


async def verify_code(
    db: AsyncSession, *, email: str, purpose: str, code: str
) -> bool:
    """校验并一次性消费验证码；失败会累计尝试次数。"""
    now = _now()
    row = (
        await db.execute(
            select(EmailVerificationCode)
            .where(
                EmailVerificationCode.email == email,
                EmailVerificationCode.purpose == purpose,
                EmailVerificationCode.consumed_at.is_(None),
            )
            .order_by(EmailVerificationCode.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if row is None:
        return False

    if _aware(row.expires_at) <= now or row.attempts >= MAX_ATTEMPTS:
        row.consumed_at = now
        await db.commit()
        return False

    if not verify_password(code.strip(), row.code_hash):
        row.attempts += 1
        if row.attempts >= MAX_ATTEMPTS:
            row.consumed_at = now
        await db.commit()
        return False

    row.consumed_at = now
    await db.commit()
    return True


async def discard_latest(db: AsyncSession, *, email: str, purpose: str) -> None:
    """邮件发送失败时作废刚签发的验证码，允许用户立即重试。"""
    await db.execute(
        update(EmailVerificationCode)
        .where(
            EmailVerificationCode.email == email,
            EmailVerificationCode.purpose == purpose,
            EmailVerificationCode.consumed_at.is_(None),
        )
        .values(consumed_at=_now())
    )
    await db.commit()
