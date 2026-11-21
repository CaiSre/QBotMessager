"""服务端会话：Cookie 只保存随机 token，数据库只保存其 SHA-256。"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from server.db.models import Session, User


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


async def create_session(
    db: AsyncSession,
    user: User,
    *,
    ttl_hours: int,
    ip: str | None = None,
    user_agent: str | None = None,
) -> str:
    token = secrets.token_urlsafe(32)
    db.add(
        Session(
            token_hash=_hash(token),
            user_id=user.id,
            ip=ip,
            user_agent=(user_agent or "")[:255] or None,
            expires_at=_utcnow() + timedelta(hours=ttl_hours),
        )
    )
    user.last_login_at = _utcnow()
    await db.commit()
    return token


async def resolve_session(db: AsyncSession, token: str) -> User | None:
    if not token:
        return None
    row = (
        await db.execute(
            select(Session, User)
            .join(User, User.id == Session.user_id)
            .where(Session.token_hash == _hash(token))
        )
    ).first()
    if row is None:
        return None
    session, user = row
    expires_at = session.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if session.revoked_at is not None or expires_at <= _utcnow():
        return None
    return user


async def revoke_session(db: AsyncSession, token: str) -> None:
    if not token:
        return
    session = (
        await db.execute(select(Session).where(Session.token_hash == _hash(token)))
    ).scalar_one_or_none()
    if session is not None and session.revoked_at is None:
        session.revoked_at = _utcnow()
        await db.commit()


async def revoke_other_sessions(db: AsyncSession, user_id: int, *, keep_token: str) -> None:
    """退出该用户除当前会话外的其他登录设备（改密后调用）。"""
    await db.execute(
        update(Session)
        .where(
            Session.user_id == user_id,
            Session.token_hash != _hash(keep_token),
            Session.revoked_at.is_(None),
        )
        .values(revoked_at=_utcnow())
    )
    await db.commit()
