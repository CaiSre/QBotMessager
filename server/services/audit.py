"""后台写操作审计。"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from server.db.models import AdminAuditLog, User


async def record_audit(
    db: AsyncSession,
    *,
    actor: User | None,
    action: str,
    target_type: str | None = None,
    target_id: object | None = None,
    detail: dict | None = None,
    ip: str | None = None,
    commit: bool = False,
) -> None:
    db.add(
        AdminAuditLog(
            actor_user_id=actor.id if actor else None,
            action=action,
            target_type=target_type,
            target_id=str(target_id) if target_id is not None else None,
            detail=detail,
            ip=ip,
        )
    )
    if commit:
        await db.commit()
