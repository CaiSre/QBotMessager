"""用户名唯一性：忽略大小写地检查占用，并为自动生成的用户名追加后缀。"""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from server.db.models import User

NAME_MAX = 128


async def name_taken(
    db: AsyncSession, name: str, *, exclude_user_id: int | None = None
) -> bool:
    conditions = [func.lower(User.name) == name.lower()]
    if exclude_user_id is not None:
        conditions.append(User.id != exclude_user_id)
    row = await db.execute(select(User.id).where(*conditions))
    return row.scalar_one_or_none() is not None


async def unique_name(db: AsyncSession, preferred: str) -> str:
    """注册时未填用户名：以邮箱前缀为基准，冲突时追加 -2、-3…"""
    base = preferred.strip()[:NAME_MAX] or "user"
    candidate = base
    index = 1
    while await name_taken(db, candidate):
        index += 1
        suffix = f"-{index}"
        candidate = base[: NAME_MAX - len(suffix)] + suffix
    return candidate
