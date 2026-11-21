"""FastAPI 依赖：当前会话与权限校验。"""

from __future__ import annotations

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from server.auth.sessions import resolve_session
from server.config import Settings
from server.db.models import ROLE_SUPER_ADMIN, STATUS_ACTIVE, User
from server.db.session import get_session


def get_app_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_session_token(request: Request) -> str:
    settings: Settings = request.app.state.settings
    return request.cookies.get(settings.cookie_name, "")


async def current_user(
    request: Request,
    db: AsyncSession = Depends(get_session),
    token: str = Depends(get_session_token),
) -> User:
    user = await resolve_session(db, token)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未登录")
    if user.status != STATUS_ACTIVE:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="账号已停用")
    request.state.current_user = user
    return user


def is_super_admin(user: User) -> bool:
    return user.role == ROLE_SUPER_ADMIN


def require_super_admin(user: User = Depends(current_user)) -> User:
    if not is_super_admin(user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="仅超级管理员可操作")
    return user
