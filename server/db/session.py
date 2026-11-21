"""异步引擎与会话管理。"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool, StaticPool

_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def build_engine(url: str) -> AsyncEngine:
    """创建异步引擎。

    MySQL 走 asyncmy 驱动；SQLite 仅用于本地测试（aiosqlite）。
    """
    kwargs: dict = {"pool_pre_ping": True, "pool_recycle": 1800, "future": True}
    if url.startswith("sqlite"):
        kwargs["poolclass"] = StaticPool if ":memory:" in url else NullPool
        kwargs.pop("pool_pre_ping")
        kwargs.pop("pool_recycle")
    return create_async_engine(url, **kwargs)


def init_engine(url: str) -> AsyncEngine:
    global _engine, _session_factory
    _engine = build_engine(url)
    _session_factory = async_sessionmaker(
        _engine, class_=AsyncSession, expire_on_commit=False
    )
    return _engine


def get_engine() -> AsyncEngine:
    if _engine is None:
        raise RuntimeError("数据库引擎未初始化，请先调用 init_engine()")
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    if _session_factory is None:
        raise RuntimeError("会话工厂未初始化，请先调用 init_engine()")
    return _session_factory


async def dispose_engine() -> None:
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _session_factory = None


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI 依赖：每请求一个会话。"""
    async with get_session_factory()() as session:
        yield session


@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    """脚本与后台任务使用的事务上下文。"""
    async with get_session_factory()() as session:
        yield session
