"""FastAPI 应用入口。

单容器内由 supervisord 拉起：uvicorn 监听 8000，Next.js 监听 3000 并把
/api/* 与 /webhook/* 反代到这里。数据库迁移（alembic upgrade head）由
entrypoint 在启动前完成，这里只做连接、引导与依赖装配。
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

import httpx2 as httpx
from fastapi import FastAPI

from server import __version__
from server.api import admin, auth, health, webhook
from server.config import get_settings
from server.db.bootstrap import bootstrap
from server.db.session import dispose_engine, init_engine, session_scope
from server.services.qq import QqClient
from server.services.throttle import AttemptLimiter, LimiterRegistry

logger = logging.getLogger(__name__)


def _configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    _configure_logging(settings.log_level)
    app.state.settings = settings

    init_engine(settings.mysql_url)
    app.state.httpx = httpx.AsyncClient(
        timeout=httpx.Timeout(15.0, connect=5.0),
        headers={"User-Agent": "qbotmessager"},
    )
    app.state.qq_client = QqClient(
        httpx.AsyncClient(timeout=httpx.Timeout(15.0, connect=5.0))
    )
    # QQ 频控按机器人 AppID 计算，多用户共用一条全局配额会互相拖慢，故按机器人分配
    app.state.limiters = LimiterRegistry(
        qps=settings.qq_qps,
        qpm=settings.qq_qpm,
        min_interval=settings.qq_min_interval,
    )
    app.state.login_limiter = AttemptLimiter(
        pair_limit=settings.login_max_failures,
        ip_limit=settings.login_ip_max_failures,
        window_seconds=settings.login_window_seconds,
    )

    try:
        async with session_scope() as db:
            await bootstrap(db, settings)
    except Exception:  # noqa: BLE001 - 引导失败不阻塞健康检查，便于排查
        logger.exception("初始化引导失败，请检查数据库连接与迁移是否执行")

    logger.info("QBotMessager 后端已启动，版本 %s", __version__)
    try:
        yield
    finally:
        await app.state.qq_client.aclose()
        await app.state.httpx.aclose()
        await dispose_engine()
        logger.info("QBotMessager 后端已停止")


def create_app() -> FastAPI:
    app = FastAPI(title="QBotMessager", version=__version__, lifespan=lifespan)
    app.include_router(health.router)
    app.include_router(webhook.router)
    app.include_router(auth.router)
    app.include_router(admin.router)
    return app


app = create_app()
