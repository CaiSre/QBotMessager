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
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy.exc import TimeoutError as DbTimeoutError

from server import __version__
from server.api import admin, auth, health, webhook
from server.config import get_settings
from server.db.bootstrap import bootstrap
from server.db.session import dispose_engine, init_engine, session_scope
from server.services.qq import QqClient
from server.services.queue import PushQueue
from server.services.runtime_settings import RuntimeSettings
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
    # 数据库连接串、加密主密钥等敏感项仍来自环境变量
    app.state.base_settings = settings

    init_engine(
        settings.mysql_url,
        pool_size=settings.db_pool_size,
        max_overflow=settings.db_max_overflow,
        pool_timeout=settings.db_pool_timeout,
    )
    app.state.httpx = httpx.AsyncClient(
        timeout=httpx.Timeout(15.0, connect=5.0),
        headers={"User-Agent": "qbotmessager"},
    )
    app.state.qq_client = QqClient(
        httpx.AsyncClient(timeout=httpx.Timeout(15.0, connect=5.0))
    )

    try:
        async with session_scope() as db:
            await bootstrap(db, settings)
    except Exception:  # noqa: BLE001 - 引导失败不阻塞健康检查，便于排查
        logger.exception("初始化引导失败，请检查数据库连接与迁移是否执行")

    runtime = RuntimeSettings(settings)
    try:
        async with session_scope() as db:
            await runtime.load(db)
    except Exception:  # noqa: BLE001 - 设置读取失败时退回环境变量与默认值
        logger.exception("加载系统设置失败，暂用环境变量与默认值")
    app.state.settings = runtime

    # QQ 频控按机器人 AppID 计算，多用户共用一条全局配额会互相拖慢，故按机器人分配
    app.state.limiters = LimiterRegistry(
        qps=runtime.qq_qps,
        qpm=runtime.qq_qpm,
        min_interval=runtime.qq_min_interval,
    )
    app.state.login_limiter = AttemptLimiter(
        pair_limit=runtime.login_max_failures,
        ip_limit=runtime.login_ip_max_failures,
        window_seconds=runtime.login_window_seconds,
    )
    runtime.apply_side_effects(app)

    # 配置了 Redis 就把实际发送交给 worker，Webhook 只入队后立即确认；
    # 连接失败时退回同步发送，避免因为队列不可用而丢消息
    app.state.push_queue = None
    if settings.redis_url.strip():
        try:
            app.state.push_queue = await PushQueue.connect(
                settings.redis_url, max_pending=settings.push_queue_max
            )
            # 连接串可能带密码，不写入日志
            logger.info("推送队列已连接")
        except Exception:  # noqa: BLE001 - 队列不可用时降级为同步推送
            logger.exception("连接 Redis 失败，推送改为同步执行")

    logger.info("QBotMessager 后端已启动，版本 %s", __version__)
    try:
        yield
    finally:
        if app.state.push_queue is not None:
            await app.state.push_queue.aclose()
        await app.state.qq_client.aclose()
        await app.state.httpx.aclose()
        await dispose_engine()
        logger.info("QBotMessager 后端已停止")


def create_app() -> FastAPI:
    app = FastAPI(title="QBotMessager", version=__version__, lifespan=lifespan)

    @app.middleware("http")
    async def _security_headers(request: Request, call_next):
        # Next 的外部 rewrite 会丢弃 next.config 里配置的响应头，接口响应需自行补齐
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        return response

    @app.exception_handler(DbTimeoutError)
    async def _db_pool_timeout(_: Request, exc: DbTimeoutError) -> JSONResponse:
        # 连接池等待超时应由调用方重试，而不是暴露成 500
        logger.warning("数据库连接池等待超时：%s", exc)
        return JSONResponse({"detail": "数据库繁忙，请稍后重试"}, status_code=503)

    app.include_router(health.router)
    app.include_router(webhook.router)
    app.include_router(auth.router)
    app.include_router(admin.router)
    return app


app = create_app()
