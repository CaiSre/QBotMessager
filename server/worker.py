"""SAQ worker：按频控节奏执行 Webhook 推送任务。

与 Web 进程共用代码，但独立持有数据库连接池、QQ 客户端与频控窗口。
QQ 主动消息频控按机器人（AppID）计算，worker 必须单进程运行。
"""

from __future__ import annotations

import logging
import time

import httpx2 as httpx
from saq import CronJob, Queue

from server.config import get_settings
from server.db.session import dispose_engine, init_engine, session_scope
from server.services.push import PushJob, execute_push
from server.services.qq import QqClient
from server.services.queue import JOB_EXPIRES_SECONDS, SentGuard
from server.services.runtime_settings import RuntimeSettings
from server.services.throttle import LimiterRegistry

logger = logging.getLogger(__name__)

_REDIS_URL = get_settings().redis_url.strip() or "redis://127.0.0.1:6379"


def _configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )


async def refresh_settings(ctx: dict) -> None:
    """定期同步库内设置，让管理员调整的频控参数与日志级别在 worker 内生效。"""
    runtime: RuntimeSettings = ctx["settings"]
    try:
        async with session_scope() as db:
            await runtime.load(db)
    except Exception:  # noqa: BLE001 - 读取失败时沿用旧值，等待下一轮
        logger.exception("worker 同步系统设置失败")
        return
    logging.getLogger().setLevel(getattr(logging, str(runtime.log_level).upper(), logging.INFO))
    ctx["limiters"].configure(
        qps=runtime.qq_qps,
        qpm=runtime.qq_qpm,
        min_interval=runtime.qq_min_interval,
    )


async def push_bot_message(ctx: dict, job: dict) -> None:
    queued = int(ctx["job"].queued or 0)
    # SAQ 没有排队过期机制：守护进程停机后重新拉起时，过旧的推送已无意义，直接丢弃
    if queued and time.time() * 1000 - queued > JOB_EXPIRES_SECONDS * 1000:
        logger.warning("推送任务排队过久，已丢弃（request_id=%s）", job.get("request_id"))
        return

    push = PushJob.from_dict(job)
    outcome = await execute_push(
        push,
        settings=ctx["settings"],
        client=ctx["qq_client"],
        limiter=ctx["limiters"].get(f"bot:{push.bot_id}"),
        sent=ctx["sent"],
    )
    if outcome.failed and outcome.retryable:
        # 全部目标都是可重试失败时整体重排；已成功的目标由 SentGuard 跳过，不会重复推送
        raise RuntimeError("QQ 推送失败，等待重试")


async def startup(ctx: dict) -> None:
    settings = get_settings()
    _configure_logging(settings.log_level)
    init_engine(
        settings.mysql_url,
        pool_size=settings.db_pool_size,
        max_overflow=settings.db_max_overflow,
        pool_timeout=settings.db_pool_timeout,
    )
    ctx["qq_client"] = QqClient(httpx.AsyncClient(timeout=httpx.Timeout(15.0, connect=5.0)))

    runtime = RuntimeSettings(settings)
    try:
        async with session_scope() as db:
            await runtime.load(db)
    except Exception:  # noqa: BLE001 - 读取失败时退回环境变量与默认值
        logger.exception("worker 加载系统设置失败，暂用环境变量与默认值")
    ctx["settings"] = runtime
    ctx["limiters"] = LimiterRegistry(
        qps=runtime.qq_qps,
        qpm=runtime.qq_qpm,
        min_interval=runtime.qq_min_interval,
    )
    ctx["sent"] = SentGuard.connect(_REDIS_URL)
    logger.info("推送 worker 已启动")


async def shutdown(ctx: dict) -> None:
    # 启动中途失败时 ctx 可能只装配了一部分，逐项判断避免清理阶段再次抛错
    if sent := ctx.get("sent"):
        await sent.aclose()
    if client := ctx.get("qq_client"):
        await client.aclose()
    await dispose_engine()
    logger.info("推送 worker 已停止")


# saq CLI 的入口：saq -q server.worker.settings
settings = {
    "queue": Queue.from_url(_REDIS_URL),
    "functions": [push_bot_message],
    # 每分钟同步一次库内设置，让管理员调整的频控参数在 worker 内生效
    "cron_jobs": [CronJob(refresh_settings, cron="* * * * *")],
    "startup": startup,
    "shutdown": shutdown,
    # 频控由进程内限流器串行化，并发只用于让不同机器人互相不阻塞
    "concurrency": 8,
    # 空闲时每次最多阻塞 5 秒，收到 SIGTERM 后能及时退出
    "dequeue_timeout": 5,
    # 停机时 SAQ 会等满这个时间再取消任务（空闲时同样等满，因为还挂着分钟级轮询任务），
    # 10 秒在「让正在发送的任务跑完」与「重启别太慢」之间取中；stopwaitsecs 需大于该值
    "shutdown_grace_period_s": 10,
}
