"""推送任务队列：Redis + SAQ。

Webhook 只做校验与入队后立即确认，实际发送由 worker 进程按频控节奏完成；
未配置 REDIS_URL 时上层保持同步发送，单机或测试环境无需额外组件。
"""

from __future__ import annotations

from redis.asyncio import Redis
from saq import Queue

from server.services.push import PushJob

PUSH_FUNCTION = "push_bot_message"

# 队列积压超过该值即拒绝入队，由上游平台按失败重试（GitHub 不会重投，入队侧改为同步发送），
# 避免任务无限堆积后在数小时后集中补发
DEFAULT_MAX_PENDING = 200

# 入队超过该秒数仍未开始的任务直接丢弃，避免服务停摆后把过期消息补发出来。
# 上限 200 条按每条 1~2 个目标、0.21s 间隔估算，排空约需 7 分钟，留出余量。
JOB_EXPIRES_SECONDS = 900

# 单个任务的执行上限与重试次数：2 次尝试足以覆盖一次瞬时失败，又不至于长时间占住频控配额
JOB_TIMEOUT_SECONDS = 180
JOB_RETRIES = 2
JOB_RETRY_DELAY_SECONDS = 5
JOB_RESULT_TTL_SECONDS = 600


class QueueFull(RuntimeError):
    """队列积压达到上限。"""


class SentGuard:
    """记录已成功推送的目标。

    SAQ 是「至少一次」语义：worker 启动时的清理可能与刚取出的任务并发，任务超时或
    停机时也可能被取消后重排，重跑的整条任务不应把已经送达的目标再发一遍。
    键由调用方给出（现为「请求 ID + 目标」）。
    """

    def __init__(self, redis: Redis, *, ttl: int = JOB_EXPIRES_SECONDS) -> None:
        self._redis = redis
        self.ttl = ttl

    @classmethod
    def connect(cls, url: str, *, ttl: int = JOB_EXPIRES_SECONDS) -> SentGuard:
        return cls(Redis.from_url(url), ttl=ttl)

    @staticmethod
    def _key(job_key: str) -> str:
        return f"saq:sent:{job_key}"

    async def done(self, job_key: str) -> bool:
        return bool(await self._redis.exists(self._key(job_key)))

    async def mark(self, job_key: str) -> None:
        await self._redis.set(self._key(job_key), 1, ex=self.ttl)

    async def aclose(self) -> None:
        await self._redis.aclose()


class PushQueue:
    def __init__(self, queue: Queue, *, max_pending: int = DEFAULT_MAX_PENDING) -> None:
        self._queue = queue
        self.max_pending = max_pending

    @classmethod
    async def connect(cls, url: str, *, max_pending: int = DEFAULT_MAX_PENDING) -> PushQueue:
        queue = Queue.from_url(url)
        await queue.connect()
        return cls(queue, max_pending=max_pending)

    async def pending(self) -> int:
        return int(await self._queue.count("queued"))

    async def enqueue(self, job: PushJob, *, job_id: str) -> bool:
        """入队；返回 False 表示同一投递仍在队列中（重复投递）。

        推送完成后的重复投递会重新入队，由 worker 的 SentGuard 跳过已成功执行的任务。
        """
        if await self.pending() >= self.max_pending:
            raise QueueFull(f"推送队列积压已达 {self.max_pending}")
        queued = await self._queue.enqueue(
            PUSH_FUNCTION,
            job=job.to_dict(),
            key=job_id,
            timeout=JOB_TIMEOUT_SECONDS,
            retries=JOB_RETRIES,
            retry_delay=JOB_RETRY_DELAY_SECONDS,
            ttl=JOB_RESULT_TTL_SECONDS,
        )
        return queued is not None

    async def aclose(self) -> None:
        await self._queue.disconnect()
