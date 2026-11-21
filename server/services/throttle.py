"""进程内限速器：滑动窗口 QPS/QPM + 最小发送间隔。

QQ 主动消息频控是账号级的（未认证 5/qps、30/qpm），因此必须单 worker、单副本运行。
"""

from __future__ import annotations

import asyncio
import time
from collections import deque


class RateLimiter:
    def __init__(
        self,
        *,
        qps: int = 5,
        qpm: int = 30,
        min_interval: float = 0.21,
    ) -> None:
        self.qps = max(1, qps)
        self.qpm = max(1, qpm)
        self.min_interval = max(0.0, min_interval)
        self._second_window: deque[float] = deque()
        self._minute_window: deque[float] = deque()
        self._last_sent: float = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """获取一次发送许可（阻塞直到满足频率限制）。"""
        async with self._lock:
            while True:
                now = time.monotonic()
                self._prune(now)
                if (
                    len(self._second_window) < self.qps
                    and len(self._minute_window) < self.qpm
                ):
                    wait = self.min_interval - (now - self._last_sent)
                    if wait > 0:
                        await asyncio.sleep(wait)
                        now = time.monotonic()
                    self._last_sent = now
                    self._second_window.append(now)
                    self._minute_window.append(now)
                    return
                # 窗口已满：睡到最早的记录过期
                oldest = min(
                    self._second_window[0] if self._second_window else now,
                    self._minute_window[0] if self._minute_window else now,
                )
                sleep_for = max(0.01, min(oldest + 1.0 - now, 1.0))
                await asyncio.sleep(sleep_for)

    def _prune(self, now: float) -> None:
        while self._second_window and now - self._second_window[0] >= 1.0:
            self._second_window.popleft()
        while self._minute_window and now - self._minute_window[0] >= 60.0:
            self._minute_window.popleft()
