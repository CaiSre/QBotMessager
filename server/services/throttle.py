"""进程内限速器：滑动窗口 QPS/QPM + 最小发送间隔，以及登录失败计数限速。

QQ 主动消息频控是账号级（按机器人 AppID）的，因此必须单 worker、单副本运行。
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


class LimiterRegistry:
    """按 key（机器人）分配独立限流器。

    QQ 的主动消息频控按机器人（AppID）维度计算，多个用户共用一条全局配额会互相
    拖慢，因此每个机器人各维护一份窗口。键沿用 QqClient 的 `bot:<id>` 约定。
    """

    def __init__(
        self,
        *,
        qps: int = 5,
        qpm: int = 30,
        min_interval: float = 0.21,
    ) -> None:
        self._qps = qps
        self._qpm = qpm
        self._min_interval = min_interval
        self._limiters: dict[str, RateLimiter] = {}

    def get(self, key: str) -> RateLimiter:
        limiter = self._limiters.get(key)
        if limiter is None:
            limiter = RateLimiter(
                qps=self._qps, qpm=self._qpm, min_interval=self._min_interval
            )
            self._limiters[key] = limiter
        return limiter


def _is_shared_peer(ip: str | None) -> bool:
    """判断客户端地址能否区分来源。

    后端只监听 127.0.0.1、由同机 Next 反代访问时，请求方地址始终是回环地址，
    这时按 IP 计数会把所有用户算作同一个来源：一次撞库就能把所有账号一起锁死。
    这种情况只按 (来源, 账号) 计数。
    """
    if not ip:
        return True
    if ip in ("::1", "localhost"):
        return True
    return ip.startswith("127.")


class AttemptLimiter:
    """登录失败计数限速。

    同时按 (客户端 IP, 账号) 与 客户端 IP 两个维度计数：前者拦针对单个账号的爆破，
    后者拦大范围撞库；因为按组合计数，攻击者无法只靠一个来源锁死他人账号。
    客户端地址无法区分来源时（见 _is_shared_peer）只启用前一个维度。

    计数保存在进程内，与 QQ 频控一样要求单 worker、单副本运行。
    """

    _MAX_KEYS = 4096

    def __init__(
        self,
        *,
        pair_limit: int = 5,
        ip_limit: int = 30,
        window_seconds: int = 900,
    ) -> None:
        self.pair_limit = max(1, pair_limit)
        self.ip_limit = max(1, ip_limit)
        self.window_seconds = max(1, window_seconds)
        self._failures: dict[str, deque[float]] = {}
        self._lock = asyncio.Lock()

    @staticmethod
    def _pair_key(ip: str | None, account: str) -> str:
        return f"pair:{ip or '-'}|{account}"

    @staticmethod
    def _ip_key(ip: str | None) -> str:
        return f"ip:{ip or '-'}"

    def _prune_bucket(self, key: str, now: float) -> deque[float]:
        bucket = self._failures.get(key)
        if bucket is None:
            return deque()
        while bucket and now - bucket[0] >= self.window_seconds:
            bucket.popleft()
        if not bucket:
            self._failures.pop(key, None)
        return bucket

    def _wait_of(self, bucket: deque[float], now: float, limit: int) -> int:
        if len(bucket) < limit:
            return 0
        return max(1, int(bucket[0] + self.window_seconds - now) + 1)

    async def remaining_wait(self, ip: str | None, account: str) -> int:
        """超限时返回还需等待的秒数，未超限返回 0。"""
        now = time.monotonic()
        async with self._lock:
            pair = self._prune_bucket(self._pair_key(ip, account), now)
            wait = self._wait_of(pair, now, self.pair_limit)
            if not _is_shared_peer(ip):
                by_ip = self._prune_bucket(self._ip_key(ip), now)
                wait = max(wait, self._wait_of(by_ip, now, self.ip_limit))
            return wait

    async def record_failure(self, ip: str | None, account: str) -> None:
        now = time.monotonic()
        async with self._lock:
            keys = [self._pair_key(ip, account)]
            if not _is_shared_peer(ip):
                keys.append(self._ip_key(ip))
            for key in keys:
                bucket = self._failures.setdefault(key, deque())
                bucket.append(now)
            if len(self._failures) > self._MAX_KEYS:
                self._prune_all(now)

    async def reset(self, ip: str | None, account: str) -> None:
        """登录成功后清掉该 (IP, 账号) 的计数；IP 维度保留，避免靠偶发成功绕过。"""
        async with self._lock:
            self._failures.pop(self._pair_key(ip, account), None)

    def _prune_all(self, now: float) -> None:
        for key in list(self._failures):
            self._prune_bucket(key, now)
