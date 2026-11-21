"""限速器：窗口与最小间隔。"""

from __future__ import annotations

import asyncio
import time

from server.services.throttle import RateLimiter


async def test_min_interval_spacing() -> None:
    limiter = RateLimiter(qps=50, qpm=600, min_interval=0.05)
    started = time.perf_counter()
    for _ in range(3):
        await limiter.acquire()
    elapsed = time.perf_counter() - started
    assert elapsed >= 0.09


async def test_qps_window_blocks_burst() -> None:
    limiter = RateLimiter(qps=2, qpm=600, min_interval=0)
    started = time.perf_counter()
    for _ in range(3):
        await limiter.acquire()
    elapsed = time.perf_counter() - started
    # 第 3 次必须等到窗口滑出，约 1s
    assert elapsed >= 0.9


async def test_concurrent_acquire_is_serialized() -> None:
    limiter = RateLimiter(qps=50, qpm=600, min_interval=0.02)
    started = time.perf_counter()
    await asyncio.gather(*(limiter.acquire() for _ in range(3)))
    assert time.perf_counter() - started >= 0.04
