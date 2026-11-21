"""限速器：窗口与最小间隔。"""

from __future__ import annotations

import asyncio
import time

from server.services.throttle import AttemptLimiter, LimiterRegistry, RateLimiter


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


async def test_registry_gives_each_bot_its_own_window() -> None:
    registry = LimiterRegistry(qps=2, qpm=600, min_interval=0)

    first = registry.get("bot:1")
    assert registry.get("bot:1") is first
    assert registry.get("bot:2") is not first

    # 第一个机器人用满自己的 QPS 窗口，不影响第二个机器人
    await first.acquire()
    await first.acquire()
    started = time.perf_counter()
    await registry.get("bot:2").acquire()
    assert time.perf_counter() - started < 0.5


async def test_attempt_limiter_counts_per_pair_and_per_ip() -> None:
    limiter = AttemptLimiter(pair_limit=2, ip_limit=10, window_seconds=60)

    for _ in range(2):
        await limiter.record_failure("1.2.3.4", "a@example.com")
    assert await limiter.remaining_wait("1.2.3.4", "a@example.com") > 0
    # 同一 IP 下换账号仍可用，IP 额度还没用完
    assert await limiter.remaining_wait("1.2.3.4", "b@example.com") == 0
    # 别的 IP 完全不受影响
    assert await limiter.remaining_wait("5.6.7.8", "a@example.com") == 0


async def test_attempt_limiter_ip_budget_blocks_wide_sweep() -> None:
    limiter = AttemptLimiter(pair_limit=5, ip_limit=3, window_seconds=60)

    for index in range(3):
        await limiter.record_failure("1.2.3.4", f"user{index}@example.com")
    assert await limiter.remaining_wait("1.2.3.4", "fresh@example.com") > 0


async def test_attempt_limiter_reset_clears_pair_only() -> None:
    limiter = AttemptLimiter(pair_limit=2, ip_limit=10, window_seconds=60)

    await limiter.record_failure("1.2.3.4", "a@example.com")
    await limiter.record_failure("1.2.3.4", "a@example.com")
    assert await limiter.remaining_wait("1.2.3.4", "a@example.com") > 0

    await limiter.reset("1.2.3.4", "a@example.com")
    assert await limiter.remaining_wait("1.2.3.4", "a@example.com") == 0
    # IP 维度的计数保留，避免靠偶发成功绕过
    await limiter.record_failure("1.2.3.4", "b@example.com")
    await limiter.record_failure("1.2.3.4", "b@example.com")
    await limiter.record_failure("1.2.3.4", "b@example.com")
    assert await limiter.remaining_wait("1.2.3.4", "b@example.com") > 0


async def test_attempt_limiter_ignores_ip_budget_for_shared_peer() -> None:
    """来源地址是回环（反代未透传客户端 IP）时，IP 维度会把所有用户算成一个人。"""
    limiter = AttemptLimiter(pair_limit=5, ip_limit=3, window_seconds=60)

    for index in range(10):
        await limiter.record_failure("127.0.0.1", f"user{index}@example.com")

    # 别的账号不受牵连，否则一次撞库会把所有人一起锁死
    assert await limiter.remaining_wait("127.0.0.1", "fresh@example.com") == 0
    # 同一账号仍然按组合计数限速
    for _ in range(5):
        await limiter.record_failure("127.0.0.1", "user0@example.com")
    assert await limiter.remaining_wait("127.0.0.1", "user0@example.com") > 0
