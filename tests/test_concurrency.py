"""Fair async bulkhead behavior."""

from __future__ import annotations

import asyncio
import time

import pytest
from contextunity.core.concurrency import (
    BulkheadDeadlineExceededError,
    BulkheadQueueFullError,
    FairAsyncBulkhead,
)


@pytest.mark.asyncio
async def test_round_robin_serves_other_tenant_before_same_tenant_reentry() -> None:
    bulkhead = FairAsyncBulkhead(
        enabled=True,
        global_limit=1,
        per_tenant_limit=1,
        max_queue=8,
        per_tenant_queue_limit=4,
    )
    order: list[str] = []
    first_entered = asyncio.Event()
    release_first = asyncio.Event()

    async def run(tenant: str, hold: bool = False) -> None:
        async with bulkhead.acquire(tenant, deadline_at=time.monotonic() + 1):
            order.append(tenant)
            if hold:
                first_entered.set()
                await release_first.wait()

    first = asyncio.create_task(run("a", True))
    await first_entered.wait()
    same_tenant = asyncio.create_task(run("a"))
    other_tenant = asyncio.create_task(run("b"))
    await asyncio.sleep(0)
    release_first.set()
    await asyncio.gather(first, same_tenant, other_tenant)
    assert order == ["a", "b", "a"]


@pytest.mark.asyncio
async def test_cancelled_last_waiter_cannot_duplicate_round_robin_turn() -> None:
    bulkhead = FairAsyncBulkhead(
        enabled=True,
        global_limit=2,
        per_tenant_limit=2,
        max_queue=8,
        per_tenant_queue_limit=4,
    )
    holders_entered = asyncio.Event()
    release_holders = asyncio.Event()
    release_workers = asyncio.Event()
    holder_count = 0
    order: list[str] = []
    two_workers_entered = asyncio.Event()

    async def hold_capacity() -> None:
        nonlocal holder_count
        async with bulkhead.acquire("holder", deadline_at=time.monotonic() + 1):
            holder_count += 1
            if holder_count == 2:
                holders_entered.set()
            await release_holders.wait()

    async def run_worker(tenant_id: str) -> None:
        async with bulkhead.acquire(tenant_id, deadline_at=time.monotonic() + 1):
            order.append(tenant_id)
            if len(order) == 2:
                two_workers_entered.set()
            await release_workers.wait()

    holders = [asyncio.create_task(hold_capacity()) for _ in range(2)]
    await holders_entered.wait()

    cancelled = asyncio.create_task(bulkhead.acquire("a", deadline_at=time.monotonic() + 1).__aenter__())
    await asyncio.sleep(0)
    cancelled.cancel()
    await asyncio.gather(cancelled, return_exceptions=True)

    workers = [
        asyncio.create_task(run_worker("a")),
        asyncio.create_task(run_worker("a")),
        asyncio.create_task(run_worker("b")),
    ]
    await asyncio.sleep(0)
    release_holders.set()
    await two_workers_entered.wait()
    release_workers.set()
    await asyncio.gather(*holders, *workers)

    assert order[:2] == ["a", "b"]


@pytest.mark.asyncio
async def test_per_tenant_queue_reserves_capacity_for_other_tenant() -> None:
    bulkhead = FairAsyncBulkhead(
        enabled=True,
        global_limit=1,
        per_tenant_limit=1,
        max_queue=4,
        per_tenant_queue_limit=1,
    )
    release = asyncio.Event()

    async def hold() -> None:
        async with bulkhead.acquire("a", deadline_at=time.monotonic() + 1):
            await release.wait()

    owner = asyncio.create_task(hold())
    await asyncio.sleep(0)
    queued = asyncio.create_task(bulkhead.acquire("a", deadline_at=time.monotonic() + 1).__aenter__())
    await asyncio.sleep(0)
    with pytest.raises(BulkheadQueueFullError) as captured:
        async with bulkhead.acquire("a", deadline_at=time.monotonic() + 1):
            pass
    assert captured.value.message == "bulkhead queue capacity exhausted"
    assert captured.value.details == {
        "waiting_global": 1,
        "waiting_global_limit": 4,
        "waiting_tenant": 1,
        "waiting_tenant_limit": 1,
    }
    other = asyncio.create_task(bulkhead.acquire("b", deadline_at=time.monotonic() + 1).__aenter__())
    release.set()
    await owner
    lease_b = await other
    assert lease_b.queue_wait_ms >= 0
    queued.cancel()
    await asyncio.gather(queued, return_exceptions=True)


@pytest.mark.asyncio
async def test_deadline_and_cancellation_do_not_leak_slots() -> None:
    bulkhead = FairAsyncBulkhead(
        enabled=True,
        global_limit=1,
        per_tenant_limit=1,
        max_queue=4,
        per_tenant_queue_limit=2,
    )
    async with bulkhead.acquire("a", deadline_at=time.monotonic() + 1):
        with pytest.raises(BulkheadDeadlineExceededError):
            async with bulkhead.acquire("b", deadline_at=time.monotonic() + 0.01):
                pass
        waiter = asyncio.create_task(bulkhead.acquire("b", deadline_at=time.monotonic() + 1).__aenter__())
        await asyncio.sleep(0)
        waiter.cancel()
        await asyncio.gather(waiter, return_exceptions=True)
    async with bulkhead.acquire("b", deadline_at=time.monotonic() + 0.2):
        assert bulkhead.active_global == 1


@pytest.mark.asyncio
async def test_zero_length_queue_allows_only_immediately_runnable_work() -> None:
    bulkhead = FairAsyncBulkhead(
        enabled=True,
        global_limit=1,
        per_tenant_limit=1,
        max_queue=0,
        per_tenant_queue_limit=0,
    )

    async with bulkhead.acquire("a", deadline_at=time.monotonic() + 1):
        assert bulkhead.active_global == 1
        with pytest.raises(BulkheadQueueFullError):
            async with bulkhead.acquire("b", deadline_at=time.monotonic() + 1):
                pass

    async with bulkhead.acquire("b", deadline_at=time.monotonic() + 1):
        assert bulkhead.active_global == 1
