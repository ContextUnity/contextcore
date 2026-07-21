"""Bounded fair async bulkhead primitives shared by services.

The scheduler is process-local infrastructure. It owns no service policy and
never retries work. Waiting tenants are served round-robin; one tenant cannot
consume every queued position or reserve a global execution slot while blocked
on its tenant limit.
"""

from __future__ import annotations

import asyncio
import time
from collections import deque
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from dataclasses import dataclass

from contextunity.core.exceptions import ContextUnityError


class BulkheadQueueFullError(ContextUnityError):
    """A bounded bulkhead queue has no capacity for this tenant."""

    code: str = "RESOURCE_EXHAUSTED"
    fault_class: str = "infra_fault"


class BulkheadDeadlineExceededError(ContextUnityError):
    """Bulkhead did not complete before the caller's absolute deadline."""

    code: str = "DEADLINE_EXCEEDED"
    fault_class: str = "infra_fault"


@dataclass(frozen=True, slots=True)
class BulkheadLease:
    """Metadata for one granted scheduler slot."""

    queue_wait_ms: float


@dataclass(slots=True)
class _Waiter:
    tenant_id: str
    ready: asyncio.Future[None]
    enqueued_at: float
    granted: bool = False


class FairAsyncBulkhead:
    """Round-robin global/per-tenant async bulkhead with bounded queues."""

    def __init__(
        self,
        *,
        enabled: bool,
        global_limit: int,
        per_tenant_limit: int,
        max_queue: int,
        per_tenant_queue_limit: int,
    ) -> None:
        if global_limit < 1 or per_tenant_limit < 1:
            raise ValueError("bulkhead concurrency limits must be positive")
        if max_queue < 0 or per_tenant_queue_limit < 0:
            raise ValueError("bulkhead queue limits must be non-negative")
        self.enabled = enabled
        self.global_limit = global_limit
        self.per_tenant_limit = per_tenant_limit
        self.max_queue = max_queue
        self.per_tenant_queue_limit = per_tenant_queue_limit
        self._lock = asyncio.Lock()
        self._queues: dict[str, deque[_Waiter]] = {}
        self._tenant_order: deque[str] = deque()
        self._active_global = 0
        self._active_tenant: dict[str, int] = {}
        self._waiting = 0

    @property
    def active_global(self) -> int:
        return self._active_global

    @property
    def waiting_global(self) -> int:
        return self._waiting

    def active_for_tenant(self, tenant_id: str) -> int:
        return self._active_tenant.get(tenant_id, 0)

    def waiting_for_tenant(self, tenant_id: str) -> int:
        queue = self._queues.get(tenant_id)
        return len(queue) if queue is not None else 0

    def _drop_empty_queue_locked(self, tenant_id: str) -> None:
        queue = self._queues.get(tenant_id)
        if queue is not None and not queue:
            self._queues.pop(tenant_id, None)
            self._tenant_order = deque(
                queued_tenant for queued_tenant in self._tenant_order if queued_tenant != tenant_id
            )

    def _dispatch_locked(self) -> None:
        """Grant available slots in tenant round-robin order."""
        while self._active_global < self.global_limit and self._tenant_order:
            tenant_count = len(self._tenant_order)
            granted = False
            for _ in range(tenant_count):
                tenant_id = self._tenant_order.popleft()
                queue = self._queues.get(tenant_id)
                if queue is None:
                    continue
                while queue and queue[0].ready.done():
                    queue.popleft()
                    self._waiting -= 1
                if not queue:
                    self._drop_empty_queue_locked(tenant_id)
                    continue
                if self._active_tenant.get(tenant_id, 0) >= self.per_tenant_limit:
                    self._tenant_order.append(tenant_id)
                    continue
                waiter = queue.popleft()
                self._waiting -= 1
                waiter.granted = True
                self._active_global += 1
                self._active_tenant[tenant_id] = self._active_tenant.get(tenant_id, 0) + 1
                if queue:
                    self._tenant_order.append(tenant_id)
                else:
                    self._drop_empty_queue_locked(tenant_id)
                waiter.ready.set_result(None)
                granted = True
                break
            if not granted:
                return

    async def _remove_or_release_waiter(self, waiter: _Waiter) -> None:
        async with self._lock:
            if waiter.granted:
                self._active_global -= 1
                remaining = self._active_tenant.get(waiter.tenant_id, 0) - 1
                if remaining > 0:
                    self._active_tenant[waiter.tenant_id] = remaining
                else:
                    self._active_tenant.pop(waiter.tenant_id, None)
                waiter.granted = False
                if len(self._tenant_order) > 1 and self._tenant_order[0] == waiter.tenant_id:
                    self._tenant_order.rotate(-1)
            else:
                queue = self._queues.get(waiter.tenant_id)
                if queue is not None:
                    try:
                        queue.remove(waiter)
                    except ValueError:
                        pass
                    else:
                        self._waiting -= 1
                    self._drop_empty_queue_locked(waiter.tenant_id)
                if not waiter.ready.done():
                    waiter.ready.cancel()
            self._dispatch_locked()

    @asynccontextmanager
    async def acquire(
        self,
        tenant_id: str,
        *,
        deadline_at: float,
    ) -> AsyncGenerator[BulkheadLease, None]:
        """Wait for and hold one slot until the context exits.

        ``deadline_at`` is an absolute ``time.monotonic()`` value shared with
        every later stage of the caller operation.
        """
        if not self.enabled:
            yield BulkheadLease(queue_wait_ms=0.0)
            return
        if not tenant_id:
            raise ValueError("bulkhead requires a tenant_id")
        loop = asyncio.get_running_loop()
        waiter = _Waiter(
            tenant_id=tenant_id,
            ready=loop.create_future(),
            enqueued_at=time.monotonic(),
        )
        async with self._lock:
            tenant_active = self._active_tenant.get(tenant_id, 0)
            immediately_runnable = (
                self._waiting == 0 and self._active_global < self.global_limit and tenant_active < self.per_tenant_limit
            )
            if immediately_runnable:
                waiter.granted = True
                self._active_global += 1
                self._active_tenant[tenant_id] = tenant_active + 1
                waiter.ready.set_result(None)
            else:
                tenant_waiting = self.waiting_for_tenant(tenant_id)
                if self._waiting >= self.max_queue or tenant_waiting >= self.per_tenant_queue_limit:
                    raise BulkheadQueueFullError(
                        message="bulkhead queue capacity exhausted",
                        waiting_global=self._waiting,
                        waiting_global_limit=self.max_queue,
                        waiting_tenant=tenant_waiting,
                        waiting_tenant_limit=self.per_tenant_queue_limit,
                    )
                existing_queue = self._queues.get(tenant_id)
                if existing_queue is None:
                    queue = deque[_Waiter]()
                    self._queues[tenant_id] = queue
                    self._tenant_order.append(tenant_id)
                else:
                    queue = existing_queue
                queue.append(waiter)
                self._waiting += 1
                self._dispatch_locked()
        try:
            remaining = deadline_at - time.monotonic()
            if remaining <= 0:
                raise BulkheadDeadlineExceededError(message="bulkhead deadline exceeded")
            try:
                async with asyncio.timeout(remaining):
                    await waiter.ready
            except TimeoutError as exc:
                raise BulkheadDeadlineExceededError(message="bulkhead deadline exceeded") from exc
            lease = BulkheadLease(queue_wait_ms=max(0.0, (time.monotonic() - waiter.enqueued_at) * 1000.0))
            yield lease
        finally:
            await asyncio.shield(self._remove_or_release_waiter(waiter))


__all__ = [
    "BulkheadDeadlineExceededError",
    "BulkheadLease",
    "BulkheadQueueFullError",
    "FairAsyncBulkhead",
]
