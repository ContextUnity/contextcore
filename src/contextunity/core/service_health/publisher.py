"""Fail-isolated process-local aggregation of bounded degradation signals."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from contextlib import suppress
from datetime import UTC, datetime
from typing import Protocol

from contextunity.core.logging import get_contextunit_logger

from .models import (
    ServiceDegradationSignal,
    ServiceDegradationSnapshot,
    ServiceDegradationTransition,
    ServiceRuntimeIdentity,
)

logger = get_contextunit_logger(__name__)


class ServiceDegradationSnapshotStore(Protocol):
    async def write_snapshot(self, snapshot: ServiceDegradationSnapshot) -> bool: ...

    async def close(self) -> None: ...


class ServiceDegradationPublisher:
    """Deduplicate transitions and project a bounded full snapshot."""

    def __init__(
        self,
        *,
        identity: ServiceRuntimeIdentity,
        store: ServiceDegradationSnapshotStore,
        max_active_signals: int,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._identity = identity
        self._store = store
        self._max_active_signals = max_active_signals
        self._clock = clock or (lambda: datetime.now(UTC))
        self._signals: dict[tuple[str, str], ServiceDegradationSignal] = {}
        self._revision = 0
        self._lock = asyncio.Lock()
        self._refresh_task: asyncio.Task[None] | None = None
        self._submission_task: asyncio.Task[None] | None = None
        self._pending_transitions: dict[tuple[str, str], ServiceDegradationTransition] = {}
        self._pending_reconciliation: tuple[ServiceDegradationTransition, ...] | None = None
        self._projection_dirty = False
        self._closed = False

    @property
    def identity(self) -> ServiceRuntimeIdentity:
        return self._identity

    def submit(self, transition: ServiceDegradationTransition) -> bool:
        """Coalesce one optional source transition without blocking its caller."""
        if self._closed:
            return False
        key = (transition.component, transition.code.value)
        self._pending_transitions[key] = transition
        task = self._submission_task
        if task is None or task.done():
            self._submission_task = asyncio.create_task(
                self._drain_submissions(),
                name=f"service-degradation-submit:{self._identity.service}",
            )
        return True

    def submit_reconciliation(
        self,
        transitions: tuple[ServiceDegradationTransition, ...],
    ) -> bool:
        """Coalesce a level-triggered source sample without delaying its owner."""
        if self._closed:
            return False
        self._pending_reconciliation = transitions
        task = self._submission_task
        if task is None or task.done():
            self._submission_task = asyncio.create_task(
                self._drain_submissions(),
                name=f"service-degradation-submit:{self._identity.service}",
            )
        return True

    async def report(self, transition: ServiceDegradationTransition) -> bool:
        """Apply one closed transition; projection failures never escape."""
        return await self.report_many((transition,))

    async def report_many(
        self,
        transitions: tuple[ServiceDegradationTransition, ...],
    ) -> bool:
        """Apply one typed source status as one full atomic process snapshot."""
        if not transitions:
            return True
        async with self._lock:
            prospective = set(self._signals)
            for transition in transitions:
                key = (transition.component, transition.code.value)
                if transition.state == "active":
                    prospective.add(key)
                else:
                    prospective.discard(key)
            if len(prospective) > self._max_active_signals:
                logger.warning(
                    "Service degradation signal cap reached for %s",
                    self._identity.service,
                )
                return False

            now = self._clock()
            for transition in transitions:
                key = (transition.component, transition.code.value)
                if transition.state == "active":
                    current = self._signals.get(key)
                    self._signals[key] = ServiceDegradationSignal(
                        component=transition.component,
                        code=transition.code,
                        severity=transition.severity,
                        first_observed_at=(current.first_observed_at if current is not None else now),
                        last_observed_at=now,
                        count=(min(current.count + 1, 1_000_000) if current is not None else 1),
                    )
                else:
                    self._signals.pop(key, None)
            self._revision += 1
            return await self._persist_current(now)

    async def reconcile(
        self,
        transitions: tuple[ServiceDegradationTransition, ...],
    ) -> bool:
        """Idempotently reconcile one level-triggered typed source status."""
        if not transitions:
            return True
        async with self._lock:
            changed = any(
                ((transition.component, transition.code.value) in self._signals) != (transition.state == "active")
                for transition in transitions
            )
            if not changed:
                return True
            prospective = set(self._signals)
            for transition in transitions:
                key = (transition.component, transition.code.value)
                if transition.state == "active":
                    prospective.add(key)
                else:
                    prospective.discard(key)
            if len(prospective) > self._max_active_signals:
                return False
            now = self._clock()
            for transition in transitions:
                key = (transition.component, transition.code.value)
                if transition.state == "active" and key not in self._signals:
                    self._signals[key] = ServiceDegradationSignal(
                        component=transition.component,
                        code=transition.code,
                        severity=transition.severity,
                        first_observed_at=now,
                        last_observed_at=now,
                        count=1,
                    )
                elif transition.state == "recovered":
                    self._signals.pop(key, None)
            self._revision += 1
            return await self._persist_current(now)

    def start(self, *, refresh_interval_seconds: float) -> None:
        if self._refresh_task is not None:
            raise RuntimeError("service degradation publisher already started")
        self._refresh_task = asyncio.create_task(
            self._refresh_loop(refresh_interval_seconds),
            name=f"service-degradation-refresh:{self._identity.service}",
        )

    async def close(self) -> None:
        self._closed = True
        for task in (self._refresh_task, self._submission_task):
            if task is not None:
                _ = task.cancel()
                with suppress(asyncio.CancelledError):
                    await task
        self._pending_transitions.clear()
        self._pending_reconciliation = None
        async with self._lock:
            if self._signals or self._projection_dirty:
                self._signals.clear()
                self._revision += 1
                _ = await self._persist_current(self._clock())
        await self._store.close()

    async def _drain_submissions(self) -> None:
        while self._pending_transitions or self._pending_reconciliation is not None:
            reconciliation = self._pending_reconciliation
            self._pending_reconciliation = None
            pending = tuple(self._pending_transitions.values())
            self._pending_transitions.clear()
            if reconciliation is not None:
                _ = await self.reconcile(reconciliation)
            if pending:
                _ = await self.report_many(pending)

    async def _refresh_loop(self, interval: float) -> None:
        while True:
            await asyncio.sleep(interval)
            async with self._lock:
                if self._signals or self._projection_dirty:
                    _ = await self._persist_current(self._clock())

    async def _persist_current(self, observed_at: datetime) -> bool:
        success = await self._write_current(observed_at)
        self._projection_dirty = not success
        return success

    async def _write_current(self, observed_at: datetime) -> bool:
        snapshot = ServiceDegradationSnapshot(
            identity=self._identity,
            revision=self._revision,
            updated_at=observed_at,
            signals=tuple(
                sorted(
                    self._signals.values(),
                    key=lambda item: item.code.value,
                )
            ),
        )
        try:
            return await self._store.write_snapshot(snapshot)
        except Exception as exc:
            logger.warning(
                "Service degradation projection failed for %s/%s: %s",
                self._identity.service,
                self._identity.instance,
                type(exc).__name__,
            )
            return False


__all__ = ["ServiceDegradationPublisher", "ServiceDegradationSnapshotStore"]
