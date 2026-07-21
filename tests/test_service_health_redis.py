"""CU-455 runtime-fenced service registration and Redis wire contracts."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from uuid import UUID

import pytest
from contextunity.core.discovery.async_client import (
    RedisCommandError,
    RedisCommandPart,
    RedisResponse,
    _read_response,
)
from contextunity.core.discovery.services import (
    _claim_registration,
    _refresh_registration_if_current,
    _release_registration_if_current,
    _service_record,
)
from contextunity.core.service_health import (
    ServiceDegradationCode,
    ServiceDegradationSignal,
    ServiceDegradationSnapshot,
    ServiceDegradationTransition,
    ServiceHealthTarget,
    ServiceRuntimeIdentity,
)
from contextunity.core.service_health.config import ResolvedServiceDegradationConfig
from contextunity.core.service_health.publisher import ServiceDegradationPublisher
from contextunity.core.service_health.redis import (
    RedisServiceDegradationStore,
    SnapshotReadResult,
    snapshot_key,
)

_OLD = UUID("00000000-0000-4000-8000-000000000001")
_NEW = UUID("00000000-0000-4000-8000-000000000002")
_NOW = datetime(2026, 7, 20, 15, 30, tzinfo=UTC)


def _identity(runtime_id: UUID) -> ServiceRuntimeIdentity:
    return ServiceRuntimeIdentity(
        environment="local",
        service="worker",
        instance="default",
        runtime_id=runtime_id,
        target=ServiceHealthTarget(
            transport="grpc",
            health_service="contextunity.worker.WorkerService",
        ),
    )


class _FakeAsyncRedis:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    async def setex(self, key: str, _ttl: int, value: str) -> RedisResponse:
        self.values[key] = value
        return "OK"

    async def eval(
        self,
        script: str,
        _numkeys: int,
        key: RedisCommandPart,
        runtime_id: RedisCommandPart,
        *args: RedisCommandPart,
    ) -> RedisResponse:
        assert isinstance(key, str) and isinstance(runtime_id, str)
        raw = self.values.get(key)
        current = json.loads(raw) if raw is not None else {}
        if current.get("runtime_id") != runtime_id:
            return 0
        if "redis.call('del'" in script.lower():
            self.values.pop(key, None)
            return 1
        value, _ttl = args
        assert isinstance(value, str)
        self.values[key] = value
        return 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "wire",
    (
        b"$70000\r\n",
        b"$-2\r\n",
        (b"*1\r\n" * 17) + b"$0\r\n\r\n",
    ),
)
async def test_resp_decoder_rejects_oversized_invalid_or_deep_frames_before_body(
    wire: bytes,
) -> None:
    reader = asyncio.StreamReader()
    reader.feed_data(wire)
    reader.feed_eof()
    with pytest.raises(RedisCommandError):
        await _read_response(reader)


@pytest.mark.asyncio
async def test_registry_refresh_and_release_are_fenced_by_runtime_uuid() -> None:
    redis = _FakeAsyncRedis()
    key = "contextunity:services:worker:default"
    old_value = _service_record(
        service="worker",
        instance="default",
        endpoint="127.0.0.1:50052",
        tenants=[],
        metadata=None,
        identity=_identity(_OLD),
    )
    new_value = _service_record(
        service="worker",
        instance="default",
        endpoint="127.0.0.1:50052",
        tenants=[],
        metadata=None,
        identity=_identity(_NEW),
    )

    await _claim_registration(redis, key=key, value=old_value, ttl=30)
    assert await _refresh_registration_if_current(
        redis,
        key=key,
        runtime_id=_OLD,
        value=old_value,
        ttl=30,
    )

    await _claim_registration(redis, key=key, value=new_value, ttl=30)
    assert not await _refresh_registration_if_current(
        redis,
        key=key,
        runtime_id=_OLD,
        value=old_value,
        ttl=30,
    )
    assert json.loads(redis.values[key])["runtime_id"] == str(_NEW)
    assert not await _release_registration_if_current(redis, key=key, runtime_id=_OLD)
    assert key in redis.values
    assert await _release_registration_if_current(redis, key=key, runtime_id=_NEW)
    assert key not in redis.values


class _ProjectionRedis:
    def __init__(self, registry_value: str) -> None:
        self.registry_value = registry_value
        self.projected: dict[str, str] = {}

    async def eval(
        self,
        _script: str,
        numkeys: int,
        *args: RedisCommandPart,
    ) -> RedisResponse:
        if numkeys == 2:
            registry_key, projection_key, runtime_id = args
            assert isinstance(registry_key, str) and isinstance(projection_key, str)
            if json.loads(self.registry_value).get("runtime_id") != runtime_id:
                return ["stale_runtime"]
            payload = self.projected.get(projection_key)
            return ["snapshot", payload] if payload is not None else ["absent"]
        registry_key, projection_key, _channel, runtime_id, _ttl, payload, _hint = args
        assert isinstance(registry_key, str) and isinstance(projection_key, str)
        if json.loads(self.registry_value).get("runtime_id") != runtime_id:
            return 0
        assert isinstance(payload, str)
        self.projected[projection_key] = payload
        return 1

    async def get(self, key: str) -> str | None:
        return self.projected.get(key)

    async def aclose(self) -> None:
        return None


@pytest.mark.asyncio
async def test_projection_store_rejects_stale_runtime_and_persists_empty_recovery_marker() -> None:
    config = ResolvedServiceDegradationConfig(
        environment="local",
        redis_url="redis://localhost:6379",
        snapshot_ttl_seconds=60,
        refresh_interval_seconds=10,
        connect_timeout_seconds=0.5,
        io_timeout_seconds=1.0,
        max_active_signals=16,
        max_snapshot_bytes=8192,
    )
    client = _ProjectionRedis(
        _service_record(
            service="worker",
            instance="default",
            endpoint="127.0.0.1:50052",
            tenants=[],
            metadata=None,
            identity=_identity(_OLD),
        )
    )
    store = RedisServiceDegradationStore(client=client, config=config)
    signal = ServiceDegradationSignal(
        component="brain_embedding",
        code=ServiceDegradationCode.BRAIN_EMBEDDING_VECTOR_BACKEND_UNAVAILABLE,
        severity="critical",
        first_observed_at=_NOW,
        last_observed_at=_NOW,
        count=1,
    )
    active = ServiceDegradationSnapshot(identity=_identity(_OLD), revision=1, updated_at=_NOW, signals=(signal,))
    assert await store.write_snapshot(active)
    assert snapshot_key(_identity(_OLD)) in client.projected

    client.registry_value = _service_record(
        service="worker",
        instance="default",
        endpoint="127.0.0.1:50052",
        tenants=[],
        metadata=None,
        identity=_identity(_NEW),
    )
    assert not await store.write_snapshot(active.model_copy(update={"revision": 2}))
    client.registry_value = _service_record(
        service="worker",
        instance="default",
        endpoint="127.0.0.1:50052",
        tenants=[],
        metadata=None,
        identity=_identity(_OLD),
    )
    empty = active.model_copy(update={"revision": 3, "signals": ()})
    assert await store.write_snapshot(empty)
    assert snapshot_key(_identity(_OLD)) in client.projected
    assert await store.read_snapshot(_identity(_OLD), now=_NOW) == SnapshotReadResult.valid(empty)


class _AtomicReadRedis:
    def __init__(self, registry_value: str, snapshot: str | None) -> None:
        self.registry_value = registry_value
        self.snapshot = snapshot

    async def eval(
        self,
        _script: str,
        _numkeys: int,
        *_args: RedisCommandPart,
    ) -> RedisResponse:
        runtime_id = _args[-1]
        assert isinstance(runtime_id, str)
        if json.loads(self.registry_value).get("runtime_id") != runtime_id:
            return ["stale_runtime"]
        return ["snapshot", self.snapshot] if self.snapshot is not None else ["absent"]

    async def get(self, _key: str) -> str | None:
        raise AssertionError("snapshot reads must be registry-fenced Lua operations")

    async def aclose(self) -> None:
        return None


@pytest.mark.asyncio
async def test_snapshot_read_atomically_rejects_replaced_runtime_and_distinguishes_invalid_payload() -> None:
    config = ResolvedServiceDegradationConfig(
        environment="local",
        redis_url="redis://localhost:6379",
        snapshot_ttl_seconds=60,
        refresh_interval_seconds=10,
        connect_timeout_seconds=0.5,
        io_timeout_seconds=1.0,
        max_active_signals=16,
        max_snapshot_bytes=8192,
    )
    active = ServiceDegradationSnapshot(identity=_identity(_OLD), revision=1, updated_at=_NOW, signals=())
    stale_store = RedisServiceDegradationStore(
        client=_AtomicReadRedis(
            _service_record(
                service="worker",
                instance="default",
                endpoint="127.0.0.1:50052",
                tenants=[],
                metadata=None,
                identity=_identity(_NEW),
            ),
            active.model_dump_json(),
        ),
        config=config,
    )
    assert await stale_store.read_snapshot(_identity(_OLD)) == SnapshotReadResult.stale_runtime()

    invalid_store = RedisServiceDegradationStore(
        client=_AtomicReadRedis(
            _service_record(
                service="worker",
                instance="default",
                endpoint="127.0.0.1:50052",
                tenants=[],
                metadata=None,
                identity=_identity(_OLD),
            ),
            "{not-json}",
        ),
        config=config,
    )
    assert await invalid_store.read_snapshot(_identity(_OLD)) == SnapshotReadResult.invalid()


class _SnapshotStore:
    def __init__(
        self,
        *,
        succeeds: bool = True,
        results: list[bool] | None = None,
    ) -> None:
        self.succeeds = succeeds
        self.results = list(results or [])
        self.snapshots: list[ServiceDegradationSnapshot] = []
        self.closed = False

    async def write_snapshot(self, snapshot: ServiceDegradationSnapshot) -> bool:
        self.snapshots.append(snapshot)
        return self.results.pop(0) if self.results else self.succeeds

    async def close(self) -> None:
        self.closed = True


@pytest.mark.asyncio
async def test_publisher_deduplicates_and_recovered_removes_signal() -> None:
    store = _SnapshotStore()
    publisher = ServiceDegradationPublisher(
        identity=_identity(_OLD), store=store, max_active_signals=16, clock=lambda: _NOW
    )
    active = ServiceDegradationTransition(
        component="brain_embedding",
        code=ServiceDegradationCode.BRAIN_EMBEDDING_VECTOR_BACKEND_UNAVAILABLE,
        severity="critical",
        state="active",
    )
    recovered = active.model_copy(update={"state": "recovered"})

    assert await publisher.report(active)
    assert await publisher.report(active)
    assert await publisher.report(recovered)
    first, second, third = store.snapshots
    assert first.signals[0].count == 1
    assert second.signals[0].count == 2
    assert third.signals == ()
    assert [first.revision, second.revision, third.revision] == [1, 2, 3]
    await publisher.close()
    assert store.closed


@pytest.mark.asyncio
async def test_publisher_reports_one_full_snapshot_for_one_typed_status_batch() -> None:
    store = _SnapshotStore()
    publisher = ServiceDegradationPublisher(
        identity=_identity(_OLD), store=store, max_active_signals=16, clock=lambda: _NOW
    )
    transitions = tuple(
        ServiceDegradationTransition(
            component="fault_spool",
            code=code,
            severity=severity,
            state="active",
        )
        for code, severity in (
            (ServiceDegradationCode.ROUTER_FAULT_SPOOL_BACKLOG, "warning"),
            (ServiceDegradationCode.ROUTER_FAULT_SPOOL_FULL, "critical"),
        )
    )
    assert await publisher.reconcile(transitions)
    assert await publisher.reconcile(transitions)
    assert len(store.snapshots) == 1
    assert {signal.code for signal in store.snapshots[0].signals} == {
        ServiceDegradationCode.ROUTER_FAULT_SPOOL_BACKLOG,
        ServiceDegradationCode.ROUTER_FAULT_SPOOL_FULL,
    }


@pytest.mark.asyncio
async def test_failed_recovery_delete_is_retried_until_projection_is_clean() -> None:
    store = _SnapshotStore(results=[True, False, True])
    publisher = ServiceDegradationPublisher(
        identity=_identity(_OLD), store=store, max_active_signals=16, clock=lambda: _NOW
    )
    active = ServiceDegradationTransition(
        component="brain_embedding",
        code=ServiceDegradationCode.BRAIN_EMBEDDING_VECTOR_BACKEND_UNAVAILABLE,
        severity="critical",
        state="active",
    )
    assert await publisher.report(active)
    assert not await publisher.report(active.model_copy(update={"state": "recovered"}))
    publisher.start(refresh_interval_seconds=0.01)
    await asyncio.sleep(0.03)
    await publisher.close()
    assert len(store.snapshots) == 3
    assert store.snapshots[-1].signals == ()


@pytest.mark.asyncio
async def test_publisher_submit_returns_before_a_stalled_projection_write() -> None:
    class _SlowStore(_SnapshotStore):
        def __init__(self) -> None:
            super().__init__()
            self.entered = asyncio.Event()

        async def write_snapshot(self, snapshot: ServiceDegradationSnapshot) -> bool:
            self.snapshots.append(snapshot)
            if len(self.snapshots) == 1:
                self.entered.set()
                await asyncio.Event().wait()
            return True

    store = _SlowStore()
    publisher = ServiceDegradationPublisher(
        identity=_identity(_OLD), store=store, max_active_signals=16, clock=lambda: _NOW
    )
    transition = ServiceDegradationTransition(
        component="brain_embedding",
        code=ServiceDegradationCode.BRAIN_EMBEDDING_VECTOR_BACKEND_UNAVAILABLE,
        severity="critical",
        state="active",
    )
    assert publisher.submit(transition)
    await asyncio.wait_for(store.entered.wait(), timeout=0.1)
    await asyncio.wait_for(publisher.close(), timeout=0.1)
    assert store.closed


@pytest.mark.asyncio
async def test_publisher_failure_is_fail_isolated() -> None:
    store = _SnapshotStore(succeeds=False)
    publisher = ServiceDegradationPublisher(
        identity=_identity(_OLD), store=store, max_active_signals=16, clock=lambda: _NOW
    )
    transition = ServiceDegradationTransition(
        component="brain_embedding",
        code=ServiceDegradationCode.BRAIN_EMBEDDING_VECTOR_BACKEND_UNAVAILABLE,
        severity="critical",
        state="active",
    )
    assert not await publisher.report(transition)
    await publisher.close()


def test_service_record_contains_closed_runtime_target_without_tenant_health_data() -> None:
    payload = json.loads(
        _service_record(
            service="worker",
            instance="default",
            endpoint="127.0.0.1:50052",
            tenants=["tenant-a"],
            metadata={"port": 50052},
            identity=_identity(_OLD),
        )
    )
    assert payload["runtime_id"] == str(_OLD)
    assert payload["transport"] == "grpc"
    assert payload["health_service"] == "contextunity.worker.WorkerService"
    assert "health_path" not in payload
    assert "environment" not in payload


pytestmark = pytest.mark.unit
