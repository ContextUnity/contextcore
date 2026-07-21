"""Fakeredis proof for CU-455 runtime fencing, TTL, delete, and hint."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from uuid import UUID

import pytest
from contextunity.core.discovery.config import redis_key
from contextunity.core.discovery.services import _service_record
from contextunity.core.service_health import (
    ServiceDegradationCode,
    ServiceDegradationSignal,
    ServiceDegradationSnapshot,
    ServiceHealthTarget,
    ServiceRuntimeIdentity,
)
from contextunity.core.service_health.config import ResolvedServiceDegradationConfig
from contextunity.core.service_health.redis import (
    RedisServiceDegradationStore,
    SnapshotReadResult,
    snapshot_key,
)
from fakeredis import FakeAsyncRedis, FakeServer


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


@pytest.mark.asyncio
async def test_fakeredis_snapshot_is_ttl_bounded_hinted_deleted_and_runtime_fenced() -> None:
    server = FakeServer()
    admin = FakeAsyncRedis(server=server, decode_responses=True)
    store_client = FakeAsyncRedis(server=server, decode_responses=True)
    assert await admin.ping()

    config = ResolvedServiceDegradationConfig(
        environment="local",
        redis_url="redis://fakeredis/0",
        snapshot_ttl_seconds=15,
        refresh_interval_seconds=2,
        connect_timeout_seconds=0.5,
        io_timeout_seconds=1.0,
        max_active_signals=16,
        max_snapshot_bytes=8192,
    )
    store = RedisServiceDegradationStore(client=store_client, config=config)
    old = _identity(UUID("00000000-0000-4000-8000-000000000001"))
    new = _identity(UUID("00000000-0000-4000-8000-000000000002"))
    registry = redis_key("worker", "default")
    await admin.setex(
        registry,
        30,
        _service_record(
            service="worker",
            instance="default",
            endpoint="127.0.0.1:50052",
            tenants=[],
            metadata=None,
            identity=old,
        ),
    )
    now = datetime.now(UTC)
    active = ServiceDegradationSnapshot(
        identity=old,
        revision=1,
        updated_at=now,
        signals=(
            ServiceDegradationSignal(
                component="brain_embedding",
                code=ServiceDegradationCode.BRAIN_EMBEDDING_VECTOR_BACKEND_UNAVAILABLE,
                severity="critical",
                first_observed_at=now,
                last_observed_at=now,
                count=1,
            ),
        ),
    )
    channel = "contextunity:service-degradation:v1:local:changed"
    pubsub = admin.pubsub()
    await pubsub.subscribe(channel)
    _ = await pubsub.get_message(ignore_subscribe_messages=False, timeout=1)
    assert await store.write_snapshot(active)
    assert await store.read_snapshot(old) == SnapshotReadResult.valid(active)
    ttl = await admin.ttl(snapshot_key(old))
    assert 0 < ttl <= config.snapshot_ttl_seconds
    message = None
    for _ in range(20):
        message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=0.1)
        if message is not None:
            break
        await asyncio.sleep(0.01)
    assert message is not None
    assert json.loads(message["data"])["identity"]["runtime_id"] == str(old.runtime_id)

    await admin.setex(
        registry,
        30,
        _service_record(
            service="worker",
            instance="default",
            endpoint="127.0.0.1:50052",
            tenants=[],
            metadata=None,
            identity=new,
        ),
    )
    assert not await store.write_snapshot(active.model_copy(update={"revision": 2}))
    assert await store.read_snapshot(old) == SnapshotReadResult.stale_runtime()
    assert await admin.exists(snapshot_key(old)) == 1

    await admin.setex(
        registry,
        30,
        _service_record(
            service="worker",
            instance="default",
            endpoint="127.0.0.1:50052",
            tenants=[],
            metadata=None,
            identity=old,
        ),
    )
    recovered = active.model_copy(update={"revision": 3, "signals": ()})
    assert await store.write_snapshot(recovered)
    assert await admin.exists(snapshot_key(old)) == 1
    assert await store.read_snapshot(old) == SnapshotReadResult.valid(recovered)
    await admin.delete(registry)
    assert not await store.write_snapshot(active.model_copy(update={"revision": 4}))

    await pubsub.aclose()
    await store.close()
    await admin.aclose()
