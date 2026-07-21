"""CU-455 full-state reconciliation keeps liveness independent from degradation."""

from __future__ import annotations

import asyncio
import socket
import time
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from unittest.mock import AsyncMock
from uuid import UUID

import pytest
from contextunity.core.config import SharedConfig
from contextunity.core.discovery import ServiceInfo, discover_services
from contextunity.core.service_health import (
    ServiceDegradationCode,
    ServiceDegradationSignal,
    ServiceDegradationSnapshot,
    ServiceHealthTarget,
    ServiceRuntimeIdentity,
)
from contextunity.core.service_health import reader as reader_module
from contextunity.core.service_health.reader import ServiceHealthReader
from contextunity.core.service_health.redis import SnapshotReadResult

_RUNTIME = UUID("00000000-0000-4000-8000-000000000455")
_NOW = datetime(2026, 7, 20, 16, 0, tzinfo=UTC)
_IDENTITY = ServiceRuntimeIdentity(
    environment="local",
    service="worker",
    instance="default",
    runtime_id=_RUNTIME,
    target=ServiceHealthTarget(
        transport="grpc",
        health_service="contextunity.worker.WorkerService",
    ),
)


class _Store:
    def __init__(
        self,
        snapshots: list[SnapshotReadResult | Exception],
    ) -> None:
        self._snapshots = snapshots

    async def read_snapshot(self, _identity: ServiceRuntimeIdentity) -> SnapshotReadResult:
        result = self._snapshots.pop(0)
        if isinstance(result, Exception):
            raise result
        return result

    async def close(self) -> None:
        return None


@pytest.mark.asyncio
async def test_reader_reconciles_active_then_observed_recovery_without_changing_liveness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    row = ServiceInfo(
        service="worker",
        instance="default",
        endpoint="127.0.0.1:50052",
        runtime_id=_RUNTIME,
        health_target=_IDENTITY.target,
    )
    snapshot = ServiceDegradationSnapshot(
        identity=_IDENTITY,
        revision=1,
        updated_at=_NOW,
        signals=(
            ServiceDegradationSignal(
                component="brain_embedding",
                code=ServiceDegradationCode.BRAIN_EMBEDDING_VECTOR_BACKEND_UNAVAILABLE,
                severity="critical",
                first_observed_at=_NOW,
                last_observed_at=_NOW,
                count=1,
            ),
        ),
    )
    store = _Store(
        [
            SnapshotReadResult.valid(snapshot),
            ConnectionError("Redis unavailable"),
            SnapshotReadResult.valid(snapshot.model_copy(update={"revision": 2, "signals": ()})),
        ]
    )

    monkeypatch.setattr(reader_module, "discover_services", lambda **_kwargs: [row])

    async def _store_factory(_config: object) -> _Store:
        return store

    monkeypatch.setattr(reader_module, "create_redis_degradation_store", _store_factory)
    config = SharedConfig.model_validate(
        {
            "local_mode": True,
            "redis": {"enabled": True, "url": "redis://localhost:6379"},
            "service_degradation": {"enabled": True, "environment": "local"},
        }
    )
    reader = ServiceHealthReader(config)
    reader._probe = AsyncMock(return_value="serving")

    active = (await reader.read())[0]
    unavailable = (await reader.read())[0]
    recovered = (await reader.read())[0]
    assert active.liveness == unavailable.liveness == recovered.liveness == "serving"
    assert active.degradation == "active"
    assert unavailable.degradation == "unknown"
    assert recovered.degradation == "recovered"
    assert recovered.signals == ()


@pytest.mark.asyncio
async def test_reader_skips_one_malformed_registry_row_without_losing_valid_peer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    valid = ServiceInfo(
        service="worker",
        instance="default",
        endpoint="127.0.0.1:50052",
        runtime_id=_RUNTIME,
        health_target=_IDENTITY.target,
    )
    malformed = ServiceInfo(
        service="worker",
        instance="INVALID/INSTANCE",
        endpoint="127.0.0.1:50052",
        runtime_id=_RUNTIME,
        health_target=_IDENTITY.target,
    )
    monkeypatch.setattr(
        reader_module,
        "discover_services",
        lambda **_kwargs: [malformed, valid],
    )
    config = SharedConfig.model_validate(
        {"local_mode": True, "redis": {"enabled": True, "url": "redis://localhost:6379"}}
    )
    reader = ServiceHealthReader(config)
    reader._probe = AsyncMock(return_value="serving")
    views = await reader.read()
    assert len(views) == 1
    assert views[0].identity is not None
    assert views[0].identity.instance == "default"


@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint", ["8.8.8.8:80", "169.254.169.254:80"])
async def test_reader_rejects_non_private_registry_endpoint_before_probe_io(
    endpoint: str,
) -> None:
    row = ServiceInfo(
        service="forge",
        instance="default",
        endpoint=endpoint,
        runtime_id=_RUNTIME,
        health_target=ServiceHealthTarget(transport="http", health_path="/healthz"),
    )
    reader = ServiceHealthReader(SharedConfig())
    assert await reader._probe(row) == "unavailable"


@pytest.mark.asyncio
async def test_endpoint_resolution_uses_a_bounded_owned_resolver(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _slow_lookup(*_args: object, **_kwargs: object) -> list[object]:
        time.sleep(0.05)
        return []

    monkeypatch.setattr(socket, "getaddrinfo", _slow_lookup)
    monkeypatch.setattr(reader_module, "_DNS_RESOLUTION_TIMEOUT_SECONDS", 0.01)
    with pytest.raises(TimeoutError):
        await reader_module._resolve_safe_endpoint("worker.internal:50052")


@pytest.mark.asyncio
async def test_grpc_probe_connects_to_validated_address_without_dns_re_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    row = ServiceInfo(
        service="worker",
        instance="default",
        endpoint="worker.internal:50052",
        runtime_id=_RUNTIME,
        health_target=_IDENTITY.target,
    )
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 50052))],
    )
    captured: dict[str, str | None] = {}

    class _Channel:
        async def close(self) -> None:
            return None

    class _Stub:
        async def Check(self, _request: object, *, timeout: float) -> object:
            assert timeout == 1.0
            return type("Response", (), {"status": 1})()

    def _channel(
        target: str,
        *,
        config: SharedConfig,
        tls_server_name_override: str | None = None,
    ) -> _Channel:
        captured["target"] = target
        captured["server_name"] = tls_server_name_override
        return _Channel()

    monkeypatch.setattr(reader_module, "create_channel", _channel)
    monkeypatch.setattr(reader_module.health_pb2_grpc, "HealthStub", lambda _channel: _Stub())
    reader = ServiceHealthReader(SharedConfig())
    assert await reader._probe(row) == "serving"
    assert captured == {"target": "127.0.0.1:50052", "server_name": "worker.internal"}


@pytest.mark.asyncio
async def test_snapshot_absence_never_invents_recovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    row = ServiceInfo(
        service="worker",
        instance="default",
        endpoint="127.0.0.1:50052",
        runtime_id=_RUNTIME,
        health_target=_IDENTITY.target,
    )
    signal = ServiceDegradationSignal(
        component="brain_embedding",
        code=ServiceDegradationCode.BRAIN_EMBEDDING_VECTOR_BACKEND_UNAVAILABLE,
        severity="critical",
        first_observed_at=_NOW,
        last_observed_at=_NOW,
        count=1,
    )
    active = ServiceDegradationSnapshot(identity=_IDENTITY, revision=1, updated_at=_NOW, signals=(signal,))
    store = _Store([SnapshotReadResult.valid(active), SnapshotReadResult.absent()])
    monkeypatch.setattr(reader_module, "discover_services", lambda **_kwargs: [row])

    async def _store_factory(_config: object) -> _Store:
        return store

    monkeypatch.setattr(reader_module, "create_redis_degradation_store", _store_factory)
    reader = ServiceHealthReader(
        SharedConfig.model_validate(
            {
                "local_mode": True,
                "redis": {"enabled": True, "url": "redis://localhost:6379"},
                "service_degradation": {"enabled": True, "environment": "local"},
            }
        )
    )
    reader._probe = AsyncMock(return_value="serving")
    assert (await reader.read())[0].degradation == "active"
    assert (await reader.read())[0].degradation == "unknown"


@pytest.mark.asyncio
async def test_grpc_channel_construction_failure_is_one_peer_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    row = ServiceInfo(
        service="worker",
        instance="default",
        endpoint="127.0.0.1:50052",
        runtime_id=_RUNTIME,
        health_target=_IDENTITY.target,
    )
    monkeypatch.setattr(
        reader_module,
        "create_channel",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("bad TLS path")),
    )
    assert await ServiceHealthReader(SharedConfig())._probe(row) == "unavailable"


@pytest.mark.asyncio
async def test_invalid_snapshot_never_becomes_recovered_and_disappeared_runtime_is_pruned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    row = ServiceInfo(
        service="worker",
        instance="default",
        endpoint="127.0.0.1:50052",
        runtime_id=_RUNTIME,
        health_target=_IDENTITY.target,
    )
    signal = ServiceDegradationSignal(
        component="brain_embedding",
        code=ServiceDegradationCode.BRAIN_EMBEDDING_VECTOR_BACKEND_UNAVAILABLE,
        severity="critical",
        first_observed_at=_NOW,
        last_observed_at=_NOW,
        count=1,
    )
    active = ServiceDegradationSnapshot(identity=_IDENTITY, revision=1, updated_at=_NOW, signals=(signal,))
    store = _Store([SnapshotReadResult.valid(active), SnapshotReadResult.invalid()])
    rows: list[list[ServiceInfo]] = [[row], [row], []]
    monkeypatch.setattr(reader_module, "discover_services", lambda **_kwargs: rows.pop(0))

    async def _store_factory(_config: object) -> _Store:
        return store

    monkeypatch.setattr(reader_module, "create_redis_degradation_store", _store_factory)
    config = SharedConfig.model_validate(
        {
            "local_mode": True,
            "redis": {"enabled": True, "url": "redis://localhost:6379"},
            "service_degradation": {"enabled": True, "environment": "local"},
        }
    )
    reader = ServiceHealthReader(config)
    reader._probe = AsyncMock(return_value="serving")
    assert (await reader.read())[0].degradation == "active"
    assert (await reader.read())[0].degradation == "unknown"
    assert set(reader._previous_active) == {(_IDENTITY.service, _IDENTITY.instance, str(_RUNTIME))}
    assert await reader.read() == ()
    # A capped discovery sample cannot prove the runtime disappeared.
    assert set(reader._previous_active) == {(_IDENTITY.service, _IDENTITY.instance, str(_RUNTIME))}


@pytest.mark.asyncio
async def test_forge_health_probe_does_not_follow_redirects() -> None:
    redirected = False

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            nonlocal redirected
            if self.path == "/healthz":
                self.send_response(302)
                self.send_header("Location", "/redirected")
                self.end_headers()
                return
            redirected = True
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')

        def log_message(self, _format: str, *_args: object) -> None:
            return None

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    row = ServiceInfo(
        service="forge",
        instance="default",
        endpoint=f"127.0.0.1:{server.server_port}",
        runtime_id=_RUNTIME,
        health_target=ServiceHealthTarget(transport="http", health_path="/healthz"),
    )
    try:
        reader = ServiceHealthReader(SharedConfig())
        assert await reader._probe(row) == "not_serving"
        assert not redirected
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)


@pytest.mark.asyncio
async def test_reader_isolates_one_failed_probe_and_returns_completed_peers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = ServiceInfo(
        service="worker",
        instance="first",
        endpoint="127.0.0.1:50052",
        runtime_id=_RUNTIME,
        health_target=_IDENTITY.target,
    )
    second = ServiceInfo(
        service="worker",
        instance="second",
        endpoint="127.0.0.1:50052",
        runtime_id=UUID("00000000-0000-4000-8000-000000000456"),
        health_target=_IDENTITY.target,
    )
    monkeypatch.setattr(reader_module, "discover_services", lambda **_kwargs: [first, second])
    reader = ServiceHealthReader(SharedConfig())

    async def _probe(row: ServiceInfo) -> str:
        if row.instance == "first":
            raise RuntimeError("broken TLS configuration")
        return "serving"

    reader._probe = _probe
    views = await reader.read()
    assert [(view.identity.instance, view.liveness) for view in views if view.identity] == [
        ("first", "unavailable"),
        ("second", "serving"),
    ]


@pytest.mark.asyncio
async def test_reader_returns_fast_peer_when_another_probe_exceeds_global_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    slow = ServiceInfo(
        service="worker",
        instance="slow",
        endpoint="127.0.0.1:50052",
        runtime_id=_RUNTIME,
        health_target=_IDENTITY.target,
    )
    fast = ServiceInfo(
        service="worker",
        instance="fast",
        endpoint="127.0.0.1:50052",
        runtime_id=UUID("00000000-0000-4000-8000-000000000456"),
        health_target=_IDENTITY.target,
    )
    monkeypatch.setattr(reader_module, "discover_services", lambda **_kwargs: [slow, fast])
    monkeypatch.setattr(reader_module, "_READ_TIMEOUT_SECONDS", 0.01)
    reader = ServiceHealthReader(SharedConfig())

    async def _probe(row: ServiceInfo) -> str:
        if row.instance == "slow":
            await asyncio.sleep(60)
        return "serving"

    reader._probe = _probe
    views = await reader.read()
    assert [view.identity.instance for view in views if view.identity] == ["fast"]


def test_health_discovery_rejects_unbounded_or_invalid_result_ceiling() -> None:
    with pytest.raises(ValueError, match="max_results"):
        discover_services(max_results=0)
    with pytest.raises(ValueError, match="max_results"):
        discover_services(max_results=257)


@pytest.mark.asyncio
async def test_reader_reuses_store_reconnects_after_failure_and_closes_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    row = ServiceInfo(
        service="worker",
        instance="default",
        endpoint="127.0.0.1:50052",
        runtime_id=_RUNTIME,
        health_target=_IDENTITY.target,
    )
    created: list[_Store] = []

    class _ClosingStore(_Store):
        def __init__(self, snapshots: list[SnapshotReadResult | Exception]) -> None:
            super().__init__(snapshots)
            self.close_calls = 0

        async def close(self) -> None:
            self.close_calls += 1

    first = _ClosingStore([ConnectionError("redis unavailable")])
    second = _ClosingStore([SnapshotReadResult.invalid(), SnapshotReadResult.invalid()])

    async def _store_factory(_config: object) -> _ClosingStore:
        store = first if not created else second
        created.append(store)
        return store

    monkeypatch.setattr(reader_module, "discover_services", lambda **_kwargs: [row])
    monkeypatch.setattr(reader_module, "create_redis_degradation_store", _store_factory)
    reader = ServiceHealthReader(
        SharedConfig.model_validate(
            {
                "local_mode": True,
                "redis": {"enabled": True, "url": "redis://localhost:6379"},
                "service_degradation": {"enabled": True, "environment": "local"},
            }
        )
    )
    reader._probe = AsyncMock(return_value="serving")

    assert (await reader.read())[0].degradation == "unknown"
    assert (await reader.read())[0].degradation == "unknown"
    assert (await reader.read())[0].degradation == "unknown"
    await reader.aclose()

    assert created == [first, second]
    assert first.close_calls == 1
    assert second.close_calls == 1


@pytest.mark.asyncio
async def test_reader_gate_off_reports_no_invented_registry_state() -> None:
    reader = ServiceHealthReader(SharedConfig())
    assert await reader.read() == ()


pytestmark = pytest.mark.unit
