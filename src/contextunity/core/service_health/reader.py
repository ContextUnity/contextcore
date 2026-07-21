"""Reconciled operator reader: registry identity, transport health, then snapshot."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from functools import partial
from http.client import HTTPConnection
from typing import Protocol, runtime_checkable
from urllib.parse import urlsplit

import grpc
from contextunity.core.config import SharedConfig
from contextunity.core.discovery import ServiceInfo, discover_services
from contextunity.core.grpc_utils import create_channel
from contextunity.core.logging import get_contextunit_logger
from contextunity.core.parsing import json_loads
from grpc_health.v1 import health_pb2, health_pb2_grpc
from pydantic import TypeAdapter, ValidationError

from .config import ResolvedServiceDegradationConfig, resolve_service_degradation_config
from .models import ServiceHealthView, ServiceLivenessState, ServiceName, ServiceRuntimeIdentity
from .redis import SnapshotReadResult, create_redis_degradation_store

logger = get_contextunit_logger(__name__)


_SERVICE_NAME_ADAPTER: TypeAdapter[ServiceName] = TypeAdapter(ServiceName)


@dataclass(frozen=True, slots=True)
class _ResolvedEndpoint:
    host: str
    port: int
    address: str

    @property
    def grpc_target(self) -> str:
        return f"[{self.address}]:{self.port}" if ":" in self.address else f"{self.address}:{self.port}"


_DNS_RESOLUTION_TIMEOUT_SECONDS = 1.0
_RESOLVER_EXECUTOR = ThreadPoolExecutor(max_workers=4, thread_name_prefix="service-health-dns")


async def _resolve_safe_endpoint(endpoint: str) -> _ResolvedEndpoint:
    if "://" in endpoint or "/" in endpoint or "@" in endpoint:
        raise ValueError("service endpoint must be host:port only")
    try:
        parsed = urlsplit(f"//{endpoint}")
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError("service endpoint has an invalid port") from exc
    if parsed.query or parsed.fragment or parsed.path:
        raise ValueError("service endpoint cannot contain path, query, or fragment")
    if not host or port is None or not 1 <= port <= 65_535:
        raise ValueError("service endpoint requires a bounded host and port")
    loop = asyncio.get_running_loop()
    infos = await asyncio.wait_for(
        loop.run_in_executor(
            _RESOLVER_EXECUTOR,
            partial(socket.getaddrinfo, host, port, type=socket.SOCK_STREAM),
        ),
        timeout=_DNS_RESOLUTION_TIMEOUT_SECONDS,
    )
    if not infos:
        raise ValueError("service endpoint did not resolve")
    addresses: list[str] = []
    for info in infos:
        sockaddr = info[4]
        address_text = str(sockaddr[0]).split("%", maxsplit=1)[0]
        address = ipaddress.ip_address(address_text)
        if (
            address.is_global
            or address.is_multicast
            or address.is_unspecified
            or address.is_reserved
            or address.is_link_local
            or not (address.is_private or address.is_loopback)
        ):
            raise ValueError("service endpoint resolves outside the private service network")
        if address_text not in addresses:
            addresses.append(address_text)
    return _ResolvedEndpoint(host=host, port=port, address=addresses[0])


@runtime_checkable
class _HealthStub(Protocol):
    async def Check(
        self,
        request: health_pb2.HealthCheckRequest,
        *,
        timeout: float,
    ) -> health_pb2.HealthCheckResponse: ...


class _SnapshotStore(Protocol):
    async def read_snapshot(self, identity: ServiceRuntimeIdentity) -> object: ...

    async def close(self) -> None: ...


_DISCOVERY_TIMEOUT_SECONDS = 2.0
_READ_TIMEOUT_SECONDS = 5.0
_MAX_CONCURRENT_PROBES = 16


class ServiceHealthReader:
    """Build bounded views without allowing degradation to govern liveness."""

    def __init__(self, config: SharedConfig) -> None:
        self._config = config
        self._previous_active: dict[tuple[str, str, str], float] = {}
        self._store: _SnapshotStore | None = None
        self._store_lock = asyncio.Lock()

    async def read(self) -> tuple[ServiceHealthView, ...]:
        config = self._config
        redis_config = config.redis
        if not redis_config.enabled or not redis_config.url:
            return ()
        try:
            rows = sorted(
                await asyncio.wait_for(
                    asyncio.to_thread(
                        discover_services,
                        redis_url=redis_config.url,
                        max_results=128,
                    ),
                    timeout=_DISCOVERY_TIMEOUT_SECONDS,
                ),
                key=lambda row: (row.service, row.instance),
            )
        except Exception as exc:
            logger.warning("Service-health discovery unavailable: %s", type(exc).__name__)
            return ()
        projection = resolve_service_degradation_config(config)
        environment = (
            projection.environment if projection is not None else ("local" if config.local_mode else "default")
        )
        history_ttl_seconds = projection.snapshot_ttl_seconds if projection is not None else 300
        now = time.monotonic()
        self._previous_active = {
            key: observed_at
            for key, observed_at in self._previous_active.items()
            if now - observed_at <= history_ttl_seconds
        }
        valid_rows: list[tuple[ServiceInfo, ServiceRuntimeIdentity, tuple[str, str, str]]] = []
        for row in rows:
            if row.runtime_id is None or row.health_target is None:
                continue
            if row.service not in {"brain", "forge", "router", "shield", "worker"}:
                continue
            try:
                identity = ServiceRuntimeIdentity(
                    environment=environment,
                    service=_SERVICE_NAME_ADAPTER.validate_python(row.service),
                    instance=row.instance,
                    runtime_id=row.runtime_id,
                    target=row.health_target,
                )
            except (ValidationError, ValueError) as exc:
                logger.warning("Ignoring invalid service-health registry row: %s", type(exc).__name__)
                continue
            valid_rows.append((row, identity, (row.service, row.instance, str(row.runtime_id))))
        if not valid_rows:
            return ()
        store = await self._get_store(projection) if projection is not None else None
        semaphore = asyncio.Semaphore(_MAX_CONCURRENT_PROBES)
        store_failed = [False]
        tasks = [
            asyncio.create_task(self._read_row(row, identity, key, store, semaphore, store_failed))
            for row, identity, key in valid_rows
        ]
        done, pending = await asyncio.wait(tasks, timeout=_READ_TIMEOUT_SECONDS)
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
            logger.warning("Service-health read timed out for %d peer(s)", len(pending))
        views = [task.result() for task in done if not task.cancelled()]
        if store is not None and store_failed[0]:
            await self._discard_store(store)
        return tuple(
            sorted(
                views,
                key=lambda view: (
                    view.identity.service if view.identity is not None else "",
                    view.identity.instance if view.identity is not None else "",
                ),
            )
        )

    async def aclose(self) -> None:
        """Close the reader-owned degradation store exactly once."""
        async with self._store_lock:
            store = self._store
            self._store = None
        if store is not None:
            try:
                await store.close()
            except Exception as exc:
                logger.warning("Service degradation store cleanup failed: %s", type(exc).__name__)

    async def _get_store(self, projection: ResolvedServiceDegradationConfig) -> _SnapshotStore | None:
        async with self._store_lock:
            if self._store is not None:
                return self._store
            try:
                self._store = await create_redis_degradation_store(projection)
            except Exception as exc:
                logger.warning("Service degradation store unavailable: %s", type(exc).__name__)
            return self._store

    async def _discard_store(self, store: _SnapshotStore) -> None:
        async with self._store_lock:
            if self._store is not store:
                return
            self._store = None
        try:
            await store.close()
        except Exception as exc:
            logger.warning("Service degradation store cleanup failed: %s", type(exc).__name__)

    async def _read_row(
        self,
        row: ServiceInfo,
        identity: ServiceRuntimeIdentity,
        previous_key: tuple[str, str, str],
        store: _SnapshotStore | None,
        semaphore: asyncio.Semaphore,
        store_failed: list[bool],
    ) -> ServiceHealthView:
        async with semaphore:
            try:
                liveness = await self._probe(row)
            except Exception as exc:
                logger.warning("Service-health probe unavailable: %s", type(exc).__name__)
                liveness = "unavailable"
            degradation = "unknown"
            signals = ()
            if store is not None:
                try:
                    result = await store.read_snapshot(identity)
                except Exception as exc:
                    logger.warning("Service degradation read unavailable: %s", type(exc).__name__)
                    store_failed[0] = True
                    result = SnapshotReadResult.invalid()
                if not isinstance(result, SnapshotReadResult):
                    logger.warning("Service degradation store returned an invalid result")
                    result = SnapshotReadResult.invalid()
                if result.state == "valid" and result.snapshot is not None:
                    if result.snapshot.signals:
                        degradation = "active"
                        signals = result.snapshot.signals
                        self._previous_active[previous_key] = time.monotonic()
                    elif previous_key in self._previous_active:
                        degradation = "recovered"
                        del self._previous_active[previous_key]
            return ServiceHealthView(
                identity=identity,
                liveness=liveness,
                degradation=degradation,
                signals=signals,
            )

    async def _probe(self, row: ServiceInfo) -> ServiceLivenessState:
        target = row.health_target
        assert target is not None
        try:
            endpoint = await _resolve_safe_endpoint(row.endpoint)
        except (OSError, TimeoutError, ValueError):
            return "unavailable"
        if target.transport == "grpc":
            channel = None
            try:
                channel = create_channel(
                    endpoint.grpc_target,
                    config=self._config,
                    tls_server_name_override=endpoint.host,
                )
                stub_candidate: object = health_pb2_grpc.HealthStub(channel)
                if not isinstance(stub_candidate, _HealthStub):
                    raise TypeError("official gRPC health stub does not satisfy Check contract")
                response = await stub_candidate.Check(
                    health_pb2.HealthCheckRequest(service=target.health_service),
                    timeout=1.0,
                )
                return "serving" if response.status == health_pb2.HealthCheckResponse.SERVING else "not_serving"
            except grpc.RpcError:
                return "unreachable"
            except Exception as exc:
                logger.warning("Service-health gRPC probe unavailable: %s", type(exc).__name__)
                return "unavailable"
            finally:
                if channel is not None:
                    try:
                        await channel.close()
                    except Exception as exc:
                        logger.warning("Service-health gRPC channel cleanup failed: %s", type(exc).__name__)
        return await asyncio.to_thread(self._probe_http, endpoint, target.health_path)

    @staticmethod
    def _probe_http(
        endpoint: _ResolvedEndpoint,
        path: str | None,
    ) -> ServiceLivenessState:
        connection = HTTPConnection(endpoint.address, endpoint.port, timeout=1.0)
        try:
            host = f"[{endpoint.host}]" if ":" in endpoint.host else endpoint.host
            host_header = f"{host}:{endpoint.port}"
            connection.request("GET", path or "/healthz", headers={"Host": host_header})
            response = connection.getresponse()
            if response.status != 200:
                return "not_serving"
            body = response.read(1_025)
            if len(body) > 1_024:
                return "not_serving"
            payload = json_loads(body)
            return "serving" if payload == {"status": "ok"} else "not_serving"
        except Exception:
            return "unreachable"
        finally:
            connection.close()


__all__ = ["ServiceHealthReader"]
