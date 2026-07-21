"""Service registration, heartbeat, and discovery via Redis.

Used by:
- Services: register themselves on startup (``register_service()``)
- contextunity.forge: discover all running instances (``discover_services()``)
- Projects: discover tenant-scoped services via ``discover_services(tenant_id=...)``
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from json import JSONDecodeError
from typing import Protocol
from uuid import UUID

from contextunity.core.parsing import json_dumps, json_loads
from contextunity.core.service_health.models import (
    GRPC_HEALTH_SERVICE_NAMES,
    ServiceHealthTarget,
    ServiceRuntimeIdentity,
)
from contextunity.core.types import JsonDict, JsonValue, is_json_dict, is_object_list
from pydantic import ValidationError

from ..exceptions import RedisConnectionError
from ..logging import get_contextunit_logger
from .async_client import (
    AsyncRedisCommandClient,
    RedisCommandError,
    RedisCommandPart,
    RedisResponse,
)
from .client import RedisNotAvailable, SyncRedisClient
from .config import get_prefix, get_redis_url, get_ttl, redis_key

logger = get_contextunit_logger(__name__)


class _AsyncRedisSetex(Protocol):
    async def setex(self, key: str, ttl: int, value: str) -> RedisResponse: ...


class _AsyncRedisEval(Protocol):
    async def eval(
        self,
        script: str,
        numkeys: int,
        *args: RedisCommandPart,
    ) -> RedisResponse: ...


_REFRESH_REGISTRATION_LUA = """
local raw = redis.call('get', KEYS[1])
if not raw then return 0 end
local ok, record = pcall(cjson.decode, raw)
if not ok or record['runtime_id'] ~= ARGV[1] then return 0 end
redis.call('setex', KEYS[1], tonumber(ARGV[3]), ARGV[2])
return 1
"""

_RELEASE_REGISTRATION_LUA = """
local raw = redis.call('get', KEYS[1])
if not raw then return 0 end
local ok, record = pcall(cjson.decode, raw)
if not ok or record['runtime_id'] ~= ARGV[1] then return 0 end
redis.call('del', KEYS[1])
return 1
"""


def _service_record(
    *,
    service: str,
    instance: str,
    endpoint: str,
    tenants: list[str],
    metadata: JsonDict | None,
    identity: ServiceRuntimeIdentity | None,
) -> str:
    record: JsonDict = dict(metadata or {})
    record["endpoint"] = endpoint
    record["service"] = service
    record["instance"] = instance
    tenant_values: list[JsonValue] = []
    tenant_values.extend(tenants)
    record["tenants"] = tenant_values
    if identity is not None:
        if identity.service != service or identity.instance != instance:
            raise ValueError("service registration identity does not match service/instance")
        record["runtime_id"] = str(identity.runtime_id)
        record["transport"] = identity.target.transport
        if identity.target.health_service is not None:
            record["health_service"] = identity.target.health_service
        if identity.target.health_path is not None:
            record["health_path"] = identity.target.health_path
    return json_dumps(record)


async def _claim_registration(
    client: _AsyncRedisSetex,
    *,
    key: str,
    value: str,
    ttl: int,
) -> None:
    """Make one bounded last-claim-wins initial registration write."""
    _ = await client.setex(key, ttl, value)


async def _refresh_registration_if_current(
    client: _AsyncRedisEval,
    *,
    key: str,
    runtime_id: UUID,
    value: str,
    ttl: int,
) -> bool:
    """Refresh only while this runtime still owns the shared registry key."""
    result = await client.eval(
        _REFRESH_REGISTRATION_LUA,
        1,
        key,
        str(runtime_id),
        value,
        ttl,
    )
    return result == 1


async def _release_registration_if_current(
    client: _AsyncRedisEval,
    *,
    key: str,
    runtime_id: UUID,
) -> bool:
    """Delete only while this runtime still owns the shared registry key."""
    result = await client.eval(_RELEASE_REGISTRATION_LUA, 1, key, str(runtime_id))
    return result == 1


def _parse_service_record(raw: str | bytes) -> JsonDict:
    data: object = json_loads(raw)
    if not is_json_dict(data):
        msg = "service discovery record must be a JSON object"
        raise JSONDecodeError(msg, str(raw), 0)
    return data


def _runtime_target_from_record(
    data: JsonDict,
    *,
    service: str,
) -> tuple[UUID | None, ServiceHealthTarget | None]:
    runtime_raw = data.get("runtime_id")
    target_fields = (data.get("transport"), data.get("health_service"), data.get("health_path"))
    if runtime_raw is None and all(value is None for value in target_fields):
        return None, None
    if not isinstance(runtime_raw, str):
        raise ValueError("service registry runtime_id must be a UUID string")
    runtime_id = UUID(runtime_raw)
    target = ServiceHealthTarget.model_validate(
        {
            "transport": data.get("transport"),
            "health_service": data.get("health_service"),
            "health_path": data.get("health_path"),
        }
    )
    if service == "forge":
        if target.transport != "http":
            raise ValueError("Forge registry target must be HTTP")
    elif target.transport != "grpc" or target.health_service != GRPC_HEALTH_SERVICE_NAMES.get(service):
        raise ValueError("registry service and named gRPC health target do not match")
    return runtime_id, target


@dataclass
class ServiceInfo:
    """Information about a running service instance."""

    service: str  # e.g. "brain", "router", "worker"
    instance: str  # e.g. "shared", "nszu", "default"
    endpoint: str  # e.g. "localhost:50051"
    tenants: list[str] = field(default_factory=list)  # e.g. ["traverse", "pinkpony"] or [] = all
    metadata: JsonDict = field(default_factory=dict)  # optional extra info
    runtime_id: UUID | None = None
    health_target: ServiceHealthTarget | None = None

    def serves_tenant(self, tenant_id: str) -> bool:
        """Check if this service instance serves the given tenant.

        An empty tenants list indicates that the service is shared and serves
        all tenants.

        Args:
            tenant_id: The unique identifier of the tenant.

        Returns:
            bool: True if the tenant is served, False otherwise.
        """
        return not self.tenants or tenant_id in self.tenants


# ── Registration (called by services on startup) ────────────────────


async def register_service(
    service: str,
    instance: str,
    endpoint: str,
    redis_url: str | None = None,
    tenants: list[str] | None = None,
    metadata: JsonDict | None = None,
    *,
    identity: ServiceRuntimeIdentity | None = None,
) -> asyncio.Task[None] | None:
    """Claim a registry row and refresh it only while this runtime owns it."""
    url = get_redis_url(redis_url)
    if not url:
        logger.warning(
            "Service registration DISABLED: REDIS_URL is not set. Service '%s/%s' will NOT appear in the service mesh.",
            service,
            instance,
        )
        return None

    key = redis_key(service, instance)
    value = _service_record(
        service=service,
        instance=instance,
        endpoint=endpoint,
        tenants=tenants or [],
        metadata=metadata,
        identity=identity,
    )
    ttl = get_ttl()
    client = AsyncRedisCommandClient(
        url,
        connect_timeout=3,
        io_timeout=3,
    )
    try:
        if not await client.ping():
            raise RedisCommandError("Redis PING did not return PONG")
        await _claim_registration(client, key=key, value=value, ttl=ttl)
    except Exception as exc:
        await client.aclose()
        logger.warning(
            "Service '%s/%s' registration SKIPPED — Redis unreachable (%s). The service will start without discovery.",
            service,
            instance,
            RedisConnectionError(exc, url),
        )
        return None

    async def _heartbeat() -> None:
        """Refresh the current claim; a replacement runtime permanently fences this task."""
        try:
            while True:
                await asyncio.sleep(ttl // 2 or 10)
                try:
                    if identity is None:
                        await _claim_registration(client, key=key, value=value, ttl=ttl)
                    elif not await _refresh_registration_if_current(
                        client,
                        key=key,
                        runtime_id=identity.runtime_id,
                        value=value,
                        ttl=ttl,
                    ):
                        logger.info("Heartbeat fenced by newer runtime: %s", key)
                        return
                    logger.debug("Heartbeat: %s -> %s (TTL=%ds)", key, endpoint, ttl)
                except Exception as exc:
                    logger.warning(
                        "Service '%s/%s' heartbeat failed: %s",
                        service,
                        instance,
                        RedisConnectionError(exc, url),
                    )
        except asyncio.CancelledError:
            try:
                if identity is None:
                    await client.delete(key)
                else:
                    _ = await _release_registration_if_current(
                        client,
                        key=key,
                        runtime_id=identity.runtime_id,
                    )
            except Exception as exc:
                logger.debug("Failed to release service registration %s: %s", key, exc)
            raise
        finally:
            await client.aclose()

    task = asyncio.create_task(_heartbeat(), name=f"service-heartbeat:{service}:{instance}")
    logger.info("Service registered: %s/%s at %s (tenants=%s)", service, instance, endpoint, tenants or "all")
    return task


async def deregister_service(
    service: str,
    instance: str,
    redis_url: str | None = None,
    *,
    runtime_id: UUID,
) -> bool:
    """Release only the exact runtime's registry claim."""
    url = get_redis_url(redis_url)
    if not url:
        return False

    key = redis_key(service, instance)
    client = AsyncRedisCommandClient(url, connect_timeout=3, io_timeout=3)
    try:
        released = await _release_registration_if_current(
            client,
            key=key,
            runtime_id=runtime_id,
        )
        if released:
            logger.info("Deregistered service runtime: %s", key)
        return released
    except Exception as exc:
        logger.warning(
            "Service '%s/%s' deregistration failed: %s",
            service,
            instance,
            RedisConnectionError(exc, url),
        )
        return False
    finally:
        await client.aclose()


# ── Discovery (called by contextunity.view or other services) ─────────────


def discover_services(
    service_type: str | None = None,
    tenant_id: str | None = None,
    redis_url: str | None = None,
    *,
    max_results: int | None = None,
) -> list[ServiceInfo]:
    """Discover running service instances matching criteria from Redis.

    Args:
        service_type: Service type to filter by (e.g., "brain", "router"). If None,
            returns instances of all service types.
        tenant_id: Optional tenant filter. Only services serving this tenant are returned.
            If None, returns all service instances.
        redis_url: Optional Redis URL connection string.
        max_results: Optional bounded SCAN result ceiling (1–256).

    Returns:
        list[ServiceInfo]: A list of ServiceInfo objects for discovered instances.
    """
    if max_results is not None and not 1 <= max_results <= 256:
        raise ValueError("max_results must be between 1 and 256")
    url = get_redis_url(redis_url)
    if not url:
        logger.debug("Service discovery: Redis not configured, skipping.")
        return []

    prefix = get_prefix()
    pattern = f"{prefix}:{service_type}:*" if service_type else f"{prefix}:*"

    services: list[ServiceInfo] = []
    client: SyncRedisClient | None = None
    try:
        client = SyncRedisClient(url)
        if max_results is None:
            keys = client.keys(pattern)
        else:
            keys: list[str] = []
            cursor = 0
            while True:
                cursor, batch = client.scan(
                    cursor=cursor,
                    match=pattern,
                    count=max_results,
                )
                keys.extend(batch[: max_results - len(keys)])
                if cursor == 0 or len(keys) >= max_results:
                    break
        for key in keys:
            try:
                raw = client.get(key)
            except Exception as exc:
                logger.warning("Service discovery read failed for %s: %s", key, type(exc).__name__)
                continue
            if not raw:
                continue
            try:
                data = _parse_service_record(raw)
                service_name = data.get("service")
                instance_name = data.get("instance")
                endpoint = data.get("endpoint")
                tenants_raw = data.get("tenants", [])
                tenants: list[str] = []
                if is_object_list(tenants_raw):
                    for tenant in tenants_raw:
                        if isinstance(tenant, str):
                            tenants.append(tenant)
                normalized_service = service_name if isinstance(service_name, str) else "unknown"
                runtime_id, health_target = _runtime_target_from_record(
                    data,
                    service=normalized_service,
                )
                info = ServiceInfo(
                    service=normalized_service,
                    instance=instance_name if isinstance(instance_name, str) else "unknown",
                    endpoint=endpoint if isinstance(endpoint, str) else "",
                    tenants=tenants,
                    metadata={
                        item_key: value
                        for item_key, value in data.items()
                        if item_key
                        not in (
                            "service",
                            "instance",
                            "endpoint",
                            "tenants",
                            "runtime_id",
                            "transport",
                            "health_service",
                            "health_path",
                        )
                    },
                    runtime_id=runtime_id,
                    health_target=health_target,
                )
                # Apply tenant filter if specified
                if tenant_id and not info.serves_tenant(tenant_id):
                    continue
                services.append(info)
            except (JSONDecodeError, KeyError, ValidationError, ValueError) as exc:
                logger.warning("Invalid service discovery data for %s: %s", key, exc)
    except RedisNotAvailable:
        logger.warning("Service discovery DISABLED: 'redis' package not installed in this venv.")
    except Exception as exc:
        logger.warning(
            "Service discovery for '%s' failed: %s",
            service_type or "all",
            RedisConnectionError(exc, url),
        )
    finally:
        if client is not None:
            try:
                client.close()
            except Exception as exc:
                logger.warning("Service discovery client cleanup failed: %s", type(exc).__name__)

    return services


def discover_endpoints(
    service_type: str,
    tenant_id: str | None = None,
    redis_url: str | None = None,
) -> dict[str, str]:
    """Discover endpoints for a service type, returning a mapping of instance names to endpoints.

    Args:
        service_type: Service type to discover (e.g., "brain", "router").
        tenant_id: Optional tenant filter to restrict discovered endpoints.
        redis_url: Optional Redis URL connection string.

    Returns:
        dict[str, str]: A dictionary mapping instance name to endpoint.
    """
    return {
        s.instance: s.endpoint
        for s in discover_services(
            service_type=service_type,
            tenant_id=tenant_id,
            redis_url=redis_url,
        )
    }
