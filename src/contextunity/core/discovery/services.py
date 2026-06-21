"""Service registration, heartbeat, and discovery via Redis.

Used by:
- Services: register themselves on startup (``register_service()``)
- contextunity.view: discover all running instances (``discover_services()``)
- Projects: discover tenant-scoped services via ``discover_services(tenant_id=...)``
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from json import JSONDecodeError
from typing import Protocol

from contextunity.core.parsing import json_dumps
from contextunity.core.types import JsonDict, is_object_list

from ..exceptions import RedisConnectionError
from ..logging import get_contextunit_logger
from .client import RedisNotAvailable, SyncRedisClient
from .config import get_prefix, get_redis_url, get_ttl, redis_key
from .types import parse_json_object

logger = get_contextunit_logger(__name__)


class _AsyncRedisProbe(Protocol):
    def ping(self, **kwargs: object) -> object: ...


def _probe_redis(client: _AsyncRedisProbe) -> object:
    return client.ping()


@dataclass
class ServiceInfo:
    """Information about a running service instance."""

    service: str  # e.g. "brain", "router", "worker"
    instance: str  # e.g. "shared", "nszu", "default"
    endpoint: str  # e.g. "localhost:50051"
    tenants: list[str] = field(default_factory=list)  # e.g. ["traverse", "pinkpony"] or [] = all
    metadata: JsonDict = field(default_factory=dict)  # optional extra info

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
) -> asyncio.Task[None] | None:
    """Register a service instance in Redis and start the heartbeat loop.

    Args:
        service: Service type (e.g., "brain", "router", "worker").
        instance: Unique name for this instance (e.g., "shared", "nszu").
        endpoint: gRPC server endpoint string (e.g., "localhost:50051").
        redis_url: Optional Redis URL connection string.
        tenants: List of tenant IDs this instance serves. An empty list or None
            indicates a shared instance serving all tenants.
        metadata: Optional metadata dictionary associated with the instance.

    Returns:
        asyncio.Task[None] | None: The background heartbeat task, or None if
        Redis is unavailable or connection fails.
    """
    try:
        import redis.asyncio as aioredis
    except ImportError:
        logger.warning(
            "Service registration DISABLED: 'redis' package not installed in this venv. "
            + "Install it via the [redis] extra: uv pip install 'context%s[redis]'",
            service,
        )
        return None

    url = get_redis_url(redis_url)
    if not url:
        logger.warning(
            "Service registration DISABLED: REDIS_URL is not set. Service '%s/%s' will NOT appear in the service mesh.",
            service,
            instance,
        )
        return None

    key = redis_key(service, instance)
    value = json_dumps(
        {
            "endpoint": endpoint,
            "service": service,
            "instance": instance,
            "tenants": tenants or [],
            **(metadata or {}),
        }
    )
    ttl = get_ttl()

    async def _heartbeat():
        """Periodically refresh the key to signal liveness."""
        r = aioredis.from_url(
            url,
            decode_responses=True,
            socket_connect_timeout=3,
            socket_timeout=3,
        )
        try:
            while True:
                try:
                    await r.setex(key, ttl, value)
                    logger.debug("Heartbeat: %s -> %s (TTL=%ds)", key, endpoint, ttl)
                except Exception as e:
                    logger.warning(
                        "Service '%s/%s' heartbeat failed: %s", service, instance, RedisConnectionError(e, url)
                    )
                # Sleep for half the TTL to ensure overlap
                await asyncio.sleep(ttl // 2 or 10)
        except asyncio.CancelledError:
            # Deregister on shutdown
            try:
                await r.delete(key)
                logger.info("Deregistered service: %s", key)
            except Exception as e:
                logger.debug("Failed to deregister service %s: %s", key, e)
            raise
        finally:
            await r.aclose()

    # Validate connectivity before starting heartbeat. Redis here is only used for
    # service-mesh discovery/heartbeat — it is NOT required for a service to function.
    # So a connection failure degrades gracefully (start without discovery) with a
    # clear, actionable message rather than crashing startup with a raw exception.
    probe = aioredis.from_url(url, decode_responses=True, socket_connect_timeout=5)
    probe_client: _AsyncRedisProbe = probe
    try:
        ping_result: object = _probe_redis(probe_client)
        if asyncio.iscoroutine(ping_result):
            await ping_result
    except Exception as e:
        err = RedisConnectionError(e, url)
        logger.warning(
            "Service '%s/%s' registration SKIPPED — Redis unreachable (%s). "
            "The service will start WITHOUT mesh discovery. "
            "Set redis.enabled=false to silence this, or fix the Redis connection to enable discovery.",
            service,
            instance,
            err,
        )
        return None
    finally:
        await probe.aclose()

    task = asyncio.create_task(_heartbeat())
    logger.info("Service registered: %s/%s at %s (tenants=%s)", service, instance, endpoint, tenants or "all")
    return task


async def deregister_service(
    service: str,
    instance: str,
    redis_url: str | None = None,
) -> None:
    """Explicitly deregister a service instance.

    Args:
        service: Service type of the instance.
        instance: Name of the instance to deregister.
        redis_url: Optional Redis URL connection string.
    """
    try:
        import redis.asyncio as aioredis
    except ImportError:
        return

    url = get_redis_url(redis_url)
    if not url:
        return

    key = redis_key(service, instance)
    r = aioredis.from_url(
        url,
        decode_responses=True,
        socket_connect_timeout=3,
        socket_timeout=3,
    )
    try:
        await r.delete(key)
        logger.info("Deregistered service: %s", key)
    except Exception as e:
        logger.warning("Service '%s/%s' deregistration failed: %s", service, instance, RedisConnectionError(e, url))
    finally:
        await r.aclose()


# ── Discovery (called by contextunity.view or other services) ─────────────


def discover_services(
    service_type: str | None = None,
    tenant_id: str | None = None,
    redis_url: str | None = None,
) -> list[ServiceInfo]:
    """Discover running service instances matching criteria from Redis.

    Args:
        service_type: Service type to filter by (e.g., "brain", "router"). If None,
            returns instances of all service types.
        tenant_id: Optional tenant filter. Only services serving this tenant are returned.
            If None, returns all service instances.
        redis_url: Optional Redis URL connection string.

    Returns:
        list[ServiceInfo]: A list of ServiceInfo objects for discovered instances.
    """
    url = get_redis_url(redis_url)
    if not url:
        logger.debug("Service discovery: Redis not configured, skipping.")
        return []

    prefix = get_prefix()
    pattern = f"{prefix}:{service_type}:*" if service_type else f"{prefix}:*"

    services: list[ServiceInfo] = []
    try:
        r = SyncRedisClient(url)
        keys = r.keys(pattern)
        for key in keys:
            raw = r.get(key)
            if not raw:
                continue
            try:
                data = parse_json_object(raw)
                service_name = data.get("service")
                instance_name = data.get("instance")
                endpoint = data.get("endpoint")
                tenants_raw = data.get("tenants", [])
                tenants: list[str] = []
                if is_object_list(tenants_raw):
                    for tenant in tenants_raw:
                        if isinstance(tenant, str):
                            tenants.append(tenant)
                info = ServiceInfo(
                    service=service_name if isinstance(service_name, str) else "unknown",
                    instance=instance_name if isinstance(instance_name, str) else "unknown",
                    endpoint=endpoint if isinstance(endpoint, str) else "",
                    tenants=tenants,
                    metadata={
                        key: value
                        for key, value in data.items()
                        if key not in ("service", "instance", "endpoint", "tenants")
                    },
                )
                # Apply tenant filter if specified
                if tenant_id and not info.serves_tenant(tenant_id):
                    continue
                services.append(info)
            except (JSONDecodeError, KeyError) as e:
                logger.warning("Invalid service discovery data for %s: %s", key, e)
        r.close()
    except RedisNotAvailable:
        logger.warning("Service discovery DISABLED: 'redis' package not installed in this venv.")
    except Exception as e:
        logger.warning("Service discovery for '%s' failed: %s", service_type or "all", RedisConnectionError(e, url))

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
