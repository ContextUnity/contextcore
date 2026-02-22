"""Service discovery for ContextUnity services.

Provides registration (heartbeat) and discovery of running service instances
via Redis. Used by:
- Services: register themselves on startup (call `register_service()` in server main)
- ContextView: discover all running instances (call `discover_services()`) — admin, no tenant filter
- Projects: discover only their tenant-scoped services via `discover_services(tenant_id=...)`

All discovery uses the SAME shared Redis that services already connect to.
ContextView knows Redis via REDIS_URL in settings.py — same Redis as Brain/Router/Worker.

Redis dependency is OPTIONAL — if redis is not installed, registration/discovery
are no-ops (graceful degradation).
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import Optional

from .config import load_shared_config_from_env

logger = logging.getLogger(__name__)

# Default prefix for all service discovery keys in Redis
DEFAULT_PREFIX = "contextunity:services"
DEFAULT_TTL = 30  # seconds


@dataclass
class ServiceInfo:
    """Information about a running service instance."""

    service: str  # e.g. "brain", "router", "worker"
    instance: str  # e.g. "shared", "nszu", "default"
    endpoint: str  # e.g. "localhost:50051"
    tenants: list[str] = field(default_factory=list)  # e.g. ["traverse", "pinkpony"] or [] = all
    metadata: dict = field(default_factory=dict)  # optional extra info

    def serves_tenant(self, tenant_id: str) -> bool:
        """Check if this service instance serves a given tenant.

        Empty tenants list means the service is shared (serves all tenants).
        """
        return not self.tenants or tenant_id in self.tenants


def _get_prefix() -> str:
    """Get service discovery key prefix from shared config."""
    config = load_shared_config_from_env()
    return getattr(config, "service_discovery_prefix", None) or DEFAULT_PREFIX


def _get_ttl() -> int:
    """Get service discovery TTL from shared config."""
    config = load_shared_config_from_env()
    ttl = getattr(config, "service_discovery_ttl", None)
    return int(ttl) if ttl else DEFAULT_TTL


def _get_redis_url(redis_url: str | None) -> str | None:
    """Resolve Redis URL from explicit arg or shared config."""
    if redis_url:
        return redis_url
    return load_shared_config_from_env().redis_url


def _redis_key(service: str, instance: str) -> str:
    return f"{_get_prefix()}:{service}:{instance}"


# ── Registration (called by services on startup) ────────────────────


async def register_service(
    service: str,
    instance: str,
    endpoint: str,
    redis_url: Optional[str] = None,
    tenants: Optional[list[str]] = None,
    metadata: Optional[dict] = None,
) -> Optional[asyncio.Task]:
    """Register a service instance in Redis and start heartbeat.

    Args:
        service: Service type ("brain", "router", "worker", "commerce", "view")
        instance: Instance name ("shared", "nszu", "default")
        endpoint: gRPC endpoint ("localhost:50051")
        redis_url: Redis URL (defaults to REDIS_URL env var)
        tenants: List of tenant IDs this instance serves.
                 Empty list or None = shared instance (serves all tenants).
                 Example: ["traverse", "pinkpony"] or ["nszu"]
        metadata: Optional metadata dict (port, version, etc.)

    Returns:
        Background heartbeat task, or None if Redis is unavailable.
    """
    try:
        import redis.asyncio as aioredis
    except ImportError:
        logger.debug("redis not installed — service discovery registration skipped")
        return None

    url = _get_redis_url(redis_url)
    if not url:
        logger.debug("REDIS_URL not set — service discovery registration skipped")
        return None

    key = _redis_key(service, instance)
    value = json.dumps(
        {
            "endpoint": endpoint,
            "service": service,
            "instance": instance,
            "tenants": tenants or [],
            **(metadata or {}),
        }
    )
    ttl = _get_ttl()

    async def _heartbeat():
        """Periodically refresh the key to signal liveness."""
        r = aioredis.from_url(url, decode_responses=True)
        try:
            while True:
                try:
                    await r.setex(key, ttl, value)
                    logger.debug("Heartbeat: %s -> %s (TTL=%ds)", key, endpoint, ttl)
                except Exception as e:
                    logger.warning("Service discovery heartbeat failed: %s", e)
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

    task = asyncio.create_task(_heartbeat())
    logger.info("Service registered: %s/%s at %s (tenants=%s)", service, instance, endpoint, tenants or "all")
    return task


async def deregister_service(
    service: str,
    instance: str,
    redis_url: Optional[str] = None,
) -> None:
    """Explicitly deregister a service instance."""
    try:
        import redis.asyncio as aioredis
    except ImportError:
        return

    url = _get_redis_url(redis_url)
    if not url:
        return

    key = _redis_key(service, instance)
    r = aioredis.from_url(url, decode_responses=True)
    try:
        await r.delete(key)
        logger.info("Deregistered service: %s", key)
    except Exception as e:
        logger.warning("Service deregistration failed: %s", e)
    finally:
        await r.aclose()


# ── Discovery (called by ContextView or other services) ─────────────


def discover_services(
    service_type: Optional[str] = None,
    tenant_id: Optional[str] = None,
    redis_url: Optional[str] = None,
) -> list[ServiceInfo]:
    """Discover running service instances from Redis (synchronous).

    Args:
        service_type: Filter by service type ("brain", "router", etc.)
                      If None, returns all services.
        tenant_id: Filter by tenant scope. If set, only returns services that
                   serve this tenant (or shared services with empty tenants list).
                   If None, returns ALL services (admin mode for ContextView).
        redis_url: Redis URL (defaults to REDIS_URL env var)

    Returns:
        List of ServiceInfo for discovered instances.
    """
    try:
        import redis as redis_sync
    except ImportError:
        logger.debug("redis not installed — service discovery unavailable")
        return []

    url = _get_redis_url(redis_url)
    if not url:
        return []

    prefix = _get_prefix()
    pattern = f"{prefix}:{service_type}:*" if service_type else f"{prefix}:*"

    services: list[ServiceInfo] = []
    try:
        r = redis_sync.from_url(url, decode_responses=True)
        keys = r.keys(pattern)
        for key in keys:
            raw = r.get(key)
            if not raw:
                continue
            try:
                data = json.loads(raw)
                info = ServiceInfo(
                    service=data.get("service", "unknown"),
                    instance=data.get("instance", "unknown"),
                    endpoint=data.get("endpoint", ""),
                    tenants=data.get("tenants", []),
                    metadata={k: v for k, v in data.items() if k not in ("service", "instance", "endpoint", "tenants")},
                )
                # Apply tenant filter if specified
                if tenant_id and not info.serves_tenant(tenant_id):
                    continue
                services.append(info)
            except (json.JSONDecodeError, KeyError) as e:
                logger.warning("Invalid service discovery data for %s: %s", key, e)
        r.close()
    except Exception as e:
        logger.warning("Service discovery failed: %s", e)

    return services


def discover_endpoints(
    service_type: str,
    tenant_id: Optional[str] = None,
    redis_url: Optional[str] = None,
) -> dict[str, str]:
    """Discover endpoints for a service type as {instance_name: endpoint} dict.

    Args:
        service_type: Service type to discover ("brain", "router", etc.)
        tenant_id: If set, only returns services scoped to this tenant.
                   None = return all (admin mode).
        redis_url: Redis URL override.

    Returns:
        Dict mapping instance name to endpoint.
    """
    return {
        s.instance: s.endpoint
        for s in discover_services(
            service_type=service_type,
            tenant_id=tenant_id,
            redis_url=redis_url,
        )
    }


# ── Project Registry (VULN-4 Layer C: server-side ownership) ────────


PROJECTS_PREFIX = "contextunity:projects"


def _project_key(project_id: str) -> str:
    return f"{PROJECTS_PREFIX}:{project_id}"


def register_project(
    project_id: str,
    owner_tenant: str,
    *,
    tools: list[str] | None = None,
    redis_url: str | None = None,
) -> bool:
    """Register a project in the global project registry.

    Called during RegisterTools. Stores who owns the project so Router
    can verify ownership on subsequent requests.

    If project is already registered by a DIFFERENT owner, returns False
    (ownership conflict). Same owner re-registering is idempotent.

    Args:
        project_id: Project identifier (e.g. "nszu")
        owner_tenant: Tenant that owns this project (from token.allowed_tenants)
        tools: List of tool names being registered
        redis_url: Redis URL (defaults to REDIS_URL env var)

    Returns:
        True if registered successfully, False if ownership conflict.
    """
    try:
        import redis as redis_sync
    except ImportError:
        logger.warning(
            "Project registry: redis not installed — ownership enforcement DISABLED for '%s'. "
            "Install redis to enable project hijack protection.",
            project_id,
        )
        return True  # Graceful degradation — visible in logs

    url = _get_redis_url(redis_url)
    if not url:
        logger.warning(
            "Project registry: REDIS_URL not configured — ownership enforcement DISABLED for '%s'. "
            "Set REDIS_URL to enable project hijack protection.",
            project_id,
        )
        return True  # Graceful degradation — visible in logs

    key = _project_key(project_id)
    try:
        r = redis_sync.from_url(url, decode_responses=True)
        existing = r.get(key)

        if existing:
            data = json.loads(existing)
            existing_owner = data.get("owner_tenant", "")
            if existing_owner and existing_owner != owner_tenant:
                logger.warning(
                    "Project registry: ownership conflict for '%s' — registered owner='%s', attempted owner='%s'",
                    project_id,
                    existing_owner,
                    owner_tenant,
                )
                r.close()
                return False

        # Register or update
        value = json.dumps(
            {
                "project_id": project_id,
                "owner_tenant": owner_tenant,
                "tools": tools or [],
            }
        )
        r.set(key, value)  # No TTL — projects are permanent until deregistered
        r.close()

        logger.info(
            "Project registry: registered '%s' owner='%s' tools=%s",
            project_id,
            owner_tenant,
            tools or [],
        )
        return True

    except Exception as e:
        logger.warning("Project registry failed: %s", e)
        return True  # Graceful degradation


def verify_project_owner(
    project_id: str,
    claimed_tenant: str,
    *,
    redis_url: str | None = None,
) -> bool:
    """Verify that claimed_tenant owns project_id.

    Returns True if:
    - Project is registered and owned by claimed_tenant
    - Project is not registered (first-time registration allowed)
    - Redis is unavailable (graceful degradation)

    Returns False if:
    - Project is registered but owned by a DIFFERENT tenant

    Args:
        project_id: Project to verify
        claimed_tenant: Tenant claiming ownership
        redis_url: Redis URL override
    """
    try:
        import redis as redis_sync
    except ImportError:
        logger.warning(
            "Project ownership check: redis not installed — SKIPPING verification for '%s:%s'. "
            "Install redis to enable project hijack protection.",
            project_id,
            claimed_tenant,
        )
        return True  # Graceful degradation — visible in logs

    url = _get_redis_url(redis_url)
    if not url:
        logger.warning(
            "Project ownership check: REDIS_URL not configured — SKIPPING verification for '%s:%s'. "
            "Set REDIS_URL to enable project hijack protection.",
            project_id,
            claimed_tenant,
        )
        return True  # Graceful degradation — visible in logs

    try:
        r = redis_sync.from_url(url, decode_responses=True)
        raw = r.get(_project_key(project_id))
        r.close()

        if not raw:
            return True  # First-time registration allowed

        data = json.loads(raw)
        owner = data.get("owner_tenant", "")
        return not owner or owner == claimed_tenant

    except Exception as e:
        logger.warning("Project ownership verification failed: %s", e)
        return True  # Graceful degradation


def get_registered_projects(
    redis_url: str | None = None,
) -> list[dict]:
    """List all registered projects. Used by ContextView admin dashboard.

    Returns:
        List of project registry entries.
    """
    try:
        import redis as redis_sync
    except ImportError:
        return []

    url = _get_redis_url(redis_url)
    if not url:
        return []

    try:
        r = redis_sync.from_url(url, decode_responses=True)
        keys = r.keys(f"{PROJECTS_PREFIX}:*")
        projects = []
        for key in keys:
            raw = r.get(key)
            if raw:
                try:
                    projects.append(json.loads(raw))
                except json.JSONDecodeError:
                    pass
        r.close()
        return projects
    except Exception as e:
        logger.warning("Project registry list failed: %s", e)
        return []


__all__ = [
    "ServiceInfo",
    "register_service",
    "deregister_service",
    "discover_services",
    "discover_endpoints",
    "register_project",
    "verify_project_owner",
    "get_registered_projects",
]
