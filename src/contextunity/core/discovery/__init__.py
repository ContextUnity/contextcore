"""Service discovery for ContextUnity services.

Provides registration (heartbeat) and discovery of running service instances
via Redis. Used by:
- Services: register themselves on startup (call ``register_service()`` in server main)
- contextunity.forge: discover all running instances (call ``discover_services()``) — admin, no tenant filter
- Projects: discover only their tenant-scoped services via ``discover_services(tenant_id=...)``

All discovery uses the SAME shared Redis that services already connect to.
contextunity.forge knows Redis via REDIS_URL / service config — same Redis as Brain/Router/Worker.

Redis dependency is OPTIONAL — if redis is not installed, registration/discovery
are no-ops (graceful degradation).
"""

from .client import SyncRedisClient
from .config import get_prefix, get_redis_url, get_ttl, redis_key
from .resolve import resolve_service_endpoint
from .services import (
    ServiceInfo,
    deregister_service,
    discover_endpoints,
    discover_services,
    register_service,
)

_get_redis_url = get_redis_url
_redis_key = redis_key

__all__ = [
    # Types
    "ServiceInfo",
    "SyncRedisClient",
    # Service registration & discovery
    "register_service",
    "deregister_service",
    "discover_services",
    "discover_endpoints",
    "resolve_service_endpoint",
    # Private but consumed by cli/mint.py
    "get_redis_url",
    "redis_key",
    "get_prefix",
    "get_ttl",
    "_get_redis_url",
    "_redis_key",
]
