"""Service discovery for ContextUnity services.

Provides registration (heartbeat) and discovery of running service instances
via Redis. Used by:
- Services: register themselves on startup (call ``register_service()`` in server main)
- contextunity.view: discover all running instances (call ``discover_services()``) — admin, no tenant filter
- Projects: discover only their tenant-scoped services via ``discover_services(tenant_id=...)``

All discovery uses the SAME shared Redis that services already connect to.
contextunity.view knows Redis via REDIS_URL in settings.py — same Redis as Brain/Router/Worker.

Redis dependency is OPTIONAL — if redis is not installed, registration/discovery
are no-ops (graceful degradation).
"""

from .client import SyncRedisClient
from .config import PROJECTS_PREFIX, get_prefix, get_redis_url, get_ttl, project_key, redis_key
from .contracts import ProjectStore
from .project_keys import (
    get_or_create_project_stream_secret,
    get_project_key,
    get_project_stream_secret,
    update_project_public_key,
    update_project_stream_secret,
)
from .projects import (
    ProjectKeyInfo,
    ProjectRecord,
    get_registered_projects,
    register_project,
    verify_project_owner,
)
from .resolve import resolve_service_endpoint
from .services import (
    ServiceInfo,
    deregister_service,
    discover_endpoints,
    discover_services,
    register_service,
)
from .store import (
    InMemoryProjectStore,
    get_project_store,
    reset_project_store,
    set_project_store,
)

_get_redis_url = get_redis_url
_redis_key = redis_key

__all__ = [
    # Types
    "ServiceInfo",
    "ProjectKeyInfo",
    "ProjectRecord",
    "ProjectStore",
    "InMemoryProjectStore",
    "SyncRedisClient",
    # Service registration & discovery
    "register_service",
    "deregister_service",
    "discover_services",
    "discover_endpoints",
    "resolve_service_endpoint",
    # Project registry
    "register_project",
    "verify_project_owner",
    "get_registered_projects",
    # Project key material
    "update_project_public_key",
    "update_project_stream_secret",
    "get_project_stream_secret",
    "get_or_create_project_stream_secret",
    "get_project_key",
    "get_project_store",
    "set_project_store",
    "reset_project_store",
    # Private but consumed by cli/mint.py
    "PROJECTS_PREFIX",
    "get_redis_url",
    "redis_key",
    "get_prefix",
    "get_ttl",
    "project_key",
    "_get_redis_url",
    "_redis_key",
]
