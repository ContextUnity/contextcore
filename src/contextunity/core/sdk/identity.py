"""ContextUnity SDK — Project Identity (Runtime Singleton).

After SDK bootstrap reads the manifest, project identity is cached here.
Any project code can import ``get_project_id()`` / ``get_allowed_tenants()``
instead of reading env vars or Django settings.

Usage::

    from contextunity.core.sdk.identity import get_project_id, get_allowed_tenants

    token = ContextToken(
        token_id=f"{get_project_id()}-service",
        allowed_tenants=get_allowed_tenants(),
        ...
    )

Set by bootstrap — not meant to be called by project code directly::

    from contextunity.core.sdk.identity import set_project_identity
    set_project_identity(
        project_id="nszu",
        allowed_tenants=("nszu", "nszu-staging"),
    )
"""

from __future__ import annotations

import threading

from contextunity.core.logging import get_contextunit_logger
from contextunity.core.manifest.models import WorkerBindingsBundle

logger = get_contextunit_logger(__name__)

_lock = threading.Lock()
_project_id: str = ""
_allowed_tenants: tuple[str, ...] = ()
_worker_bindings: WorkerBindingsBundle = WorkerBindingsBundle()
_required_services: dict[str, bool] = {}


def set_project_identity(*, project_id: str, allowed_tenants: tuple[str, ...]) -> None:
    """Cache project identity from manifest.

    Args:
        project_id: The unique project identifier.
        allowed_tenants: Full security-scope tenant set for this project.
    """
    global _project_id, _allowed_tenants
    if not allowed_tenants:
        raise ValueError("set_project_identity requires non-empty allowed_tenants")
    with _lock:
        _project_id = project_id
        _allowed_tenants = tuple(allowed_tenants)
    logger.debug(
        "Project identity set: project_id=%s allowed_tenants=%s",
        project_id,
        allowed_tenants,
    )


def set_worker_bindings(bindings: WorkerBindingsBundle | None) -> None:
    """Cache compiled worker bindings from manifest bootstrap."""
    global _worker_bindings
    with _lock:
        _worker_bindings = bindings or WorkerBindingsBundle()


def get_worker_bindings() -> WorkerBindingsBundle:
    """Get cached worker bindings compiled from the manifest."""
    with _lock:
        return _worker_bindings.model_copy(deep=True)


def set_required_services(services: dict[str, bool] | None) -> None:
    """Cache enabled service flags from manifest for Shield auto-provisioning."""
    global _required_services
    with _lock:
        _required_services = dict(services or {})


def get_required_services() -> dict[str, bool]:
    """Get cached required services derived from manifest."""
    return dict(_required_services)


def get_project_id() -> str:
    """Get cached project ID (from manifest ``project.id``)."""
    return _project_id


def get_allowed_tenants() -> tuple[str, ...]:
    """Get cached security-scope tenants for this project."""
    return _allowed_tenants


def get_tenant_id() -> str:
    """Legacy helper — returns the first allowed tenant.

    Prefer ``get_allowed_tenants()`` for multi-tenant projects.
    """
    return _allowed_tenants[0] if _allowed_tenants else ""


def reset_project_identity() -> None:
    """Reset identity — for testing only."""
    global _project_id, _allowed_tenants, _worker_bindings, _required_services
    with _lock:
        _project_id = ""
        _allowed_tenants = ()
        _worker_bindings = WorkerBindingsBundle()
        _required_services = {}


__all__ = [
    "get_allowed_tenants",
    "get_project_id",
    "get_tenant_id",
    "get_worker_bindings",
    "get_required_services",
    "reset_project_identity",
    "set_project_identity",
    "set_worker_bindings",
    "set_required_services",
]
