"""ContextUnity SDK — Project Identity (Runtime Singleton).

After SDK bootstrap reads the manifest, project identity is cached here.
Any project code can import get_project_id() / get_tenant_id() instead of
reading env vars or Django settings.

Usage:

    from contextunity.core.sdk.identity import get_project_id, get_tenant_id

    token = ContextToken(
        token_id=f"{get_project_id()}-service",
        allowed_tenants=(get_tenant_id(),),
        ...
    )

Set by bootstrap — not meant to be called by project code directly:

    from contextunity.core.sdk.identity import set_project_identity
    set_project_identity(project_id="nszu", tenant_id="nszu")
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from contextunity.core.tokens import ContextToken

from contextunity.core.logging import get_contextunit_logger

logger = get_contextunit_logger(__name__)

_lock = threading.Lock()
_project_id: str = ""
_tenant_id: str = ""
_worker_bindings: dict = {}


def set_project_identity(*, project_id: str, tenant_id: str) -> None:
    """Cache project identity from manifest. Called by bootstrap."""
    global _project_id, _tenant_id
    with _lock:
        _project_id = project_id
        _tenant_id = tenant_id
    logger.debug("Project identity set: project_id=%s, tenant_id=%s", project_id, tenant_id)


def set_worker_bindings(bindings: dict | None) -> None:
    """Cache compiled worker bindings from manifest bootstrap."""
    global _worker_bindings
    with _lock:
        _worker_bindings = dict(bindings or {})


def get_worker_bindings() -> dict:
    """Get cached worker bindings compiled from the manifest."""
    return dict(_worker_bindings)


def get_project_id() -> str:
    """Get cached project ID (from manifest project.id).

    Returns empty string if bootstrap hasn't run yet.
    """
    return _project_id


def get_tenant_id() -> str:
    """Get cached tenant ID (from manifest project.tenant).

    Returns empty string if bootstrap hasn't run yet.
    """
    return _tenant_id


def _reset() -> None:
    """Reset identity — for testing only."""
    global _project_id, _tenant_id, _worker_bindings
    with _lock:
        _project_id = ""
        _tenant_id = ""
        _worker_bindings = {}


def mint_client_token(
    user_id: str | None = None, ttl_s: int = 120, extra_permissions: list[str] | None = None
) -> "ContextToken":
    """Mint a per-request ContextToken for invoking Router/Brain services.

    Automatically grants sensible defaults for a project backend making
    requests on behalf of a user within the project's own tenant boundary:
    (ROUTER_EXECUTE, GRAPH_ALL, TOOL_ALL, BRAIN_READ/WRITE, TRACE_WRITE, ZERO_ALL).

    Args:
        user_id: The ID/email of the user initiating the request.
        ttl_s: Token validity in seconds (default 2 minutes).
        extra_permissions: Optional extra permission constants to include.
    """
    import time

    from contextunity.core.permissions import Permissions
    from contextunity.core.tokens import ContextToken

    uid = user_id or "service"

    # Per-request client tokens carry scopes that SecureNode/SecureTool
    # will attenuate during graph execution. Each scope listed here is
    # verified by TokenBuilder.attenuate — if missing, the node raises
    # PermissionError.
    #
    # NOT included (separate service tokens used instead):
    #   brain:*            → get_brain_service_token() (read permissions)
    #   worker:*           → service-level token in client.py
    #   shield:secrets:write → bootstrap-only, never per-request
    perms = {
        Permissions.ROUTER_EXECUTE,
        Permissions.TRACE_WRITE,
        Permissions.MEMORY_WRITE,
        # SecureNode: tool bindings → SecureTool._enforce_permission
        Permissions.TOOL_ALL,
        # SecureNode: LLM key access via shield:secrets:read
        Permissions.SHIELD_SECRETS_READ,
        # SecureNode: PII masking (zero:anonymize, zero:deanonymize)
        Permissions.ZERO_ALL,
        # Subagent spawning
        Permissions.GRAPH_ALL,
    }
    if extra_permissions:
        perms.update(extra_permissions)

    project_id = get_project_id()
    if not project_id:
        raise ValueError("Cannot mint client token: project_id is empty (SDK bootstrap not run)")

    return ContextToken(
        token_id=f"{project_id}-client-{uid}",
        user_id=uid,
        permissions=tuple(perms),
        allowed_tenants=(get_tenant_id(),),
        exp_unix=time.time() + ttl_s,
    )


__all__ = [
    "get_project_id",
    "get_tenant_id",
    "get_worker_bindings",
    "set_project_identity",
    "set_worker_bindings",
    "mint_client_token",
]
