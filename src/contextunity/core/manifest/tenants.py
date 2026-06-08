"""Project tenant scope resolution for registration and execution."""

from __future__ import annotations

from contextunity.core.exceptions import ConfigurationError, SecurityError
from contextunity.core.types import is_object_list

from .models import ProjectSection, RouterRegistrationBundle


def resolve_project_allowed_tenants(project: ProjectSection) -> list[str]:
    """Return explicit allowed tenants for a project manifest section.

    Resolution order:
    1. ``project.allowed_tenants`` when non-empty.
    2. ``[project.tenant]`` when ``tenant`` is set (legacy single-tenant manifest).
    3. ``[project.id]`` when no tenant scope is declared.

    Args:
        project: Validated project section from the manifest.

    Returns:
        Non-empty list of tenant ids usable as security scope for this project.
    """
    if project.allowed_tenants:
        tenants = [tenant for tenant in project.allowed_tenants if tenant]
        if tenants:
            return tenants
    if project.tenant:
        return [project.tenant]
    if project.id:
        return [project.id]
    raise ConfigurationError(message="Project section must define 'id' for tenant scope resolution")


def resolve_bundle_allowed_tenants(bundle: dict[str, object]) -> list[str]:
    """Resolve allowed tenants from a registration bundle payload.

    Args:
        bundle: Router registration bundle dict.

    Returns:
        Non-empty tenant scope list.

    Raises:
        ConfigurationError: When bundle lacks project_id or tenant scope.
    """
    project_id_raw = bundle.get("project_id")
    if not isinstance(project_id_raw, str) or not project_id_raw:
        raise ConfigurationError(message="RegisterManifest bundle missing non-empty 'project_id'")

    allowed_raw = bundle.get("allowed_tenants")
    if is_object_list(allowed_raw):
        allowed: list[str] = []
        for item in allowed_raw:
            if isinstance(item, str) and item:
                allowed.append(item)
        if allowed:
            return allowed

    tenant_id_raw = bundle.get("tenant_id")
    if isinstance(tenant_id_raw, str) and tenant_id_raw:
        return [tenant_id_raw]

    return [project_id_raw]


def parse_allowed_tenants_field(raw: object) -> list[str] | None:
    """Parse a manifest ``allowed_tenants`` list, ignoring empty entries."""
    if not is_object_list(raw):
        return None
    tenants: list[str] = []
    for item in raw:
        if isinstance(item, str) and item:
            tenants.append(item)
    return tenants or None


def validate_tenant_subset(
    narrower: list[str],
    *,
    project_scope: list[str],
    context: str,
) -> None:
    """Validate that *narrower* tenants are declared within *project_scope*."""
    scope = set(project_scope)
    excess = [tenant for tenant in narrower if tenant not in scope]
    if excess:
        raise ConfigurationError(
            message=(f"{context} allowed_tenants {sorted(excess)} exceed project scope {sorted(scope)}")
        )


def resolve_effective_allowed_tenants(
    *,
    project_tenants: list[str],
    graph_tenants: list[str] | None = None,
    node_tenants: list[str] | None = None,
    token_tenants: tuple[str, ...] | None = None,
    token_is_admin: bool = False,
) -> tuple[str, ...]:
    """Resolve execution tenant scope: project → graph → node → token intersection.

    Each override must be a subset of the current effective scope. When the incoming
    token scope is provided, the result is intersected with that set. Only tokens
    with the explicit ``admin:all`` capability may bypass tenant intersection.

    Args:
        project_tenants: Full project security scope.
        graph_tenants: Optional graph-level override.
        node_tenants: Optional node-level override.
        token_tenants: Optional runtime token scope.
        token_is_admin: Whether the runtime token has ``admin:all``.

    Returns:
        Non-empty effective tenant tuple.

    Raises:
        ConfigurationError: When overrides exceed their parent scope or resolve empty.
        SecurityError: When token scope does not intersect the manifest scope.
    """
    if not project_tenants:
        raise ConfigurationError(message="project_tenants must be non-empty")

    effective = list(project_tenants)
    if graph_tenants:
        validate_tenant_subset(graph_tenants, project_scope=effective, context="Graph")
        effective = list(graph_tenants)
    if node_tenants:
        validate_tenant_subset(node_tenants, project_scope=effective, context="Node")
        effective = list(node_tenants)

    if token_tenants is not None and not token_is_admin:
        token_set = set(token_tenants)
        intersected = [tenant for tenant in effective if tenant in token_set]
        if not intersected:
            raise SecurityError(
                message=(
                    "Token tenant scope does not intersect manifest scope: "
                    f"token={sorted(token_set)}, manifest={sorted(effective)}"
                )
            )
        effective = intersected

    if not effective:
        raise ConfigurationError(message="Effective allowed_tenants resolved empty")
    return tuple(effective)


def apply_allowed_tenants_to_bundle(bundle: RouterRegistrationBundle, project: ProjectSection) -> None:
    """Populate ``allowed_tenants`` on a compiled bundle and drop legacy ``tenant_id``."""
    bundle.allowed_tenants = resolve_project_allowed_tenants(project)
    bundle.tenant_id = ""


def _registration_caller_tenants(caller: object) -> tuple[str, ...] | None:
    """Extract ``allowed_tenants`` from registration auth context or token."""
    from contextunity.core.authz.context import VerifiedAuthContext
    from contextunity.core.tokens import ContextToken

    if isinstance(caller, VerifiedAuthContext):
        return caller.effective_tenants
    if isinstance(caller, ContextToken):
        return caller.allowed_tenants
    return None


def _registration_caller_is_admin(caller: object) -> bool:
    """Return whether a registration caller has explicit global admin access."""
    from contextunity.core.authz.context import VerifiedAuthContext
    from contextunity.core.tokens import ContextToken

    if isinstance(caller, (VerifiedAuthContext, ContextToken)):
        return caller.has_permission("admin:all")
    return False


def require_token_covers_allowed_tenants(
    caller: object,
    *,
    allowed_tenants: list[str],
    project_id: str,
) -> None:
    """Require registration caller token scope to cover the full project tenant set.

    Tokens with ``admin:all`` may register any project scope.
    Project bootstrap tokens must include **every** tenant declared on the bundle.

    Raises:
        ConfigurationError: When the bundle tenant scope is empty.
        SecurityError: When caller tenants are missing or do not cover the bundle scope.
    """
    if not allowed_tenants:
        raise ConfigurationError(message=f"Project '{project_id}' registration bundle has empty allowed_tenants")

    caller_tenants = _registration_caller_tenants(caller)
    if caller_tenants is None:
        raise SecurityError(
            message=(f"Registration auth context for project '{project_id}' does not expose allowed_tenants")
        )
    if _registration_caller_is_admin(caller):
        return

    token_tenants = set(caller_tenants)
    missing = [tenant for tenant in allowed_tenants if tenant not in token_tenants]
    if missing:
        raise SecurityError(
            message=(
                f"Registration token for project '{project_id}' is missing tenant scope "
                f"{missing}. Token allows {sorted(token_tenants)}; "
                f"project requires {allowed_tenants}."
            )
        )


__all__ = [
    "apply_allowed_tenants_to_bundle",
    "parse_allowed_tenants_field",
    "require_token_covers_allowed_tenants",
    "resolve_bundle_allowed_tenants",
    "resolve_effective_allowed_tenants",
    "resolve_project_allowed_tenants",
    "validate_tenant_subset",
]
