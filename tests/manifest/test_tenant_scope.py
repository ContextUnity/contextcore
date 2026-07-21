"""Tests for manifest tenant scope resolution and token attenuation."""

from __future__ import annotations

import pytest
from contextunity.core.authz.context import VerifiedAuthContext
from contextunity.core.exceptions import ConfigurationError, SecurityError
from contextunity.core.manifest.tenants import (
    require_token_covers_allowed_tenants,
    resolve_effective_allowed_tenants,
    validate_tenant_subset,
)
from contextunity.core.permissions.validation import validate_attenuation_tenants
from contextunity.core.tokens import ContextToken, TokenBuilder


def test_resolve_effective_allowed_tenants_graph_node_narrowing() -> None:
    effective = resolve_effective_allowed_tenants(
        project_tenants=["sample_project", "sample_project-staging"],
        graph_tenants=["sample_project-staging"],
        node_tenants=["sample_project-staging"],
        token_tenants=("sample_project", "sample_project-staging"),
    )
    assert effective == ("sample_project-staging",)


def test_resolve_effective_allowed_tenants_rejects_graph_exceeding_project() -> None:
    with pytest.raises(ConfigurationError):
        validate_tenant_subset(
            ["other"],
            project_scope=["sample_project"],
            context="Graph",
        )


def test_resolve_effective_allowed_tenants_token_intersection_fail_closed() -> None:
    with pytest.raises(SecurityError):
        resolve_effective_allowed_tenants(
            project_tenants=["sample_project", "sample_project-staging"],
            graph_tenants=["sample_project-staging"],
            token_tenants=("sample_project",),
        )


def test_token_builder_attenuate_narrows_allowed_tenants() -> None:
    parent = ContextToken(
        token_id="parent",
        permissions=("tool:sql:execute",),
        allowed_tenants=("sample_project", "sample_project-staging"),
    )
    child = TokenBuilder().attenuate(
        parent,
        allowed_tenants=("sample_project-staging",),
        agent_id="node:sql_tool",
    )
    assert child.allowed_tenants == ("sample_project-staging",)


def test_token_builder_attenuate_rejects_tenant_expansion() -> None:
    parent = ContextToken(
        token_id="parent",
        permissions=("tool:sql:execute",),
        allowed_tenants=("sample_project",),
    )
    with pytest.raises(SecurityError):
        TokenBuilder().attenuate(parent, allowed_tenants=("sample_project", "other"))


def test_validate_attenuation_tenants_admin_parent() -> None:
    assert validate_attenuation_tenants((), ("sample_project-staging",), parent_is_admin=True) == (
        "sample_project-staging",
    )


def test_validate_attenuation_tenants_empty_non_admin_parent_rejects_expansion() -> None:
    with pytest.raises(SecurityError):
        validate_attenuation_tenants((), ("sample_project-staging",))


def test_resolve_effective_allowed_tenants_empty_non_admin_token_fails_closed() -> None:
    with pytest.raises(SecurityError):
        resolve_effective_allowed_tenants(
            project_tenants=["sample_project"],
            token_tenants=(),
        )


def test_resolve_effective_allowed_tenants_admin_token_bypasses_scope() -> None:
    assert resolve_effective_allowed_tenants(
        project_tenants=["sample_project"],
        token_tenants=(),
        token_is_admin=True,
    ) == ("sample_project",)


def test_require_token_covers_allowed_tenants_accepts_verified_auth_context() -> None:
    token = ContextToken(
        token_id="bootstrap",
        permissions=("tools:register:sample_project",),
        allowed_tenants=("sample_project", "sample_project-staging"),
    )
    from contextunity.core.tokens import ProjectBound

    auth_ctx = VerifiedAuthContext.from_token(token, "raw-token", project_binding=ProjectBound("sample_project"))
    require_token_covers_allowed_tenants(
        auth_ctx,
        allowed_tenants=["sample_project", "sample_project-staging"],
        project_id="sample_project",
    )


def test_require_token_covers_allowed_tenants_rejects_missing_scope_on_auth_context() -> None:
    token = ContextToken(
        token_id="bootstrap",
        permissions=("tools:register:sample_project",),
        allowed_tenants=("sample_project",),
    )
    from contextunity.core.tokens import ProjectBound

    auth_ctx = VerifiedAuthContext.from_token(token, "raw-token", project_binding=ProjectBound("sample_project"))
    with pytest.raises(SecurityError):
        require_token_covers_allowed_tenants(
            auth_ctx,
            allowed_tenants=["sample_project", "sample_project-staging"],
            project_id="sample_project",
        )


def test_require_token_covers_allowed_tenants_rejects_empty_non_admin_scope() -> None:
    token = ContextToken(
        token_id="bootstrap",
        permissions=("tools:register:sample_project",),
    )
    from contextunity.core.tokens import ProjectBound

    auth_ctx = VerifiedAuthContext.from_token(token, "raw-token", project_binding=ProjectBound("sample_project"))

    with pytest.raises(SecurityError):
        require_token_covers_allowed_tenants(
            auth_ctx,
            allowed_tenants=["sample_project"],
            project_id="sample_project",
        )
