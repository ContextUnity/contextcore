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
        project_tenants=["nszu", "nszu-staging"],
        graph_tenants=["nszu-staging"],
        node_tenants=["nszu-staging"],
        token_tenants=("nszu", "nszu-staging"),
    )
    assert effective == ("nszu-staging",)


def test_resolve_effective_allowed_tenants_rejects_graph_exceeding_project() -> None:
    with pytest.raises(ConfigurationError):
        validate_tenant_subset(
            ["other"],
            project_scope=["nszu"],
            context="Graph",
        )


def test_resolve_effective_allowed_tenants_token_intersection_fail_closed() -> None:
    with pytest.raises(SecurityError):
        resolve_effective_allowed_tenants(
            project_tenants=["nszu", "nszu-staging"],
            graph_tenants=["nszu-staging"],
            token_tenants=("nszu",),
        )


def test_token_builder_attenuate_narrows_allowed_tenants() -> None:
    parent = ContextToken(
        token_id="parent",
        permissions=("tool:sql:execute",),
        allowed_tenants=("nszu", "nszu-staging"),
    )
    child = TokenBuilder().attenuate(
        parent,
        allowed_tenants=("nszu-staging",),
        agent_id="node:sql_tool",
    )
    assert child.allowed_tenants == ("nszu-staging",)


def test_token_builder_attenuate_rejects_tenant_expansion() -> None:
    parent = ContextToken(
        token_id="parent",
        permissions=("tool:sql:execute",),
        allowed_tenants=("nszu",),
    )
    with pytest.raises(SecurityError):
        TokenBuilder().attenuate(parent, allowed_tenants=("nszu", "other"))


def test_validate_attenuation_tenants_admin_parent() -> None:
    assert validate_attenuation_tenants((), ("nszu-staging",), parent_is_admin=True) == ("nszu-staging",)


def test_validate_attenuation_tenants_empty_non_admin_parent_rejects_expansion() -> None:
    with pytest.raises(SecurityError):
        validate_attenuation_tenants((), ("nszu-staging",))


def test_resolve_effective_allowed_tenants_empty_non_admin_token_fails_closed() -> None:
    with pytest.raises(SecurityError):
        resolve_effective_allowed_tenants(
            project_tenants=["nszu"],
            token_tenants=(),
        )


def test_resolve_effective_allowed_tenants_admin_token_bypasses_scope() -> None:
    assert resolve_effective_allowed_tenants(
        project_tenants=["nszu"],
        token_tenants=(),
        token_is_admin=True,
    ) == ("nszu",)


def test_require_token_covers_allowed_tenants_accepts_verified_auth_context() -> None:
    token = ContextToken(
        token_id="bootstrap",
        permissions=("tools:register:nszu",),
        allowed_tenants=("nszu", "nszu-staging"),
    )
    auth_ctx = VerifiedAuthContext.from_token(token, "raw-token", project_id="nszu")
    require_token_covers_allowed_tenants(
        auth_ctx,
        allowed_tenants=["nszu", "nszu-staging"],
        project_id="nszu",
    )


def test_require_token_covers_allowed_tenants_rejects_missing_scope_on_auth_context() -> None:
    token = ContextToken(
        token_id="bootstrap",
        permissions=("tools:register:nszu",),
        allowed_tenants=("nszu",),
    )
    auth_ctx = VerifiedAuthContext.from_token(token, "raw-token", project_id="nszu")
    with pytest.raises(SecurityError):
        require_token_covers_allowed_tenants(
            auth_ctx,
            allowed_tenants=["nszu", "nszu-staging"],
            project_id="nszu",
        )


def test_require_token_covers_allowed_tenants_rejects_empty_non_admin_scope() -> None:
    token = ContextToken(
        token_id="bootstrap",
        permissions=("tools:register:nszu",),
    )
    auth_ctx = VerifiedAuthContext.from_token(token, "raw-token", project_id="nszu")

    with pytest.raises(SecurityError):
        require_token_covers_allowed_tenants(
            auth_ctx,
            allowed_tenants=["nszu"],
            project_id="nszu",
        )
