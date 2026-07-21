"""Behavioral checks for tenant identifier and fallback boundaries."""

from __future__ import annotations

import pytest
from contextunity.core.exceptions import ConfigurationError, SecurityError
from contextunity.core.manifest.models import ProjectSection
from contextunity.core.tenant_policy import (
    DOC_TENANT_ID,
    TEST_TENANT_ID,
    resolve_documentation_tenant,
    validate_tenant_id,
)
from contextunity.core.tokens import ContextToken
from pydantic import ValidationError


def test_reserved_identifier_is_rejected_for_project_scope() -> None:
    with pytest.raises(ValidationError):
        ProjectSection(id="_private", name="Example")


def test_reserved_identifier_is_rejected_in_explicit_scope() -> None:
    with pytest.raises(ValidationError):
        ProjectSection(id="example", name="Example", allowed_tenants=["_private"])


def test_platform_identifier_is_accepted_only_when_explicitly_reserved() -> None:
    assert validate_tenant_id(DOC_TENANT_ID, allow_reserved=True) == DOC_TENANT_ID
    with pytest.raises(ConfigurationError):
        validate_tenant_id("_private", allow_reserved=True)


def test_documentation_scope_falls_back_to_test_storage() -> None:
    assert resolve_documentation_tenant(DOC_TENANT_ID) == DOC_TENANT_ID
    assert resolve_documentation_tenant("_invalid") == TEST_TENANT_ID


class TestTokenTenantResolution:
    """Explicit targets are authorized; implicit resolution must be unambiguous."""

    def test_single_tenant_scope_resolves_without_selector(self) -> None:
        from contextunity.core.authz import resolve_token_tenant

        token = ContextToken(token_id="single", allowed_tenants=("tenant-a",))

        assert resolve_token_tenant(token, boundary="test") == "tenant-a"

    def test_multi_tenant_scope_requires_explicit_selector(self) -> None:
        from contextunity.core.authz import resolve_token_tenant

        token = ContextToken(token_id="multi", allowed_tenants=("tenant-a", "tenant-b"))

        with pytest.raises(SecurityError, match="multiple allowed_tenants"):
            resolve_token_tenant(token, boundary="test")

    def test_explicit_selector_must_be_authorized(self) -> None:
        from contextunity.core.authz import resolve_token_tenant

        token = ContextToken(token_id="scoped", allowed_tenants=("tenant-a",))

        with pytest.raises(SecurityError, match="outside token scope"):
            resolve_token_tenant(token, requested_tenant_id="tenant-b", boundary="test")

    def test_missing_token_never_adopts_payload_tenant(self) -> None:
        from contextunity.core.authz import resolve_token_tenant

        with pytest.raises(SecurityError, match="verified ContextToken"):
            resolve_token_tenant(None, requested_tenant_id="payload-tenant", boundary="test")
