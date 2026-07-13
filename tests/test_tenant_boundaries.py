"""Behavioral checks for tenant identifier and fallback boundaries."""

from __future__ import annotations

import pytest
from contextunity.core.exceptions import ConfigurationError
from contextunity.core.manifest.models import ProjectSection
from contextunity.core.tenant_policy import (
    DOC_TENANT_ID,
    TEST_TENANT_ID,
    resolve_documentation_tenant,
    validate_tenant_id,
)
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
