"""Canonical tenant classes and reserved-tenant validation."""

from __future__ import annotations

from typing import Literal

from .exceptions import ConfigurationError

DOC_TENANT_ID = "_doc"
TEST_TENANT_ID = "_test"
SYSTEM_TENANT_ID = "_system"
RESERVED_TENANT_IDS = frozenset({DOC_TENANT_ID, TEST_TENANT_ID, SYSTEM_TENANT_ID})
SYSTEM_ALLOWED_RECORD_KINDS = frozenset({"blackboard", "cell", "trace"})
SYSTEM_ALLOWED_CELL_KINDS = frozenset({"config", "summary"})
SYSTEM_ALLOWED_SOURCE_TYPES = frozenset({"config", "retention", "tool"})

TenantClass = Literal["project", "documentation", "test", "system"]


def classify_tenant(tenant_id: str) -> TenantClass:
    """Return the canonical class for a validated tenant identifier."""
    if tenant_id == DOC_TENANT_ID:
        return "documentation"
    if tenant_id == TEST_TENANT_ID:
        return "test"
    if tenant_id == SYSTEM_TENANT_ID:
        return "system"
    return "project"


def validate_tenant_id(tenant_id: str, *, allow_reserved: bool = True) -> str:
    """Validate a tenant identifier at a contract boundary.

    Project-owned tenant identifiers may not start with ``_``. The three
    reserved identifiers are accepted only by platform paths that explicitly
    opt into reserved tenants.
    """
    if not tenant_id.strip():
        raise ConfigurationError(message="tenant_id must be a non-empty string")
    normalized = tenant_id.strip()
    if normalized.startswith("_") and (not allow_reserved or normalized not in RESERVED_TENANT_IDS):
        raise ConfigurationError(
            message=(f"Tenant '{normalized}' is reserved; use one of {sorted(RESERVED_TENANT_IDS)} for platform paths")
        )
    return normalized


def is_project_tenant(tenant_id: str) -> bool:
    """Return whether *tenant_id* is a non-reserved project tenant."""
    return classify_tenant(tenant_id) == "project" and not tenant_id.startswith("_")


def resolve_documentation_tenant(configured_tenant: str) -> str:
    """Resolve docs output to ``_doc`` or the safe ``_test`` fallback."""
    if configured_tenant in {DOC_TENANT_ID, TEST_TENANT_ID}:
        return configured_tenant
    return TEST_TENANT_ID


def is_production_learning_tenant(tenant_id: str) -> bool:
    """Return whether tenant data may update production learning signals."""
    return tenant_id not in {TEST_TENANT_ID, DOC_TENANT_ID, SYSTEM_TENANT_ID}


def is_production_export_tenant(tenant_id: str) -> bool:
    """Return whether tenant data may enter a production portable archive."""
    return tenant_id != TEST_TENANT_ID


__all__ = [
    "DOC_TENANT_ID",
    "RESERVED_TENANT_IDS",
    "SYSTEM_ALLOWED_CELL_KINDS",
    "SYSTEM_ALLOWED_RECORD_KINDS",
    "SYSTEM_ALLOWED_SOURCE_TYPES",
    "SYSTEM_TENANT_ID",
    "TEST_TENANT_ID",
    "TenantClass",
    "classify_tenant",
    "is_project_tenant",
    "is_production_export_tenant",
    "is_production_learning_tenant",
    "resolve_documentation_tenant",
    "validate_tenant_id",
]
