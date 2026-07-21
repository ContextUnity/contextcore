"""Local operator authorization profile tests."""

from contextunity.core.operator_auth import mint_local_operator_token
from contextunity.core.permissions import Permissions


def test_tenant_scoped_operator_can_read_protected_trace_detail() -> None:
    _bearer, token, _expires_at = mint_local_operator_token(
        platform_secret="test-platform-secret-that-is-long-enough",
        allowed_tenants=("tenant-a",),
    )

    assert token.has_permission(Permissions.TRACE_READ)
    assert token.has_permission(Permissions.TRACE_ARTIFACT_READ)
    assert not token.has_permission(Permissions.TRACE_ARTIFACT_LIFECYCLE)


def test_platform_operator_can_introspect_router_registrations() -> None:
    _bearer, token, _expires_at = mint_local_operator_token(
        platform_secret="test-platform-secret",
    )

    assert token.has_permission(Permissions.ADMIN_ALL)
    assert token.has_permission(Permissions.ROUTER_INTROSPECT)
