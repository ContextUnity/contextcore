"""Project-scoped introspection permission checks."""

from __future__ import annotations

from contextunity.core.permissions import Permissions
from contextunity.core.permissions.access import has_introspection_access


def test_introspect_project_permission() -> None:
    assert has_introspection_access((Permissions.introspect("sample_project"),), "sample_project")
    assert not has_introspection_access((Permissions.introspect("sample_project"),), "acme")


def test_register_permission_implies_introspect() -> None:
    assert has_introspection_access((Permissions.register("sample_project"),), "sample_project")


def test_bare_router_introspect_does_not_grant_all_projects() -> None:
    assert not has_introspection_access((Permissions.ROUTER_INTROSPECT,), "sample_project")
