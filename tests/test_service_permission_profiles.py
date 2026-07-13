"""Regression tests for shared autonomous-service permission profiles."""

from __future__ import annotations

import pytest
from contextunity.core.cli.validate import _derive_permissions
from contextunity.core.exceptions import ConfigurationError
from contextunity.core.permissions import (
    Permissions,
    brain_caller_permissions,
    service_session_permissions,
)


def test_manifest_policy_derivation_covers_worker_session_contract() -> None:
    manifest = {
        "services": {
            "worker": {"enabled": True},
            "shield": {"enabled": True},
        },
    }

    derived = set(_derive_permissions(manifest))

    assert set(service_session_permissions("worker")) <= derived
    assert Permissions.BRAIN_EMBED in derived
    assert Permissions.DOCS_READ in derived
    assert set(service_session_permissions("shield")) <= derived


def test_worker_brain_token_is_bounded_by_worker_session() -> None:
    assert set(brain_caller_permissions("worker")) <= set(
        service_session_permissions("worker"),
    )


@pytest.mark.parametrize(
    ("resolver", "subject"),
    [
        (service_session_permissions, "unknown-service"),
        (brain_caller_permissions, "unknown-caller"),
    ],
)
def test_unknown_permission_profile_fails_closed(resolver, subject: str) -> None:
    with pytest.raises(ConfigurationError, match="Known values"):
        resolver(subject)
