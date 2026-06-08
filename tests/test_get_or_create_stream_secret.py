"""Tests for ``get_or_create_project_stream_secret``.

The function is the idempotent counterpart to ``update_project_stream_secret``:
hash-match re-registration calls it so active ToolExecutorStream sessions
reconnect with the same key instead of being forced to re-handshake.
New projects still get a fresh 256-bit URL-safe token.
"""

from __future__ import annotations

import re

import pytest
from contextunity.core.discovery import (
    get_or_create_project_stream_secret,
    get_project_stream_secret,
    update_project_stream_secret,
)
from contextunity.core.discovery.store import (
    InMemoryProjectStore,
    set_project_store,
)


@pytest.fixture(autouse=True)
def _isolated_store() -> None:
    """Each test runs against a fresh in-memory store."""
    set_project_store(InMemoryProjectStore())
    yield
    set_project_store(InMemoryProjectStore())


def test_returns_new_secret_when_none_stored() -> None:
    secret = get_or_create_project_stream_secret("proj_fresh")
    # Looks like a 256-bit URL-safe token (43 chars, url-safe alphabet)
    assert isinstance(secret, str)
    assert len(secret) >= 40
    assert re.fullmatch(r"[A-Za-z0-9_-]+", secret) is not None
    # Now persisted in the store
    assert get_project_stream_secret("proj_fresh") == secret


def test_returns_existing_secret_on_second_call() -> None:
    first = get_or_create_project_stream_secret("proj_idem")
    second = get_or_create_project_stream_secret("proj_idem")
    assert first == second
    # Also: third call still the same
    third = get_or_create_project_stream_secret("proj_idem")
    assert first == third


def test_does_not_overwrite_existing_secret() -> None:
    """Pre-seeding a secret via ``update_project_stream_secret`` must not be replaced."""
    custom = "preexisting-custom-token-value"
    assert update_project_stream_secret("proj_pre", custom) is True
    returned = get_or_create_project_stream_secret("proj_pre")
    assert returned == custom
    # And the store still has the custom one
    assert get_project_stream_secret("proj_pre") == custom


def test_different_projects_get_independent_secrets() -> None:
    a = get_or_create_project_stream_secret("proj_a")
    b = get_or_create_project_stream_secret("proj_b")
    assert a != b
    assert get_project_stream_secret("proj_a") == a
    assert get_project_stream_secret("proj_b") == b
