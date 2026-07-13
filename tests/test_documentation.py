"""Tests for shared documentation metadata primitives."""

from __future__ import annotations

from contextunity.core.documentation import (
    DEFAULT_LIFECYCLE,
    DEFAULT_VISIBILITY,
    DOCUMENTATION_CELL_KIND,
    content_hash_of,
)


def test_documentation_metadata_defaults_are_canonical() -> None:
    """All services share one canonical documentation-cell metadata shape."""
    assert DEFAULT_LIFECYCLE == "draft"
    assert DEFAULT_VISIBILITY == "internal"
    assert DOCUMENTATION_CELL_KIND == "documentation"


def test_content_hash_is_stable_and_content_sensitive() -> None:
    """Documentation identity is deterministic without importing Brain."""
    assert content_hash_of("same") == content_hash_of("same")
    assert content_hash_of("same") != content_hash_of("different")
    assert content_hash_of("same").startswith("sha256:")
