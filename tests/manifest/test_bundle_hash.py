from __future__ import annotations

from contextunity.core.manifest.bundle_hash import compute_registration_bundle_hash


def test_registration_bundle_hash_changes_when_inline_secret_rotates() -> None:
    original = {"project_id": "acme", "secrets": {"api_key": "old"}}
    rotated = {"project_id": "acme", "secrets": {"api_key": "new"}}

    assert compute_registration_bundle_hash(original) != compute_registration_bundle_hash(rotated)
