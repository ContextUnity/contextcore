from __future__ import annotations

from contextunity.core.manifest.bundle_hash import compute_registration_bundle_hash


def _bundle() -> dict[str, object]:
    return {
        "project_id": "acme",
        "graph": {"entrypoint": "writer", "edges": []},
        "prompts": {"writer": {"ref": "writer.system", "version": "v1"}},
        "tools": {"search": {"timeout_ms": 500}},
        "models": {"writer": {"provider": "openai", "model": "gpt-5"}},
    }


def test_registration_bundle_hash_is_stable_for_equal_canonical_content() -> None:
    first = _bundle()
    reordered = {
        "models": first["models"],
        "tools": first["tools"],
        "prompts": first["prompts"],
        "graph": first["graph"],
        "project_id": first["project_id"],
    }

    assert compute_registration_bundle_hash(first) == compute_registration_bundle_hash(reordered)


def test_registration_bundle_hash_changes_for_each_material_runtime_surface() -> None:
    original = _bundle()
    variants: tuple[dict[str, object], ...] = (
        {**original, "graph": {"entrypoint": "reviewer", "edges": []}},
        {**original, "prompts": {"writer": {"ref": "writer.system", "version": "v2"}}},
        {**original, "tools": {"search": {"timeout_ms": 750}}},
        {**original, "models": {"writer": {"provider": "openai", "model": "gpt-5.1"}}},
    )

    original_hash = compute_registration_bundle_hash(original)
    assert all(compute_registration_bundle_hash(variant) != original_hash for variant in variants)


def test_registration_bundle_hash_changes_when_inline_secret_rotates() -> None:
    original = {"project_id": "acme", "secrets": {"api_key": "old"}}
    rotated = {"project_id": "acme", "secrets": {"api_key": "new"}}

    assert compute_registration_bundle_hash(original) != compute_registration_bundle_hash(rotated)
