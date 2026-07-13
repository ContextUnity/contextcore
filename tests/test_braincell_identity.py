"""Source-owned BrainCell identity contract."""

from contextunity.core.braincell_identity import (
    exact_content_fingerprint,
    normalize_braincell_content,
    source_owned_content_hash,
)


def _hash(*, producer: str, content: str, producer_key: str | None = None) -> str:
    return source_owned_content_hash(
        producer=producer,
        tenant_id="tenant-a",
        user_id="user-a",
        cell_kind="fact",
        content=content,
        producer_key=producer_key,
    )


def test_content_normalization_collapses_only_whitespace() -> None:
    assert normalize_braincell_content("  Prefers\n  Python  ") == "Prefers Python"
    assert _hash(producer="auto_extract", content="Prefers\nPython") == _hash(
        producer="auto_extract", content=" Prefers   Python "
    )
    assert _hash(producer="auto_extract", content="Prefers Python") != _hash(
        producer="auto_extract", content="prefers python"
    )


def test_identity_is_owned_by_producer_and_native_key() -> None:
    content = "Prefers Python"
    assert _hash(producer="auto_extract", content=content) != _hash(producer="synthesis", content=content)
    assert _hash(producer="synthesis", content=content, producer_key="preference") != _hash(
        producer="synthesis", content=content, producer_key="environment"
    )


def test_exact_fingerprint_is_shared_across_producers() -> None:
    first = exact_content_fingerprint(
        tenant_id="tenant-a",
        user_id="user-a",
        cell_kind="fact",
        content="Prefers  Python",
    )
    second = exact_content_fingerprint(
        tenant_id="tenant-a",
        user_id="user-a",
        cell_kind="fact",
        content="Prefers\nPython",
    )
    assert first == second
