"""Canonical source-owned identity primitives for BrainCell writers."""

from __future__ import annotations

from hashlib import sha256

from .parsing import json_dumps
from .types import JsonDict


def normalize_braincell_content(content: str) -> str:
    """Normalize insignificant whitespace without changing semantic casing."""
    return " ".join(content.split())


def exact_content_fingerprint(*, tenant_id: str, user_id: str | None, cell_kind: str, content: str) -> str:
    """Build a producer-neutral fingerprint for exact duplicate detection."""
    fingerprint: JsonDict = {
        "tenant_id": tenant_id.strip(),
        "user_id": user_id.strip() if user_id is not None else None,
        "cell_kind": cell_kind.strip(),
        "content": normalize_braincell_content(content),
    }
    body = json_dumps(fingerprint, sort_keys=True).encode("utf-8")
    return "sha256:" + sha256(body).hexdigest()


def source_owned_content_hash(
    *,
    producer: str,
    tenant_id: str,
    user_id: str | None,
    cell_kind: str,
    content: str,
    producer_key: str | None = None,
) -> str:
    """Build an idempotency hash whose ownership stays with one producer."""
    fingerprint: JsonDict = {
        "producer": producer.strip(),
        "content_fingerprint": exact_content_fingerprint(
            tenant_id=tenant_id,
            user_id=user_id,
            cell_kind=cell_kind,
            content=content,
        ),
    }
    if producer_key is not None:
        fingerprint["producer_key"] = producer_key.strip()
    body = json_dumps(fingerprint, sort_keys=True).encode("utf-8")
    return "sha256:" + sha256(body).hexdigest()


__all__ = [
    "exact_content_fingerprint",
    "normalize_braincell_content",
    "source_owned_content_hash",
]
