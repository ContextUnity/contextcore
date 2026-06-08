"""Deterministic hash for router registration bundle idempotency."""

from __future__ import annotations

import hashlib

from contextunity.core.parsing import json_dumps
from contextunity.core.types import is_object_dict


def compute_registration_bundle_hash(bundle: dict[str, object]) -> str:
    """Compute a stable SHA-256 hash of a registration bundle.

    Inline secrets are part of the registration state, so rotating them must
    invalidate the idempotency hash and trigger re-registration.

    Args:
        bundle: Serialized ``RouterRegistrationBundle`` dict.

    Returns:
        Lowercase hex digest string.
    """
    canonical = bundle if is_object_dict(bundle) else {}
    payload = json_dumps(canonical, sort_keys=True, ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


__all__ = ["compute_registration_bundle_hash"]
