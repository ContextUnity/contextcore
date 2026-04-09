"""Prompt integrity — signing and content-addressable versioning.

Provides pure functions for:
- Content-addressable versioning (SHA-256[:8]) — deterministic prompt identity.
- HMAC signing — tamper-proofing via the existing SigningBackend infrastructure.
- Verification — runtime integrity check before LLM invocation.

Used by:
    ArtifactGenerator / SDK bootstrap (sign + version)
    SecureNode (verify at execution time)
"""

from __future__ import annotations

import hashlib

from ..logging import get_context_unit_logger
from ..signing import HmacBackend

logger = get_context_unit_logger(__name__)


def compute_prompt_version(prompt_text: str) -> str:
    """Content-addressable version: first 8 hex chars of SHA-256.

    Any change to the prompt text (even one character) produces a different
    version string, enabling zero-config automatic versioning in traces.

    >>> compute_prompt_version("You are a helpful analyst.")
    'e3b0c442'  # (example — actual hash will differ)
    """
    digest = hashlib.sha256(prompt_text.encode("utf-8")).hexdigest()
    return digest[:8]


def sign_prompt(prompt_text: str, backend: HmacBackend) -> str:
    """Sign prompt text with the project's HMAC backend.

    Returns:
        Serialized SignedPayload string (``kid.payload_b64.signature_b64``).
    """
    signed = backend.sign(prompt_text.encode("utf-8"))
    return signed.serialize()


def verify_prompt(prompt_text: str, signature_str: str, backend: HmacBackend) -> bool:
    """Verify prompt integrity against a stored signature.

    Performs constant-time HMAC comparison.

    Args:
        prompt_text: The current prompt text to verify.
        signature_str: Serialized SignedPayload from ``sign_prompt()``.
        backend: The same HmacBackend used during signing.

    Returns:
        True if signature matches the prompt text, False otherwise.
    """
    payload_bytes = backend.verify(signature_str)
    if payload_bytes is None:
        return False
    return payload_bytes == prompt_text.encode("utf-8")


__all__ = [
    "compute_prompt_version",
    "sign_prompt",
    "verify_prompt",
]
