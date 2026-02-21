"""Signing backend interface for ContextUnity.

Provides the SigningBackend protocol — the interface that signing implementations
must satisfy. Actual implementations live in contextshield (Pro).

contextcore (public) provides:
- SigningBackend Protocol (interface)
- SignedPayload dataclass (wire format)
- get_signing_backend() factory (auto-discovers contextshield)

contextshield (pro) provides:
- Ed25519Backend — asymmetric, zero-knowledge verification
- KmsBackend — Cloud KMS/HSM, kid-based rotation

Security is DISABLED by default. Without contextshield installed,
tokens are unsigned (dev/demo mode only).

Wire format:
    kid.payload_b64.signature_b64   (3 parts, always)
"""

from __future__ import annotations

import base64
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from .config import SharedSecurityConfig

logger = logging.getLogger(__name__)


# =========================================
# Data types
# =========================================


@dataclass(frozen=True)
class SignedPayload:
    """Result of a signing operation.

    Attributes:
        payload: base64-encoded token data.
        signature: backend-specific signature string (empty = unsigned).
        kid: key identifier (for rotation support).
        algorithm: signing algorithm used ("none", "ed25519", "kms").
    """

    payload: str
    signature: str
    kid: str
    algorithm: str

    def serialize(self) -> str:
        """Serialize to wire format: kid.payload.signature (always 3 parts)."""
        return f"{self.kid}.{self.payload}.{self.signature}"


# =========================================
# Protocol
# =========================================


@runtime_checkable
class SigningBackend(Protocol):
    """Protocol for signing backends.

    Implementations must provide:
    - algorithm: string identifier (e.g. "ed25519", "kms")
    - active_kid: current key identifier for rotation
    - sign(): create a signed token
    - verify(): verify and return payload, or None if invalid

    Implementations live in contextshield (Pro).
    Install contextshield for Ed25519/KMS signing.
    """

    @property
    def algorithm(self) -> str: ...

    @property
    def active_kid(self) -> str: ...

    def sign(self, payload: bytes) -> SignedPayload: ...

    def verify(self, token_str: str) -> bytes | None:
        """Verify token and return raw payload bytes.

        Args:
            token_str: serialized token string (kid.payload.signature)

        Returns:
            Raw payload bytes if valid, None if verification fails.
        """
        ...


# =========================================
# Unsigned mode (default, no contextshield)
# =========================================


class UnsignedBackend:
    """No-op signing backend for development/demo mode.

    Tokens are base64-encoded but NOT cryptographically signed.
    This is the default when contextshield is not installed.

    ⚠️ NOT for production use — tokens can be forged.
    """

    @property
    def algorithm(self) -> str:
        return "none"

    @property
    def active_kid(self) -> str:
        return "unsigned"

    def sign(self, payload: bytes) -> SignedPayload:
        """Encode payload without signing."""
        payload_b64 = base64.b64encode(payload).decode()
        return SignedPayload(
            payload=payload_b64,
            signature="",
            kid="unsigned",
            algorithm="none",
        )

    def verify(self, token_str: str) -> bytes | None:
        """Accept any well-formed token without verification.

        ⚠️ No security — any payload is accepted.
        """
        if not token_str or not token_str.strip():
            return None

        parts = token_str.strip().split(".")

        if len(parts) == 3:
            # kid.payload.signature — standard format
            _kid, payload_b64, _sig = parts
        elif len(parts) == 2:
            # payload.signature — legacy format (backward compat)
            payload_b64, _sig = parts
        elif len(parts) == 1:
            # bare payload — oldest legacy
            payload_b64 = parts[0]
        else:
            return None

        try:
            return base64.b64decode(payload_b64)
        except Exception:
            return None


# =========================================
# Factory
# =========================================


def get_signing_backend(
    config: SharedSecurityConfig | None = None,
) -> SigningBackend:
    """Get the appropriate signing backend.

    Resolution order:
    1. If config.enabled is False → UnsignedBackend (dev mode)
    2. Try importing from contextshield (Pro)
    3. Fall back to UnsignedBackend with warning

    Args:
        config: Security configuration. None = disabled.

    Returns:
        SigningBackend instance.
    """
    if config is None or not config.enabled:
        return UnsignedBackend()

    # Try contextshield (Pro)
    try:
        from contextshield.signing import create_backend  # type: ignore[import-not-found]

        return create_backend(config)
    except ImportError:
        logger.warning(
            "Security is enabled but contextshield is not installed. "
            "Running in UNSIGNED mode — tokens are NOT cryptographically signed. "
            "Install contextshield for Ed25519/KMS signing."
        )
        return UnsignedBackend()


__all__ = [
    "SignedPayload",
    "SigningBackend",
    "UnsignedBackend",
    "get_signing_backend",
]
