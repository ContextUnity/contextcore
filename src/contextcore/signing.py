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
import hashlib
import hmac
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
# HMAC mode (basic open source security)
# =========================================


class HmacBackend:
    """Symmetric HMAC-SHA256 signing backend for ContextUnity Basic (OpenSource).

    Requires a shared secret known to all services (Signers and Verifiers).
    """

    def __init__(self, shared_secret: str, kid: str = "hmac-001"):
        if not shared_secret:
            raise ValueError("HmacBackend requires a shared_secret")
        self._secret = shared_secret.encode()
        self._kid = kid

    @property
    def algorithm(self) -> str:
        return "hmac"

    @property
    def active_kid(self) -> str:
        return self._kid

    def sign(self, payload: bytes) -> SignedPayload:
        payload_b64 = base64.b64encode(payload).decode()
        sig = hmac.new(self._secret, payload_b64.encode(), hashlib.sha256).digest()
        sig_b64 = base64.b64encode(sig).decode()
        return SignedPayload(
            payload=payload_b64,
            signature=sig_b64,
            kid=self._kid,
            algorithm=self.algorithm,
        )

    def verify(self, token_str: str) -> bytes | None:
        if not token_str or not token_str.strip():
            return None

        parts = token_str.strip().split(".")

        if len(parts) == 3:
            _kid, payload_b64, sig_b64 = parts
        elif len(parts) == 2:
            payload_b64, sig_b64 = parts
        else:
            return None

        if not sig_b64:
            return None

        try:
            expected_sig = hmac.new(self._secret, payload_b64.encode(), hashlib.sha256).digest()
            actual_sig = base64.b64decode(sig_b64)
            if not hmac.compare_digest(expected_sig, actual_sig):
                logger.warning("HMAC signature verification failed")
                return None
            return base64.b64decode(payload_b64)
        except Exception:
            logger.warning("HMAC payload base64 decode failed")
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

    # Check for basic/open-source HMAC mode built-into contextcore
    backend_type = getattr(config.signing_backend, "value", str(config.signing_backend))
    if backend_type == "hmac":
        if not config.shared_secret:
            error_msg = "HMAC backend enabled (SIGNING_BACKEND=hmac) but SIGNING_SHARED_SECRET is not set."
            logger.critical(error_msg)
            raise RuntimeError(error_msg)
        return HmacBackend(shared_secret=config.shared_secret, kid=config.signing_key_id)

    # Try contextshield (Pro)
    try:
        from contextshield.signing import create_backend  # type: ignore[import-not-found]

        return create_backend(config)
    except ImportError:
        error_msg = (
            "CRITICAL: Security enforcement is ENABLED (SECURITY_ENABLED=true) but "
            "the 'contextshield' package is not installed. "
            "Refusing to silently downgrade to UNSIGNED mode. "
            "You must install contextshield to use Ed25519/KMS security, or "
            "set SECURITY_ENABLED=false for dev/demo mode."
        )
        logger.critical(error_msg)
        raise RuntimeError(error_msg)


__all__ = [
    "SignedPayload",
    "SigningBackend",
    "UnsignedBackend",
    "HmacBackend",
    "get_signing_backend",
]
