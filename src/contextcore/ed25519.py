"""Ed25519 asymmetric signing backend.

Private key: only on signing service (Router / contextctl CLI).
Public key: on all verifying services (Brain, Worker, Commerce).

This achieves zero-knowledge verification — compromising a verifier
does NOT allow minting new tokens.

Wire format: kid.payload_b64.signature_b64 (3 parts)

Key generation:
    from contextshield.signing.ed25519 import Ed25519Backend
    Ed25519Backend.generate_keypair("keys/signing.key", "keys/signing.pub")

Dependencies: cryptography (already in ecosystem).
"""

from __future__ import annotations

import base64
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from contextcore import get_context_unit_logger
from contextcore.signing import SignedPayload

logger = get_context_unit_logger(__name__)


class Ed25519Backend:
    """Ed25519 asymmetric signing backend.

    Signer mode: provide private_key_path (can also verify).
    Verifier mode: provide public_key_path OR public_key_b64 (cannot sign).

    Args:
        private_key_path: Path to PEM-encoded Ed25519 private key (signer only).
        public_key_path: Path to PEM-encoded Ed25519 public key (verifier).
        public_key_b64: Base64-encoded DER public key bytes (verifier, from Redis/Shield).
        kid: Key identifier for rotation support.
    """

    def __init__(
        self,
        *,
        private_key_path: str | None = None,
        public_key_path: str | None = None,
        public_key_b64: str | None = None,
        kid: str = "ed25519-001",
    ) -> None:
        self._kid = kid
        self._private_key: Ed25519PrivateKey | None = None
        self._public_key: Ed25519PublicKey | None = None

        if private_key_path:
            self._private_key = self._load_private_key(private_key_path)
            # Derive public key from private key
            self._public_key = self._private_key.public_key()
            logger.info("Ed25519Backend: loaded private key (SIGNER mode), kid=%s", kid)
        elif public_key_path:
            self._public_key = self._load_public_key(public_key_path)
            logger.info("Ed25519Backend: loaded public key from file (VERIFIER mode), kid=%s", kid)
        elif public_key_b64:
            self._public_key = self._load_public_key_b64(public_key_b64)
            logger.info("Ed25519Backend: loaded public key from b64 (VERIFIER mode), kid=%s", kid)
        else:
            raise ValueError(
                "Ed25519Backend requires private_key_path (signer), "
                "public_key_path (verifier from file), or public_key_b64 (verifier from b64)"
            )

    @property
    def algorithm(self) -> str:
        return "ed25519"

    @property
    def active_kid(self) -> str:
        return self._kid

    @property
    def can_sign(self) -> bool:
        """True if this backend has a private key (signer mode)."""
        return self._private_key is not None

    def sign(self, payload: bytes) -> SignedPayload:
        """Sign payload with Ed25519 private key.

        Args:
            payload: raw bytes to sign (typically JSON-encoded token data)

        Returns:
            SignedPayload with base64 payload and base64 signature.

        Raises:
            RuntimeError: If no private key is loaded (verifier-only mode).
        """
        if self._private_key is None:
            raise RuntimeError(
                "Ed25519Backend: cannot sign — no private key loaded. This service is in verifier-only mode."
            )

        payload_b64 = base64.b64encode(payload).decode()
        signature = self._private_key.sign(payload_b64.encode())
        sig_b64 = base64.b64encode(signature).decode()

        return SignedPayload(
            payload=payload_b64,
            signature=sig_b64,
            kid=self._kid,
            algorithm=self.algorithm,
        )

    def verify(self, token_str: str) -> bytes | None:
        """Verify Ed25519 signature and return payload.

        Format: kid.payload_b64.signature_b64 (3 parts)

        Args:
            token_str: serialized token string

        Returns:
            Raw payload bytes if valid, None if invalid.
        """
        if not self._public_key:
            logger.warning("Ed25519Backend: no public key — cannot verify")
            return None

        if not token_str or not token_str.strip():
            return None

        parts = token_str.strip().split(".")

        if len(parts) != 3:
            return None

        kid, payload_b64, sig_b64 = parts

        if not sig_b64:
            # Empty signature — unsigned token
            return None

        try:
            signature = base64.b64decode(sig_b64)
        except Exception:
            logger.debug("Ed25519Backend: invalid base64 signature")
            return None

        try:
            self._public_key.verify(signature, payload_b64.encode())
        except Exception:
            logger.warning("Ed25519Backend: signature verification failed")
            return None

        try:
            return base64.b64decode(payload_b64)
        except Exception:
            logger.warning("Ed25519Backend: payload base64 decode failed")
            return None

    # =========================================
    # Key management utilities
    # =========================================

    @staticmethod
    def generate_keypair(
        private_key_path: str,
        public_key_path: str,
    ) -> None:
        """Generate a new Ed25519 keypair and save to PEM files.

        Args:
            private_key_path: Where to save the private key (PEM).
            public_key_path: Where to save the public key (PEM).
        """
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        Path(private_key_path).parent.mkdir(parents=True, exist_ok=True)
        Path(private_key_path).write_bytes(private_pem)
        Path(private_key_path).chmod(0o600)  # Owner-only read/write

        Path(public_key_path).parent.mkdir(parents=True, exist_ok=True)
        Path(public_key_path).write_bytes(public_pem)

        logger.info(
            "Ed25519 keypair generated: private=%s, public=%s",
            private_key_path,
            public_key_path,
        )

    @staticmethod
    def _load_private_key(path: str) -> Ed25519PrivateKey:
        """Load Ed25519 private key from PEM file."""
        pem_data = Path(path).read_bytes()
        key = serialization.load_pem_private_key(pem_data, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError(f"Key at {path} is not Ed25519")
        return key

    @staticmethod
    def _load_public_key(path: str) -> Ed25519PublicKey:
        """Load Ed25519 public key from PEM file."""
        pem_data = Path(path).read_bytes()
        key = serialization.load_pem_public_key(pem_data)
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError(f"Key at {path} is not Ed25519")
        return key

    @staticmethod
    def _load_public_key_b64(public_key_b64: str) -> Ed25519PublicKey:
        """Load Ed25519 public key from base64-encoded DER bytes."""
        der_bytes = base64.b64decode(public_key_b64)
        key = serialization.load_der_public_key(der_bytes)
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("Provided key is not Ed25519")
        return key


__all__ = ["Ed25519Backend"]
