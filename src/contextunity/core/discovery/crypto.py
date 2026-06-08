"""Redis-at-rest encryption (stdlib-only, zero external deps).

REDIS_SECRET_KEY=false             → No encryption (dev/testing) + WARNING
REDIS_SECRET_KEY=<32 bytes b64>    → Encrypt + integrity-protect
"""

from __future__ import annotations

import base64
import functools
import hashlib
import hmac as hmac_mod
import os

from ..config import get_core_config
from ..logging import get_contextunit_logger

logger = get_contextunit_logger(__name__)


def _get_redis_secret_key() -> str:
    return get_core_config().security.redis_secret_key.strip()


def _should_encrypt() -> bool:
    secret_key = _get_redis_secret_key()
    return bool(secret_key) and secret_key.lower() not in ("false", "0", "no", "")


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    """Generate an HMAC counter-mode keystream of arbitrary length.

    Each 32-byte block is computed as HMAC(key, nonce || counter).

    Args:
        key: The encryption key to seed the keystream.
        nonce: The initialization vector/nonce bytes.
        length: The desired length of the keystream in bytes.

    Returns:
        bytes: The generated keystream bytes.
    """
    stream = b""
    ctr = 0
    while len(stream) < length:
        stream += hmac_mod.new(key, nonce + ctr.to_bytes(4, "big"), hashlib.sha256).digest()
        ctr += 1
    return stream[:length]


@functools.cache
def _log_crypto_status_once() -> None:
    if _should_encrypt():
        logger.info("Redis encryption + integrity protection enabled")
    else:
        logger.warning(
            "REDIS_SECRET_KEY not set (or 'false'). Project secrets stored UNENCRYPTED in Redis. "
            + "Generate a key with 'mise run mint redis' and set the REDIS_SECRET_KEY env var for production use."
        )


def encrypt(plaintext: str) -> str:
    """Encrypt a plaintext string for secure storage in Redis.

    Uses an encrypt-then-MAC scheme with derived keys from the Redis secret key.
    Adds an "enc:" prefix to the base64-encoded output.

    Args:
        plaintext: The raw string to encrypt.

    Returns:
        str: The encrypted, base64-encoded string prefixed with "enc:",
        or the original plaintext if encryption is disabled.
    """
    if not plaintext:
        return plaintext
    _log_crypto_status_once()
    if not _should_encrypt():
        return plaintext
    key = base64.b64decode(_get_redis_secret_key())
    nonce = os.urandom(16)
    data = plaintext.encode()

    # Derive separate keys for encryption and MAC
    enc_key = hmac_mod.new(key, b"encrypt" + nonce, hashlib.sha256).digest()
    mac_key = hmac_mod.new(key, b"mac" + nonce, hashlib.sha256).digest()

    # Encrypt
    ks = _keystream(enc_key, nonce, len(data))
    ct = bytes(a ^ b for a, b in zip(data, ks))

    # MAC over nonce + ciphertext (encrypt-then-MAC)
    tag = hmac_mod.new(mac_key, nonce + ct, hashlib.sha256).digest()

    return "enc:" + base64.b64encode(nonce + ct + tag).decode()


def decrypt(ciphertext: str) -> str:
    """Decrypt a ciphertext string retrieved from Redis storage.

    Verifies the HMAC signature before decrypting to prevent padding or tampering attacks.

    Args:
        ciphertext: The encrypted string (starting with "enc:").

    Returns:
        str: The decrypted plaintext string.

    Raises:
        TamperDetectedError: If the HMAC signature verification fails.
    """
    if not ciphertext:
        return ciphertext
    _log_crypto_status_once()
    if not ciphertext.startswith("enc:"):
        return ciphertext  # Plaintext (dev or legacy)
    if not _should_encrypt():
        logger.error("Cannot decrypt: REDIS_SECRET_KEY not set but encrypted data found")
        return ""
    key = base64.b64decode(_get_redis_secret_key())
    raw = base64.b64decode(ciphertext[4:])
    nonce, ct, tag = raw[:16], raw[16:-32], raw[-32:]

    # Verify MAC FIRST (before decryption)
    mac_key = hmac_mod.new(key, b"mac" + nonce, hashlib.sha256).digest()
    expected_tag = hmac_mod.new(mac_key, nonce + ct, hashlib.sha256).digest()
    if not hmac_mod.compare_digest(tag, expected_tag):
        from ..exceptions import TamperDetectedError

        raise TamperDetectedError(
            "Redis integrity check failed — stored value was tampered. Project key binding may be compromised."
        )

    # Decrypt only after MAC verification passes
    enc_key = hmac_mod.new(key, b"encrypt" + nonce, hashlib.sha256).digest()
    ks = _keystream(enc_key, nonce, len(ct))
    return bytes(a ^ b for a, b in zip(ct, ks)).decode()
