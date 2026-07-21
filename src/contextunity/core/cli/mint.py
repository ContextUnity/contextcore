from __future__ import annotations

import base64
import secrets

from contextunity.core.logging import get_contextunit_logger

logger = get_contextunit_logger(__name__)


def generate_hmac_secret(urlsafe: bool = False) -> str:
    """Generate a new 32-byte secure random secret for HMAC or Fernet."""
    raw = secrets.token_bytes(32)
    if urlsafe:
        return base64.urlsafe_b64encode(raw).decode("utf-8")
    return base64.b64encode(raw).decode("utf-8")


def mint_hmac() -> None:
    """Handle the 'hmac' subcommand."""
    secret = generate_hmac_secret()

    print("✅ ContextUnity HMAC Secret Generated")
    print("====================================")
    print("This secret is used for Zero-Trust project binding.")
    print("Keep it safe. Do NOT commit it to version control.\n")
    print("🔑 Add this to your project .env:")
    print(f"CU_PROJECT_SECRET={secret}")


def mint_shield() -> None:
    """Handle the 'shield' subcommand."""
    # Fernet strict url-safe requirement
    secret = generate_hmac_secret(urlsafe=True)

    print("🛡️ contextunity.shield Master Key Generated")
    print("====================================")
    print("This secret is used to encrypt the Shield SQLite Database.")
    print("Keep it safe. Do NOT commit it to version control.\n")
    print("🔑 Add this to your contextunity.shield .env:")
    print(f"SHIELD_MASTER_KEY={secret}")
