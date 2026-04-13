"""CLI operations for ContextUnity security generation.

Provides commands to generate new HMAC secrets, Shield keys, and rotate keys
for projects connecting to contextunity.router or contextunity.shield.
"""

from __future__ import annotations

import base64
import secrets
import sys

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


def mint_redis() -> None:
    """Handle the 'redis' subcommand."""
    secret = generate_hmac_secret(urlsafe=True)

    print("🗄️ Redis Encryption Key Generated")
    print("====================================")
    print("This secret is used to encrypt project keys inside Redis.")
    print("Keep it safe. Do NOT commit it to version control.\n")
    print("🔑 Add this to your Router, Brain, and Worker .env files:")
    print(f"REDIS_SECRET_KEY={secret}")


def mint_rotate(project_id: str, redis_url: str = "") -> None:
    """Handle the 'rotate' subcommand."""
    print(f"🔄 Rotating keys for project: {project_id}")

    try:
        import contextunity.core.discovery as discovery
    except ImportError:
        print(
            "❌ Error: Redis project key management not yet fully implemented in discovery.py (Requires Phase 3).",
            file=sys.stderr,
        )
        sys.exit(1)

    projects = discovery.get_registered_projects(redis_url=redis_url)
    target_p = next((p for p in projects if p.get("project_id") == project_id), None)

    if not target_p:
        print(f"❌ Error: Project '{project_id}' not found in Redis registry.", file=sys.stderr)
        sys.exit(1)

    new_secret = generate_hmac_secret()
    owner_tenant = target_p.get("owner_tenant", "")
    tools = target_p.get("tools", [])

    success = discovery.register_project(
        project_id=project_id,
        owner_tenant=owner_tenant,
        tools=tools,
        redis_url=redis_url,
        project_secret=new_secret,
    )

    if success:
        print(f"✅ Successfully rotated HMAC secret for project '{project_id}'.")
        print("=====================================================")
        print("🔑 Provide the following new secret to the project:")
        print(f"CU_PROJECT_SECRET={new_secret}")
    else:
        print("❌ Error: Failed to update Redis registry.", file=sys.stderr)
        sys.exit(1)


def mint_rotate_redis_key(redis_url: str = "") -> None:
    """Handle regenerating all Redis items with a new REDIS_SECRET_KEY."""
    print("🔄 Re-encrypting Redis DB from old REDIS_SECRET_KEY to new REDIS_SECRET_KEY...")

    import getpass
    import os

    current_env_key = os.getenv("REDIS_SECRET_KEY")  # nosec
    prompt_text = (
        "Enter current OLD REDIS_SECRET_KEY (press Enter to use from .env): "
        if current_env_key
        else "Enter current OLD REDIS_SECRET_KEY: "
    )

    old_key = os.getenv("OLD_KEY") or getpass.getpass(prompt_text) or current_env_key  # nosec
    if not old_key:
        print("❌ Error: No OLD key provided and REDIS_SECRET_KEY not found in environment.")
        sys.exit(1)

    new_key = os.getenv("NEW_KEY") or getpass.getpass("Enter NEW REDIS_SECRET_KEY: ")  # nosec
    if not new_key:
        print("❌ Error: New key cannot be empty.")
        sys.exit(1)

    try:
        import redis as redis_sync
        from contextunity.core.discovery import PROJECTS_PREFIX, _get_redis_url
    except ImportError:
        print("❌ Error: Redis required for this operation.", file=sys.stderr)
        sys.exit(1)

    url = _get_redis_url(redis_url)
    if not url:
        print("❌ Error: No REDIS_URL provided or found in environment.", file=sys.stderr)
        sys.exit(1)

    r = redis_sync.from_url(url, decode_responses=True)

    # 1. Fetch all project keys
    cursor = "0"
    matches = []
    while cursor != 0:
        cursor, res = r.scan(cursor=cursor, match=f"{PROJECTS_PREFIX}:*", count=100)
        matches.extend(res)

    if not matches:
        print("✅ No projects to re-encrypt. You can just start using the new REDIS_SECRET_KEY.")
        sys.exit(0)

    import os

    import contextunity.core.discovery as discovery

    count = 0
    for key in set(matches):
        raw_val = r.get(key)
        if not raw_val:
            continue

        # Decrypt with OLD key
        os.environ["REDIS_SECRET_KEY"] = old_key  # nosec
        discovery._redis_secret_key = None  # Clear cache
        try:
            decrypted = discovery._decrypt(raw_val)
        except Exception as e:
            print(f"⚠️ Failed to decrypt {key} with old key: {e}", file=sys.stderr)
            continue

        # Encrypt with NEW key
        os.environ["REDIS_SECRET_KEY"] = new_key  # nosec
        discovery._redis_secret_key = None  # Clear cache
        try:
            new_encrypted = discovery._encrypt(decrypted)
        except Exception as e:
            print(f"❌ Failed to encrypt {key} with new key: {e}", file=sys.stderr)
            sys.exit(1)

        # Save back
        r.set(key, new_encrypted)
        count += 1

    print(f"✅ Successfully re-encrypted {count} Redis records.")
    print("=====================================================")
    print("🔑 Update your infrastructure/ansible and restart ALL services with the NEW key!")
