"""Environment variable helpers and systemd-creds secret reader.

Provides ``get_env``, ``get_bool_env``, ``set_env_default`` for
typed env access, and ``read_credential`` for reading secrets
from systemd ``LoadCredential`` paths with env fallback.
"""

from __future__ import annotations

import os
from pathlib import Path

# ── Environment helpers ──────────────────────────────────────────────


def get_env(name: str, default: str | None = None) -> str | None:
    """Read a stripped environment variable, returning default when empty or absent.

    Args:
        name: The name of the environment variable.
        default: The default value to return if the environment variable is not set or empty.

    Returns:
        str | None: The environment variable value or the default.
    """
    val = os.environ.get(name)
    if val is None:
        return default
    s = val.strip()
    return s if s else default


def get_bool_env(name: str, default: bool | None = None) -> bool | None:
    """Read a boolean environment variable (true/false/yes/no/1/0/on/off).

    Args:
        name: The name of the environment variable.
        default: The default value if the environment variable is not set or cannot be parsed.

    Returns:
        bool | None: True if positive match, False if negative match, or default.
    """
    raw = os.environ.get(name)
    if raw is None:
        return default
    v = raw.strip().lower()
    if v in {"1", "true", "yes", "y", "on"}:
        return True
    if v in {"0", "false", "no", "n", "off"}:
        return False
    return default


def set_env_default(name: str, value: str) -> None:
    """Set an environment variable default value if not already present.

    Prefer config/YAML/env inputs; use this only for SDK feature flags
    that must exist before third-party imports instantiate clients.

    Args:
        name: The name of the environment variable.
        value: The default value to set.
    """
    _ = os.environ.setdefault(name, value)


def load_dotenv_chain(*, max_parents: int = 8) -> None:
    """Load the nearest ``.env`` from cwd or its parents without overriding env."""
    try:
        from dotenv import load_dotenv
    except ImportError:
        return

    cwd = Path.cwd()
    for directory in (cwd, *list(cwd.parents)[:max_parents]):
        env_file = directory / ".env"
        if env_file.is_file():
            _ = load_dotenv(env_file, override=False)
            return


# ── Secret reading (Tier 1 — systemd-creds) ─────────────────────────


def read_credential(cred_name: str, fallback_value: str | None = None) -> str:
    """Read a secret: systemd-creds first, then env var, then explicit fallback.

    Resolution order:
      1. ``$CREDENTIALS_DIRECTORY/{cred_name}`` — systemd ``LoadCredentialEncrypted``
      2. ``${CRED_NAME}`` env var (auto-derived: ``openai_api_key`` → ``OPENAI_API_KEY``)
      3. Explicit ``fallback_value`` (for backward compatibility)

    Args:
        cred_name: The credential name (e.g. ``"openai_api_key"``).
        fallback_value: Optional explicit fallback. When ``None``,
            the corresponding env var ``CRED_NAME.upper()`` is checked
            automatically.

    Returns:
        str: The secret value, or empty string if not found anywhere.
    """
    # Guard against path traversal (cred_name must be a simple filename)
    if not cred_name or os.sep in cred_name or cred_name.startswith("."):
        return fallback_value or ""

    # 1. systemd-creds (prod)
    cred_path = os.environ.get("CREDENTIALS_DIRECTORY")
    if cred_path:
        full_path = os.path.join(cred_path, cred_name)
        if os.path.exists(full_path):
            with open(full_path) as f:
                return f.read().strip()

    # 2. Explicit fallback or auto-derive from env var
    if fallback_value is not None:
        return fallback_value
    return os.environ.get(cred_name.upper(), "")
