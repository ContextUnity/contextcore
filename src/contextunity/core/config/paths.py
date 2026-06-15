"""Operator state paths — shared config directory and credentials file resolution."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from contextunity.core.config.env import get_env

_CONFIG_DIR_ENV_KEYS: tuple[str, ...] = ("CU_CONFIG_DIR", "CONTEXTUNITY_CONFIG_DIR")
_OPERATOR_PROFILE_ENV_KEYS: tuple[str, ...] = ("CU_OPERATOR_PROFILE", "CU_PROFILE")


def default_operator_fallback_dirs() -> tuple[Path, ...]:
    """Config search dirs when ``CU_CONFIG_DIR`` is unset (cwd first)."""
    return (
        Path.cwd() / ".contextunity",
        Path.home() / ".contextunity",
    )


# Back-compat alias — prefer ``default_operator_fallback_dirs()`` (cwd is dynamic).
DEFAULT_OPERATOR_FALLBACK_DIRS = default_operator_fallback_dirs()


def resolve_config_dir(*, fallback_dirs: Sequence[Path] | None = None) -> Path:
    """Return the effective ContextUnity config/state directory.

    Resolution order:

    1. ``CU_CONFIG_DIR`` or ``CONTEXTUNITY_CONFIG_DIR`` env
    2. First existing directory in ``fallback_dirs`` (default: CWD/.contextunity, ~/.contextunity)
    3. ``~/.contextunity`` (default when nothing exists yet)
    """
    for key in _CONFIG_DIR_ENV_KEYS:
        raw = get_env(key)
        if raw:
            return Path(raw).expanduser()
    dirs = fallback_dirs if fallback_dirs is not None else default_operator_fallback_dirs()
    for directory in dirs:
        if directory.is_dir():
            return directory
    return Path.home() / ".contextunity"


def resolve_credentials_path(*, fallback_dirs: Sequence[Path] | None = None) -> Path:
    """Return the operator credentials file path.

    Resolution order:

    1. ``CU_OPERATOR_CREDENTIALS`` env (explicit file)
    2. ``{resolve_config_dir()}/credentials.json``
    """
    explicit = get_env("CU_OPERATOR_CREDENTIALS")
    if explicit:
        return Path(explicit).expanduser()
    return resolve_config_dir(fallback_dirs=fallback_dirs) / "credentials.json"


def resolve_operator_profile(*, default: str = "local") -> str:
    """Active credentials profile name (``local`` when unset)."""
    for key in _OPERATOR_PROFILE_ENV_KEYS:
        raw = get_env(key)
        if raw:
            return raw
    return default


__all__ = [
    "DEFAULT_OPERATOR_FALLBACK_DIRS",
    "default_operator_fallback_dirs",
    "resolve_config_dir",
    "resolve_credentials_path",
    "resolve_operator_profile",
]
