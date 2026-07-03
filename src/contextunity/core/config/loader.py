"""Config file discovery and loading — YAML and TOML.

Single factory for config file resolution shared by services and CLI.
Each caller supplies its own ``fallback_dirs``; ``CU_CONFIG_DIR``
overrides them all.  Secret-like keys are stripped automatically.
"""

from __future__ import annotations

import os
from pathlib import Path

from contextunity.core.parsing import yaml_load
from contextunity.core.types import ConfigMapping, is_json_dict

# Production directory — Ansible drops per-service config here.
SYSTEM_CONFIG_DIR = Path("/etc/contextunity")

# Keys that MUST NOT come from config files (secrets → systemd-creds / env only).
# NOTE: redis_secret_key is deprecated; project secrets are no longer stored in Redis.
_SECRET_KEYS = frozenset(
    {
        "security",
        "shield_master_key",
        "shield_encryption_key",
        "project_secret",
        "openai_api_key",
        "api_key",
        "secret_key",
        "private_key",
        "password",
        "dsn",
        "database_url",
        "shield_secret_dsn",
        "django_secret_key",
    }
)


def read_service_file(
    service_name: str,
    *,
    fallback_dirs: list[Path] | None = None,
) -> ConfigMapping:
    """Load config file for a service (YAML or TOML).

    Files are always named ``{service_name}.yml`` or ``{service_name}.toml``
    (e.g. ``brain.yml``, ``router.toml``, ``contextunity.yml``).

    **SECURITY**: Secret-like keys are stripped automatically.
    Secrets MUST use ``read_credential()`` (systemd-creds) or env vars.

    Resolution order (first existing file wins)::

        1. CU_{SERVICE}_CONFIG_FILE env             (explicit file)
        2. CU_CONFIG_DIR/{service}.yml|toml          (explicit directory)
        3. fallback_dirs/{service}.yml|toml           (default: [CWD])
        4. /etc/contextunity/{service}.yml|toml      (system fallback)

    ``CU_CONFIG_DIR`` overrides ``fallback_dirs`` when set.
    ``.env`` is loaded separately by ``load_service_config`` and is
    always resolved from CWD regardless of config directory.

    Args:
        service_name: Lowercase identifier (e.g. ``"brain"``, ``"contextunity"``).
        fallback_dirs: Directories to search when ``CU_CONFIG_DIR`` is not set.
            Defaults to ``[CWD]``.  CLI passes
            ``[CWD/.contextunity, ~/.contextunity]``.

    Returns:
        ConfigMapping: The loaded configuration dictionary, or an empty dictionary
        if no configuration file is found.
    """
    # 1. Explicit file override
    env_key = f"CU_{service_name.upper()}_CONFIG_FILE"
    env_path = os.environ.get(env_key)
    if env_path:
        p = Path(env_path)
        if p.is_file():
            return load_config_file(p)

    # 2–3. Directory search: CU_CONFIG_DIR overrides fallback_dirs
    cu_config_dir = os.environ.get("CU_CONFIG_DIR")
    if cu_config_dir:
        search_dirs = [Path(cu_config_dir)]
    else:
        search_dirs = list(fallback_dirs) if fallback_dirs else [Path.cwd()]

    # 4. System config always searched last
    search_dirs.append(SYSTEM_CONFIG_DIR)

    for directory in search_dirs:
        for ext in (".yml", ".toml"):
            candidate = directory / f"{service_name}{ext}"
            if candidate.is_file():
                return load_config_file(candidate)

    return {}


def _strip_secrets(data: ConfigMapping) -> None:
    """Recursively remove secret-like keys from a dictionary.

    Args:
        data: The dictionary to inspect and modify in-place.
    """
    for key in list(data.keys()):
        if key in _SECRET_KEYS:
            _ = data.pop(key, None)
        elif is_json_dict(nested_value := data[key]):
            _strip_secrets(nested_value)


def load_config_file(path: Path) -> ConfigMapping:
    """Load a YAML or TOML file and return its top-level dict.

    Format is detected by file extension:
    - ``.yml`` / ``.yaml`` → ``yaml.safe_load``
    - ``.toml`` → ``tomllib.load``

    Secret-like keys are stripped before returning.

    Args:
        path: The Path object of the configuration file.

    Returns:
        ConfigMapping: The loaded configuration dictionary.

    Raises:
        ConfigurationError: If the file format is unsupported or the root is not a mapping.
    """
    suffix = path.suffix.lower()

    if suffix in (".yml", ".yaml"):
        with open(path, encoding="utf-8") as f:
            loaded = yaml_load(f)
    elif suffix == ".toml":
        import tomllib

        with open(path, "rb") as f:
            loaded = tomllib.load(f)
    else:
        from contextunity.core.exceptions import ConfigurationError

        raise ConfigurationError(f"Unsupported config file format '{suffix}': {path}. Use .yml or .toml.")

    if loaded is None:
        return {}
    if not is_json_dict(loaded):
        from contextunity.core.exceptions import ConfigurationError

        raise ConfigurationError(f"Config file must be a JSON mapping, got {type(loaded).__name__}: {path}")

    _strip_secrets(loaded)
    return loaded
