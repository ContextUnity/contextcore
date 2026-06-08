"""Shared configuration contract for ContextUnity services.

Re-exports all public symbols so existing ``from contextunity.core.config import …``
statements continue to work unchanged.

Module structure::

    config/
    ├── __init__.py   ← you are here (re-exports)
    ├── models.py     ← LogLevel, SharedSecurityConfig, SharedConfig, ServiceConfig
    ├── env.py        ← get_env, get_bool_env, set_env_default, read_credential
    ├── loader.py     ← read_service_file, load_config_file (YAML + TOML)
    └── factory.py    ← get_core_config, load_service_config, ServiceConfigRegistry
"""

from .env import get_bool_env, get_env, read_credential, set_env_default
from .factory import (
    SHARED_ENV_MAPPINGS,
    ServiceConfigRegistry,
    get_core_config,
    load_service_config,
    reset_core_config,
)
from .loader import SYSTEM_CONFIG_DIR, load_config_file, read_service_file
from .models import LogLevel, ServiceConfig, SharedConfig, SharedSecurityConfig

__all__ = [
    # Models
    "SharedConfig",
    "SharedSecurityConfig",
    "ServiceConfig",
    "LogLevel",
    # Factory
    "load_service_config",
    "get_core_config",
    "reset_core_config",
    "ServiceConfigRegistry",
    "SHARED_ENV_MAPPINGS",
    # Env helpers
    "get_env",
    "get_bool_env",
    "set_env_default",
    "read_credential",
    # Loader
    "read_service_file",
    "load_config_file",
    "SYSTEM_CONFIG_DIR",
]
