"""Config factory — builds SharedConfig and ServiceConfig from YAML + env/creds.

Provides ``load_service_config`` (YAML + env/creds merge),
``get_core_config`` (cached singleton), and ``ServiceConfigRegistry``
(per-service singletons).

Resolution hierarchy (lowest → highest precedence):
  1. Config file (YAML/TOML)
  2. Env/creds mappings — unified via ``read_credential``
     (systemd-creds → env var auto-fallback)
  3. Programmatic overrides (``extra_env``, for list parsing only)
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Generic, TypeVar

from contextunity.core.types import ConfigFactory, ConfigMapping, JsonDict, is_json_dict, is_json_value
from pydantic import BaseModel

from .env import get_env, read_credential
from .loader import load_config_file, read_service_file
from .models import SharedConfig

_T = TypeVar("_T", bound=BaseModel)


# ── Shared env/creds mappings (apply to ALL services via SharedConfig) ──
#
# Keys = env var names (SCREAMING_SNAKE).
# Values = dotted config field paths.
#
# Resolution for each key goes through read_credential(key.lower()):
#   1. systemd-creds:  $CREDENTIALS_DIRECTORY/{key_lower}
#   2. env var:        ${KEY}
# If neither exists, the Pydantic field default applies.

SHARED_ENV_MAPPINGS: dict[str, str] = {
    # Logging
    "LOG_LEVEL": "log_level",
    "LOG_JSON": "log_json",
    # gRPC
    "GRPC_REUSE_PORT": "grpc_reuse_port",
    # Redis
    "REDIS_ENABLED": "redis.enabled",
    "REDIS_URL": "redis.url",
    # Observability
    "SERVICE_NAME": "service_name",
    "SERVICE_VERSION": "service_version",
    "CU_PLATFORM": "cu_platform",
    # TLS
    "GRPC_TLS_ENABLED": "tls_enabled",
    "GRPC_TLS_CA_CERT": "tls_ca_cert",
    "GRPC_TLS_CLIENT_CERT": "tls_client_cert",
    "GRPC_TLS_CLIENT_KEY": "tls_client_key",
    "GRPC_TLS_SERVER_CERT": "tls_server_cert",
    "GRPC_TLS_SERVER_KEY": "tls_server_key",
    "GRPC_TLS_REQUIRE_CLIENT_AUTH": "tls_require_client_auth",
    # Service endpoints
    "CU_ROUTER_GRPC_URL": "router_url",
    "CU_BRAIN_GRPC_URL": "brain_url",
    "CU_SHIELD_GRPC_URL": "shield_url",
    "CU_WORKER_GRPC_URL": "worker_url",
    "TEMPORAL_HOST": "temporal_host",
    # Bootstrap
    "CU_MANIFEST_PATH": "manifest_path",
    "CU_LOCAL_MODE": "local_mode",
    # Security (systemd-creds on prod, env fallback on dev)
    "REDIS_SECRET_KEY": "security.redis_secret_key",
    "CU_PROJECT_SECRET": "security.project_secret",
}


def _deep_merge(base: ConfigMapping, overlay: Mapping[str, object]) -> ConfigMapping:
    """Recursively merge values from an overlay mapping into a base dictionary."""
    for key, value in overlay.items():
        existing = base.get(key)
        if is_json_dict(value) and is_json_dict(existing):
            _ = _deep_merge(existing, value)
        elif is_json_value(value):
            base[key] = value
    return base


def _set_path(target: ConfigMapping, field_path: str, value: object) -> None:
    """Set a value in a nested dictionary using a dot-separated field path."""
    parts = field_path.split(".")
    current: ConfigMapping = target
    for part in parts[:-1]:
        existing = current.get(part)
        if not is_json_dict(existing):
            nested: JsonDict = {}
            current[part] = nested
            current = nested
        else:
            current = existing
    if is_json_value(value):
        current[parts[-1]] = value


def _apply_overrides(target: ConfigMapping, overrides: Mapping[str, object]) -> None:
    """Apply nested or dotted overrides to a target dictionary in-place."""
    for key, value in overrides.items():
        if "." in key:
            _set_path(target, key, value)
        elif is_json_dict(value):
            existing = target.get(key)
            if is_json_dict(existing):
                _ = _deep_merge(existing, value)
            else:
                nested: JsonDict = {}
                target[key] = nested
                _ = _deep_merge(nested, value)
        elif is_json_value(value):
            target[key] = value


def _resolve_mappings(
    kwargs: ConfigMapping,
    mappings: dict[str, str],
) -> None:
    """Resolve env/creds mappings via ``read_credential``."""
    for env_key, field_path in mappings.items():
        value = read_credential(env_key.lower())
        if value:
            _set_path(kwargs, field_path, value)


def load_service_config(
    cls: type[_T],
    service_name: str,
    *,
    extra_env: ConfigMapping | None = None,
    env_mappings: dict[str, str] | None = None,
    config_path: str | Path | None = None,
    fallback_dirs: list[Path] | None = None,
) -> _T:
    """Build a service config from YAML file + env/creds overrides."""
    try:
        from dotenv import load_dotenv

        env_file = Path.cwd() / ".env"
        if env_file.exists():
            _ = load_dotenv(env_file, override=False)
    except ImportError:
        pass

    kwargs: ConfigMapping = {}

    file_data = (
        load_config_file(Path(config_path))
        if config_path
        else read_service_file(service_name, fallback_dirs=fallback_dirs)
    )
    if file_data:
        _ = _deep_merge(kwargs, file_data)

    _resolve_mappings(kwargs, SHARED_ENV_MAPPINGS)

    from .models import ServiceConfig

    if issubclass(cls, ServiceConfig):
        prefix = service_name.upper()
        for field, suffix in [("host", "HOST"), ("port", "PORT")]:
            value = get_env(f"{prefix}_{suffix}")
            if value:
                kwargs[field] = value

    if env_mappings:
        _resolve_mappings(kwargs, env_mappings)

    if extra_env:
        _apply_overrides(kwargs, extra_env)

    return cls.model_validate(kwargs)


# ── Singleton cached config ─────────────────────────────────────────

_core_config: SharedConfig | None = None


def get_core_config() -> SharedConfig:
    """Get or instantiate the global cached SharedConfig singleton."""
    global _core_config
    if _core_config is None:
        _core_config = load_service_config(SharedConfig, service_name="core")
    return _core_config


def reset_core_config() -> None:
    """Reset the cached singleton so the next ``get_core_config()`` re-reads env."""
    global _core_config
    _core_config = None


# ── Service Config Registry ─────────────────────────────────────────


class ServiceConfigRegistry(Generic[_T]):
    """Centralised singleton manager for ServiceConfig subclasses."""

    _factory: ConfigFactory[_T]
    _instance: _T | None

    def __init__(self, factory: ConfigFactory[_T]) -> None:
        self._factory = factory
        self._instance = None

    def get(self) -> _T:
        if self._instance is not None:
            return self._instance
        config = self._factory()
        self.set(config)
        return config

    def set(self, config: _T) -> None:
        self._instance = config
        global _core_config
        if isinstance(config, SharedConfig):
            _core_config = config

    def reset(self) -> None:
        global _core_config
        if _core_config is self._instance:
            _core_config = None
        self._instance = None
