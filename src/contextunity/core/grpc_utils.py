"""TLS-aware gRPC channel and server credential factories.
Provides a single toggle (``GRPC_TLS_ENABLED``) to switch between insecure
(development) and mTLS (production) gRPC transport.  All services and SDK
clients use these factories so that enabling TLS is a config-only change.
Environment variables (read only when ``GRPC_TLS_ENABLED=true``):
    GRPC_TLS_CA_CERT       — path to CA certificate (required)
    GRPC_TLS_SERVER_CERT   — path to server certificate (server side)
    GRPC_TLS_SERVER_KEY    — path to server private key (server side)
    GRPC_TLS_CLIENT_CERT   — path to client certificate (client side, mTLS)
    GRPC_TLS_CLIENT_KEY    — path to client private key (client side, mTLS)
"""

from __future__ import annotations

import asyncio
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import uuid4

import grpc
import grpc.aio
from contextunity.core.parsing import json_dumps
from contextunity.core.service_health.config import resolve_service_degradation_config
from contextunity.core.service_health.grpc import install_standard_health
from contextunity.core.service_health.models import (
    GRPC_HEALTH_SERVICE_NAMES,
    ServiceHealthTarget,
    ServiceName,
    ServiceRuntimeIdentity,
)
from contextunity.core.service_health.publisher import ServiceDegradationPublisher
from contextunity.core.service_health.redis import create_redis_degradation_store
from contextunity.core.service_health.runtime import (
    ServiceRuntimeHandle,
    install_service_runtime_handle,
    remove_service_runtime_handle,
)
from contextunity.core.types import AsyncShutdownHook, JsonDict

from .logging import get_contextunit_logger

if TYPE_CHECKING:
    from .config import SharedConfig

__all__ = [
    "create_channel",
    "create_channel_sync",
    "create_server_credentials",
    "graceful_shutdown",
    "redis_register_host",
    "start_grpc_server",
    "tls_enabled",
]

logger = get_contextunit_logger(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _effective_config(config: SharedConfig | None = None) -> SharedConfig:
    """Return explicit config or fall back to the process-wide core config."""
    if config is not None:
        return config

    from .config import get_core_config

    return get_core_config()


def tls_enabled(config: SharedConfig | None = None) -> bool:
    """Check if TLS transport is enabled in the provided/effective configuration.

    Args:
        config: Optional service config. When omitted, falls back to the
            process-wide core config for backwards-compatible SDK/CLI use.

    Returns:
        bool: True if TLS is configured as enabled, False otherwise.
    """
    return _effective_config(config).tls_enabled


def _read_file(path: str) -> bytes:
    """Read the full contents of a file as bytes.

    Args:
        path: The absolute or relative filesystem path to the file.

    Returns:
        bytes: The raw byte content of the file.

    Raises:
        FileNotFoundError: If the file does not exist at the specified path.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"TLS file not found: {path}")
    return p.read_bytes()


def _require_tls_path(field: str, env_name: str, config: SharedConfig | None = None) -> str:
    """Retrieve a configured TLS file path, raising an error if it is not set.

    Args:
        field: The field name in the configuration object.
        env_name: The environment variable name (used in the error message).
        config: Optional service config carrying the TLS file paths.

    Returns:
        str: The configured file path value.

    Raises:
        ConfigurationError: If the path is not configured.
    """
    config_obj: object = _effective_config(config)
    value: object = getattr(config_obj, field, None)
    if not value or not isinstance(value, str):
        from .exceptions import ConfigurationError

        raise ConfigurationError(f"TLS is enabled but {env_name} is not set")
    return value


def _client_tls_paths(config: SharedConfig) -> tuple[str, str] | None:
    """Return client cert/key paths, enforcing mTLS config consistency."""
    from .exceptions import ConfigurationError

    client_cert_path = config.tls_client_cert
    client_key_path = config.tls_client_key

    if bool(client_cert_path) != bool(client_key_path):
        raise ConfigurationError(
            "Incomplete gRPC TLS client credentials: set both GRPC_TLS_CLIENT_CERT "
            "and GRPC_TLS_CLIENT_KEY, or unset both for server-only TLS."
        )

    if client_cert_path and client_key_path:
        return client_cert_path, client_key_path

    if config.tls_require_client_auth:
        raise ConfigurationError(
            "gRPC mTLS is required by GRPC_TLS_REQUIRE_CLIENT_AUTH=true, but client "
            "credentials are missing. Set GRPC_TLS_CLIENT_CERT and "
            "GRPC_TLS_CLIENT_KEY, or set GRPC_TLS_REQUIRE_CLIENT_AUTH=false for "
            "server-only TLS."
        )

    return None


def _validate_mesh_tls_config(config: SharedConfig, *, service_name: str) -> None:
    """Fail fast on partial TLS/mTLS mesh configuration before service startup."""
    if not tls_enabled(config):
        return

    _ = _require_tls_path("tls_ca_cert", "GRPC_TLS_CA_CERT", config)
    _ = _require_tls_path("tls_server_cert", "GRPC_TLS_SERVER_CERT", config)
    _ = _require_tls_path("tls_server_key", "GRPC_TLS_SERVER_KEY", config)
    _ = _client_tls_paths(config)
    logger.debug("%s TLS mesh configuration validated", service_name)


# ---------------------------------------------------------------------------
# Client-side: channel creation
# ---------------------------------------------------------------------------

_grpc_service_config: JsonDict = {
    "methodConfig": [
        {
            "name": [{}],
            "retryPolicy": {
                "maxAttempts": 4,
                "initialBackoff": "0.1s",
                "maxBackoff": "1s",
                "backoffMultiplier": 2,
                "retryableStatusCodes": ["UNAVAILABLE", "INTERNAL"],
            },
        }
    ]
}

_SERVICE_CONFIG = json_dumps(_grpc_service_config)

_GRPC_OPTIONS = [
    ("grpc.max_send_message_length", 50 * 1024 * 1024),
    ("grpc.max_receive_message_length", 50 * 1024 * 1024),
    ("grpc.enable_retries", 1),
    ("grpc.service_config", _SERVICE_CONFIG),
    ("grpc.keepalive_time_ms", 60000),  # Less aggressive, 60s
    ("grpc.keepalive_timeout_ms", 10000),
    (
        "grpc.keepalive_permit_without_calls",
        0,
    ),  # STRICT: Do not ping idle channels (prevents ENHANCE_YOUR_CALM server drop)
]


def create_channel(
    target: str,
    config: SharedConfig | None = None,
    *,
    tls_server_name_override: str | None = None,
) -> grpc.aio.Channel:
    """Create an async gRPC channel — TLS if configured, insecure otherwise.

    For mTLS, reads the effective config's CA certificate path, and optionally
    client certificate + key for mutual auth.

    Args:
        target: gRPC target (``host:port``).
        config: Optional service config. Pass this from long-running services so
            channel TLS matches the service config.
        tls_server_name_override: TLS authority permitted only when the caller
            already validated and pinned ``target``.

    Returns:
        ``grpc.aio.Channel`` — either secure or insecure.
    """
    if config is None:
        if not tls_enabled():
            return grpc.aio.insecure_channel(target, options=_GRPC_OPTIONS)
        config = _effective_config()
    elif not tls_enabled(config):
        return grpc.aio.insecure_channel(target, options=_GRPC_OPTIONS)

    ca_cert = _read_file(_require_tls_path("tls_ca_cert", "GRPC_TLS_CA_CERT", config))
    client_paths = _client_tls_paths(config)

    if client_paths:
        client_cert_path, client_key_path = client_paths
        client_cert = _read_file(client_cert_path)
        client_key = _read_file(client_key_path)
        credentials = grpc.ssl_channel_credentials(
            root_certificates=ca_cert,
            private_key=client_key,
            certificate_chain=client_cert,
        )
    else:
        # Server-only TLS (client trusts server but doesn't authenticate)
        credentials = grpc.ssl_channel_credentials(
            root_certificates=ca_cert,
        )

    options = list(_GRPC_OPTIONS)
    if tls_server_name_override is not None:
        options.append(("grpc.ssl_target_name_override", tls_server_name_override))
    logger.debug("Creating TLS channel to %s (mTLS=%s)", target, bool(client_paths))
    return grpc.aio.secure_channel(target, credentials, options=options)


def create_channel_sync(target: str, config: SharedConfig | None = None) -> grpc.Channel:
    """Create a synchronous gRPC channel, applying TLS credentials if configured.

    Handles root CA certificates and client cert/key for mutual TLS (mTLS)
    if client credentials are set.

    Args:
        target: The gRPC target endpoint (e.g., "host:port").
        config: Optional service config. Pass this from long-running services so
            channel TLS matches the service config.

    Returns:
        grpc.Channel: A secure or insecure synchronous gRPC channel instance.
    """
    if config is None:
        if not tls_enabled():
            return grpc.insecure_channel(target, options=_GRPC_OPTIONS)
        config = _effective_config()
    elif not tls_enabled(config):
        return grpc.insecure_channel(target, options=_GRPC_OPTIONS)

    ca_cert = _read_file(_require_tls_path("tls_ca_cert", "GRPC_TLS_CA_CERT", config))
    client_paths = _client_tls_paths(config)

    if client_paths:
        client_cert_path, client_key_path = client_paths
        client_cert = _read_file(client_cert_path)
        client_key = _read_file(client_key_path)
        credentials = grpc.ssl_channel_credentials(
            root_certificates=ca_cert,
            private_key=client_key,
            certificate_chain=client_cert,
        )
    else:
        credentials = grpc.ssl_channel_credentials(
            root_certificates=ca_cert,
        )

    logger.debug("Creating sync TLS channel to %s", target)
    return grpc.secure_channel(target, credentials, options=_GRPC_OPTIONS)


# ---------------------------------------------------------------------------
# Server-side: credentials
# ---------------------------------------------------------------------------


def create_server_credentials(config: SharedConfig | None = None) -> grpc.ServerCredentials | None:
    """Create gRPC server TLS credentials based on current configuration.

    Reads root CA certificate, server certificate, and private key files.
    Supports configuring client authentication (mTLS) requirement.

    Args:
        config: Optional service config. Pass this from service bootstraps so
            server TLS matches the service config.

    Returns:
        grpc.ServerCredentials | None: The server TLS credentials, or None if
        TLS is disabled.
    """
    if config is None:
        if not tls_enabled():
            return None
        config = _effective_config()
    elif not tls_enabled(config):
        return None

    ca_cert = _read_file(_require_tls_path("tls_ca_cert", "GRPC_TLS_CA_CERT", config))
    server_cert = _read_file(_require_tls_path("tls_server_cert", "GRPC_TLS_SERVER_CERT", config))
    server_key = _read_file(_require_tls_path("tls_server_key", "GRPC_TLS_SERVER_KEY", config))

    require_client_auth = config.tls_require_client_auth

    logger.info(
        "TLS server credentials loaded (mTLS=%s)",
        require_client_auth,
    )

    return grpc.ssl_server_credentials(
        [(server_key, server_cert)],
        root_certificates=ca_cert,
        require_client_auth=require_client_auth,
    )


def bind_server_port(
    server: grpc.aio.Server,
    port: int | str,
    service_name: str = "service",
    *,
    host: str = "0.0.0.0",
    instance_name: str = "",
    config: SharedConfig | None = None,
) -> None:
    """Bind gRPC server to port with TLS if configured, log security status.

    Replaces the copy-paste TLS-bind + shield_status block in every service.

    Args:
        server: The ``grpc.aio.Server`` to bind.
        port: Port number.
        service_name: Human label for log messages.
        host: Bind address (default ``0.0.0.0``).
        instance_name: Optional instance identifier for log messages.
        config: Optional service config carrying TLS settings.

    Raises:
        ServiceStartupError: If the port is already in use.
    """
    from .exceptions import ServiceStartupError

    # Log security posture (security is always enabled fundamentally)
    logger.debug("Security: always-on")

    # Derive env var hint from service name (e.g. "Router" → "ROUTER_PORT")
    port_env_hint = f"{service_name.upper()}_PORT"

    # Bind TLS or insecure
    tls_creds = create_server_credentials(config)
    instance_suffix = f" (instance={instance_name})" if instance_name else ""
    try:
        if tls_creds:
            _ = server.add_secure_port(f"{host}:{port}", tls_creds)
            logger.info("%s starting on %s:%s with TLS%s", service_name, host, port, instance_suffix)
        else:
            _ = server.add_insecure_port(f"{host}:{port}")
            logger.info("%s starting on %s:%s%s", service_name, host, port, instance_suffix)
    except RuntimeError as exc:
        raise ServiceStartupError(
            message=(
                f"{service_name} failed to start — port {port} is already in use. "
                f"Kill the existing process or set {port_env_hint} to a different port."
            ),
        ) from exc


# ---------------------------------------------------------------------------
# Server lifecycle: start + register
# ---------------------------------------------------------------------------


_UNIVERSAL_BIND_HOSTS = frozenset({"0.0.0.0", "::", "[::]", "*"})


def _guess_local_ipv4() -> str:
    """Best-effort routable LAN address when bind-all is configured."""
    import socket

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            _ = sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def redis_register_host(bind_host: str) -> str:
    """Host for Redis discovery endpoint — never ``0.0.0.0``."""
    normalized = bind_host.strip()
    if normalized and normalized not in _UNIVERSAL_BIND_HOSTS:
        return normalized
    return _guess_local_ipv4()


async def start_grpc_server(
    server: grpc.aio.Server,
    service_type: ServiceName,
    port: int | str,
    *,
    host: str = "",
    instance_name: str = "",
    tenants: list[str] | None = None,
    redis_url: str | None = None,
    config: SharedConfig | None = None,
) -> ServiceRuntimeHandle:
    """Start one gRPC runtime with official health and exact registry identity."""
    from .discovery import register_service

    config = _effective_config(config)
    _validate_mesh_tls_config(config, service_name=service_type)
    health_service = GRPC_HEALTH_SERVICE_NAMES.get(service_type)
    if health_service is None:
        raise ValueError(f"unsupported gRPC service runtime: {service_type}")
    instance_name = instance_name or "default"
    tenants = tenants or []
    projection = resolve_service_degradation_config(config)
    environment = projection.environment if projection is not None else ("local" if config.local_mode else "default")
    identity = ServiceRuntimeIdentity(
        environment=environment,
        service=service_type,
        instance=instance_name,
        runtime_id=uuid4(),
        target=ServiceHealthTarget(
            transport="grpc",
            health_service=health_service,
        ),
    )
    health = install_standard_health(server, service=service_type)

    bind_host = host or getattr(config, "host", "0.0.0.0") or "0.0.0.0"
    bind_server_port(
        server,
        port,
        service_type.capitalize(),
        instance_name=instance_name,
        host=bind_host,
        config=config,
    )
    await server.start()
    await health.set_serving()

    advertised_host = redis_register_host(bind_host)
    endpoint = f"{advertised_host}:{port}"
    actual_redis_url = redis_url or (config.redis.url if config.redis.enabled else None)
    heartbeat_task = await register_service(
        service=service_type,
        instance=instance_name,
        endpoint=endpoint,
        redis_url=actual_redis_url,
        tenants=tenants,
        metadata={"port": int(port)},
        identity=identity,
    )
    publisher = None
    if projection is not None and heartbeat_task is not None:
        try:
            store = await create_redis_degradation_store(projection)
            publisher = ServiceDegradationPublisher(
                identity=identity,
                store=store,
                max_active_signals=projection.max_active_signals,
            )
            publisher.start(refresh_interval_seconds=projection.refresh_interval_seconds)
        except Exception as exc:
            logger.warning(
                "Service degradation projection disabled for %s: %s",
                service_type,
                type(exc).__name__,
            )
    handle = ServiceRuntimeHandle(
        identity=identity,
        health=health,
        heartbeat_task=heartbeat_task,
        publisher=publisher,
    )
    install_service_runtime_handle(handle)
    return handle


# ---------------------------------------------------------------------------
# Server lifecycle: graceful shutdown
# ---------------------------------------------------------------------------

_shutdown_events: list[asyncio.Event] = []


def _global_signal_handler() -> None:
    """Trigger all registered stop events to initiate graceful shutdown."""
    for ev in _shutdown_events:
        ev.set()


async def graceful_shutdown(
    server: grpc.aio.Server,
    service_name: str = "service",
    *,
    runtime_handle: ServiceRuntimeHandle | None = None,
    heartbeat_task: asyncio.Task[None] | None = None,
    before_stop: AsyncShutdownHook | None = None,
    grace: float = 2,
) -> None:
    """Drain one runtime, fence its derived state, then stop the gRPC server."""
    import signal

    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()
    _shutdown_events.append(stop_event)
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            _ = loop.add_signal_handler(sig, _global_signal_handler)
        except NotImplementedError:
            pass

    _ = await stop_event.wait()
    logger.info("Shutdown signal received, stopping %s...", service_name)
    try:
        if runtime_handle is not None and runtime_handle.health is not None:
            try:
                await runtime_handle.health.set_not_serving()
            except Exception as exc:
                logger.warning("Failed to mark %s not serving: %s", service_name, type(exc).__name__)
        if before_stop:
            try:
                await before_stop()
            except Exception as exc:
                logger.warning("Pre-shutdown hook error: %s", exc)
        if runtime_handle is not None and runtime_handle.publisher is not None:
            try:
                await runtime_handle.publisher.close()
            except Exception as exc:
                logger.warning("Failed to close %s degradation publisher: %s", service_name, type(exc).__name__)
        task = runtime_handle.heartbeat_task if runtime_handle is not None else heartbeat_task
        if task is not None:
            _ = task.cancel()
            try:
                with suppress(asyncio.CancelledError):
                    await task
            except Exception as exc:
                logger.warning("Failed to close %s registry heartbeat: %s", service_name, type(exc).__name__)
    finally:
        if runtime_handle is not None:
            _ = remove_service_runtime_handle(
                runtime_handle.identity.service,
                runtime_id=runtime_handle.identity.runtime_id,
            )
        if stop_event in _shutdown_events:
            _shutdown_events.remove(stop_event)

    logger.info("Stopping %s gRPC server (%ss grace)...", service_name, grace)
    await server.stop(grace=grace)
    logger.info("%s server stopped.", service_name)
