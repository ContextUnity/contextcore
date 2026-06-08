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
from pathlib import Path
from typing import TYPE_CHECKING

import grpc
import grpc.aio
from contextunity.core.parsing import json_dumps
from contextunity.core.types import AsyncShutdownHook, JsonDict

from .logging import get_contextunit_logger

if TYPE_CHECKING:
    from .config import SharedConfig

__all__ = [
    "create_channel",
    "create_channel_sync",
    "create_server_credentials",
    "graceful_shutdown",
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
        EnvironmentError: If the path is not configured.
    """
    config_obj: object = _effective_config(config)
    value: object = getattr(config_obj, field, None)
    if not value or not isinstance(value, str):
        raise OSError(f"TLS is enabled but {env_name} is not set")
    return value


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


def create_channel(target: str, config: SharedConfig | None = None) -> grpc.aio.Channel:
    """Create an async gRPC channel — TLS if configured, insecure otherwise.

    For mTLS, reads the effective config's CA certificate path, and optionally
    client certificate + key for mutual auth.

    Args:
        target: gRPC target (``host:port``).
        config: Optional service config. Pass this from long-running services so
            channel TLS matches the service config.

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

    # mTLS: provide client cert/key for mutual authentication
    client_cert_path = config.tls_client_cert
    client_key_path = config.tls_client_key

    if client_cert_path and client_key_path:
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

    logger.debug("Creating TLS channel to %s (mTLS=%s)", target, bool(client_cert_path))
    return grpc.aio.secure_channel(target, credentials, options=_GRPC_OPTIONS)


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

    client_cert_path = config.tls_client_cert
    client_key_path = config.tls_client_key

    if client_cert_path and client_key_path:
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


async def start_grpc_server(
    server: grpc.aio.Server,
    service_type: str,
    port: int | str,
    *,
    host: str = "",
    instance_name: str = "",
    tenants: list[str] | None = None,
    redis_url: str | None = None,
    config: SharedConfig | None = None,
):
    """Bind port, start server, register in Redis for discovery.

    Combines ``bind_server_port()`` + ``server.start()`` + ``register_service()``
    into one call.  Replaces ~10 lines of boilerplate in every service.

    All discovery settings come from ``SharedConfig`` (loaded from env):

    - ``host`` → advertised endpoint host (default ``"0.0.0.0"``)
    - ``REDIS_URL`` → Redis for heartbeat registration

    Services with their own config can override ``instance_name`` and ``tenants``.
    Without overrides, defaults to instance ``"default"`` and no tenant filter.

    Args:
        server: The ``grpc.aio.Server`` to start.
        service_type: Service key (``"router"``, ``"brain"``, etc.).
        port: Port number.
        host: Advertised bind host (from ServiceConfig.host).
        instance_name: Override instance name (from service config).
        tenants: Override tenant list (from service config).
        redis_url: Optional explicit Redis connection URL.
        config: Optional service config. This is the preferred production path;
            it keeps TLS/discovery aligned with the loaded service YAML.

    Returns:
        Heartbeat task (pass to ``graceful_shutdown``).

    Example::

        heartbeat = await start_grpc_server(server, "router", 50052,
                                             host=cfg.host,
                                             instance_name=cfg.instance_name,
                                             tenants=cfg.tenants)
        await graceful_shutdown(server, "Router", heartbeat_task=heartbeat)
    """
    from .discovery import register_service

    config = _effective_config(config)

    # Use explicit overrides or hardcoded defaults
    instance_name = instance_name or "default"
    if tenants is None:
        tenants = []

    # Bind + start
    bind_server_port(
        server,
        port,
        service_type.capitalize(),
        instance_name=instance_name,
        config=config,
    )
    await server.start()

    # Register in Redis for service discovery
    advertised_host = host or getattr(config, "host", "0.0.0.0")
    endpoint = f"{advertised_host}:{port}"
    actual_redis_url = redis_url or (config.redis.url if config.redis.enabled else None)
    heartbeat_task = await register_service(
        service=service_type,
        instance=instance_name,
        endpoint=endpoint,
        redis_url=actual_redis_url,
        tenants=tenants,
        metadata={"port": int(port)},
    )

    # Log discovered service mesh peers
    try:
        from .discovery import discover_services

        if not actual_redis_url:
            logger.warning("Service mesh: REDIS_URL not set — discovery DISABLED")
        else:
            peers = discover_services(redis_url=actual_redis_url)
            if peers:
                peer_list = ", ".join(f"{p.service}={p.endpoint}" for p in peers if p.service != service_type)
                if peer_list:
                    logger.debug("Service mesh: %s", peer_list)
                else:
                    logger.debug("Service mesh: no other services registered yet")
            else:
                logger.debug("Service mesh: Redis reachable, no peers yet (normal on first start)")
    except Exception:
        pass  # Don't fail startup over discovery logging

    return heartbeat_task


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
    heartbeat_task: asyncio.Task[None] | None = None,
    before_stop: AsyncShutdownHook | None = None,
    grace: float = 2,
) -> None:
    """Wait for SIGINT/SIGTERM, then gracefully stop the gRPC server.

    Registers signal handlers and blocks until a signal is received. Once received,
    runs the `before_stop` hook, stops the gRPC server, and cancels the heartbeat task.

    Args:
        server: The running async gRPC server instance.
        service_name: A human-readable service name used in log messages.
        heartbeat_task: Optional heartbeat/registration task to cancel on shutdown.
        before_stop: Optional asynchronous callback to run before server teardown.
        grace: Grace period in seconds allowing in-flight requests to complete.
    """
    import signal

    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()
    _shutdown_events.append(stop_event)

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            _ = loop.add_signal_handler(sig, _global_signal_handler)
        except NotImplementedError:
            pass  # Windows

    _ = await stop_event.wait()
    logger.info("Shutdown signal received, stopping %s...", service_name)

    # Pre-shutdown hook (e.g. drain bidi streams)
    if before_stop:
        try:
            await before_stop()
        except Exception as exc:
            logger.warning("Pre-shutdown hook error: %s", exc)

    logger.info("Stopping %s gRPC server (%ss grace)...", service_name, grace)
    await server.stop(grace=grace)

    if heartbeat_task:
        _ = heartbeat_task.cancel()

    logger.info("%s server stopped.", service_name)
