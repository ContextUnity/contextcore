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

import logging
import os
from pathlib import Path

import grpc
import grpc.aio

__all__ = [
    "create_channel",
    "create_channel_sync",
    "create_server_credentials",
    "graceful_shutdown",
    "start_grpc_server",
    "tls_enabled",
]

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def tls_enabled() -> bool:
    """Check if TLS is configured via environment."""
    return os.getenv("GRPC_TLS_ENABLED", "false").lower() in ("true", "1", "yes")


def _read_file(path: str) -> bytes:
    """Read a file as bytes, raising a clear error on failure."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"TLS file not found: {path}")
    return p.read_bytes()


def _get_env(var: str) -> str:
    """Get a required environment variable or raise."""
    value = os.getenv(var)
    if not value:
        raise EnvironmentError(f"TLS is enabled (GRPC_TLS_ENABLED=true) but {var} is not set")
    return value


# ---------------------------------------------------------------------------
# Client-side: channel creation
# ---------------------------------------------------------------------------

_GRPC_OPTIONS = [
    ("grpc.max_send_message_length", 50 * 1024 * 1024),
    ("grpc.max_receive_message_length", 50 * 1024 * 1024),
]


def create_channel(target: str) -> grpc.aio.Channel:
    """Create an async gRPC channel — TLS if configured, insecure otherwise.

    For mTLS, reads ``GRPC_TLS_CA_CERT`` (required), and optionally
    ``GRPC_TLS_CLIENT_CERT`` + ``GRPC_TLS_CLIENT_KEY`` for mutual auth.

    Args:
        target: gRPC target (``host:port``).

    Returns:
        ``grpc.aio.Channel`` — either secure or insecure.
    """
    if not tls_enabled():
        return grpc.aio.insecure_channel(target, options=_GRPC_OPTIONS)

    ca_cert = _read_file(_get_env("GRPC_TLS_CA_CERT"))

    # mTLS: provide client cert/key for mutual authentication
    client_cert_path = os.getenv("GRPC_TLS_CLIENT_CERT")
    client_key_path = os.getenv("GRPC_TLS_CLIENT_KEY")

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


def create_channel_sync(target: str) -> grpc.Channel:
    """Create a synchronous gRPC channel — TLS if configured, insecure otherwise.

    Same logic as :func:`create_channel` but returns a blocking channel.
    """
    if not tls_enabled():
        return grpc.insecure_channel(target, options=_GRPC_OPTIONS)

    ca_cert = _read_file(_get_env("GRPC_TLS_CA_CERT"))

    client_cert_path = os.getenv("GRPC_TLS_CLIENT_CERT")
    client_key_path = os.getenv("GRPC_TLS_CLIENT_KEY")

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


def create_server_credentials() -> grpc.ServerCredentials | None:
    """Create server TLS credentials from environment.

    Returns ``None`` if TLS is not enabled — caller should fall back to
    ``server.add_insecure_port()``.

    When TLS is enabled, reads ``GRPC_TLS_SERVER_CERT``, ``GRPC_TLS_SERVER_KEY``,
    and ``GRPC_TLS_CA_CERT``.  If CA cert is provided **and**
    ``GRPC_TLS_REQUIRE_CLIENT_AUTH`` is not ``"false"``, mTLS is enforced
    (clients must present a certificate signed by the same CA).
    """
    if not tls_enabled():
        return None

    ca_cert = _read_file(_get_env("GRPC_TLS_CA_CERT"))
    server_cert = _read_file(_get_env("GRPC_TLS_SERVER_CERT"))
    server_key = _read_file(_get_env("GRPC_TLS_SERVER_KEY"))

    require_client_auth = os.getenv("GRPC_TLS_REQUIRE_CLIENT_AUTH", "true").lower() not in ("false", "0", "no")

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
    instance_name: str = "",
) -> None:
    """Bind gRPC server to port with TLS if configured, log security status.

    Replaces the copy-paste TLS-bind + shield_status block in every service.

    Args:
        server: The ``grpc.aio.Server`` to bind.
        port: Port number.
        service_name: Human label for log messages.
        instance_name: Optional instance identifier for log messages.
    """
    from .security import shield_status

    # Log security posture
    sec = shield_status()
    sec_log = logger.info if sec["security_enabled"] else logger.warning
    sec_log(
        "Security: enabled=%s, shield=%s",
        sec["security_enabled"],
        "active" if sec["shield_active"] else "not installed",
    )

    # Bind TLS or insecure
    tls_creds = create_server_credentials()
    instance_suffix = f" (instance={instance_name})" if instance_name else ""
    if tls_creds:
        server.add_secure_port(f"0.0.0.0:{port}", tls_creds)
        logger.info("%s starting on :%s with TLS%s", service_name, port, instance_suffix)
    else:
        server.add_insecure_port(f"0.0.0.0:{port}")
        logger.info("%s starting on :%s%s", service_name, port, instance_suffix)


# ---------------------------------------------------------------------------
# Server lifecycle: start + register
# ---------------------------------------------------------------------------


async def start_grpc_server(
    server: grpc.aio.Server,
    service_type: str,
    port: int | str,
    *,
    instance_name: str = "",
    tenants: list[str] | None = None,
):
    """Bind port, start server, register in Redis for discovery.

    Combines ``bind_server_port()`` + ``server.start()`` + ``register_service()``
    into one call.  Replaces ~10 lines of boilerplate in every service.

    All discovery settings come from ``SharedConfig`` (loaded from env):

    - ``GRPC_HOST`` → advertised endpoint host (default ``"localhost"``)
    - ``REDIS_URL`` → Redis for heartbeat registration

    Services with their own config can override ``instance_name`` and ``tenants``.
    Without overrides, defaults to instance ``"default"`` and no tenant filter.

    Args:
        server: The ``grpc.aio.Server`` to start.
        service_type: Service key (``"router"``, ``"brain"``, etc.).
        port: Port number.
        instance_name: Override instance name (from service config).
        tenants: Override tenant list (from service config).

    Returns:
        Heartbeat task (pass to ``graceful_shutdown``).

    Example::

        heartbeat = await start_grpc_server(server, "router", 50052,
                                             instance_name=cfg.instance_name,
                                             tenants=cfg.tenants)
        await graceful_shutdown(server, "Router", heartbeat_task=heartbeat)
    """
    from .config import load_shared_config_from_env
    from .discovery import register_service

    config = load_shared_config_from_env()

    # Use explicit overrides or hardcoded defaults
    instance_name = instance_name or "default"
    if tenants is None:
        tenants = []

    # Bind + start
    bind_server_port(server, port, service_type.capitalize(), instance_name=instance_name)
    await server.start()

    # Register in Redis for service discovery
    endpoint = f"{config.grpc_host}:{port}"
    heartbeat_task = await register_service(
        service=service_type,
        instance=instance_name,
        endpoint=endpoint,
        tenants=tenants,
        metadata={"port": int(port)},
    )

    # Log discovered service mesh peers
    try:
        from .config import load_shared_config_from_env
        from .discovery import discover_services

        _cfg = load_shared_config_from_env()
        if not _cfg.redis_url:
            logger.warning("Service mesh: REDIS_URL not set — discovery DISABLED")
        else:
            peers = discover_services()
            if peers:
                peer_list = ", ".join(f"{p.service}={p.endpoint}" for p in peers if p.service != service_type)
                if peer_list:
                    logger.info("Service mesh: %s", peer_list)
                else:
                    logger.info("Service mesh: no other services registered yet")
            else:
                logger.info("Service mesh: Redis reachable, no peers yet (normal on first start)")
    except Exception:
        pass  # Don't fail startup over discovery logging

    return heartbeat_task


# ---------------------------------------------------------------------------
# Server lifecycle: graceful shutdown
# ---------------------------------------------------------------------------


async def graceful_shutdown(
    server: grpc.aio.Server,
    service_name: str = "service",
    *,
    heartbeat_task=None,
    before_stop=None,
    grace: float = 2,
) -> None:
    """Wait for SIGINT/SIGTERM then shut down the gRPC server cleanly.

    Replaces the copy-paste shutdown pattern used across all services.

    Args:
        server: The running ``grpc.aio.Server``.
        service_name: Human label for log messages (e.g. "Brain", "Router").
        heartbeat_task: Optional Redis heartbeat task to cancel.
        before_stop: Optional async callable invoked *before* ``server.stop()``.
            Use this to drain bidi streams or close resources.
        grace: Seconds for gRPC grace period (default 2).

    Example::

        await server.start()
        heartbeat = await register_service(...)
        await graceful_shutdown(server, "Router", heartbeat_task=heartbeat,
                                before_stop=drain_streams)
    """
    import asyncio
    import signal

    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    def _handler():
        logger.info("Shutdown signal received, stopping %s...", service_name)
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _handler)

    await stop_event.wait()

    # Pre-shutdown hook (e.g. drain bidi streams)
    if before_stop:
        try:
            await before_stop()
        except Exception as exc:
            logger.warning("Pre-shutdown hook error: %s", exc)

    logger.info("Stopping %s gRPC server (%ss grace)...", service_name, grace)
    await server.stop(grace=grace)

    if heartbeat_task:
        heartbeat_task.cancel()

    logger.info("%s server stopped.", service_name)
