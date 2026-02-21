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
        return grpc.aio.insecure_channel(target)

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
    return grpc.aio.secure_channel(target, credentials)


def create_channel_sync(target: str) -> grpc.Channel:
    """Create a synchronous gRPC channel — TLS if configured, insecure otherwise.

    Same logic as :func:`create_channel` but returns a blocking channel.
    """
    if not tls_enabled():
        return grpc.insecure_channel(target)

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
    return grpc.secure_channel(target, credentials)


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
