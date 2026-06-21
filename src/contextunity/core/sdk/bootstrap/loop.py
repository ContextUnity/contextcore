"""Retry-resilient bootstrap orchestration loop.
Sequences the four bootstrap phases with infinite retry on transient
failures:
1. Shield session-token acquisition (if Shield enabled)
2. Shield secrets sync (API keys → Shield vault)
3. Router manifest registration (``RegisterManifest`` RPC)
4. Worker schedule registration (cron schedule sync)
After all registrations succeed, opens the persistent
``ToolExecutorStream`` for federated BiDi tool execution.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from contextunity.core.logging import get_contextunit_logger

from ..types import ToolHandler, ToolPayload
from .client import do_register, put_secrets_to_shield, register_schedules

if TYPE_CHECKING:
    from contextunity.core.signing import AuthBackend

logger = get_contextunit_logger(__name__)

_INITIAL_RETRY_DELAY_SECONDS = 15
_MAX_RETRY_DELAY_SECONDS = 300


def _next_retry_delay(delay_seconds: int) -> int:
    """Return the next exponential retry delay, capped at 5 minutes."""
    return min(delay_seconds * 2, _MAX_RETRY_DELAY_SECONDS)


def _is_grpc_deadline_exceeded(e: Exception) -> bool:
    try:
        import grpc

        code_fn = getattr(e, "code", None)
        return isinstance(e, grpc.RpcError) and callable(code_fn) and code_fn() == grpc.StatusCode.DEADLINE_EXCEEDED
    except ImportError:
        return False


def _format_bootstrap_error(e: Exception, operation: str) -> str:
    from contextunity.core.sdk.streaming.bidi import format_grpc_error

    formatted = format_grpc_error(e)
    if _is_grpc_deadline_exceeded(e):
        return (
            f"{formatted}. Timeout while {operation}: the gRPC call reached its client deadline before "
            "the service replied. Check service availability, network/TLS/DNS, and server-side latency."
        )
    return formatted


def _log_retry(message: str, e: Exception, operation: str, delay_seconds: int, *args: object) -> None:
    logger.error(
        "%s: %s. Retrying in %d seconds...",
        message % args if args else message,
        _format_bootstrap_error(e, operation),
        delay_seconds,
    )


def bootstrap_loop(
    router_url: str,
    project_id: str,
    payload: ToolPayload,
    tool_names: list[str],
    tool_handler: ToolHandler | None,
    resolved_secrets: dict[str, str] | None = None,
    shield_enabled: bool = False,
    shield_url: str = "",
    backend: AuthBackend | None = None,
) -> None:
    """Main bootstrap loop: [Shield token] → [Shield sync] → register → stream loop.

    Sequences the four bootstrap phases with infinite retry on transient
    failures. After all registrations succeed, it opens the persistent
    BiDi stream for federated tool execution.

    Args:
        router_url: The Router service gRPC URL.
        project_id: The identifier of the project.
        payload: The registration payload containing the manifest bundle.
        tool_names: A list of registered tool names.
        tool_handler: The tool execution handler callback.
        resolved_secrets: The resolved secrets dict to sync to Shield.
        shield_enabled: Whether Shield integration is enabled.
        shield_url: The Shield service gRPC URL.
        backend: The authentication backend.
    """
    import time

    # ── Shield session token acquisition (with retry) ─────────
    if shield_enabled and shield_url and backend is not None:
        from contextunity.core.signing import (
            HmacBackend,
            SessionTokenBackend,
            _request_session_token,
            set_signing_backend,
        )

        if isinstance(backend, HmacBackend):
            hmac_backend = backend
            retry_delay = _INITIAL_RETRY_DELAY_SECONDS
            while True:
                try:
                    from contextunity.core.sdk.identity import get_required_services

                    required_services = get_required_services()
                    token, kid, expires_at = _request_session_token(
                        project_id, shield_url, hmac_backend, required_services=required_services
                    )
                    backend = SessionTokenBackend(
                        project_id=project_id,
                        session_token=token,
                        kid=kid,
                        expires_at=expires_at,
                        shield_url=shield_url,
                        hmac_backend=hmac_backend,
                    )
                    set_signing_backend(backend)
                    logger.info("Shield session token acquired for project '%s'", project_id)
                    break
                except Exception as e:
                    _log_retry(
                        "Shield unavailable for '%s'",
                        e,
                        "requesting a Shield session token",
                        retry_delay,
                        project_id,
                    )
                    time.sleep(retry_delay)
                    retry_delay = _next_retry_delay(retry_delay)

    # ── Shield secrets sync (with retry) ──────────────────────
    from contextunity.core.sdk.streaming.bidi import run_stream_loop

    if resolved_secrets and shield_enabled:
        if not shield_url:
            logger.critical(
                (
                    "Shield is enabled in manifest but shield_url is not configured. "
                    "Set CU_SHIELD_GRPC_URL in env or config. Aborting bootstrap."
                )
            )
            return

        retry_delay = _INITIAL_RETRY_DELAY_SECONDS
        while True:
            try:
                synced = put_secrets_to_shield(project_id, resolved_secrets, shield_url, backend)
                logger.info("Synced %d API key(s) to Shield: %s", len(synced), ", ".join(synced))
                break
            except Exception as e:
                _log_retry(
                    "Shield sync FAILED for project '%s'",
                    e,
                    "syncing secrets to Shield",
                    retry_delay,
                    project_id,
                )
                time.sleep(retry_delay)
                retry_delay = _next_retry_delay(retry_delay)

    logger.info("Registering with Router at %s...", router_url)
    stream_secret: str | None = None
    retry_delay = _INITIAL_RETRY_DELAY_SECONDS
    while True:
        try:
            stream_secret, _ = do_register(router_url, project_id, payload, backend)
            break
        except Exception as e:
            _log_retry(
                "Registration failed",
                e,
                "registering manifest with Router",
                retry_delay,
            )
            time.sleep(retry_delay)
            retry_delay = _next_retry_delay(retry_delay)

    from contextunity.core.sdk.identity import get_worker_bindings

    schedules = get_worker_bindings().schedules
    if schedules:
        logger.info("Registering %s worker schedules...", len(schedules))
        retry_delay = _INITIAL_RETRY_DELAY_SECONDS
        while True:
            try:
                registered = register_schedules(project_id, schedules, backend)
                logger.info("Successfully registered %s worker schedules", registered)
                break
            except Exception as e:
                _log_retry(
                    "Failed to register schedules",
                    e,
                    "registering worker schedules with Router",
                    retry_delay,
                )
                time.sleep(retry_delay)
                retry_delay = _next_retry_delay(retry_delay)

    if not stream_secret:
        logger.warning("No stream_secret returned — stream auth may fail. Check Router security config.")

    if not tool_names:
        logger.info("No federated tools — skipping stream executor")
        return

    if not tool_handler:
        logger.warning("No tool_handler provided — stream executor has no tool to run.")
        return

    def re_register() -> tuple[str, str]:
        """Re-register manifest on stream reconnect.

        Returns:
            tuple[str, str]: A tuple containing the (stream_secret, shield_url).
        """
        return do_register(router_url, project_id, payload, backend)

    run_stream_loop(
        router_url=router_url,
        project_id=project_id,
        tool_names=tool_names,
        tool_handler=tool_handler,
        register_fn=re_register,
        stream_secret=stream_secret,
        backend=backend,
    )


_bootstrap_loop = bootstrap_loop
