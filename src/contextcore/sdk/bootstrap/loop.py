from __future__ import annotations

from typing import TYPE_CHECKING, Any, Callable

from contextcore.logging import get_context_unit_logger

from .client import _do_register, _put_secrets_to_shield

if TYPE_CHECKING:
    from contextcore.sdk.streaming.bidi import FederatedToolCallContext
    from contextcore.security.protocols import AuthBackend

logger = get_context_unit_logger(__name__)


def _bootstrap_loop(
    router_url: str,
    project_id: str,
    payload: dict[str, Any],
    tool_names: list[str],
    tool_handler: Callable[[str, dict[str, Any], FederatedToolCallContext], dict[str, Any]] | None,
    resolved_secrets: dict[str, str] | None = None,
    shield_enabled: bool = False,
    shield_url: str = "",
    backend: AuthBackend | None = None,
) -> None:
    """Main bootstrap: [Shield sync] → register → stream loop."""
    from contextcore.sdk.streaming.bidi import format_grpc_error, run_stream_loop

    if resolved_secrets and shield_enabled:
        if not shield_url:
            logger.critical(
                "Shield is enabled in manifest but shield_url is not configured. "
                "Set CONTEXTSHIELD_GRPC_URL in env or config. Aborting bootstrap."
            )
            return

        while True:
            try:
                synced = _put_secrets_to_shield(project_id, resolved_secrets, shield_url, backend)
                logger.info("Synced %d API key(s) to Shield: %s", len(synced), ", ".join(synced))
                break
            except Exception as e:
                logger.error(
                    "Shield sync FAILED for project '%s': %s. Retrying in 15 seconds...",
                    project_id,
                    format_grpc_error(e),
                )
                import time

                time.sleep(15)

    import time

    logger.info("Registering with Router at %s...", router_url)
    stream_secret: str | None = None
    while True:
        try:
            stream_secret, _ = _do_register(router_url, project_id, payload, backend)
            break
        except Exception as e:
            logger.error("Registration failed: %s. Retrying in 15 seconds...", format_grpc_error(e))
            time.sleep(15)

    from contextcore.sdk.identity import get_worker_bindings

    schedules = get_worker_bindings().get("schedules", [])
    if schedules:
        logger.info("Registering %s worker schedules...", len(schedules))
        from .client import _register_schedules

        while True:
            try:
                registered = _register_schedules(project_id, schedules, backend)
                logger.info("Successfully registered %s worker schedules", registered)
                break
            except Exception as e:
                logger.error("Failed to register schedules: %s. Retrying in 15 seconds...", format_grpc_error(e))
                time.sleep(15)

    if not stream_secret:
        logger.warning("No stream_secret returned — stream auth may fail. Check Router security config.")

    if not tool_names:
        logger.info("No federated tools — skipping stream executor")
        return

    if not tool_handler:
        logger.warning("No tool_handler provided — stream executor has no tool to run.")
        return

    def re_register():
        return _do_register(router_url, project_id, payload, backend)

    run_stream_loop(
        router_url=router_url,
        project_id=project_id,
        tool_names=tool_names,
        tool_handler=tool_handler,
        register_fn=re_register,
        stream_secret=stream_secret,
        backend=backend,
    )
