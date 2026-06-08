"""ContextUnity SDK — BiDi Stream Transport.
Generic gRPC BiDi stream lifecycle:
  - Connection + reconnection with exponential backoff
  - Heartbeat
  - Action routing to project-provided tool handlers
  - Session tracking
This module is a **transport layer** — it does NOT execute tools.
Tool execution is delegated to handlers provided by the project.
Projects use ``register_and_start()`` from ``contextunity.core.sdk.bootstrap``.
"""

from __future__ import annotations

import queue
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from typing import TYPE_CHECKING

from contextunity.core.logging import get_contextunit_logger
from contextunity.core.sdk.payload import get_int, get_str, parse_federated_execute
from contextunity.core.sdk.types import ManifestRegistrationCallback, ToolHandler, ToolResult
from contextunity.core.types import ContextUnitPayload

if TYPE_CHECKING:
    from contextunity.core import contextunit_pb2
    from contextunity.core.sdk.types import GrpcMetadata
    from contextunity.core.signing import AuthBackend
    from contextunity.core.tokens import ContextToken

logger = get_contextunit_logger(__name__)

# ── Constants ──
RECONNECT_DELAY_MIN = 5
RECONNECT_DELAY_MAX = 30
HEARTBEAT_INTERVAL = 30
TOKEN_TTL_STREAM = 3600  # 1 hour

# Session counter for tracking reconnections
_session_counter = 0
_session_lock = threading.Lock()


@dataclass(frozen=True)
class FederatedToolCallContext:
    """Verified caller context forwarded from Router to project-owned tools."""

    project_id: str
    tool_name: str
    request_id: str
    caller_tenant: str
    user_id: str | None = None


def _next_session() -> int:
    """Get the next unique session index.

    Returns:
        int: The next session index.
    """
    global _session_counter
    with _session_lock:
        _session_counter += 1
        return _session_counter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def format_grpc_error(e: Exception) -> str:
    """Format gRPC error into a concise one-liner.

    Args:
        e: The exception to format.

    Returns:
        str: The formatted error message.
    """
    try:
        import grpc

        if isinstance(e, grpc.RpcError):
            code_fn = getattr(e, "code", None)
            details_fn = getattr(e, "details", None)
            if callable(code_fn):
                raw_status: object = code_fn()
                code = raw_status.name if isinstance(raw_status, grpc.StatusCode) else str(raw_status)
            else:
                code = "UNKNOWN"
            details = details_fn() if details_fn is not None else "no details"
            return f"gRPC {code}: {details or 'no details'}"
    except ImportError:
        pass
    return str(e)[:120]


def _create_stream_metadata(
    token: ContextToken,
    backend: AuthBackend | None,
) -> GrpcMetadata:
    """Create metadata for ToolExecutorStream using the active auth backend.

    Args:
        token: The security token for authentication.
        backend: The authentication backend used to sign metadata.

    Returns:
        list[tuple[str, str]]: The list of gRPC metadata tuples.
    """

    from contextunity.core.token_utils import create_grpc_metadata_with_token

    return create_grpc_metadata_with_token(token, backend=backend)


# ---------------------------------------------------------------------------
# Reconnect Loop
# ---------------------------------------------------------------------------


def run_stream_loop(
    router_url: str,
    project_id: str,
    tool_names: list[str],
    tool_handler: ToolHandler,
    register_fn: ManifestRegistrationCallback | None = None,
    stream_secret: str = "",
    backend: AuthBackend | None = None,
) -> None:
    """Reconnect loop — keeps stream alive with exponential backoff.

    Args:
        router_url: Router gRPC address.
        project_id: Project/tenant identifier.
        tool_names: List of federated tool names to announce.
        tool_handler: Project-provided callback: (tool_name, args) -> result_dict.
        register_fn: Optional re-registration callback for reconnects.
        stream_secret: Initial stream secret from registration.
    """
    delay = RECONNECT_DELAY_MIN

    while True:
        session = _next_session()
        is_reconnect = session > 1

        if is_reconnect:
            logger.info(
                "Reconnecting (session #%d) | project=%s router=%s",
                session,
                project_id,
                router_url,
            )
        else:
            logger.info(
                "Connecting (session #%d) | project=%s router=%s",
                session,
                project_id,
                router_url,
            )

        # Re-register on reconnect
        if is_reconnect and register_fn is not None:
            try:
                logger.info("Re-registering (session #%d)...", session)
                result = register_fn()
                if result:
                    new_secret = result[0]
                    if new_secret:
                        stream_secret = new_secret
                logger.info("Re-registration OK (session #%d)", session)
                delay = RECONNECT_DELAY_MIN
            except Exception as e:
                logger.warning(
                    "Re-registration failed (session #%d): %s — waiting %ds...",
                    session,
                    format_grpc_error(e),
                    delay,
                )
                time.sleep(delay)
                delay = min(delay * 2, RECONNECT_DELAY_MAX)
                continue

        try:
            _run_stream(router_url, project_id, tool_names, tool_handler, session, stream_secret, backend)
            logger.warning(
                "Stream ended gracefully (session #%d) | reconnecting immediately",
                session,
            )
            delay = RECONNECT_DELAY_MIN
            # Graceful end — reconnect immediately without sleeping.
            # The stream closed due to idle timeout, not an error.
            continue
        except Exception as e:
            reason = format_grpc_error(e)
            logger.warning(
                "Disconnected (session #%d): %s — retry in %ds",
                session,
                reason,
                delay,
            )
        time.sleep(delay)
        delay = min(delay * 2, RECONNECT_DELAY_MAX)


# ---------------------------------------------------------------------------
# Single BiDi Session
# ---------------------------------------------------------------------------


def _run_stream(
    router_url: str,
    project_id: str,
    tool_names: list[str],
    tool_handler: ToolHandler,
    session: int,
    stream_secret: str = "",
    backend: AuthBackend | None = None,
) -> None:
    """Run a single BiDi stream session.

    Args:
        router_url: The router gRPC URL.
        project_id: The identifier of the project.
        tool_names: List of federated tool names.
        tool_handler: The target tool execution handler.
        session: The session index/counter.
        stream_secret: The stream secret.
        backend: Optional authentication backend.
    """
    import grpc
    from contextunity.core import router_pb2_grpc
    from contextunity.core.grpc_utils import create_channel_sync
    from contextunity.core.tokens import ContextToken

    token = ContextToken(
        token_id=f"{project_id}-executor",
        permissions=("stream:executor", f"stream:executor:{project_id}"),
        allowed_tenants=(project_id,),
        exp_unix=time.time() + TOKEN_TTL_STREAM,
    )
    metadata = _create_stream_metadata(token, backend)

    channel = create_channel_sync(router_url)
    try:
        logger.info("Connected (session #%d) | channel ready", session)
        stub = router_pb2_grpc.RouterServiceStub(channel)

        response_queue: queue.Queue[contextunit_pb2.ContextUnit | None] = queue.Queue()
        heartbeat_count = 0

        def request_generator() -> Iterator[contextunit_pb2.ContextUnit]:
            """Generate stream of outgoing requests, heartbeats, and responses for the bidirectional stream."""
            nonlocal heartbeat_count
            from contextunity.core import ContextUnit, contextunit_pb2

            ready_unit = ContextUnit(
                payload={
                    "action": "ready",
                    "project_id": project_id,
                    "tools": tool_names,
                    "stream_secret": stream_secret,
                },
                provenance=[f"{project_id}:stream_executor:ready"],
            )
            yield ready_unit.to_protobuf(contextunit_pb2)
            logger.info(
                "Ready (session #%d) | tools=%s, waiting for requests...",
                session,
                tool_names,
            )

            # Yield responses + heartbeats
            while True:
                try:
                    msg = response_queue.get(timeout=HEARTBEAT_INTERVAL)
                    if msg is None:
                        break
                    yield msg
                except queue.Empty:
                    heartbeat_count += 1
                    hb = ContextUnit(
                        payload={"action": "heartbeat"},
                        provenance=[f"{project_id}:stream_executor:heartbeat"],
                    )
                    yield hb.to_protobuf(contextunit_pb2)
                    logger.debug("Heartbeat #%d (session #%d)", heartbeat_count, session)

        responses = stub.ToolExecutorStream(
            request_generator(),
            metadata=metadata,
            wait_for_ready=True,
        )

        # Process incoming requests from Router
        for msg in responses:
            from contextunity.core.signing.shield_client import protobuf_payload_dict

            payload_dict = protobuf_payload_dict(msg.payload)
            action = get_str(payload_dict, "action")

            if action == "execute":
                _handle_execute(
                    payload=payload_dict,
                    tool_handler=tool_handler,
                    project_id=project_id,
                    response_queue=response_queue,
                    session=session,
                )
            elif action == "keepalive":
                logger.debug("Router keepalive (session #%d)", session)
            elif action == "_registered":
                logger.info("Stream authenticated by Router (session #%d)", session)
            elif action == "error":
                error_msg = get_str(payload_dict, "error", "unknown")
                logger.warning(
                    "Router error (session #%d): %s",
                    session,
                    error_msg,
                )
                # Break stream so reconnect loop re-registers with Router.
                break
            else:
                logger.warning("Unknown action '%s' (session #%d)", action, session)

    except grpc.RpcError:
        raise
    finally:
        channel.close()


# ---------------------------------------------------------------------------
# Tool Dispatch (transport — delegates to handler)
# ---------------------------------------------------------------------------


def _handle_execute(
    payload: ContextUnitPayload,
    tool_handler: ToolHandler,
    project_id: str,
    response_queue: queue.Queue[contextunit_pb2.ContextUnit | None],
    session: int,
) -> None:
    """Route tool execute request to the project-provided handler.

    Args:
        payload: The payload dictionary to process.
        tool_handler: The tool handler callback.
        project_id: The identifier of the project.
        response_queue: The response queue.
        session: The session index/counter.
    """
    from contextunity.core import ContextUnit, contextunit_pb2

    execute = parse_federated_execute(payload)
    request_id = execute["request_id"]
    tool_name = execute["tool"]
    args = execute["args"]
    caller_tenant = execute["caller_tenant"]
    user_id = execute["user_id"]

    auth_context = FederatedToolCallContext(
        project_id=project_id,
        tool_name=tool_name,
        request_id=request_id,
        caller_tenant=caller_tenant,
        user_id=user_id,
    )

    sql_preview = get_str(args, "sql").replace("\n", " ")[:100]
    logger.info(
        "Execute (session #%d) | tool=%s req=%s... sql=%s...",
        session,
        tool_name,
        request_id[:8],
        sql_preview,
    )

    start = time.time()
    result: ToolResult
    try:
        # Delegate to project-provided handler
        result = tool_handler(tool_name, args, auth_context)
        elapsed_ms = int((time.time() - start) * 1000)
        result["action"] = "result"
        result["request_id"] = request_id
        row_count = get_int(result, "row_count", 0)
        logger.info(
            "Result (session #%d) | req=%s... rows=%d time=%dms",
            session,
            request_id[:8],
            row_count,
            elapsed_ms,
        )
    except Exception as e:
        elapsed_ms = int((time.time() - start) * 1000)
        logger.error(
            "Failed (session #%d) | req=%s... error=%s time=%dms",
            session,
            request_id[:8],
            e,
            elapsed_ms,
        )
        result = {
            "action": "error",
            "request_id": request_id,
            "error": str(e),
        }

    resp_unit = ContextUnit(
        payload=result,
        provenance=[f"{project_id}:stream_executor:result"],
    )
    response_queue.put(resp_unit.to_protobuf(contextunit_pb2))


__all__ = [
    "FederatedToolCallContext",
    "ToolHandler",
    "run_stream_loop",
]
