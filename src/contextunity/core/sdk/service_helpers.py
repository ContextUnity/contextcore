"""Shared gRPC service helpers — parse_unit / make_response.

Canonical implementations used by all services. Import from here
instead of duplicating in each service.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from uuid import UUID

from contextunity.core import ContextUnit, SecurityScopes, contextunit_pb2
from contextunity.core.types import GrpcRequest, GrpcServicerContext


def parse_unit(request: contextunit_pb2.ContextUnit) -> ContextUnit:
    """Parse a protobuf request into a ContextUnit.

    Args:
        request: Raw gRPC protobuf ContextUnit request object.

    Returns:
        Deserialized ContextUnit.
    """
    return ContextUnit.from_protobuf(request)


def make_response(
    payload: Mapping[str, object],
    trace_id: str | UUID | None = None,
    security: SecurityScopes | None = None,
    parent_unit: ContextUnit | None = None,
) -> contextunit_pb2.ContextUnit:
    """Create a ContextUnit response protobuf message.

    Args:
        payload: Response payload data.
        trace_id: Trace identifier (inherited from parent_unit if None).
        security: Security scopes to attach (optional).
        parent_unit: Parent ContextUnit to inherit trace_id from.

    Returns:
        The populated protobuf ContextUnit message.
    """
    resolved_trace_id: UUID
    if trace_id is None and parent_unit:
        resolved_trace_id = parent_unit.trace_id
    elif isinstance(trace_id, str):
        resolved_trace_id = UUID(trace_id)
    elif isinstance(trace_id, UUID):
        resolved_trace_id = trace_id
    else:
        resolved_trace_id = uuid.uuid4()

    unit = ContextUnit(
        payload=dict(payload),
        trace_id=resolved_trace_id,
        security=security or SecurityScopes(),
    )
    return unit.to_protobuf(contextunit_pb2)


def contextunit_error_response_factory(
    request: GrpcRequest,
    context: GrpcServicerContext,
    exc: Exception,
) -> contextunit_pb2.ContextUnit:
    """Build a standardized ContextUnit error response for unary gRPC handlers.

    Used with ``@grpc_error_handler(response_factory=...)`` so clients receive a
    structured error payload instead of an aborted RPC. Security-sensitive
    exceptions return a generic message; details remain in logs and trailing
    metadata.
    """
    _ = context
    from contextunity.core.exceptions import SecurityError

    if isinstance(exc, SecurityError):
        error_type = "permission_denied"
        error_msg = "Permission denied"
    elif isinstance(exc, ValueError):
        error_type = "validation"
        error_msg = str(exc) or "Validation error"
    elif isinstance(exc, PermissionError):
        error_type = "permission_denied"
        error_msg = "Permission denied"
    else:
        error_type = type(exc).__name__
        error_msg = f"Internal error: {type(exc).__name__}"

    try:
        if isinstance(request, contextunit_pb2.ContextUnit):
            unit = parse_unit(request)
            trace_id = str(unit.trace_id)
            security = unit.security
        else:
            raise ValueError("malformed request")
    except Exception:  # graceful-degrade: error path must always return a unit
        trace_id = str(uuid.uuid4())
        security = None

    return make_response(
        payload={"error": error_msg, "error_type": error_type},
        trace_id=trace_id,
        security=security,
    )


__all__ = ["parse_unit", "make_response", "contextunit_error_response_factory"]
