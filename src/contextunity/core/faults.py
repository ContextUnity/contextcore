"""Shared fault taxonomy.

Canonical classification for "who/what caused this failure", shared by Brain
and Router so a failed run's Q-value consequences land on the right party:
only genuine agent mistakes degrade a learned quality score. Infra, upstream,
policy, and reference failures are recorded as evidence without poisoning
that signal — the single place this decision is made, instead of every
caller inventing its own attribution logic.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal, Protocol, TypedDict, TypeGuard, runtime_checkable

from .types import JsonDict

FaultClass = Literal["agent_fault", "infra_fault", "upstream_fault", "policy_fault", "reference_fault"]

# Named constants so call sites reference the canonical value, not a magic string.
AGENT_FAULT: FaultClass = "agent_fault"
INFRA_FAULT: FaultClass = "infra_fault"
UPSTREAM_FAULT: FaultClass = "upstream_fault"
POLICY_FAULT: FaultClass = "policy_fault"
REFERENCE_FAULT: FaultClass = "reference_fault"

FAULT_CLASSES: tuple[FaultClass, ...] = (
    AGENT_FAULT,
    INFRA_FAULT,
    UPSTREAM_FAULT,
    POLICY_FAULT,
    REFERENCE_FAULT,
)

# Only agent_fault may automatically degrade a learned Q-value. Explicit
# human/admin review may still set any Q-value directly regardless of class
# — this gates *automatic* fault-driven penalties only.
Q_PENALIZING_FAULT_CLASSES: frozenset[FaultClass] = frozenset({"agent_fault"})


def is_fault_class(value: object) -> TypeGuard[FaultClass]:
    """Narrow an arbitrary value to ``FaultClass`` if it's one of the five."""
    return value in FAULT_CLASSES


def penalizes_agent_q(fault_class: FaultClass | None) -> bool:
    """Whether this fault class is allowed to automatically degrade Q-values."""
    return fault_class in Q_PENALIZING_FAULT_CLASSES


@runtime_checkable
class _DeclaresFaultClass(Protocol):
    """Structural check for exceptions that already know their own class
    (e.g. ``PassByRefError``, ``SynapseTenantMismatchError``) — trust them
    directly instead of re-deriving from the exception type."""

    fault_class: str


def _duck_typed_status_code(exc: BaseException) -> int | None:
    """Extract an HTTP-like status code from a third-party client exception
    without importing httpx/requests/grpc/etc. Most HTTP client libraries
    expose either ``.status_code`` or ``.response.status_code`` on their
    exception types; this reads either shape and narrows immediately with
    ``isinstance`` rather than trusting the dynamic attribute blindly.
    """
    direct = getattr(exc, "status_code", None)
    if isinstance(direct, int):
        return direct
    response = getattr(exc, "response", None)
    nested = getattr(response, "status_code", None)
    if isinstance(nested, int):
        return nested
    return None


def classify_exception(exc: BaseException) -> FaultClass:
    """Best-effort classification of a raised exception into a fault class.

    Rules, in order:

    1. The exception already declares its own ``fault_class`` (typed
       ContextUnity errors like ``PassByRefError``/``SynapseTenantMismatchError``)
       — trust it directly, no re-derivation.
    2. Duck-typed HTTP-like status code: 401/403 -> ``policy_fault`` (denied
       permissions); 429 or 5xx -> ``upstream_fault`` (rate-limit/external
       unavailable).
    3. ``PermissionError`` -> ``policy_fault``.
    4. ``TimeoutError`` / ``ConnectionError`` / ``MemoryError`` / other
       ``OSError`` -> ``infra_fault`` (DB unavailable, OOM, internal timeout).
       A federated tool call failing with one of these bubbles up as
       ``upstream_fault`` instead — federated call sites pass
       ``fault_class="upstream_fault"`` explicitly to ``fault_event()``
       rather than relying on this generic default, since the same
       exception *type* means something different depending on whether the
       failing service is ours or a third party's.
    5. ``ValueError`` / ``TypeError`` / pydantic ``ValidationError`` ->
       ``agent_fault`` (validation/model/tool-output errors).
    6. Unknown exception types default to ``agent_fault`` — fail toward
       attribution rather than silently exempting an unrecognized failure
       from Q consequences; an unrecognized exception is far more likely to
       be a genuine bug in agent/tool code than an infra/upstream condition
       nobody has classified yet.
    """
    if isinstance(exc, _DeclaresFaultClass) and is_fault_class(exc.fault_class):
        return exc.fault_class

    status_code = _duck_typed_status_code(exc)
    if status_code is not None:
        if status_code in (401, 403):
            return "policy_fault"
        if status_code == 429 or 500 <= status_code < 600:
            return "upstream_fault"

    if isinstance(exc, PermissionError):
        return "policy_fault"

    if isinstance(exc, TimeoutError | ConnectionError | MemoryError | OSError):
        return "infra_fault"

    if isinstance(exc, ValueError | TypeError):
        return "agent_fault"

    try:
        from pydantic import ValidationError as _PydanticValidationError
    except ImportError:
        _PydanticValidationError = None
    if _PydanticValidationError is not None and isinstance(exc, _PydanticValidationError):
        return "agent_fault"

    return "agent_fault"


class FaultEvent(TypedDict, total=False):
    """DebugBus-ready typed event envelope — the DLQ-0 record body used
    when DebugBus storage is unavailable."""

    event_type: str
    fault_class: str
    tenant_id: str | None
    graph_run_id: str | None
    node_id: str | None
    synapse_id: str | None
    ref_kind: str | None
    ref_id: str | None
    content_hash: str | None
    error_code: str
    retryable: bool
    provenance: list[str]
    ts: str
    service: str | None
    component: str | None
    phase: int | None
    metadata: JsonDict


def fault_event(
    exc: BaseException,
    *,
    event_type: str,
    error_code: str,
    tenant_id: str | None = None,
    graph_run_id: str | None = None,
    node_id: str | None = None,
    synapse_id: str | None = None,
    ref_kind: str | None = None,
    ref_id: str | None = None,
    content_hash: str | None = None,
    retryable: bool = False,
    provenance: list[str] | None = None,
    fault_class: FaultClass | None = None,
    service: str | None = None,
    component: str | None = None,
    phase: int | None = None,
    metadata: JsonDict | None = None,
) -> JsonDict:
    """Shape any exception as a DebugBus-ready event envelope.

    Covers both a typed-error envelope shape (``ref_kind``/``content_hash``/
    ``ts``) and the Event Journal/DLQ-0 blueprint shape (``service``/
    ``component``/``phase``/``metadata``) — one function, superset of
    fields, so callers don't need two builders.

    Args:
        exc: The exception being reported.
        event_type: Dotted event name, e.g. ``"brain.synapse.write_failed"``.
        error_code: Stable error code, e.g. ``"reference.hash_mismatch"``.
        tenant_id: Tenant scope, when known.
        graph_run_id: Run identifier, when known.
        node_id: Graph node identifier, when known.
        synapse_id: Synapse identifier, when the failure relates to one.
        ref_kind: PassByRef kind, when the failure relates to one.
        ref_id: PassByRef target identifier, when the failure relates to one.
        content_hash: Content hash, when the failure relates to one.
        retryable: Whether replaying this event later may succeed.
        provenance: Call-site chain, e.g. ``["router.compiler", "brain.synapse"]``.
        fault_class: Explicit override. When omitted, derived via
            ``classify_exception(exc)`` — pass this explicitly whenever the
            call site already knows more than the exception type alone can
            say (see the federated-tool note on ``classify_exception``).
        service: Owning service, e.g. ``"ContextBrain"``.
        component: Owning component, e.g. ``"synapses"``.
        phase: Optional numeric tag for grouping events by rollout stage.
        metadata: Extensible bag for anything not in the fixed envelope
            fields (e.g. model id, tool binding) — kept generic rather than
            growing the envelope's fixed field list per caller.

    Returns:
        A JSON-serializable dict matching the DLQ-0 envelope shape.
    """
    resolved_class: FaultClass = fault_class or classify_exception(exc)
    return {
        "event_type": event_type,
        "fault_class": resolved_class,
        "tenant_id": tenant_id,
        "graph_run_id": graph_run_id,
        "node_id": node_id,
        "synapse_id": synapse_id,
        "ref_kind": ref_kind,
        "ref_id": ref_id,
        "content_hash": content_hash,
        "error_code": error_code,
        "retryable": retryable,
        "provenance": list(provenance) if provenance else [],
        "ts": datetime.now(UTC).isoformat(),
        "service": service,
        "component": component,
        "phase": phase,
        "metadata": dict(metadata) if metadata else {},
    }


__all__ = [
    "AGENT_FAULT",
    "FAULT_CLASSES",
    "INFRA_FAULT",
    "POLICY_FAULT",
    "Q_PENALIZING_FAULT_CLASSES",
    "REFERENCE_FAULT",
    "UPSTREAM_FAULT",
    "FaultClass",
    "FaultEvent",
    "classify_exception",
    "fault_event",
    "is_fault_class",
    "penalizes_agent_q",
]
