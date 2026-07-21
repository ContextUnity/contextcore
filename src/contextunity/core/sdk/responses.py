"""Typed response contracts for SDK client methods.

Each ``TypedDict`` here represents the shape returned by a specific SDK
client method.  Nested JSON metadata uses ``JsonDict``; open gRPC sub-maps
use ``ContextUnitPayload``.

Convention:
    - Names follow ``{Service}{Operation}Result`` pattern.
    - All fields that may be absent use ``total=False`` or ``NotRequired``.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Literal, TypeAlias, TypedDict, TypeGuard

from contextunity.core.sdk.payload import get_str
from contextunity.core.types import ContextUnitPayload, JsonDict

# ---- Shield responses --------------------------------------------------------
#
# Shield unary RPCs return open ``ContextUnitPayload``. TypedDicts below document
# common wire keys; SDK clients return the full payload via ``copy_wire_payload``.

ScanResult: TypeAlias = ContextUnitPayload
SecretResult: TypeAlias = ContextUnitPayload
PutSecretResult: TypeAlias = ContextUnitPayload
ListSecretsResult: TypeAlias = ContextUnitPayload
RotateSecretResult: TypeAlias = ContextUnitPayload
EncryptResult: TypeAlias = ContextUnitPayload
DecryptResult: TypeAlias = ContextUnitPayload
SessionTokenResult: TypeAlias = ContextUnitPayload
PublicKeyResult: TypeAlias = ContextUnitPayload
RotateKeyResult: TypeAlias = ContextUnitPayload
ShieldStatsResult: TypeAlias = ContextUnitPayload


class ScanWireFields(TypedDict, total=False):
    """Common ``ShieldClient.scan()`` wire keys (see live Shield firewall handler)."""

    allowed: bool
    blocked: bool
    reason: str
    severity: str
    latency_ms: float
    threats: list[JsonDict]
    error: str
    message: str


class SecretWireFields(TypedDict, total=False):
    """Common ``ShieldClient.get_secret()`` wire keys."""

    path: str
    value: str
    version: int
    tenant_id: str
    created_at: str
    tags: JsonDict
    encryption_backend: str
    expires_at: str
    error: str
    message: str


class PutSecretWireFields(TypedDict, total=False):
    """Common ``ShieldClient.put_secret()`` wire keys."""

    path: str
    version: int
    created_at: str
    status: str
    expires_at: str
    error: str
    message: str


class ListSecretsWireFields(TypedDict, total=False):
    """Common ``ShieldClient.list_secrets()`` wire keys."""

    secrets: list[JsonDict]
    error: str
    message: str


class RotateSecretWireFields(TypedDict, total=False):
    """Common ``ShieldClient.rotate_secret()`` wire keys."""

    path: str
    old_version: int
    new_version: int
    status: str
    error: str
    message: str


class EncryptWireFields(TypedDict, total=False):
    """Common ``ShieldClient.encrypt()`` wire keys."""

    ciphertext_b64: str
    error: str
    message: str


class DecryptWireFields(TypedDict, total=False):
    """Common ``ShieldClient.decrypt()`` wire keys."""

    plaintext: str
    error: str
    message: str


class SessionTokenWireFields(TypedDict, total=False):
    """Common ``ShieldClient.issue_session_token()`` wire keys."""

    token: str
    project_id: str
    error: str
    message: str


class PublicKeyWireFields(TypedDict, total=False):
    """Common ``ShieldClient.get_project_public_key()`` wire keys."""

    public_key: str
    algorithm: str
    error: str
    message: str


class RotateKeyWireFields(TypedDict, total=False):
    """Common ``ShieldClient.rotate_project_key()`` wire keys."""

    new_public_key: str
    error: str
    message: str


class ShieldStatsWireFields(TypedDict, total=False):
    """Common ``ShieldClient.get_stats()`` wire keys."""

    secrets_count: int
    projects_count: int
    uptime_seconds: float


# ---- Brain responses ---------------------------------------------------------
#
# Unary Brain RPCs that return open wire maps use ``ContextUnitPayload`` aliases
# below. Streaming methods map stream items onto domain records separately.


GraphSearchResult: TypeAlias = ContextUnitPayload
MemoryLayerName: TypeAlias = Literal["conversation_records", "cells", "embedding_jobs"]


class GraphSearchWireFields(TypedDict, total=False):
    """Common ``BrainClient.graph_search()`` wire keys."""

    nodes: list[JsonDict]
    edges: list[JsonDict]
    error: str
    message: str


class SynapseRecord(TypedDict, total=False):
    """Single BrainSynapse learning-trace record from Brain (query_synapses)."""

    id: str
    graph_name: str
    graph_run_id: str
    node_id: str
    node_name: str
    agent_id: str
    action_type: str
    action_data: JsonDict
    action_data_ref: str
    context_summary: str
    thought_trace_ref: str
    content_hash: str
    node_role: str
    fault_class: str
    status: str
    q_action: float
    q_hypothesis: float
    q_relevance: float
    q_composite: float
    scope_path: str
    metadata: JsonDict
    created_at: str
    updated_at: str


# ---- Worker responses --------------------------------------------------------
#
# Worker unary RPCs return open ``ContextUnitPayload``. TypedDicts document common
# wire keys; SDK clients preserve the full server response via ``copy_wire_payload``.

StartWorkflowResult: TypeAlias = ContextUnitPayload
GetTaskStatusResult: TypeAlias = ContextUnitPayload
ExecuteCodeResult: TypeAlias = ContextUnitPayload
RegisterSchedulesResult: TypeAlias = ContextUnitPayload


class StartWorkflowWireFields(TypedDict, total=False):
    """Common ``WorkerClient.start_workflow()`` wire keys."""

    workflow_id: str
    run_id: str
    status: str
    error: str


class GetTaskStatusWireFields(TypedDict, total=False):
    """Common ``WorkerClient.get_task_status()`` wire keys."""

    status: str
    result: JsonDict
    error: str


class ExecuteCodeWireFields(TypedDict, total=False):
    """Common ``WorkerClient.execute_code()`` wire keys."""

    stdout: str
    stderr: str
    exit_code: int
    error: str


class RegisterSchedulesWireFields(TypedDict, total=False):
    """Common ``WorkerClient.register_schedules()`` wire keys."""

    status: str
    registered_count: int
    error: str


# ---- Router responses --------------------------------------------------------
#
# Router unary RPCs return open ``ContextUnitPayload``. TypedDicts document common
# wire keys; SDK clients preserve the full server response via ``copy_wire_payload``.

ExecuteAgentResult: TypeAlias = ContextUnitPayload
ExecuteNodeResult: TypeAlias = ContextUnitPayload


class ExecuteAgentWireFields(TypedDict, total=False):
    """Common ``RouterClient.execute_agent()`` wire keys."""

    response: str
    session_id: str
    metadata: JsonDict
    error: str
    message: str


class ExecuteNodeWireFields(TypedDict, total=False):
    """Common ``RouterClient.execute_node()`` wire keys."""

    output: ContextUnitPayload
    node_name: str
    execution_ms: int
    error: str
    message: str


# ---- Router stream payloads (wire = open graph state) -------------------------

StreamPayload: TypeAlias = ContextUnitPayload
"""Single ``StreamAgent`` / ``StreamDispatcher`` wire payload.

Router sets ``event_type`` (``progress`` | ``result`` | ``brain_event`` | ``done`` | ``error``)
and may spill arbitrary graph state keys alongside envelope fields (``node``, ``step``, …).
Domain output keys (``answer``, ``matches``, …) live here — not in core TypedDicts.
"""

StreamEvent = StreamPayload
"""Backward-compatible alias for :data:`StreamPayload`."""


def is_progress_event(d: Mapping[str, object]) -> TypeGuard[StreamPayload]:
    """Return True when ``d`` is a Router stream progress payload."""
    return get_str(d, "event_type") == "progress"


def is_result_event(d: Mapping[str, object]) -> TypeGuard[StreamPayload]:
    """Return True when ``d`` is a Router stream result payload (final graph state)."""
    return get_str(d, "event_type") == "result"


def is_brain_event(d: Mapping[str, object]) -> TypeGuard[StreamPayload]:
    """Return True when ``d`` is a Router stream brain side-channel payload."""
    return get_str(d, "event_type") == "brain_event"


def is_terminal_event(d: Mapping[str, object]) -> TypeGuard[StreamPayload]:
    """Return True when ``d`` is a terminal ``done`` / ``error`` stream payload."""
    event_type = get_str(d, "event_type")
    return event_type in ("done", "error")


# ---- Brain trace responses ---------------------------------------------------


class TraceRecord(TypedDict, total=False):
    """Single agent execution trace from Brain."""

    id: str
    agent_id: str
    graph_name: str
    session_id: str
    user_id: str
    tool_calls: list[ContextUnitPayload]
    token_usage: JsonDict
    timing_ms: int
    security_flags: JsonDict
    metadata: JsonDict
    provenance: list[str]
    graph_run_id: str
    payload_digest: str
    terminal_status: str
    terminal_reason: str
    trace_schema_version: str
    prompt_evidence: list[JsonDict]
    steps: list[JsonDict]
    created_at: str


class TraceFinalizationReceipt(TypedDict):
    """Durable Brain receipt for one terminal graph-run finalization."""

    trace_id: str
    graph_run_id: str
    digest: str
    outcome: Literal["created", "duplicate"]


__all__ = [
    # Shield
    "ScanResult",
    "SecretResult",
    "PutSecretResult",
    "ListSecretsResult",
    "RotateSecretResult",
    "EncryptResult",
    "DecryptResult",
    "SessionTokenResult",
    "PublicKeyResult",
    "RotateKeyResult",
    "ShieldStatsResult",
    "ScanWireFields",
    "SecretWireFields",
    "PutSecretWireFields",
    "ListSecretsWireFields",
    "RotateSecretWireFields",
    "EncryptWireFields",
    "DecryptWireFields",
    "SessionTokenWireFields",
    "PublicKeyWireFields",
    "RotateKeyWireFields",
    "ShieldStatsWireFields",
    # Brain
    "GraphSearchResult",
    "GraphSearchWireFields",
    "SynapseRecord",
    "TraceRecord",
    "TraceFinalizationReceipt",
    # Worker
    "StartWorkflowResult",
    "GetTaskStatusResult",
    "ExecuteCodeResult",
    "RegisterSchedulesResult",
    "StartWorkflowWireFields",
    "GetTaskStatusWireFields",
    "ExecuteCodeWireFields",
    "RegisterSchedulesWireFields",
    # Router
    "ExecuteAgentResult",
    "ExecuteNodeResult",
    "ExecuteAgentWireFields",
    "ExecuteNodeWireFields",
    "StreamPayload",
    "StreamEvent",
    "is_progress_event",
    "is_result_event",
    "is_brain_event",
    "is_terminal_event",
]
