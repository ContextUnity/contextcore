"""Shared SDK typing aliases.

Centralizes lightweight JSON/payload aliases used across bootstrap, identity,
and streaming helpers to keep contracts consistent.
"""

from __future__ import annotations

from collections.abc import Awaitable, Iterator, Mapping
from typing import (
    TYPE_CHECKING,
    ClassVar,
    Literal,
    NotRequired,
    Protocol,
    TypeAlias,
    TypedDict,
    TypeVar,
    runtime_checkable,
)

from contextunity.core.control import ControlAction, ControlReason
from contextunity.core.manifest.models import WorkerBindingsBundle
from contextunity.core.types import (
    ContextUnitPayload,
    JsonDict,
    JsonPrimitive,
    JsonValue,
    is_object_dict,
    is_object_list,
    is_object_set,
    is_object_tuple,
)
from pydantic import BaseModel, ConfigDict

if TYPE_CHECKING:
    import grpc.aio
    from contextunity.core import contextunit_pb2
    from contextunity.core.sdk.streaming.bidi import FederatedToolCallContext
    from contextunity.core.tokens import ContextToken

    UnaryContextUnitRpc: TypeAlias = grpc.aio.UnaryUnaryMultiCallable[
        contextunit_pb2.ContextUnit,
        contextunit_pb2.ContextUnit,
    ]
else:
    import grpc.aio
    from contextunity.core import contextunit_pb2

    UnaryContextUnitRpc = grpc.aio.UnaryUnaryMultiCallable[
        contextunit_pb2.ContextUnit,
        contextunit_pb2.ContextUnit,
    ]

type BrainReadKind = Literal["cell_search", "memory_read", "synapse_query"]
type BrainReadDepth = Literal["shallow", "standard", "deep", "research"]
type BrainReadExecutionOutcome = Literal["executed", "coalesced", "cache_hit"]
type BrainReadEvidenceOutcome = Literal[
    "executed",
    "coalesced",
    "cache_hit",
    "queue_full",
    "deadline_exceeded",
    "brain_unavailable",
]
BRAIN_READ_KINDS: tuple[BrainReadKind, ...] = (
    "cell_search",
    "memory_read",
    "synapse_query",
)
BRAIN_READ_DEPTHS: tuple[BrainReadDepth, ...] = (
    "shallow",
    "standard",
    "deep",
    "research",
)
BRAIN_READ_EXECUTION_OUTCOMES: tuple[BrainReadExecutionOutcome, ...] = (
    "executed",
    "coalesced",
    "cache_hit",
)
BRAIN_READ_EVIDENCE_OUTCOMES: tuple[BrainReadEvidenceOutcome, ...] = (
    *BRAIN_READ_EXECUTION_OUTCOMES,
    "queue_full",
    "deadline_exceeded",
    "brain_unavailable",
)


T_co = TypeVar("T_co", covariant=True)
_RequestT = TypeVar("_RequestT")
_ResponseT = TypeVar("_ResponseT")

ToolPayload: TypeAlias = ContextUnitPayload
ToolResult: TypeAlias = ContextUnitPayload
PromptMap: TypeAlias = Mapping[str, str | JsonDict]
USER_PROMPT_REDACTED_PREVIEW = "[redacted]"
"""Only user-prompt preview value permitted on the execution-trace wire."""


class ProviderUsageDetailsWire(TypedDict):
    """Bounded admitted provider counters for one model attempt."""

    schema_id: str
    values: dict[str, str]


class TraceUsageWire(TypedDict):
    """Router-normalized terminal usage transported without recomputation."""

    input_tokens: int
    output_tokens: int
    cost_micros: int
    provider_details: NotRequired[ProviderUsageDetailsWire]


class PromptEvidenceWire(TypedDict):
    """Bounded prompt evidence; user content is always default-denied."""

    role: Literal["user", "system"]
    redacted_preview: str
    redaction_policy_version: Literal["contextunity.prompt-redaction/v1"]
    prompt_ref: NotRequired[str]
    prompt_version: NotRequired[str]


class AgenticGuidanceDescriptorWire(TypedDict):
    """Identify the verified guidance artifact without transporting its content."""

    artifact_id: Literal["core.agentic-ethos"]
    artifact_version: str
    content_digest: str
    release_id: str


class AgenticGuidanceEvidenceWire(TypedDict):
    """Carry one origin-derived applicability result as bounded trace metadata."""

    origin: str
    purpose: str
    mode: Literal["required", "forbidden"]
    outcome: Literal["applied_once", "not_applicable"]
    policy_version: str
    policy_digest: str
    descriptor: AgenticGuidanceDescriptorWire | None


class ExecutionTraceArtifactIdentityWire(TypedDict):
    """Immutable tenant/project/run/provider-attempt artifact identity."""

    tenant_id: str
    project_id: str
    trace_id: str
    graph_run_id: str
    invocation_id: str
    provider_attempt_id: str
    artifact_kind: Literal["model_io"]


class ExecutionTraceArtifactRefWire(TypedDict):
    """Raw-content-free protected artifact reference attached to one model attempt."""

    artifact_id: str
    identity: ExecutionTraceArtifactIdentityWire
    capture_state: Literal["captured", "disabled", "redacted", "rejected", "unavailable"]
    storage_state: Literal["hot", "archiving", "cold", "restoring", "purging", "purged"]
    content_digest: NotRequired[str]
    request_bytes: int
    response_bytes: int


type TraceControlAction = ControlAction
type TraceControlReason = ControlReason


class TraceReplanRequestWire(TypedDict):
    run_id: str
    reason: TraceControlReason
    verifier_ref: str
    policy_digest: str
    plan_id: NotRequired[str]
    plan_revision: NotRequired[int]
    parent_plan_id: NotRequired[str]
    parent_plan_revision: NotRequired[int]
    prior_replan_ref: NotRequired[str]
    failed_task_ids: list[str]
    stalled_task_ids: list[str]
    remaining_provider_attempts: int
    remaining_node_attempts: int
    remaining_graph_cycles: int
    remaining_side_effect_attempts: int
    remaining_input_tokens: int
    remaining_output_tokens: int
    remaining_cost_micros: int
    remaining_wall_time_ms: int
    fault_refs: list[str]
    effect_receipt_refs: list[str]
    progress_hashes: list[str]
    stagnation_hashes: list[str]


class TraceStepWire(TypedDict):
    """One closed ordered terminal execution attempt."""

    sequence: int
    attempt_id: str
    invocation_id: NotRequired[str]
    parent_attempt_id: NotRequired[str]
    kind: Literal["node", "model", "tool", "control"]
    name: str
    status: Literal["succeeded", "failed", "cancelled"]
    duration_ms: int
    usage: TraceUsageWire
    guidance_evidence: NotRequired[AgenticGuidanceEvidenceWire]
    artifact_ref: NotRequired[ExecutionTraceArtifactRefWire]
    error_code: NotRequired[str]
    control_action: NotRequired[TraceControlAction]
    control_reason: NotRequired[TraceControlReason]
    evidence_refs: NotRequired[list[str]]
    replan_request: NotRequired[TraceReplanRequestWire]


class ToolEffectReceiptWire(TypedDict):
    """Raw-content-free terminal projection of one Router tool-effect receipt."""

    receipt_id: str
    operation_id: str
    idempotency_key: str
    effect_state: Literal["not_started", "committed", "unknown", "compensated"]
    replay_safe: bool
    adapter_id: str
    capability_id: str
    effect_or_result_hash: str


class GraphCycleWire(TypedDict):
    """Distinct graph-cycle identity, never a node-attempt alias."""

    cycle_id: str
    sequence: int


class ChronosDecisionWire(TypedDict):
    """Raw-content-free in-GraphRun RouterChronos decision."""

    run_id: str
    sequence: int
    kind: Literal[
        "run_started",
        "schedule_eligible",
        "deadline_expired",
        "node_attempt_budget_exhausted",
        "graph_cycle_budget_exhausted",
    ]
    elapsed_ms: int
    deadline_ms: int


class BrainReadEvidenceWire(TypedDict):
    """Raw-content-free Brain-read control outcome."""

    query_kind: BrainReadKind
    requested_depth: BrainReadDepth
    effective_depth: BrainReadDepth
    outcome: BrainReadEvidenceOutcome
    degraded: bool
    queue_wait_ms: int
    duration_ms: int
    retryable: bool
    fault_ref: str | None


class TraceControlEvidenceWire(TypedDict):
    """Bounded control evidence attached to one completed Execution Trace."""

    node_attempts: int
    failed_node_attempts: int
    model_attempts: int
    failed_model_attempts: int
    tool_attempts: int
    failed_tool_attempts: int
    graph_cycles: int
    contribution_refs: list[str]
    invalid_contribution_refs: list[str]
    fault_refs: list[str]
    effect_receipt_refs: list[str]
    effect_receipts: list[ToolEffectReceiptWire]
    fan_in_refs: list[str]
    graph_cycle_refs: list[GraphCycleWire]
    chronos_decisions: list[ChronosDecisionWire]
    brain_reads: list[BrainReadEvidenceWire]


class FinalVerdictWire(TypedDict):
    """Closed terminal decision evidence without mutation authority."""

    verdict_digest: str
    terminal_status: Literal["succeeded", "failed", "cancelled"]
    terminal_reason: str
    verifier_ref: str
    verifier_evidence_refs: list[str]
    fault_class: str | None
    attribution_candidates: list[str]
    node_attempts: int
    model_attempts: int
    tool_attempts: int
    input_tokens: int
    output_tokens: int
    cost_micros: int
    duration_ms: int


class TerminalTraceContentWire(TypedDict):
    """Canonical terminal trace content before its digest is attached."""

    schema_version: Literal[
        "contextunity.execution-trace/v3",
        "contextunity.execution-trace/v4",
        "contextunity.execution-trace/v5",
        "contextunity.execution-trace/v6",
    ]
    trace_id: str
    graph_run_id: str
    tenant_id: str
    agent_id: str
    session_id: str | None
    user_id: str | None
    project_id: str
    graph_name: str
    registration_hash: NotRequired[str]
    plan_id: NotRequired[str]
    plan_revision: NotRequired[int]
    parent_plan_id: NotRequired[str]
    parent_plan_revision: NotRequired[int]
    replan_ref: NotRequired[str]
    terminal_status: Literal["succeeded", "failed", "cancelled"]
    terminal_reason: Literal[
        "verified_success",
        "failed",
        "blocked",
        "budget_exhausted",
        "cancelled",
        "human_review_required",
        "replan_requested",
    ]
    duration_ms: int
    steps: list[TraceStepWire]
    usage: TraceUsageWire
    prompt_evidence: list[PromptEvidenceWire]
    provenance: list[str]
    security_flags: list[str]
    control_evidence: NotRequired[TraceControlEvidenceWire]
    final_verdict: NotRequired[FinalVerdictWire]


class TerminalTraceWire(TerminalTraceContentWire):
    """Closed L3 terminal trace accepted by Brain's existing LogTrace RPC."""

    digest: str


WorkerBindings = WorkerBindingsBundle


@runtime_checkable
class TokenProviderFactory(Protocol):
    """Lazy provider for a fresh token object or pre-signed bearer per call."""

    def __call__(self) -> ContextToken | str: ...


@runtime_checkable
class FederatedToolCallable(Protocol):
    """Project tool function registered via ``@federated_tool`` or ``@tool``."""

    def __call__(self, *args: object, **kwargs: object) -> object: ...


@runtime_checkable
class AsyncFederatedToolCallable(Protocol):
    """Async toolkit bridge wrapper around a federated ``@tool`` method."""

    async def __call__(self, *args: object, **kwargs: object) -> object: ...


type FederatedToolHandler = FederatedToolCallable | AsyncFederatedToolCallable


@runtime_checkable
class SyncIteratorFactory(Protocol[T_co]):
    """Factory returning a blocking iterator (used by sync stream bridges)."""

    def __call__(self) -> Iterator[T_co]: ...


@runtime_checkable
class ManifestRegistrationCallback(Protocol):
    """Bootstrap reconnect hook returning the Shield URL, if any."""

    def __call__(self) -> str: ...


@runtime_checkable
class TokenStringProvider(Protocol):
    """Lazy factory returning a bearer token string or structured ``ContextToken``."""

    def __call__(self) -> "ContextToken | str": ...


@runtime_checkable
class ReplaceableClientCallDetails(Protocol):
    """gRPC client call details supporting metadata replacement."""

    metadata: object | None

    def _replace(self, **kwargs: object) -> "grpc.aio.ClientCallDetails": ...


@runtime_checkable
class GrpcUnaryUnaryClientContinuation(Protocol[_RequestT, _ResponseT]):
    """Next handler in the async client interceptor chain."""

    def __call__(
        self,
        client_call_details: "grpc.aio.ClientCallDetails",
        request: _RequestT,
        /,
    ) -> Awaitable["grpc.aio.UnaryUnaryCall[_RequestT, _ResponseT]"]: ...


class ToolHandler(Protocol):
    """Protocol for unified federated tool execution handlers."""

    def __call__(
        self,
        tool_name: str,
        args: ContextUnitPayload,
        auth_ctx: FederatedToolCallContext,
    ) -> ContextUnitPayload: ...


# ---- StructData typing -------------------------------------------------------
#
# Canonical JSON types live in ``contextunity.core.types``; SDK re-exports them
# under the StructData* names for router/brain integration boundaries.

StructDataPrimitive = JsonPrimitive
StructDataValue = JsonValue
StructData = JsonDict


def coerce_struct_data(value: object) -> JsonValue:
    """Best-effort conversion into JSON-serializable StructDataValue.

    Used at integration boundaries where external SDKs return loosely-typed
    Python objects. Intentionally conservative.
    """
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if is_object_dict(value):
        out: StructData = {}
        for key, item in value.items():
            out[str(key)] = coerce_struct_data(item)
        return out
    if is_object_list(value):
        return [coerce_struct_data(item) for item in value]
    if is_object_tuple(value):
        return [coerce_struct_data(item) for item in value]
    if is_object_set(value):
        return [coerce_struct_data(item) for item in sorted(value, key=str)]
    # Fallback: stringify unknown objects (keeps JSON serializable)
    return str(value)


# ---- Payload base model -------------------------------------------------------


class StrictPayloadModel(BaseModel):
    """Base model for gRPC payload contracts.

    ``extra='forbid'`` prevents payload injection attacks.
    All service payload models should inherit from this class.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid",
        hide_input_in_errors=True,
    )


# ---- gRPC metadata typing ----------------------------------------------------

GrpcMetadataEntry: TypeAlias = tuple[str, str | bytes]
# Sync/async gRPC stubs expect an immutable tuple of pairs (``grpc._Metadata``).
GrpcMetadata: TypeAlias = tuple[GrpcMetadataEntry, ...]


__all__ = [
    "ContextUnitPayload",
    "JsonPrimitive",
    "JsonValue",
    "JsonDict",
    "ToolPayload",
    "ToolResult",
    "PromptMap",
    "USER_PROMPT_REDACTED_PREVIEW",
    "TraceUsageWire",
    "PromptEvidenceWire",
    "BRAIN_READ_DEPTHS",
    "BRAIN_READ_EVIDENCE_OUTCOMES",
    "BRAIN_READ_EXECUTION_OUTCOMES",
    "BRAIN_READ_KINDS",
    "BrainReadDepth",
    "BrainReadEvidenceOutcome",
    "BrainReadExecutionOutcome",
    "BrainReadKind",
    "ProviderUsageDetailsWire",
    "AgenticGuidanceDescriptorWire",
    "AgenticGuidanceEvidenceWire",
    "BrainReadEvidenceWire",
    "ExecutionTraceArtifactIdentityWire",
    "ExecutionTraceArtifactRefWire",
    "TraceControlAction",
    "TraceControlReason",
    "TraceReplanRequestWire",
    "TraceStepWire",
    "ToolEffectReceiptWire",
    "GraphCycleWire",
    "ChronosDecisionWire",
    "TraceControlEvidenceWire",
    "TerminalTraceContentWire",
    "TerminalTraceWire",
    "WorkerBindingsBundle",
    "WorkerBindings",
    "TokenProviderFactory",
    "FederatedToolCallable",
    "AsyncFederatedToolCallable",
    "FederatedToolHandler",
    "SyncIteratorFactory",
    "ManifestRegistrationCallback",
    "TokenStringProvider",
    "ReplaceableClientCallDetails",
    "GrpcUnaryUnaryClientContinuation",
    "UnaryContextUnitRpc",
    "ToolHandler",
    "StructDataPrimitive",
    "StructDataValue",
    "StructData",
    "coerce_struct_data",
    "StrictPayloadModel",
    "GrpcMetadataEntry",
    "GrpcMetadata",
]
