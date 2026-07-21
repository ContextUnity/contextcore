"""ContextUnit SDK - Core data structures and clients for ContextUnity protocol.

All gRPC communication uses ContextUnit as the universal data contract.
Domain-specific data is passed via the payload field.

This module re-exports all public API from submodules for backward compatibility.
"""

from __future__ import annotations

# Re-export all public API
from .agentic_guidance import (
    AGENTIC_GUIDANCE_POLICY_V1_DIGEST,
    INVOCATION_PURPOSES_V1,
    TRUSTED_AGENTIC_GUIDANCE_RELEASES_V1,
    AgenticGuidanceDescriptor,
    AgenticGuidanceEnvelope,
    AgenticGuidanceEvidence,
    AgenticGuidanceMode,
    InvocationOrigin,
    InvocationPurpose,
    invocation_purpose_v1,
    trusted_agentic_guidance_artifact_v1,
)
from .bootstrap import bootstrap_django, bootstrap_standalone, register_and_start
from .clients import RouterClient, ShieldClient, WorkerClient
from .clients.brain import BrainClient
from .contextunit import ContextUnit
from .conversation import (
    ConversationAppendReceipt,
    ConversationHistoryStats,
    ConversationRecord,
    ConversationRecordRef,
    ConversationRetentionReceipt,
)
from .execution_trace_artifacts import (
    ArtifactCaptureState,
    ArtifactKind,
    ArtifactStorageState,
    ExecutionTraceArtifactArchiveReceipt,
    ExecutionTraceArtifactFinalizationReceipt,
    ExecutionTraceArtifactIdentity,
    ExecutionTraceArtifactLifecycleProfile,
    ExecutionTraceArtifactRef,
    ExecutionTraceArtifactReservationReceipt,
    ModelIOChannel,
    ModelIOContent,
    ModelIOContentKind,
    ModelIOContentPart,
    ModelIOMimeType,
    ModelIOProviderStatus,
    ProtectedExecutionTraceArtifactEnvelope,
    ProtectedModelIOSettings,
    ProtectExecutionTraceArtifactRequest,
    UnprotectedExecutionTraceArtifact,
    UnprotectExecutionTraceArtifactRequest,
)
from .models import CellSearchResult, CotStep, SecurityScopes, UnitMetrics
from .provider_usage import (
    ANTHROPIC_USAGE_SCHEMA_V1,
    GOOGLE_USAGE_SCHEMA_V1,
    MAX_PROVIDER_USAGE_DETAILS,
    MAX_PROVIDER_USAGE_KEY_LENGTH,
    MAX_PROVIDER_USAGE_VALUE,
    OPENAI_USAGE_SCHEMA_V1,
    ProviderUsageDetails,
    ProviderUsageDetailSchema,
    ProviderUsageField,
    ProviderUsageRelation,
    ProviderUsageUnit,
    trusted_provider_usage_schema,
)
from .streaming import FederatedToolCallContext
from .toolkit import FederatedToolkit, ToolConfig, ToolkitResolutionError, tool
from .tools import ToolRegistry, federated_tool

__all__ = [
    # Core data structures
    "AGENTIC_GUIDANCE_POLICY_V1_DIGEST",
    "INVOCATION_PURPOSES_V1",
    "TRUSTED_AGENTIC_GUIDANCE_RELEASES_V1",
    "AgenticGuidanceDescriptor",
    "AgenticGuidanceEnvelope",
    "AgenticGuidanceEvidence",
    "AgenticGuidanceMode",
    "InvocationOrigin",
    "InvocationPurpose",
    "invocation_purpose_v1",
    "trusted_agentic_guidance_artifact_v1",
    "ArtifactCaptureState",
    "ArtifactKind",
    "ArtifactStorageState",
    "ExecutionTraceArtifactArchiveReceipt",
    "ExecutionTraceArtifactFinalizationReceipt",
    "ExecutionTraceArtifactIdentity",
    "ExecutionTraceArtifactLifecycleProfile",
    "ExecutionTraceArtifactRef",
    "ExecutionTraceArtifactReservationReceipt",
    "ModelIOChannel",
    "ModelIOContent",
    "ModelIOContentKind",
    "ModelIOContentPart",
    "ModelIOMimeType",
    "ModelIOProviderStatus",
    "ProtectExecutionTraceArtifactRequest",
    "ProtectedExecutionTraceArtifactEnvelope",
    "ProtectedModelIOSettings",
    "UnprotectExecutionTraceArtifactRequest",
    "UnprotectedExecutionTraceArtifact",
    "ANTHROPIC_USAGE_SCHEMA_V1",
    "GOOGLE_USAGE_SCHEMA_V1",
    "MAX_PROVIDER_USAGE_DETAILS",
    "MAX_PROVIDER_USAGE_KEY_LENGTH",
    "MAX_PROVIDER_USAGE_VALUE",
    "OPENAI_USAGE_SCHEMA_V1",
    "ProviderUsageDetails",
    "ProviderUsageDetailSchema",
    "ProviderUsageField",
    "ProviderUsageRelation",
    "ProviderUsageUnit",
    "trusted_provider_usage_schema",
    "ContextUnit",
    "ConversationAppendReceipt",
    "ConversationHistoryStats",
    "ConversationRecord",
    "ConversationRecordRef",
    "ConversationRetentionReceipt",
    "CellSearchResult",
    "CotStep",
    "UnitMetrics",
    "SecurityScopes",
    "FederatedToolCallContext",
    # Clients
    "BrainClient",
    "RouterClient",
    "ShieldClient",
    "WorkerClient",
    # Bootstrap
    "register_and_start",
    "bootstrap_django",
    "bootstrap_standalone",
    # Tool decorator
    "federated_tool",
    "ToolRegistry",
    # Toolkits
    "FederatedToolkit",
    "tool",
    "ToolConfig",
    "ToolkitResolutionError",
]
