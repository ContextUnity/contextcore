"""Closed metadata contracts for origin-derived model guidance decisions."""

from __future__ import annotations

from enum import StrEnum
from hashlib import sha256
from json import dumps as canonical_dumps
from typing import ClassVar, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class InvocationOrigin(StrEnum):
    """Identify reviewed Router call sites without accepting free-form caller labels."""

    GRAPH_LLM_NODE = "graph_llm_node"
    COMPILED_AGENT = "compiled_agent"
    DISPATCHER_AGENT = "dispatcher_agent"
    PLATFORM_GENERATION = "platform_generation"
    PLATFORM_CLASSIFY = "platform_classify"
    PLATFORM_GENERATE_CONTENT = "platform_generate_content"
    PLATFORM_REVIEW_CONTENT = "platform_review_content"
    PLATFORM_FILTER_CONTENT = "platform_filter_content"
    PLATFORM_PLAN_CONTENT = "platform_plan_content"
    PLATFORM_MATCH_SEMANTIC = "platform_match_semantic"
    PLATFORM_SQL = "platform_sql"
    PLATFORM_INTENT = "platform_intent"
    PLATFORM_NO_RESULTS = "platform_no_results"
    PLATFORM_RLM = "platform_rlm"
    PLATFORM_SUGGEST = "platform_suggest"
    PLATFORM_SYNTHESIZER = "platform_synthesizer"
    NER_EXTRACTION = "ner_extraction"
    KEYPHRASE_EXTRACTION = "keyphrase_extraction"
    AUTO_EXTRACT = "auto_extract"
    CLI_MODEL_PROBE = "cli_model_probe"


class InvocationPurpose(StrEnum):
    """Describe why a model is called after deriving it from a registered origin."""

    AGENTIC_PLANNING = "agentic_planning"
    AGENTIC_REASONING = "agentic_reasoning"
    AGENTIC_EXECUTION = "agentic_execution"
    STRUCTURED_EXTRACTION = "structured_extraction"
    CLASSIFICATION = "classification"
    VERIFICATION = "verification"
    EVALUATION = "evaluation"
    PROBE = "probe"
    EMBEDDING = "embedding"


class AgenticGuidanceMode(StrEnum):
    """Require guidance for agentic work or prove its absence for bounded work."""

    REQUIRED = "required"
    FORBIDDEN = "forbidden"


INVOCATION_PURPOSES_V1: tuple[tuple[InvocationOrigin, InvocationPurpose], ...] = (
    (InvocationOrigin.GRAPH_LLM_NODE, InvocationPurpose.AGENTIC_REASONING),
    (InvocationOrigin.COMPILED_AGENT, InvocationPurpose.AGENTIC_EXECUTION),
    (InvocationOrigin.DISPATCHER_AGENT, InvocationPurpose.AGENTIC_EXECUTION),
    (InvocationOrigin.PLATFORM_GENERATION, InvocationPurpose.AGENTIC_REASONING),
    (InvocationOrigin.PLATFORM_CLASSIFY, InvocationPurpose.CLASSIFICATION),
    (InvocationOrigin.PLATFORM_GENERATE_CONTENT, InvocationPurpose.AGENTIC_REASONING),
    (InvocationOrigin.PLATFORM_REVIEW_CONTENT, InvocationPurpose.VERIFICATION),
    (InvocationOrigin.PLATFORM_FILTER_CONTENT, InvocationPurpose.CLASSIFICATION),
    (InvocationOrigin.PLATFORM_PLAN_CONTENT, InvocationPurpose.AGENTIC_PLANNING),
    (InvocationOrigin.PLATFORM_MATCH_SEMANTIC, InvocationPurpose.CLASSIFICATION),
    (InvocationOrigin.PLATFORM_SQL, InvocationPurpose.AGENTIC_REASONING),
    (InvocationOrigin.PLATFORM_INTENT, InvocationPurpose.CLASSIFICATION),
    (InvocationOrigin.PLATFORM_NO_RESULTS, InvocationPurpose.AGENTIC_REASONING),
    (InvocationOrigin.PLATFORM_RLM, InvocationPurpose.AGENTIC_REASONING),
    (InvocationOrigin.PLATFORM_SUGGEST, InvocationPurpose.STRUCTURED_EXTRACTION),
    (InvocationOrigin.PLATFORM_SYNTHESIZER, InvocationPurpose.AGENTIC_REASONING),
    (InvocationOrigin.NER_EXTRACTION, InvocationPurpose.STRUCTURED_EXTRACTION),
    (InvocationOrigin.KEYPHRASE_EXTRACTION, InvocationPurpose.STRUCTURED_EXTRACTION),
    (InvocationOrigin.AUTO_EXTRACT, InvocationPurpose.STRUCTURED_EXTRACTION),
    (InvocationOrigin.CLI_MODEL_PROBE, InvocationPurpose.PROBE),
)
_AGENTIC_PURPOSES = frozenset(
    {
        InvocationPurpose.AGENTIC_PLANNING,
        InvocationPurpose.AGENTIC_REASONING,
        InvocationPurpose.AGENTIC_EXECUTION,
    }
)
TRUSTED_AGENTIC_GUIDANCE_RELEASES_V1: tuple[tuple[str, str, str], ...] = (
    (
        "2026.07.1",
        "v1",
        "176ed2a85316a932a2f88a90d2f987e5d2855aeb2038379a74dbbcabbd563cd1",
    ),
    (
        "2026.07.0",
        "v1",
        "ff14cb3679b9c72894e5a6175cca0bad2022d3e4a41e37ff1be1464bc52dfa5d",
    ),
)
AGENTIC_GUIDANCE_POLICY_V1_DIGEST = sha256(
    canonical_dumps(
        {origin.value: purpose.value for origin, purpose in INVOCATION_PURPOSES_V1},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
).hexdigest()


def invocation_purpose_v1(origin: InvocationOrigin) -> InvocationPurpose:
    """Resolve the policy-v1 classification shared by Router and Trace validation."""
    for registered_origin, purpose in INVOCATION_PURPOSES_V1:
        if registered_origin is origin:
            return purpose
    raise ValueError("unregistered invocation origin")


def trusted_agentic_guidance_artifact_v1(release_id: str) -> tuple[str, str]:
    """Resolve the version and digest Brain may trust without artifact content."""
    for registered_release, artifact_version, content_digest in TRUSTED_AGENTIC_GUIDANCE_RELEASES_V1:
        if registered_release == release_id:
            return artifact_version, content_digest
    raise ValueError("unknown agentic guidance release descriptor")


class AgenticGuidanceEnvelope(BaseModel):
    """Bind reviewed instruction content to the fixed platform artifact identity."""

    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
    )

    artifact_id: Literal["core.agentic-ethos"] = "core.agentic-ethos"
    artifact_version: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"[A-Za-z0-9][A-Za-z0-9._-]*",
    )
    content: str = Field(min_length=1, max_length=4096, repr=False)
    content_digest: str = Field(pattern=r"[0-9a-f]{64}")

    @model_validator(mode="after")
    def validate_content_digest(self) -> "AgenticGuidanceEnvelope":
        """Reject modified instruction content without exposing it in errors."""
        if sha256(self.content.encode("utf-8")).hexdigest() != self.content_digest:
            raise ValueError("agentic guidance envelope digest does not match content")
        return self


class AgenticGuidanceDescriptor(BaseModel):
    """Carry a verified artifact identity without exposing its instruction text."""

    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
    )

    artifact_id: Literal["core.agentic-ethos"] = "core.agentic-ethos"
    artifact_version: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"[A-Za-z0-9][A-Za-z0-9._-]*",
    )
    content_digest: str = Field(pattern=r"[0-9a-f]{64}")
    release_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"[A-Za-z0-9][A-Za-z0-9._-]*",
    )


class AgenticGuidanceEvidence(BaseModel):
    """Persist a bounded applicability result while excluding guidance and prompts."""

    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
    )

    origin: InvocationOrigin
    purpose: InvocationPurpose
    mode: AgenticGuidanceMode
    outcome: Literal["applied_once", "not_applicable"]
    policy_version: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"[A-Za-z0-9][A-Za-z0-9._-]*",
    )
    policy_digest: str = Field(pattern=r"[0-9a-f]{64}")
    descriptor: AgenticGuidanceDescriptor | None = None

    @model_validator(mode="after")
    def validate_applicability_projection(self) -> "AgenticGuidanceEvidence":
        """Reject evidence that contradicts the resolved applicability mode."""
        if self.mode is AgenticGuidanceMode.REQUIRED:
            if self.outcome != "applied_once" or self.descriptor is None:
                raise ValueError("required guidance needs one descriptor and applied_once evidence")
        elif self.outcome != "not_applicable" or self.descriptor is not None:
            raise ValueError("forbidden guidance must have no descriptor and not_applicable evidence")
        if self.policy_version != "v1":
            raise ValueError("unknown agentic guidance policy version")
        if self.policy_digest != AGENTIC_GUIDANCE_POLICY_V1_DIGEST:
            raise ValueError("agentic guidance policy digest is not trusted")
        if self.purpose is not invocation_purpose_v1(self.origin):
            raise ValueError("agentic guidance origin and purpose do not match policy")
        expected_mode = (
            AgenticGuidanceMode.REQUIRED if self.purpose in _AGENTIC_PURPOSES else AgenticGuidanceMode.FORBIDDEN
        )
        if self.mode is not expected_mode:
            raise ValueError("agentic guidance purpose and mode do not match policy")
        if self.descriptor is not None:
            artifact_version, content_digest = trusted_agentic_guidance_artifact_v1(self.descriptor.release_id)
            if self.descriptor.artifact_version != artifact_version or self.descriptor.content_digest != content_digest:
                raise ValueError("agentic guidance descriptor does not match trusted release")
        return self


__all__ = [
    "AgenticGuidanceDescriptor",
    "AgenticGuidanceEnvelope",
    "AgenticGuidanceEvidence",
    "AgenticGuidanceMode",
    "AGENTIC_GUIDANCE_POLICY_V1_DIGEST",
    "INVOCATION_PURPOSES_V1",
    "TRUSTED_AGENTIC_GUIDANCE_RELEASES_V1",
    "InvocationOrigin",
    "InvocationPurpose",
    "invocation_purpose_v1",
    "trusted_agentic_guidance_artifact_v1",
]
