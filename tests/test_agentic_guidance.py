"""Shared metadata contracts for Router guidance and Brain Trace."""

from __future__ import annotations

import pytest
from contextunity.core.sdk.agentic_guidance import (
    AgenticGuidanceDescriptor,
    AgenticGuidanceEnvelope,
    AgenticGuidanceEvidence,
    AgenticGuidanceMode,
    InvocationOrigin,
    InvocationPurpose,
)
from pydantic import ValidationError


def test_envelope_binds_fixed_artifact_identity_and_hides_content_on_failure() -> None:
    content = "reviewed instruction"
    envelope = AgenticGuidanceEnvelope(
        artifact_version="v1",
        content=content,
        content_digest="b3ded4954dfe718841c32204f9d2ed8dc6a764262be1a1819eb3d06c7673b5c1",
    )
    assert content not in repr(envelope)

    with pytest.raises(ValidationError, match="digest") as error:
        AgenticGuidanceEnvelope(
            artifact_version="v1",
            content=content,
            content_digest="0" * 64,
        )

    assert content not in str(error.value)


def test_evidence_rejects_mode_outcome_and_descriptor_mismatch() -> None:
    descriptor = AgenticGuidanceDescriptor(
        artifact_version="v1",
        content_digest="176ed2a85316a932a2f88a90d2f987e5d2855aeb2038379a74dbbcabbd563cd1",
        release_id="2026.07.1",
    )
    required = {
        "origin": InvocationOrigin.GRAPH_LLM_NODE,
        "purpose": InvocationPurpose.AGENTIC_REASONING,
        "mode": AgenticGuidanceMode.REQUIRED,
        "outcome": "applied_once",
        "policy_version": "v1",
        "policy_digest": "b1c8f3995fae62701ab5a955083d6ba7b211d7a6f371cf4e67c061e3580a6e8b",
        "descriptor": descriptor,
    }
    assert AgenticGuidanceEvidence.model_validate(required).descriptor == descriptor

    with pytest.raises(ValidationError, match="required guidance"):
        AgenticGuidanceEvidence.model_validate({**required, "descriptor": None})
    with pytest.raises(ValidationError, match="forbidden guidance"):
        AgenticGuidanceEvidence.model_validate(
            {
                **required,
                "mode": AgenticGuidanceMode.FORBIDDEN,
                "outcome": "not_applicable",
            }
        )
    raw_sentinel = "RAW_GUIDANCE_SENTINEL_must_not_enter_errors"
    with pytest.raises(ValidationError, match="Extra inputs") as raw_error:
        AgenticGuidanceEvidence.model_validate({**required, "content": raw_sentinel})
    assert raw_sentinel not in str(raw_error.value)


def test_evidence_rejects_origin_purpose_mode_and_policy_mismatch() -> None:
    base = {
        "origin": InvocationOrigin.GRAPH_LLM_NODE,
        "purpose": InvocationPurpose.AGENTIC_REASONING,
        "mode": AgenticGuidanceMode.REQUIRED,
        "outcome": "applied_once",
        "policy_version": "v1",
        "policy_digest": "b1c8f3995fae62701ab5a955083d6ba7b211d7a6f371cf4e67c061e3580a6e8b",
        "descriptor": AgenticGuidanceDescriptor(
            artifact_version="v1",
            content_digest="176ed2a85316a932a2f88a90d2f987e5d2855aeb2038379a74dbbcabbd563cd1",
            release_id="2026.07.1",
        ),
    }

    with pytest.raises(ValidationError, match="origin and purpose"):
        AgenticGuidanceEvidence.model_validate({**base, "purpose": InvocationPurpose.CLASSIFICATION})
    with pytest.raises(ValidationError, match="purpose and mode"):
        AgenticGuidanceEvidence.model_validate(
            {
                **base,
                "mode": AgenticGuidanceMode.FORBIDDEN,
                "outcome": "not_applicable",
                "descriptor": None,
            }
        )
    with pytest.raises(ValidationError, match="policy digest"):
        AgenticGuidanceEvidence.model_validate({**base, "policy_digest": "0" * 64})
    with pytest.raises(ValidationError, match="trusted release"):
        AgenticGuidanceEvidence.model_validate(
            {
                **base,
                "descriptor": AgenticGuidanceDescriptor(
                    artifact_version="v1",
                    content_digest="0" * 64,
                    release_id="2026.07.1",
                ),
            }
        )
    with pytest.raises(ValidationError, match="trusted release"):
        AgenticGuidanceEvidence.model_validate(
            {
                **base,
                "descriptor": AgenticGuidanceDescriptor(
                    artifact_version="v2",
                    content_digest="176ed2a85316a932a2f88a90d2f987e5d2855aeb2038379a74dbbcabbd563cd1",
                    release_id="2026.07.1",
                ),
            }
        )
    with pytest.raises(ValidationError, match="unknown agentic guidance release descriptor"):
        AgenticGuidanceEvidence.model_validate(
            {
                **base,
                "descriptor": AgenticGuidanceDescriptor(
                    artifact_version="v1",
                    content_digest="0" * 64,
                    release_id="untrusted",
                ),
            }
        )
