from uuid import uuid4

import pytest
from contextunity.core.sdk.execution_trace_artifacts import (
    ExecutionTraceArtifactIdentity,
    ExecutionTraceArtifactRef,
    ModelIOContent,
    ModelIOContentPart,
)
from pydantic import ValidationError


def _identity() -> ExecutionTraceArtifactIdentity:
    return ExecutionTraceArtifactIdentity(
        tenant_id="tenant-a",
        project_id="project-a",
        trace_id=uuid4(),
        graph_run_id=uuid4(),
        invocation_id=uuid4(),
        provider_attempt_id=uuid4(),
        artifact_kind="model_io",
    )


def _part(*, sequence: int, channel: str, content: str) -> ModelIOContentPart:
    encoded = content.encode("utf-8")
    return ModelIOContentPart(
        sequence=sequence,
        channel=channel,
        content_kind="text",
        mime_type="text/plain",
        content=content,
        byte_count=len(encoded),
    )


def test_model_io_content_is_closed_ordered_and_bounded() -> None:
    request = _part(sequence=0, channel="system", content="be concise")
    response = _part(sequence=0, channel="assistant", content="done")

    content = ModelIOContent(
        request_parts=[request],
        response_parts=[response],
        provider_status="succeeded",
    )

    assert content.content_schema == "contextunity.model-io-content/v1"
    assert content.request_parts[0].content == "be concise"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("channel", "reasoning"),
        ("content_kind", "binary"),
        ("mime_type", "application/octet-stream"),
    ],
)
def test_model_io_part_rejects_open_or_hidden_content_kinds(field: str, value: str) -> None:
    payload = _part(sequence=0, channel="user", content="hello").model_dump()
    payload[field] = value

    with pytest.raises(ValidationError):
        ModelIOContentPart.model_validate(payload)


def test_model_io_part_hides_raw_content_from_validation_error() -> None:
    sentinel = "secret-value-that-must-not-enter-errors"
    payload = _part(sequence=0, channel="user", content=sentinel).model_dump()
    payload["byte_count"] = 1

    with pytest.raises(ValidationError) as exc:
        ModelIOContentPart.model_validate(payload)

    assert sentinel not in str(exc.value)


def test_model_io_content_rejects_non_contiguous_order() -> None:
    with pytest.raises(ValidationError, match="contiguous"):
        ModelIOContent(
            request_parts=[_part(sequence=1, channel="user", content="hello")],
            response_parts=[],
            provider_status="failed",
        )


def test_artifact_ref_carries_no_protected_content_or_location() -> None:
    ref = ExecutionTraceArtifactRef(
        artifact_id=uuid4(),
        identity=_identity(),
        capture_state="captured",
        storage_state="hot",
        content_digest="hmac-sha256:" + "b" * 64,
        request_bytes=12,
        response_bytes=4,
    )
    payload = ref.model_dump(mode="json")

    assert "content" not in payload
    assert "ciphertext" not in payload
    assert "object_uri" not in payload

    with pytest.raises(ValidationError):
        ExecutionTraceArtifactRef.model_validate({**payload, "object_uri": "s3://forbidden"})
