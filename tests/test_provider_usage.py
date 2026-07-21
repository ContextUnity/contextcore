from __future__ import annotations

import pytest
from contextunity.core.sdk.provider_usage import (
    MAX_PROVIDER_USAGE_VALUE,
    OPENAI_USAGE_SCHEMA_V1,
    ProviderUsageDetails,
    trusted_provider_usage_schema,
)
from pydantic import ValidationError


def test_provider_usage_details_validate_against_trusted_schema() -> None:
    details = ProviderUsageDetails(
        schema_id=OPENAI_USAGE_SCHEMA_V1.schema_id,
        values={
            "openai.cached_input_tokens": 7,
            "openai.reasoning_output_tokens": 3,
        },
    )

    assert (
        details.validate_against(
            trusted_provider_usage_schema(details.schema_id),
            input_tokens=10,
            output_tokens=4,
        )
        is details
    )


@pytest.mark.parametrize(
    "payload",
    [
        {"schema_id": "unknown.usage/v1", "values": {"unknown.counter": 1}},
        {
            "schema_id": OPENAI_USAGE_SCHEMA_V1.schema_id,
            "values": {"openai.cached_input_tokens": True},
        },
        {
            "schema_id": OPENAI_USAGE_SCHEMA_V1.schema_id,
            "values": {"openai.cached_input_tokens": -1},
        },
        {
            "schema_id": OPENAI_USAGE_SCHEMA_V1.schema_id,
            "values": {"openai.cached_input_tokens": MAX_PROVIDER_USAGE_VALUE + 1},
        },
        {
            "schema_id": OPENAI_USAGE_SCHEMA_V1.schema_id,
            "values": {"openai.raw.payload": {"secret": "forbidden"}},
        },
        {
            "schema_id": OPENAI_USAGE_SCHEMA_V1.schema_id,
            "values": {f"openai.counter_{index}": index for index in range(33)},
        },
    ],
)
def test_provider_usage_details_reject_malformed_payloads(payload: object) -> None:
    with pytest.raises((ValidationError, ValueError)):
        details = ProviderUsageDetails.model_validate(payload)
        schema = trusted_provider_usage_schema(details.schema_id)
        details.validate_against(schema, input_tokens=10, output_tokens=10)


def test_provider_usage_details_reject_undeclared_and_contradictory_counters() -> None:
    undeclared = ProviderUsageDetails(
        schema_id=OPENAI_USAGE_SCHEMA_V1.schema_id,
        values={"openai.future_counter": 1},
    )
    with pytest.raises(ValueError, match="not declared"):
        undeclared.validate_against(
            OPENAI_USAGE_SCHEMA_V1,
            input_tokens=10,
            output_tokens=10,
        )

    contradictory = ProviderUsageDetails(
        schema_id=OPENAI_USAGE_SCHEMA_V1.schema_id,
        values={"openai.cached_input_tokens": 11},
    )
    with pytest.raises(ValueError, match="exceeds"):
        contradictory.validate_against(
            OPENAI_USAGE_SCHEMA_V1,
            input_tokens=10,
            output_tokens=10,
        )


def test_unknown_provider_usage_schema_fails_closed() -> None:
    with pytest.raises(ValueError, match="unknown provider usage schema"):
        trusted_provider_usage_schema("unknown.usage/v1")
