"""Closed provider-owned token usage detail contracts.

Only bounded counters admitted by a versioned provider schema may cross the
Router accounting, Brain Trace, or external telemetry boundaries. Raw provider
usage payloads are never retained.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field, model_validator

MAX_PROVIDER_USAGE_DETAILS = 32
MAX_PROVIDER_USAGE_KEY_LENGTH = 128
MAX_PROVIDER_USAGE_VALUE = 2**64 - 1
_PROVIDER_USAGE_KEY = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+$")
_SCHEMA_ID = re.compile(r"^[a-z][a-z0-9_.-]*/v[1-9][0-9]*$")


class ProviderUsageUnit(StrEnum):
    """Closed units accepted by usage-detail schemas."""

    TOKENS = "tokens"
    REQUESTS = "requests"


class ProviderUsageRelation(StrEnum):
    """How a detail counter relates to stable token totals."""

    INPUT_SUBSET = "input_subset"
    OUTPUT_SUBSET = "output_subset"
    INDEPENDENT = "independent"


class ProviderUsageField(BaseModel):
    """One provider-owned declared counter."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    key: str = Field(min_length=3, max_length=MAX_PROVIDER_USAGE_KEY_LENGTH)
    unit: ProviderUsageUnit
    relation: ProviderUsageRelation

    @model_validator(mode="after")
    def validate_key(self) -> "ProviderUsageField":
        if _PROVIDER_USAGE_KEY.fullmatch(self.key) is None:
            raise ValueError("provider usage key is not canonical")
        return self


class ProviderUsageDetailSchema(BaseModel):
    """Versioned provider-owned allowlist for bounded usage counters."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    schema_id: str = Field(min_length=4, max_length=128)
    provider: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_]*$")
    fields: tuple[ProviderUsageField, ...] = Field(
        min_length=1,
        max_length=MAX_PROVIDER_USAGE_DETAILS,
    )

    @model_validator(mode="after")
    def validate_schema(self) -> "ProviderUsageDetailSchema":
        if _SCHEMA_ID.fullmatch(self.schema_id) is None:
            raise ValueError("provider usage schema id is not canonical")
        if not self.schema_id.startswith(f"{self.provider}."):
            raise ValueError("provider usage schema id has the wrong provider namespace")
        keys = tuple(field.key for field in self.fields)
        if len(keys) != len(set(keys)):
            raise ValueError("provider usage schema fields must be unique")
        if any(not key.startswith(f"{self.provider}.") for key in keys):
            raise ValueError("provider usage field has the wrong provider namespace")
        return self

    def field_map(self) -> dict[str, ProviderUsageField]:
        """Return a new closed lookup map for validation."""
        return {field.key: field for field in self.fields}


ANTHROPIC_USAGE_SCHEMA_V1 = ProviderUsageDetailSchema(
    schema_id="anthropic.messages.usage/v1",
    provider="anthropic",
    fields=(
        ProviderUsageField(
            key="anthropic.cache_read_input_tokens",
            unit=ProviderUsageUnit.TOKENS,
            relation=ProviderUsageRelation.INPUT_SUBSET,
        ),
        ProviderUsageField(
            key="anthropic.cache_creation_input_tokens",
            unit=ProviderUsageUnit.TOKENS,
            relation=ProviderUsageRelation.INPUT_SUBSET,
        ),
        ProviderUsageField(
            key="anthropic.cache_creation.ephemeral_5m_input_tokens",
            unit=ProviderUsageUnit.TOKENS,
            relation=ProviderUsageRelation.INPUT_SUBSET,
        ),
        ProviderUsageField(
            key="anthropic.cache_creation.ephemeral_1h_input_tokens",
            unit=ProviderUsageUnit.TOKENS,
            relation=ProviderUsageRelation.INPUT_SUBSET,
        ),
    ),
)
GOOGLE_USAGE_SCHEMA_V1 = ProviderUsageDetailSchema(
    schema_id="google.generative.usage/v1",
    provider="google",
    fields=(
        ProviderUsageField(
            key="google.cache_read_input_tokens",
            unit=ProviderUsageUnit.TOKENS,
            relation=ProviderUsageRelation.INPUT_SUBSET,
        ),
        ProviderUsageField(
            key="google.reasoning_output_tokens",
            unit=ProviderUsageUnit.TOKENS,
            relation=ProviderUsageRelation.OUTPUT_SUBSET,
        ),
    ),
)
OPENAI_USAGE_SCHEMA_V1 = ProviderUsageDetailSchema(
    schema_id="openai.responses.usage/v1",
    provider="openai",
    fields=(
        ProviderUsageField(
            key="openai.cached_input_tokens", unit=ProviderUsageUnit.TOKENS, relation=ProviderUsageRelation.INPUT_SUBSET
        ),
        ProviderUsageField(
            key="openai.audio_input_tokens", unit=ProviderUsageUnit.TOKENS, relation=ProviderUsageRelation.INPUT_SUBSET
        ),
        ProviderUsageField(
            key="openai.reasoning_output_tokens",
            unit=ProviderUsageUnit.TOKENS,
            relation=ProviderUsageRelation.OUTPUT_SUBSET,
        ),
        ProviderUsageField(
            key="openai.audio_output_tokens",
            unit=ProviderUsageUnit.TOKENS,
            relation=ProviderUsageRelation.OUTPUT_SUBSET,
        ),
        ProviderUsageField(
            key="openai.accepted_prediction_output_tokens",
            unit=ProviderUsageUnit.TOKENS,
            relation=ProviderUsageRelation.OUTPUT_SUBSET,
        ),
        ProviderUsageField(
            key="openai.rejected_prediction_output_tokens",
            unit=ProviderUsageUnit.TOKENS,
            relation=ProviderUsageRelation.OUTPUT_SUBSET,
        ),
    ),
)
_TRUSTED_PROVIDER_USAGE_SCHEMAS = {
    schema.schema_id: schema for schema in (ANTHROPIC_USAGE_SCHEMA_V1, GOOGLE_USAGE_SCHEMA_V1, OPENAI_USAGE_SCHEMA_V1)
}


def trusted_provider_usage_schema(schema_id: str) -> ProviderUsageDetailSchema:
    """Resolve a versioned schema published by a reviewed provider adapter."""
    schema = _TRUSTED_PROVIDER_USAGE_SCHEMAS.get(schema_id)
    if schema is None:
        raise ValueError("unknown provider usage schema")
    return schema


class ProviderUsageDetails(BaseModel):
    """Admitted provider counters transported without raw response metadata."""

    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        hide_input_in_errors=True,
    )

    schema_id: str = Field(min_length=4, max_length=128)
    values: dict[str, int] = Field(default_factory=dict, max_length=MAX_PROVIDER_USAGE_DETAILS)

    @model_validator(mode="after")
    def validate_shape(self) -> "ProviderUsageDetails":
        if _SCHEMA_ID.fullmatch(self.schema_id) is None:
            raise ValueError("provider usage schema id is not canonical")
        for key, value in self.values.items():
            if len(key) > MAX_PROVIDER_USAGE_KEY_LENGTH or _PROVIDER_USAGE_KEY.fullmatch(key) is None:
                raise ValueError("provider usage key is not canonical")
            if value < 0 or value > MAX_PROVIDER_USAGE_VALUE:
                raise ValueError("provider usage value is out of range")
        return self

    def validate_against(
        self,
        schema: ProviderUsageDetailSchema,
        *,
        input_tokens: int,
        output_tokens: int,
    ) -> "ProviderUsageDetails":
        """Fail closed against one adapter-owned schema and stable totals."""
        if self.schema_id != schema.schema_id:
            raise ValueError("provider usage schema does not match details")
        fields = schema.field_map()
        for key, value in self.values.items():
            field = fields.get(key)
            if field is None:
                raise ValueError("provider usage key is not declared")
            if field.unit is ProviderUsageUnit.TOKENS:
                if field.relation is ProviderUsageRelation.INPUT_SUBSET and value > input_tokens:
                    raise ValueError("provider input subset exceeds stable input total")
                if field.relation is ProviderUsageRelation.OUTPUT_SUBSET and value > output_tokens:
                    raise ValueError("provider output subset exceeds stable output total")
        return self


__all__ = [
    "MAX_PROVIDER_USAGE_DETAILS",
    "MAX_PROVIDER_USAGE_KEY_LENGTH",
    "MAX_PROVIDER_USAGE_VALUE",
    "ANTHROPIC_USAGE_SCHEMA_V1",
    "GOOGLE_USAGE_SCHEMA_V1",
    "OPENAI_USAGE_SCHEMA_V1",
    "ProviderUsageDetails",
    "ProviderUsageDetailSchema",
    "ProviderUsageField",
    "ProviderUsageRelation",
    "ProviderUsageUnit",
    "trusted_provider_usage_schema",
]
