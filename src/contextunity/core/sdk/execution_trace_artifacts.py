"""Closed contracts for protected per-attempt Execution Trace artifacts."""

from __future__ import annotations

from base64 import b64decode
from binascii import Error as BinasciiError
from typing import ClassVar, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

ArtifactKind = Literal["model_io"]
ArtifactCaptureState = Literal["captured", "disabled", "redacted", "rejected", "unavailable"]
ArtifactStorageState = Literal["hot", "archiving", "cold", "restoring", "purging", "purged"]
ModelIOChannel = Literal["system", "user", "assistant", "tool"]
ModelIOContentKind = Literal["text", "json", "tool_schema", "tool_arguments", "tool_result"]
ModelIOMimeType = Literal["text/plain", "application/json"]
ModelIOProviderStatus = Literal["succeeded", "failed", "cancelled"]

_KEYED_DIGEST_PATTERN = r"^hmac-sha256:[0-9a-f]{64}$"
_SAFE_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$"


class _StrictArtifactModel(BaseModel):
    """Forbid extension bags and hide protected inputs from validation errors."""

    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
    )


class ExecutionTraceArtifactIdentity(_StrictArtifactModel):
    """Immutable identity for one artifact under one provider attempt."""

    tenant_id: str = Field(min_length=1, max_length=128, pattern=_SAFE_ID_PATTERN)
    project_id: str = Field(min_length=1, max_length=128, pattern=_SAFE_ID_PATTERN)
    trace_id: UUID
    graph_run_id: UUID
    invocation_id: UUID
    provider_attempt_id: UUID
    artifact_kind: ArtifactKind


class ModelIOContentPart(_StrictArtifactModel):
    """One ordered admitted textual or structured model-I/O content part."""

    sequence: int = Field(ge=0, le=63)
    channel: ModelIOChannel
    content_kind: ModelIOContentKind
    mime_type: ModelIOMimeType
    content: str = Field(max_length=65_536, repr=False)
    byte_count: int = Field(ge=0, le=65_536)

    @model_validator(mode="after")
    def validate_part(self) -> "ModelIOContentPart":
        """Bind safe size and MIME semantics to the exact admitted text."""
        if len(self.content.encode("utf-8")) != self.byte_count:
            raise ValueError("model I/O part byte_count does not match content")
        structured = self.content_kind in {
            "json",
            "tool_schema",
            "tool_arguments",
            "tool_result",
        }
        if structured != (self.mime_type == "application/json"):
            raise ValueError("model I/O content kind does not match MIME type")
        return self


class ModelIOContent(_StrictArtifactModel):
    """Exact bounded provider-bound request and visible provider response."""

    content_schema: Literal["contextunity.model-io-content/v1"] = "contextunity.model-io-content/v1"
    request_parts: list[ModelIOContentPart] = Field(min_length=1, max_length=64)
    response_parts: list[ModelIOContentPart] = Field(default_factory=list, max_length=64)
    provider_status: ModelIOProviderStatus

    @model_validator(mode="after")
    def validate_order_and_status(self) -> "ModelIOContent":
        """Require canonical independent request/response ordering."""
        for label, parts in (
            ("request", self.request_parts),
            ("response", self.response_parts),
        ):
            if [part.sequence for part in parts] != list(range(len(parts))):
                raise ValueError(f"model I/O {label} part order must be contiguous")
        if self.provider_status == "succeeded" and not self.response_parts:
            raise ValueError("successful model I/O requires a visible response part")
        return self


class ExecutionTraceArtifactLifecycleProfile(_StrictArtifactModel):
    """C0-owned hot/archive/optional-purge policy for protected artifacts."""

    profile_id: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_-]*$")
    hot_for_days: int = Field(ge=0, le=36_500)
    archive_after_days: int | None = Field(default=None, ge=0, le=36_500)
    purge_after_days: int | None = Field(default=None, ge=0, le=36_500)
    offload_profile_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=64,
        pattern=r"^[a-z][a-z0-9_-]*$",
    )
    legal_hold: bool = False

    @model_validator(mode="after")
    def validate_lifecycle(self) -> "ExecutionTraceArtifactLifecycleProfile":
        if (self.archive_after_days is None) != (self.offload_profile_id is None):
            raise ValueError("artifact archive policy requires one offload profile")
        if self.archive_after_days is not None and self.archive_after_days < self.hot_for_days:
            raise ValueError("artifact archive cannot precede the hot retention window")
        floor = self.archive_after_days or self.hot_for_days
        if self.purge_after_days is not None and self.purge_after_days < floor:
            raise ValueError("artifact purge cannot precede hot/archive retention")
        if self.legal_hold and self.purge_after_days is not None:
            raise ValueError("legal-hold artifact profiles cannot schedule purge")
        return self


class ProtectedModelIOSettings(_StrictArtifactModel):
    """C0 protector availability, payload ceilings and lifecycle allowlist."""

    protector: Literal["disabled", "shield_rpc"] = "disabled"
    max_part_bytes: int = Field(default=65_536, ge=1, le=1_048_576)
    max_total_bytes: int = Field(default=262_144, ge=1, le=4_194_304)
    max_parts: int = Field(default=64, ge=1, le=128)
    lifecycle_profiles: tuple[ExecutionTraceArtifactLifecycleProfile, ...] = ()

    @model_validator(mode="after")
    def validate_protected_capture(self) -> "ProtectedModelIOSettings":
        ids = tuple(profile.profile_id for profile in self.lifecycle_profiles)
        if len(ids) != len(set(ids)):
            raise ValueError("artifact lifecycle profile ids must be unique")
        if self.protector == "shield_rpc" and not self.lifecycle_profiles:
            raise ValueError("shield_rpc protector requires lifecycle profiles")
        if self.max_part_bytes > self.max_total_bytes:
            raise ValueError("artifact part ceiling cannot exceed total ceiling")
        return self

    def lifecycle_profile(self, profile_id: str) -> ExecutionTraceArtifactLifecycleProfile:
        """Resolve one allowlisted lifecycle profile without fallback."""
        for profile in self.lifecycle_profiles:
            if profile.profile_id == profile_id:
                return profile
        raise ValueError("unknown artifact lifecycle profile")


class ProtectExecutionTraceArtifactRequest(_StrictArtifactModel):
    """Purpose-bound plaintext sent only to Shield's artifact protector."""

    purpose: Literal["execution_trace_artifact/model_io"]
    identity: ExecutionTraceArtifactIdentity
    artifact_id: UUID
    plaintext_b64: str = Field(min_length=4, max_length=5_592_408, repr=False)

    @model_validator(mode="after")
    def validate_plaintext(self) -> "ProtectExecutionTraceArtifactRequest":
        try:
            plaintext = b64decode(self.plaintext_b64, validate=True)
        except (BinasciiError, ValueError) as exc:
            raise ValueError("artifact plaintext is not canonical base64") from exc
        if not plaintext or len(plaintext) > 4 * 1024 * 1024:
            raise ValueError("artifact plaintext exceeds the protection budget")
        return self


class ProtectedExecutionTraceArtifactEnvelope(_StrictArtifactModel):
    """Opaque Shield ciphertext plus deterministic keyed content evidence."""

    purpose: Literal["execution_trace_artifact/model_io"]
    identity: ExecutionTraceArtifactIdentity
    artifact_id: UUID
    ciphertext_b64: str = Field(min_length=4, max_length=8_388_608, repr=False)
    content_digest: str = Field(pattern=_KEYED_DIGEST_PATTERN)
    algorithm: Literal["fernet-v1"]
    key_epoch: str = Field(min_length=1, max_length=128, pattern=_SAFE_ID_PATTERN)


class UnprotectExecutionTraceArtifactRequest(_StrictArtifactModel):
    """Identity-bound request to recover one already-authorized artifact."""

    envelope: ProtectedExecutionTraceArtifactEnvelope


class UnprotectedExecutionTraceArtifact(_StrictArtifactModel):
    """Ephemeral Shield read result returned only after identity verification."""

    purpose: Literal["execution_trace_artifact/model_io"]
    identity: ExecutionTraceArtifactIdentity
    artifact_id: UUID
    plaintext_b64: str = Field(min_length=4, max_length=5_592_408, repr=False)
    content_digest: str = Field(pattern=_KEYED_DIGEST_PATTERN)


class ExecutionTraceArtifactArchiveReceipt(_StrictArtifactModel):
    """Opaque Worker storage receipt; never contains an object URI or credential."""

    artifact_id: UUID
    identity: ExecutionTraceArtifactIdentity
    content_digest: str = Field(pattern=_KEYED_DIGEST_PATTERN)
    offload_profile_id: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[a-z][a-z0-9_-]*$",
    )
    archive_generation: UUID
    source_revision: int = Field(ge=2)


class ExecutionTraceArtifactReservationReceipt(_StrictArtifactModel):
    """Brain receipt proving protected request persistence before provider egress."""

    artifact_id: UUID
    content_digest: str = Field(pattern=_KEYED_DIGEST_PATTERN)
    revision: int = Field(ge=1)
    outcome: Literal["created", "duplicate"]


class ExecutionTraceArtifactRef(_StrictArtifactModel):
    """Bounded raw-content-free reference allowed in immutable Trace JSON."""

    artifact_id: UUID
    identity: ExecutionTraceArtifactIdentity
    capture_state: ArtifactCaptureState
    storage_state: ArtifactStorageState
    content_digest: str | None = Field(default=None, pattern=_KEYED_DIGEST_PATTERN)
    request_bytes: int = Field(ge=0, le=4 * 1024 * 1024)
    response_bytes: int = Field(ge=0, le=4 * 1024 * 1024)

    @model_validator(mode="after")
    def validate_states(self) -> "ExecutionTraceArtifactRef":
        """Prevent payload-bearing state claims for uncaptured evidence."""
        if self.capture_state == "captured" and self.content_digest is None:
            raise ValueError("captured artifact refs require a keyed content digest")
        if self.capture_state != "captured" and self.storage_state != "purged":
            raise ValueError("uncaptured artifact refs must resolve to a purged tombstone")
        if self.capture_state != "captured" and self.content_digest is not None:
            raise ValueError("uncaptured artifact refs cannot claim a content digest")
        return self


class ExecutionTraceArtifactFinalizationReceipt(_StrictArtifactModel):
    """Brain receipt plus the bounded ref admitted into terminal Trace v4."""

    artifact_id: UUID
    content_digest: str = Field(pattern=_KEYED_DIGEST_PATTERN)
    revision: int = Field(ge=2)
    outcome: Literal["finalized", "duplicate"]
    artifact_ref: ExecutionTraceArtifactRef


__all__ = [
    "ArtifactCaptureState",
    "ArtifactKind",
    "ArtifactStorageState",
    "ExecutionTraceArtifactArchiveReceipt",
    "ExecutionTraceArtifactFinalizationReceipt",
    "ExecutionTraceArtifactIdentity",
    "ExecutionTraceArtifactLifecycleProfile",
    "ExecutionTraceArtifactRef",
    "ExecutionTraceArtifactReservationReceipt",
    "ProtectExecutionTraceArtifactRequest",
    "ProtectedExecutionTraceArtifactEnvelope",
    "ProtectedModelIOSettings",
    "UnprotectExecutionTraceArtifactRequest",
    "UnprotectedExecutionTraceArtifact",
    "ModelIOChannel",
    "ModelIOContent",
    "ModelIOContentKind",
    "ModelIOContentPart",
    "ModelIOMimeType",
    "ModelIOProviderStatus",
]
