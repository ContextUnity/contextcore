"""Closed CU-455 service runtime, degradation, and operator-view contracts."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import ClassVar, Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

ServiceName = Literal["brain", "forge", "router", "shield", "worker"]
ServiceTransport = Literal["grpc", "http"]
ServiceSeverity = Literal["warning", "critical"]
ServiceTransitionState = Literal["active", "recovered"]
ServiceLivenessState = Literal["serving", "not_serving", "unreachable", "unavailable"]
ServiceDegradationState = Literal["active", "none", "recovered", "unknown"]

IDENTIFIER_PATTERN = r"^[a-z][a-z0-9_-]{0,31}$"
SNAPSHOT_VERSION = "contextunity.service-degradation/v1"
HINT_VERSION = "contextunity.service-degradation-hint/v1"

GRPC_HEALTH_SERVICE_NAMES: dict[str, str] = {
    "brain": "contextunity.brain.BrainService",
    "router": "contextunity.router.RouterService",
    "shield": "contextunity.shield.ShieldService",
    "worker": "contextunity.worker.WorkerService",
}


class ServiceDegradationCode(StrEnum):
    """Only source conditions admitted to the v1 degradation plane."""

    BRAIN_EMBEDDING_VECTOR_BACKEND_UNAVAILABLE = "brain.embedding.vector_backend_unavailable"
    ROUTER_FAULT_SPOOL_BACKLOG = "router.fault_spool.backlog"
    ROUTER_FAULT_SPOOL_NEAR_LIMIT = "router.fault_spool.near_limit"
    ROUTER_FAULT_SPOOL_FULL = "router.fault_spool.full"
    ROUTER_FAULT_SPOOL_POISON_PRESENT = "router.fault_spool.poison_present"


_CODE_SHAPE: dict[ServiceDegradationCode, tuple[str, ServiceSeverity]] = {
    ServiceDegradationCode.BRAIN_EMBEDDING_VECTOR_BACKEND_UNAVAILABLE: (
        "brain_embedding",
        "critical",
    ),
    ServiceDegradationCode.ROUTER_FAULT_SPOOL_BACKLOG: ("fault_spool", "warning"),
    ServiceDegradationCode.ROUTER_FAULT_SPOOL_NEAR_LIMIT: ("fault_spool", "warning"),
    ServiceDegradationCode.ROUTER_FAULT_SPOOL_FULL: ("fault_spool", "critical"),
    ServiceDegradationCode.ROUTER_FAULT_SPOOL_POISON_PRESENT: (
        "fault_spool",
        "critical",
    ),
}


class _ClosedModel(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)


class ServiceHealthTarget(_ClosedModel):
    """Discriminated, non-user-widenable transport-health target."""

    transport: ServiceTransport
    health_service: str | None = None
    health_path: str | None = None

    @model_validator(mode="after")
    def validate_target(self) -> Self:
        if self.transport == "grpc":
            if self.health_service not in GRPC_HEALTH_SERVICE_NAMES.values():
                raise ValueError("unknown official gRPC health service")
            if self.health_path is not None:
                raise ValueError("gRPC health target cannot contain an HTTP path")
        else:
            if self.health_path != "/healthz":
                raise ValueError("Forge HTTP health target must be /healthz")
            if self.health_service is not None:
                raise ValueError("HTTP health target cannot contain a gRPC service")
        return self


class ServiceRuntimeIdentity(_ClosedModel):
    """Exact identity of one registered service process boot."""

    environment: str = Field(pattern=IDENTIFIER_PATTERN)
    service: ServiceName
    instance: str = Field(pattern=IDENTIFIER_PATTERN)
    runtime_id: UUID
    target: ServiceHealthTarget

    @model_validator(mode="after")
    def validate_service_target(self) -> Self:
        expected = GRPC_HEALTH_SERVICE_NAMES.get(self.service)
        if self.service == "forge":
            if self.target.transport != "http":
                raise ValueError("Forge must use the closed HTTP health target")
        elif self.target.transport != "grpc" or self.target.health_service != expected:
            raise ValueError("service and official gRPC health target do not match")
        return self


class ServiceDegradationTransition(_ClosedModel):
    """Source adapter input; recovered state is never persisted."""

    component: Literal["brain_embedding", "fault_spool"]
    code: ServiceDegradationCode
    severity: ServiceSeverity
    state: ServiceTransitionState

    @model_validator(mode="after")
    def validate_code_shape(self) -> Self:
        if (self.component, self.severity) != _CODE_SHAPE[self.code]:
            raise ValueError("component/severity do not match the closed degradation code")
        return self


class ServiceDegradationSignal(_ClosedModel):
    """One active, deduplicated signal stored in a full snapshot."""

    component: Literal["brain_embedding", "fault_spool"]
    code: ServiceDegradationCode
    severity: ServiceSeverity
    first_observed_at: datetime
    last_observed_at: datetime
    count: int = Field(ge=1, le=1_000_000)

    @model_validator(mode="after")
    def validate_signal(self) -> Self:
        if (self.component, self.severity) != _CODE_SHAPE[self.code]:
            raise ValueError("component/severity do not match the closed degradation code")
        if self.first_observed_at.utcoffset() is None or self.last_observed_at.utcoffset() is None:
            raise ValueError("signal timestamps must be timezone-aware")
        if self.last_observed_at < self.first_observed_at:
            raise ValueError("last_observed_at cannot precede first_observed_at")
        return self


class ServiceDegradationSnapshot(_ClosedModel):
    """Versioned full active-signal state for one exact runtime."""

    version: Literal["contextunity.service-degradation/v1"] = SNAPSHOT_VERSION
    identity: ServiceRuntimeIdentity
    revision: int = Field(ge=1)
    updated_at: datetime
    signals: tuple[ServiceDegradationSignal, ...] = Field(default=(), max_length=32)

    @model_validator(mode="after")
    def validate_sorted_unique_signals(self) -> Self:
        if self.updated_at.utcoffset() is None:
            raise ValueError("snapshot updated_at must be timezone-aware")
        codes = [signal.code.value for signal in self.signals]
        if codes != sorted(codes) or len(codes) != len(set(codes)):
            raise ValueError("snapshot signals must be unique and sorted by code")
        return self


class ServiceDegradationHint(_ClosedModel):
    """Ephemeral post-mutation refresh hint; never retained history."""

    version: Literal["contextunity.service-degradation-hint/v1"] = HINT_VERSION
    identity: ServiceRuntimeIdentity
    revision: int = Field(ge=1)


class ServiceHealthView(_ClosedModel):
    """Reader output that keeps transport liveness and degradation distinct."""

    identity: ServiceRuntimeIdentity | None = None
    liveness: ServiceLivenessState
    degradation: ServiceDegradationState
    signals: tuple[ServiceDegradationSignal, ...] = ()


__all__ = [
    "GRPC_HEALTH_SERVICE_NAMES",
    "HINT_VERSION",
    "IDENTIFIER_PATTERN",
    "SNAPSHOT_VERSION",
    "ServiceDegradationCode",
    "ServiceDegradationHint",
    "ServiceDegradationSignal",
    "ServiceDegradationSnapshot",
    "ServiceDegradationState",
    "ServiceDegradationTransition",
    "ServiceHealthTarget",
    "ServiceHealthView",
    "ServiceLivenessState",
    "ServiceName",
    "ServiceRuntimeIdentity",
]
