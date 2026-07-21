"""CU-455 closed service-health contracts and C0 resolution."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import pytest
from contextunity.core.config import SharedConfig
from contextunity.core.service_health import (
    ServiceDegradationCode,
    ServiceDegradationConfig,
    ServiceDegradationSignal,
    ServiceDegradationSnapshot,
    ServiceDegradationTransition,
    ServiceHealthTarget,
    ServiceRuntimeIdentity,
    resolve_service_degradation_config,
)
from pydantic import ValidationError

_RUNTIME_ID = UUID("00000000-0000-4000-8000-000000000455")
_NOW = datetime(2026, 7, 20, 15, 30, tzinfo=UTC)


def _identity() -> ServiceRuntimeIdentity:
    return ServiceRuntimeIdentity(
        environment="local",
        service="worker",
        instance="default",
        runtime_id=_RUNTIME_ID,
        target=ServiceHealthTarget(
            transport="grpc",
            health_service="contextunity.worker.WorkerService",
        ),
    )


def test_closed_runtime_identity_and_health_targets_reject_scope_widening() -> None:
    identity = _identity()
    assert identity.target.health_service == "contextunity.worker.WorkerService"

    with pytest.raises(ValidationError):
        ServiceRuntimeIdentity.model_validate(
            {
                **identity.model_dump(mode="json"),
                "environment": "Prod/../../tenant",
            }
        )
    with pytest.raises(ValidationError):
        ServiceHealthTarget(transport="grpc", health_service="contextunity.evil.Service")
    with pytest.raises(ValidationError):
        ServiceHealthTarget(transport="http", health_path="/admin/health")
    with pytest.raises(ValidationError):
        ServiceHealthTarget.model_validate({"transport": "http", "health_path": "/healthz", "tenant_id": "secret"})


def test_snapshot_is_active_only_sorted_bounded_and_extra_forbid() -> None:
    signal = ServiceDegradationSignal(
        component="brain_embedding",
        code=ServiceDegradationCode.BRAIN_EMBEDDING_VECTOR_BACKEND_UNAVAILABLE,
        severity="critical",
        first_observed_at=_NOW,
        last_observed_at=_NOW,
        count=1,
    )
    snapshot = ServiceDegradationSnapshot(
        identity=_identity(),
        revision=1,
        updated_at=_NOW,
        signals=(signal,),
    )
    assert snapshot.signals == (signal,)
    payload = snapshot.model_dump(mode="json")
    assert "state" not in payload["signals"][0]
    assert "tenant_id" not in str(payload)

    with pytest.raises(ValidationError):
        ServiceDegradationSignal.model_validate({**signal.model_dump(), "error": "raw"})
    with pytest.raises(ValidationError, match="timezone-aware"):
        ServiceDegradationSignal.model_validate(
            {
                **signal.model_dump(),
                "first_observed_at": _NOW.replace(tzinfo=None),
            }
        )
    with pytest.raises(ValidationError):
        ServiceDegradationTransition(
            component="brain_embedding",
            code=ServiceDegradationCode.ROUTER_FAULT_SPOOL_BACKLOG,
            severity="warning",
            state="active",
        )


def test_service_degradation_config_is_default_off_and_resolves_environment() -> None:
    default = SharedConfig()
    assert default.service_degradation == ServiceDegradationConfig()
    assert resolve_service_degradation_config(default) is None

    local = SharedConfig(
        local_mode=True,
        service_degradation=ServiceDegradationConfig(enabled=True),
    )
    local = SharedConfig.model_validate(local.model_dump(mode="json"))
    resolved = resolve_service_degradation_config(local)
    assert resolved is not None
    assert resolved.environment == "local"
    assert resolved.redis_url == local.redis.url

    non_local = SharedConfig(
        local_mode=False,
        service_degradation=ServiceDegradationConfig(enabled=True),
    )
    with pytest.raises(ValueError, match="environment"):
        resolve_service_degradation_config(non_local)


def test_service_degradation_config_rejects_conflicting_bounds_and_disabled_redis() -> None:
    with pytest.raises(ValidationError):
        ServiceDegradationConfig(
            enabled=True,
            environment="prod",
            snapshot_ttl_seconds=10,
            refresh_interval_seconds=5,
        )

    config = SharedConfig(
        local_mode=False,
        redis={"enabled": False, "url": "redis://localhost:6379/0"},
        service_degradation={"enabled": True, "environment": "prod"},
    )
    assert resolve_service_degradation_config(config) is None


pytestmark = pytest.mark.unit
