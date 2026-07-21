"""Bounded service liveness and derived degradation contracts."""

from .config import (
    ResolvedServiceDegradationConfig,
    ServiceDegradationConfig,
    resolve_service_degradation_config,
)
from .models import (
    GRPC_HEALTH_SERVICE_NAMES,
    ServiceDegradationCode,
    ServiceDegradationHint,
    ServiceDegradationSignal,
    ServiceDegradationSnapshot,
    ServiceDegradationTransition,
    ServiceHealthTarget,
    ServiceHealthView,
    ServiceRuntimeIdentity,
)
from .publisher import ServiceDegradationPublisher
from .runtime import (
    ServiceRuntimeHandle,
    get_service_runtime_handle,
    try_get_service_degradation_publisher,
)

__all__ = [
    "GRPC_HEALTH_SERVICE_NAMES",
    "ResolvedServiceDegradationConfig",
    "ServiceDegradationCode",
    "ServiceDegradationConfig",
    "ServiceDegradationHint",
    "ServiceDegradationSignal",
    "ServiceDegradationSnapshot",
    "ServiceDegradationTransition",
    "ServiceDegradationPublisher",
    "ServiceHealthTarget",
    "ServiceHealthView",
    "ServiceRuntimeHandle",
    "ServiceRuntimeIdentity",
    "get_service_runtime_handle",
    "resolve_service_degradation_config",
    "try_get_service_degradation_publisher",
]
