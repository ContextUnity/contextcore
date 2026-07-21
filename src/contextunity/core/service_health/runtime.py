"""Process-local ownership for one exact service runtime handle."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

from .grpc import StandardGrpcHealthLifecycle
from .models import ServiceDegradationTransition, ServiceName, ServiceRuntimeIdentity


class ServiceDegradationPublisherProtocol(Protocol):
    def submit(self, transition: ServiceDegradationTransition) -> bool: ...

    def submit_reconciliation(
        self,
        transitions: tuple[ServiceDegradationTransition, ...],
    ) -> bool: ...

    async def report(self, transition: ServiceDegradationTransition) -> bool: ...

    async def report_many(
        self,
        transitions: tuple[ServiceDegradationTransition, ...],
    ) -> bool: ...

    async def reconcile(
        self,
        transitions: tuple[ServiceDegradationTransition, ...],
    ) -> bool: ...

    async def close(self) -> None: ...


@dataclass(slots=True)
class ServiceRuntimeHandle:
    """Lifecycle resources bound to one exact process boot."""

    identity: ServiceRuntimeIdentity
    health: StandardGrpcHealthLifecycle | None
    heartbeat_task: asyncio.Task[None] | None
    publisher: ServiceDegradationPublisherProtocol | None


_RUNTIME_HANDLES: dict[ServiceName, ServiceRuntimeHandle] = {}


def install_service_runtime_handle(handle: ServiceRuntimeHandle) -> None:
    service = handle.identity.service
    if service in _RUNTIME_HANDLES:
        raise RuntimeError(f"service runtime handle already installed for {service}")
    _RUNTIME_HANDLES[service] = handle


def get_service_runtime_handle(service: ServiceName) -> ServiceRuntimeHandle | None:
    return _RUNTIME_HANDLES.get(service)


def try_get_service_degradation_publisher(
    service: ServiceName,
) -> ServiceDegradationPublisherProtocol | None:
    handle = get_service_runtime_handle(service)
    return handle.publisher if handle is not None else None


def remove_service_runtime_handle(service: ServiceName, *, runtime_id: UUID) -> bool:
    handle = _RUNTIME_HANDLES.get(service)
    if handle is None or handle.identity.runtime_id != runtime_id:
        return False
    del _RUNTIME_HANDLES[service]
    return True


def reset_service_runtime_registry() -> None:
    """Testing-only state reset; production teardown uses exact removal."""
    _RUNTIME_HANDLES.clear()


__all__ = [
    "ServiceDegradationPublisherProtocol",
    "ServiceRuntimeHandle",
    "get_service_runtime_handle",
    "install_service_runtime_handle",
    "remove_service_runtime_handle",
    "reset_service_runtime_registry",
    "try_get_service_degradation_publisher",
]
