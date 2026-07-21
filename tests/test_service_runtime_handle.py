"""CU-455 process-local runtime handle ownership and cleanup."""

from __future__ import annotations

from uuid import UUID

import pytest
from contextunity.core.service_health import (
    ServiceDegradationTransition,
    ServiceHealthTarget,
    ServiceRuntimeIdentity,
)
from contextunity.core.service_health.runtime import (
    ServiceRuntimeHandle,
    get_service_runtime_handle,
    install_service_runtime_handle,
    remove_service_runtime_handle,
    reset_service_runtime_registry,
    try_get_service_degradation_publisher,
)

_RUNTIME = UUID("00000000-0000-4000-8000-000000000455")


class _Publisher:
    async def report(self, _transition: ServiceDegradationTransition) -> bool:
        return True

    async def report_many(
        self,
        _transitions: tuple[ServiceDegradationTransition, ...],
    ) -> bool:
        return True

    async def reconcile(
        self,
        _transitions: tuple[ServiceDegradationTransition, ...],
    ) -> bool:
        return True

    async def close(self) -> None:
        return None


def _handle() -> ServiceRuntimeHandle:
    return ServiceRuntimeHandle(
        identity=ServiceRuntimeIdentity(
            environment="local",
            service="worker",
            instance="default",
            runtime_id=_RUNTIME,
            target=ServiceHealthTarget(
                transport="grpc",
                health_service="contextunity.worker.WorkerService",
            ),
        ),
        health=None,
        heartbeat_task=None,
        publisher=_Publisher(),
    )


def test_runtime_handle_install_lookup_and_exact_cleanup() -> None:
    reset_service_runtime_registry()
    handle = _handle()
    install_service_runtime_handle(handle)
    assert get_service_runtime_handle("worker") is handle
    assert try_get_service_degradation_publisher("worker") is handle.publisher

    wrong_runtime = UUID("00000000-0000-4000-8000-000000000999")
    assert not remove_service_runtime_handle("worker", runtime_id=wrong_runtime)
    assert get_service_runtime_handle("worker") is handle
    assert remove_service_runtime_handle("worker", runtime_id=_RUNTIME)
    assert get_service_runtime_handle("worker") is None


def test_duplicate_process_service_handle_fails_closed() -> None:
    reset_service_runtime_registry()
    handle = _handle()
    install_service_runtime_handle(handle)
    with pytest.raises(RuntimeError, match="already installed"):
        install_service_runtime_handle(handle)
    reset_service_runtime_registry()


pytestmark = pytest.mark.unit
