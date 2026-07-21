"""Official gRPC health lifecycle for ContextUnity service servers."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

import grpc
from contextunity.core.narrowing import object_attr
from contextunity.core.service_health.models import GRPC_HEALTH_SERVICE_NAMES, ServiceName
from grpc_health.v1 import health, health_pb2, health_pb2_grpc


@runtime_checkable
class _HealthRegistrar(Protocol):
    def __call__(
        self,
        servicer: health.HealthServicer,
        server: grpc.aio.Server,
    ) -> None: ...


class StandardGrpcHealthLifecycle:
    """Own aggregate plus exact named-service health state."""

    def __init__(self, servicer: health.HealthServicer, *, service_name: str) -> None:
        self._servicer = servicer
        self._service_name = service_name

    @property
    def service_name(self) -> str:
        return self._service_name

    async def set_serving(self) -> None:
        self._servicer.set("", health_pb2.HealthCheckResponse.SERVING)
        self._servicer.set(
            self._service_name,
            health_pb2.HealthCheckResponse.SERVING,
        )

    async def set_not_serving(self) -> None:
        self._servicer.set("", health_pb2.HealthCheckResponse.NOT_SERVING)
        self._servicer.set(
            self._service_name,
            health_pb2.HealthCheckResponse.NOT_SERVING,
        )


def install_standard_health(
    server: grpc.aio.Server,
    *,
    service: ServiceName,
) -> StandardGrpcHealthLifecycle:
    """Register the official health service before a gRPC server starts."""
    service_name = GRPC_HEALTH_SERVICE_NAMES.get(service)
    if service_name is None:
        raise ValueError(f"service {service!r} does not own a gRPC health target")
    servicer = health.HealthServicer()
    registrar_candidate = object_attr(
        health_pb2_grpc,
        "add_HealthServicer_to_server",
    )
    if not isinstance(registrar_candidate, _HealthRegistrar):
        raise TypeError("official gRPC health registrar has an invalid contract")
    registrar_candidate(servicer, server)
    return StandardGrpcHealthLifecycle(servicer, service_name=service_name)


__all__ = [
    "GRPC_HEALTH_SERVICE_NAMES",
    "StandardGrpcHealthLifecycle",
    "install_standard_health",
]
