"""CU-455 official gRPC health lifecycle and exact public-method boundary."""

from __future__ import annotations

import asyncio
from uuid import UUID

import grpc
import pytest
from contextunity.core.grpc_utils import _global_signal_handler, graceful_shutdown
from contextunity.core.security.interceptors import _should_skip
from contextunity.core.service_health import ServiceHealthTarget, ServiceRuntimeIdentity
from contextunity.core.service_health.grpc import GRPC_HEALTH_SERVICE_NAMES, install_standard_health
from contextunity.core.service_health.runtime import ServiceRuntimeHandle
from grpc_health.v1 import health_pb2, health_pb2_grpc


def test_health_and_reflection_skip_only_exact_standard_service_paths() -> None:
    assert _should_skip("/grpc.health.v1.Health/Check")
    assert _should_skip("/grpc.health.v1.Health/Watch")
    assert _should_skip("/grpc.reflection.v1.ServerReflection/ServerReflectionInfo")
    assert not _should_skip("/grpc.health.v1.Health/CheckExtra")
    assert not _should_skip("/grpc.reflection.v1.ServerReflection/Other")
    assert not _should_skip("/evil.grpc.health.v1.Health/Check")
    assert not _should_skip("/contextunity.router.RouterService/grpc.health.v1")
    assert not _should_skip("grpc.health.v1.Health/Check")


@pytest.mark.asyncio
async def test_official_health_sets_aggregate_and_exact_named_service() -> None:
    server = grpc.aio.server()
    lifecycle = install_standard_health(server, service="worker")
    port = server.add_insecure_port("127.0.0.1:0")
    await server.start()
    channel = grpc.aio.insecure_channel(f"127.0.0.1:{port}")
    stub = health_pb2_grpc.HealthStub(channel)
    try:
        await lifecycle.set_serving()
        for service_name in ("", GRPC_HEALTH_SERVICE_NAMES["worker"]):
            response = await stub.Check(health_pb2.HealthCheckRequest(service=service_name))
            assert response.status == health_pb2.HealthCheckResponse.SERVING

        await lifecycle.set_not_serving()
        response = await stub.Check(health_pb2.HealthCheckRequest(service=GRPC_HEALTH_SERVICE_NAMES["worker"]))
        assert response.status == health_pb2.HealthCheckResponse.NOT_SERVING
    finally:
        await channel.close()
        await server.stop(grace=0)


@pytest.mark.asyncio
async def test_shutdown_marks_health_not_serving_before_service_specific_drain() -> None:
    server = grpc.aio.server()
    lifecycle = install_standard_health(server, service="worker")
    port = server.add_insecure_port("127.0.0.1:0")
    await server.start()
    await lifecycle.set_serving()
    channel = grpc.aio.insecure_channel(f"127.0.0.1:{port}")
    stub = health_pb2_grpc.HealthStub(channel)
    identity = ServiceRuntimeIdentity(
        environment="local",
        service="worker",
        instance="default",
        runtime_id=UUID("00000000-0000-4000-8000-000000000455"),
        target=ServiceHealthTarget(
            transport="grpc",
            health_service=GRPC_HEALTH_SERVICE_NAMES["worker"],
        ),
    )
    handle = ServiceRuntimeHandle(
        identity=identity,
        health=lifecycle,
        heartbeat_task=None,
        publisher=None,
    )

    async def _before_stop() -> None:
        response = await stub.Check(health_pb2.HealthCheckRequest(service=GRPC_HEALTH_SERVICE_NAMES["worker"]))
        assert response.status == health_pb2.HealthCheckResponse.NOT_SERVING

    shutdown = asyncio.create_task(
        graceful_shutdown(
            server,
            "Worker",
            runtime_handle=handle,
            before_stop=_before_stop,
            grace=0,
        )
    )
    await asyncio.sleep(0)
    _global_signal_handler()
    try:
        await shutdown
    finally:
        await channel.close()


pytestmark = pytest.mark.unit
