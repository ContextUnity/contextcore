"""Integration tests for gRPC infrastructure (channels, options, and payloads)."""

import asyncio

import grpc
import grpc.aio
import pytest
import pytest_asyncio
from contextunity.core import SharedConfig
from contextunity.core.grpc_utils import create_channel, create_channel_sync


class _DynamicEchoHandler(grpc.GenericRpcHandler):
    """A generic gRPC handler that just echoes bytes back."""

    def service(self, handler_call_details):
        if handler_call_details.method == "/test.Echo/EchoBytes":

            async def echo(request, context):
                return request

            return grpc.unary_unary_rpc_method_handler(
                echo,
                request_deserializer=lambda x: x,
                response_serializer=lambda x: x,
            )
        return None


@pytest_asyncio.fixture
async def echo_server(unused_tcp_port):
    """Start an async inproc gRPC server for testing."""
    server = grpc.aio.server(
        options=[
            ("grpc.max_receive_message_length", 50 * 1024 * 1024),
            ("grpc.max_send_message_length", 50 * 1024 * 1024),
        ]
    )
    server.add_generic_rpc_handlers((_DynamicEchoHandler(),))

    endpoint = f"127.0.0.1:{unused_tcp_port}"
    server.add_insecure_port(endpoint)

    await server.start()
    yield endpoint
    await server.stop(grace=0)


async def test_async_channel_max_message_length(echo_server, monkeypatch):
    """Test that create_channel applies max message length options correctly."""
    # Force tls_enabled to false to ensure insecure channel is created
    monkeypatch.setattr("contextunity.core.grpc_utils.tls_enabled", lambda *args, **kwargs: False)

    channel = create_channel(echo_server)

    # Send a 5MB payload, which exceeds the default 4MB limit.
    # If the _GRPC_OPTIONS are mutated or removed, this will raise RESOURCE_EXHAUSTED.
    large_payload = b"x" * (5 * 1024 * 1024)

    call = channel.unary_unary(
        "/test.Echo/EchoBytes",
        request_serializer=lambda x: x,
        response_deserializer=lambda x: x,
    )

    response = await call(large_payload)
    assert response == large_payload
    await channel.close()


@pytest.mark.asyncio
async def test_sync_channel_max_message_length(echo_server, monkeypatch):
    """Test that create_channel_sync applies max message length options correctly."""
    monkeypatch.setattr("contextunity.core.grpc_utils.tls_enabled", lambda *args, **kwargs: False)

    channel = create_channel_sync(echo_server)

    large_payload = b"y" * (5 * 1024 * 1024)

    call = channel.unary_unary(
        "/test.Echo/EchoBytes",
        request_serializer=lambda x: x,
        response_deserializer=lambda x: x,
    )

    response = await asyncio.to_thread(call, large_payload)
    assert response == large_payload
    channel.close()


async def test_sync_channel_uses_explicit_tls_config(monkeypatch):
    """Explicit service config drives client TLS without touching global core config."""
    config = SharedConfig(
        tls_enabled=True,
        tls_ca_cert="/service/ca.crt",
        tls_client_cert="/service/client.crt",
        tls_client_key="/service/client.key",
    )
    created = {}

    def fail_global_config():
        raise AssertionError("global core config must not be read when explicit config is passed")

    def fake_ssl_channel_credentials(**kwargs):
        created["credentials_kwargs"] = kwargs
        return "credentials"

    def fake_secure_channel(target, credentials, options):
        created["target"] = target
        created["credentials"] = credentials
        created["options"] = options
        return "channel"

    monkeypatch.setattr("contextunity.core.config.get_core_config", fail_global_config)
    monkeypatch.setattr("contextunity.core.grpc_utils._read_file", lambda path: path.encode())
    monkeypatch.setattr("grpc.ssl_channel_credentials", fake_ssl_channel_credentials)
    monkeypatch.setattr("grpc.secure_channel", fake_secure_channel)

    channel = create_channel_sync("shield.internal:50054", config=config)

    assert channel == "channel"
    assert created["target"] == "shield.internal:50054"
    assert created["credentials"] == "credentials"
    assert created["credentials_kwargs"] == {
        "root_certificates": b"/service/ca.crt",
        "private_key": b"/service/client.key",
        "certificate_chain": b"/service/client.crt",
    }


pytestmark = [pytest.mark.asyncio, pytest.mark.unit]
