"""Integration tests for gRPC infrastructure (channels, options, and payloads)."""

import asyncio
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address
from pathlib import Path

import grpc
import grpc.aio
import pytest
import pytest_asyncio
from contextunity.core import SharedConfig
from contextunity.core.exceptions import ConfigurationError
from contextunity.core.grpc_utils import (
    _validate_mesh_tls_config,
    create_channel,
    create_channel_sync,
    create_server_credentials,
)
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


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


def _new_private_key() -> RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _cert_name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _write_private_key(path: Path, key: RSAPrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


def _write_certificate(path: Path, cert: x509.Certificate) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _certificate_builder(subject: x509.Name, issuer: x509.Name, public_key: rsa.RSAPublicKey):
    now = datetime.now(timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
    )


def _generate_mtls_files(tmp_path: Path) -> dict[str, str]:
    ca_key = _new_private_key()
    ca_name = _cert_name("ContextUnity Test CA")
    ca_cert = (
        _certificate_builder(ca_name, ca_name, ca_key.public_key())
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    server_key = _new_private_key()
    server_name = _cert_name("localhost")
    server_cert = (
        _certificate_builder(server_name, ca_name, server_key.public_key())
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(IPv4Address("127.0.0.1"))]),
            critical=False,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    client_key = _new_private_key()
    client_name = _cert_name("contextunity-test-client")
    client_cert = (
        _certificate_builder(client_name, ca_name, client_key.public_key())
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    paths = {
        "ca": tmp_path / "ca.crt",
        "server_cert": tmp_path / "server.crt",
        "server_key": tmp_path / "server.key",
        "client_cert": tmp_path / "client.crt",
        "client_key": tmp_path / "client.key",
    }
    _write_certificate(paths["ca"], ca_cert)
    _write_certificate(paths["server_cert"], server_cert)
    _write_private_key(paths["server_key"], server_key)
    _write_certificate(paths["client_cert"], client_cert)
    _write_private_key(paths["client_key"], client_key)
    return {name: str(path) for name, path in paths.items()}


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


@pytest.mark.asyncio
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


@pytest.mark.asyncio
async def test_async_channel_mtls_round_trip(tmp_path, unused_tcp_port):
    paths = _generate_mtls_files(tmp_path)
    config = SharedConfig(
        tls_enabled=True,
        tls_ca_cert=paths["ca"],
        tls_server_cert=paths["server_cert"],
        tls_server_key=paths["server_key"],
        tls_client_cert=paths["client_cert"],
        tls_client_key=paths["client_key"],
        tls_require_client_auth=True,
    )

    server = grpc.aio.server()
    server.add_generic_rpc_handlers((_DynamicEchoHandler(),))
    credentials = create_server_credentials(config)
    assert credentials is not None
    endpoint = f"127.0.0.1:{unused_tcp_port}"
    _ = server.add_secure_port(endpoint, credentials)
    await server.start()

    channel = create_channel(endpoint, config=config)
    try:
        call = channel.unary_unary(
            "/test.Echo/EchoBytes",
            request_serializer=lambda x: x,
            response_deserializer=lambda x: x,
        )
        response = await call(b"mtls-ok", timeout=3)
        assert response == b"mtls-ok"
    finally:
        await channel.close()
        await server.stop(grace=0)


@pytest.mark.asyncio
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


def test_sync_channel_requires_client_credentials_when_mtls_required(monkeypatch):
    config = SharedConfig(
        tls_enabled=True,
        tls_ca_cert="/service/ca.crt",
        tls_require_client_auth=True,
    )

    monkeypatch.setattr("contextunity.core.grpc_utils._read_file", lambda path: path.encode())

    with pytest.raises(ConfigurationError, match="GRPC_TLS_CLIENT_CERT"):
        create_channel_sync("shield.internal:50054", config=config)


def test_async_channel_rejects_partial_client_credentials(monkeypatch):
    config = SharedConfig(
        tls_enabled=True,
        tls_ca_cert="/service/ca.crt",
        tls_client_cert="/service/client.crt",
        tls_require_client_auth=False,
    )

    monkeypatch.setattr("contextunity.core.grpc_utils._read_file", lambda path: path.encode())

    with pytest.raises(ConfigurationError, match="GRPC_TLS_CLIENT_KEY"):
        create_channel("shield.internal:50054", config=config)


def test_sync_channel_allows_server_only_tls_when_client_auth_disabled(monkeypatch):
    config = SharedConfig(
        tls_enabled=True,
        tls_ca_cert="/service/ca.crt",
        tls_require_client_auth=False,
    )
    created = {}

    def fake_ssl_channel_credentials(**kwargs):
        created["credentials_kwargs"] = kwargs
        return "credentials"

    monkeypatch.setattr("contextunity.core.grpc_utils._read_file", lambda path: path.encode())
    monkeypatch.setattr("grpc.ssl_channel_credentials", fake_ssl_channel_credentials)
    monkeypatch.setattr("grpc.secure_channel", lambda target, credentials, options: "channel")

    assert create_channel_sync("shield.internal:50054", config=config) == "channel"
    assert created["credentials_kwargs"] == {"root_certificates": b"/service/ca.crt"}


def test_mesh_tls_startup_validator_requires_client_credentials():
    config = SharedConfig(
        tls_enabled=True,
        tls_ca_cert="/service/ca.crt",
        tls_server_cert="/service/server.crt",
        tls_server_key="/service/server.key",
        tls_require_client_auth=True,
    )

    with pytest.raises(ConfigurationError, match="GRPC_TLS_CLIENT_CERT"):
        _validate_mesh_tls_config(config, service_name="shield")


pytestmark = pytest.mark.unit
