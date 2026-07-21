"""Base service client — shared infrastructure for all ContextUnity gRPC clients.
Eliminates the duplicated ``_ensure_protos`` / ``__init__`` / ``_get_metadata``
boilerplate across Shield, Zero, Worker, and Brain clients.
Each concrete client sets class-level attributes to declare which service
it connects to, and inherits all connection lifecycle management.
"""

from __future__ import annotations

import types
from typing import TYPE_CHECKING, ClassVar, Generic, Self, TypeVar

from contextunity.core.grpc_client_errors import wrap_client_error
from contextunity.core.logging import get_contextunit_logger

from ..contextunit import ContextUnit

if TYPE_CHECKING:
    import grpc.aio
    from contextunity.core import ContextToken
    from contextunity.core.sdk.contextunit import ContextUnitProtoModule
    from contextunity.core.sdk.types import GrpcMetadata, TokenProviderFactory, UnaryContextUnitRpc
    from contextunity.core.signing.protocols import AuthBackend
    from contextunity.core.types import ContextUnitPayload

logger = get_contextunit_logger(__name__)

#: The concrete (async) gRPC stub class a client drives, e.g.
#: ``BrainServiceAsyncStub``. Subclasses bind it via ``_stub_class``.
StubT = TypeVar("StubT")


class BaseServiceClient(Generic[StubT]):
    """Shared base for all ContextUnity gRPC service clients.

    Generic over ``StubT`` — the concrete async gRPC stub class the client
    drives (e.g. ``BrainServiceAsyncStub``). Subclasses set ``_stub_class`` so
    that ``self._stub`` and every RPC accessor are fully typed.

    Subclasses declare their service identity via class variables:

    - ``_service_name``: Service identifier (e.g. ``"shield"``).
    - ``_default_port``: Fallback port for discovery (e.g. ``"50054"``).
    - ``_config_url_attr``: Attribute on ``SharedConfig`` holding the URL
      (e.g. ``"shield_url"``).
    - ``_stub_class``: Generated async stub class (e.g. ``BrainServiceAsyncStub``).
    """

    _service_name: ClassVar[str]
    _default_port: ClassVar[str]
    _config_url_attr: ClassVar[str]
    _stub_class: ClassVar[type]

    host: str
    channel: grpc.aio.Channel
    _cu_pb2: ContextUnitProtoModule
    _stub: StubT

    def __init__(
        self,
        host: str | None = None,
        token: ContextToken | TokenProviderFactory | None = None,
        tenant_id: str | None = None,
        auth_backend: AuthBackend | None = None,
    ) -> None:
        """Initialize a new instance of BaseServiceClient.

        Args:
            host (str | None): The host address of the service.
            token (ContextToken | TokenProviderFactory | None): The security token for authentication.
            tenant_id (str | None): The tenant id parameter.
            auth_backend: Optional client-owned signing backend. Autonomous
                services should pass this explicitly in shared-process runtimes.
        """
        from contextunity.core import contextunit_pb2
        from contextunity.core.config import get_core_config
        from contextunity.core.discovery import resolve_service_endpoint
        from contextunity.core.grpc_utils import create_channel
        from contextunity.core.sdk.types import TokenProviderFactory as TokenProviderFactoryProtocol

        self._cu_pb2 = contextunit_pb2

        from contextunity.core.tokens import ContextToken as _CT

        self._token: ContextToken | None = None
        self._token_factory: TokenProviderFactory | None = None
        self._auth_backend = auth_backend
        if isinstance(token, _CT):
            self._token = token
        elif isinstance(token, TokenProviderFactoryProtocol):
            self._token_factory = token

        config = get_core_config()
        discovery_tenant = tenant_id
        if self._token is not None:
            from contextunity.core.authz import resolve_token_tenant
            from contextunity.core.exceptions import SecurityError

            try:
                discovery_tenant = resolve_token_tenant(
                    self._token,
                    requested_tenant_id=tenant_id,
                    boundary=f"{self._service_name} client discovery",
                )
            except SecurityError:
                if tenant_id is not None:
                    raise
                discovery_tenant = None
        configured_host = getattr(config, self._config_url_attr, "") or ""

        self.host = host or resolve_service_endpoint(
            self._service_name,
            configured_host=configured_host,
            default_host=f"localhost:{self._default_port}",
            tenant_id=discovery_tenant,
        )

        self.channel = create_channel(self.host)
        self._stub = self._stub_class(self.channel)

    def _get_metadata(self) -> GrpcMetadata:
        """Build gRPC metadata with signed token for requests.

        Returns:
            GrpcMetadata: A tuple of ``(key, value)`` metadata pairs.
        """
        from contextunity.core import create_grpc_metadata_with_token
        from contextunity.core.signing import get_signing_backend

        if self._token_factory is not None:
            resolved = self._token_factory()
        else:
            resolved = self._token

        if isinstance(resolved, str):
            return (("authorization", f"Bearer {resolved}"),)

        backend = self._auth_backend or get_signing_backend()
        return create_grpc_metadata_with_token(resolved, backend=backend)

    async def _call_unary(
        self,
        rpc: UnaryContextUnitRpc,
        payload: ContextUnitPayload,
        *,
        rpc_name: str,
    ) -> ContextUnitPayload:
        """Dispatch a unary gRPC call using a typed stub RPC method.

        Args:
            rpc: Typed unary RPC method from the service stub (e.g. ``self._stub.Scan``).
            payload: The request payload carried by the ContextUnit envelope.
            rpc_name: Human-readable RPC label used for provenance and error wrapping.

        Returns:
            ContextUnitPayload: The response ContextUnit payload.
        """
        unit = ContextUnit(
            payload=payload,
            provenance=[f"sdk:{self._service_name}_client:{rpc_name.lower()}"],
        )
        req = unit.to_protobuf(self._cu_pb2)
        with wrap_client_error(self._service_name.title(), rpc_name):
            response_pb = await rpc(req, metadata=self._get_metadata())
        return ContextUnit.from_protobuf(response_pb).payload

    async def close(self) -> None:
        """Close the underlying gRPC channel."""
        if self.channel:
            await self.channel.close()

    async def __aenter__(self) -> Self:
        """Enter the async context manager, returning the connected client."""
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> None:
        """Exit the async context manager, closing the gRPC channel.

        Args:
            exc_type: The exception type, if one was raised in the context.
            exc_val: The exception instance, if any.
            exc_tb: The traceback, if any.
        """
        await self.close()


__all__ = ["BaseServiceClient"]
