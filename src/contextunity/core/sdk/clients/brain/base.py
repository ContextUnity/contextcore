"""BrainClient base - initialization and proto imports."""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar, override

from contextunity.core.brain_pb2_grpc import BrainServiceStub
from contextunity.core.logging import get_contextunit_logger

from .._base import BaseServiceClient

if TYPE_CHECKING:
    from typing import TypeAlias

    from contextunity.core import ContextToken
    from contextunity.core.brain_pb2_grpc import BrainServiceAsyncStub
    from contextunity.core.sdk.types import GrpcMetadata, TokenProviderFactory
    from contextunity.core.signing.protocols import AuthBackend

    _BrainBase: TypeAlias = BaseServiceClient[BrainServiceAsyncStub]
else:
    _BrainBase = BaseServiceClient

logger = get_contextunit_logger(__name__)


class BrainClientBase(_BrainBase):
    """Base class for BrainClient with gRPC connection management.

    Inherits connection lifecycle from ``BaseServiceClient``.
    Overrides ``_get_metadata()`` with Brain-specific auth:

    1. **Forwarding** (Router → Brain): reuse the pre-serialized token
       string from the current auth context — no re-signing needed.
    2. **Local signing** (platform service → Brain): sign the
       ContextToken via the local signing backend.
    """

    _service_name: ClassVar[str] = "brain"
    _default_port: ClassVar[str] = "50051"
    _config_url_attr: ClassVar[str] = "brain_url"
    _stub_class: ClassVar[type] = BrainServiceStub

    token: ContextToken | None

    def __init__(
        self,
        host: str | None = None,
        token: ContextToken | TokenProviderFactory | None = None,
        tenant_id: str | None = None,
        auth_backend: AuthBackend | None = None,
    ) -> None:
        """Initialize the BrainClient base instance.

        Args:
            host: Optional explicit gRPC host address.
            token: Authentication token or token factory.
            tenant_id: Optional tenant identifier for identity scoping.
            auth_backend: Optional client-owned backend for autonomous service calls.
        """
        super().__init__(
            host=host,
            token=token,
            tenant_id=tenant_id,
            auth_backend=auth_backend,
        )
        # Expose token directly for backward compatibility —
        # some callers check ``client.token`` (legacy pattern).
        self.token = self._token

    @override
    def _get_metadata(self) -> GrpcMetadata:
        """Get gRPC metadata with token for requests.

        BrainClient is intended for **platform service tools** (Router,
        Worker, View, Workshop, Zero) — internal components that hold
        their own service tokens.

        Two paths:
        1. **Forwarding** (Router → Brain): Use the pre-serialized token
           string from the current auth context. No re-signing needed —
           the token was already signed by the originating project.
        2. **Local signing** (platform service → Brain): Sign the
           ContextToken via the local signing backend. Used by Worker,
           View, Workshop, and other platform services that originate
           Brain calls with their own service tokens.

        .. note::

           Direct Project/Extension → Brain usage (e.g. Commerce
           taxonomy_sync, brain_sync, matcher) is **legacy** from early
           Commerce coupling. These should migrate to Router graph
           pipelines (Gardener/Enricher/Writer) and Worker batch
           offloading.

        .. todo::

           Reconsider direct extension→Brain path after Phase 3 of
           development. Target: extensions call Router/Worker only;
           BrainClient stays platform-internal.

        Returns:
            List of (key, value) tuples for gRPC metadata

        Raises:
            PermissionError: If neither a token nor a client-owned backend is available.
        """
        if self._token is None and self._token_factory is None and self._auth_backend is None:
            raise PermissionError("BrainClient: no ContextToken or client-owned AuthBackend available")

        # Path 1: Forward the original pre-serialized token string
        # (available when running inside a service with an active gRPC auth context)
        try:
            from contextunity.core.authz.context import get_auth_context

            auth_ctx = get_auth_context()
            if auth_ctx and auth_ctx.token_string and (self._token is None or self._token == auth_ctx.token):
                return (("authorization", f"Bearer {auth_ctx.token_string}"),)
        except Exception:
            pass

        # Path 2: Sign the token locally (platform service originator)
        # Falls through to the base class implementation.
        return super()._get_metadata()


__all__ = ["BrainClientBase", "logger"]
