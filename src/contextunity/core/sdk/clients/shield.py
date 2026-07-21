"""ShieldClient - SDK client for contextunity.shield service."""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from contextunity.core.sdk.execution_trace_artifacts import (
    ProtectedExecutionTraceArtifactEnvelope,
    ProtectExecutionTraceArtifactRequest,
    UnprotectedExecutionTraceArtifact,
    UnprotectExecutionTraceArtifactRequest,
)
from contextunity.core.sdk.payload import copy_wire_payload
from contextunity.core.shield_pb2_grpc import ShieldServiceStub
from contextunity.core.types import ContextUnitPayload

from ._base import BaseServiceClient

if TYPE_CHECKING:
    from typing import TypeAlias

    from contextunity.core.shield_pb2_grpc import ShieldServiceAsyncStub

    _ShieldBase: TypeAlias = BaseServiceClient[ShieldServiceAsyncStub]
else:
    _ShieldBase = BaseServiceClient


class ShieldClient(_ShieldBase):
    """Client for interacting with contextunity.shield using ContextUnit protocol."""

    _service_name: ClassVar[str] = "shield"
    _default_port: ClassVar[str] = "50054"
    _config_url_attr: ClassVar[str] = "shield_url"
    _stub_class: ClassVar[type] = ShieldServiceStub

    async def scan(self, *, content: str, categories: list[str] | None = None) -> ContextUnitPayload:
        """Scan content for compliance violations against Shield policies."""
        res = await self._call_unary(
            self._stub.Scan,
            {"text": content, "validators": categories or []},
            rpc_name="Scan",
        )
        return copy_wire_payload(res)

    async def get_secret(
        self,
        *,
        path: str,
        version: int | None = None,
        tenant_id: str | None = None,
    ) -> ContextUnitPayload:
        """Retrieve a secret from the Shield vault."""
        payload: ContextUnitPayload = {"path": path}
        if version is not None:
            payload["version"] = version
        if tenant_id is not None:
            payload["tenant_id"] = tenant_id
        res = await self._call_unary(self._stub.GetSecret, payload, rpc_name="GetSecret")
        return copy_wire_payload(res)

    async def put_secret(
        self,
        *,
        path: str,
        value: str,
        tags: dict[str, str] | None = None,
        ttl_seconds: int | None = None,
        tenant_id: str | None = None,
    ) -> ContextUnitPayload:
        """Store a secret in the Shield vault."""
        payload: ContextUnitPayload = {
            "path": path,
            "value": value,
            "tags": tags or {},
        }
        if ttl_seconds is not None:
            payload["ttl_seconds"] = ttl_seconds
        if tenant_id is not None:
            payload["tenant_id"] = tenant_id
        res = await self._call_unary(self._stub.PutSecret, payload, rpc_name="PutSecret")
        return copy_wire_payload(res)

    async def list_secrets(
        self,
        *,
        prefix: str = "",
        tenant_id: str | None = None,
    ) -> ContextUnitPayload:
        """List secrets in the Shield vault by prefix."""
        payload: ContextUnitPayload = {"prefix": prefix}
        if tenant_id is not None:
            payload["tenant_id"] = tenant_id
        res = await self._call_unary(
            self._stub.ListSecrets,
            payload,
            rpc_name="ListSecrets",
        )
        return copy_wire_payload(res)

    async def rotate_secret(
        self,
        *,
        path: str,
        new_value: str,
        invalidate_previous: bool = False,
        tenant_id: str | None = None,
    ) -> ContextUnitPayload:
        """Rotate an existing secret in the Shield vault."""
        payload: ContextUnitPayload = {
            "path": path,
            "new_value": new_value,
            "invalidate_previous": invalidate_previous,
        }
        if tenant_id is not None:
            payload["tenant_id"] = tenant_id
        res = await self._call_unary(
            self._stub.RotateSecret,
            payload,
            rpc_name="RotateSecret",
        )
        return copy_wire_payload(res)

    async def protect_execution_trace_artifact(
        self,
        request: ProtectExecutionTraceArtifactRequest,
    ) -> ProtectedExecutionTraceArtifactEnvelope:
        """Protect one closed purpose/identity-bound Trace artifact."""
        payload: ContextUnitPayload = request.model_dump(mode="json")
        res = await self._call_unary(self._stub.Encrypt, payload, rpc_name="Encrypt")
        return ProtectedExecutionTraceArtifactEnvelope.model_validate(copy_wire_payload(res))

    async def unprotect_execution_trace_artifact(
        self,
        request: UnprotectExecutionTraceArtifactRequest,
    ) -> UnprotectedExecutionTraceArtifact:
        """Recover one already-authorized identity-bound Trace artifact."""
        payload: ContextUnitPayload = request.model_dump(mode="json")
        res = await self._call_unary(self._stub.Decrypt, payload, rpc_name="Decrypt")
        return UnprotectedExecutionTraceArtifact.model_validate(copy_wire_payload(res))

    async def issue_session_token(
        self,
        *,
        project_id: str,
        required_services: dict[str, bool] | None = None,
    ) -> ContextUnitPayload:
        """Request a signed session token for cross-service authentication."""
        payload: ContextUnitPayload = {"project_id": project_id}
        if required_services:
            payload["required_services"] = required_services
        res = await self._call_unary(self._stub.IssueSessionToken, payload, rpc_name="IssueSessionToken")
        return copy_wire_payload(res)

    async def get_project_public_key(self, *, project_id: str) -> ContextUnitPayload:
        """Get the public key used by Shield for a given project."""
        res = await self._call_unary(
            self._stub.GetProjectPublicKey,
            {"project_id": project_id},
            rpc_name="GetProjectPublicKey",
        )
        return copy_wire_payload(res)

    async def rotate_project_key(self, *, project_id: str) -> ContextUnitPayload:
        """Rotate the cryptographic key pair for a given project."""
        res = await self._call_unary(
            self._stub.RotateProjectKey,
            {"project_id": project_id},
            rpc_name="RotateProjectKey",
        )
        return copy_wire_payload(res)

    async def get_stats(self) -> ContextUnitPayload:
        """Retrieve runtime metrics and statistics from the Shield service."""
        res = await self._call_unary(self._stub.GetStats, {}, rpc_name="GetStats")
        return copy_wire_payload(res)


__all__ = ["ShieldClient"]
