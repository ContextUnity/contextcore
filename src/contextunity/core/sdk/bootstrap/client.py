"""gRPC transport for SDK bootstrap.
Handles three bootstrap-phase RPCs:
- ``RegisterManifest`` to Router (register tools/graphs)
- ``PutSecret`` to Shield (sync API keys)
- ``RegisterSchedules`` to Worker (register cron schedules)
These functions are called by :mod:`~contextunity.core.sdk.bootstrap.loop`.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from contextunity.core.logging import get_contextunit_logger
from contextunity.core.sdk.types import ToolPayload
from contextunity.core.types import WireValue

if TYPE_CHECKING:
    from contextunity.core.signing import AuthBackend

logger = get_contextunit_logger(__name__)

_REGISTRATION_TIMEOUT = 15
_TOKEN_TTL_REGISTER = 300


def _resolve_auth_backend(backend: AuthBackend | None):
    """Prefer the global signing backend set during bootstrap (SessionTokenBackend)."""
    from contextunity.core.exceptions import ConfigurationError
    from contextunity.core.signing import get_signing_backend

    try:
        return get_signing_backend()
    except ConfigurationError:
        if backend is not None:
            return backend
        raise ConfigurationError(
            "Bootstrap RPC requires an auth backend — call set_signing_backend() first.",
            code="CONFIGURATION_ERROR",
        ) from None


def _bootstrap_metadata(
    *,
    project_id: str,
    backend: AuthBackend | None,
    token_id_suffix: str,
    permissions: tuple[str, ...],
    allowed_tenants: tuple[str, ...] | None = None,
):
    """Build gRPC metadata for bootstrap RPCs.

    Uses ``create_grpc_metadata_with_token`` so ``SessionTokenBackend`` exchanges
    the attenuated ``ContextToken`` for an Ed25519 session token (Shield enterprise).
    """
    from contextunity.core.token_utils import create_grpc_metadata_with_token
    from contextunity.core.tokens import ContextToken

    auth = _resolve_auth_backend(backend)
    token = ContextToken(
        token_id=f"{project_id}-{token_id_suffix}",
        permissions=permissions,
        allowed_tenants=allowed_tenants or (project_id,),
        exp_unix=time.time() + _TOKEN_TTL_REGISTER,
    )
    return create_grpc_metadata_with_token(token, backend=auth)


def do_register(
    router_url: str,
    project_id: str,
    payload: ToolPayload,
    backend: AuthBackend | None,
) -> tuple[str, str]:
    """Send RegisterManifest gRPC request to Router.

    Args:
        router_url: The Router service gRPC URL.
        project_id: The identifier of the project.
        payload: The registration payload containing the manifest bundle.
        backend: The authentication backend used to sign the registration token.

    Returns:
        tuple[str, str]: A tuple containing the (stream_secret, shield_url) returned by Router.
    """
    from contextunity.core import ContextUnit, contextunit_pb2, router_pb2_grpc
    from contextunity.core.grpc_utils import create_channel_sync
    from contextunity.core.sdk.contextunit import ContextUnit as SdkContextUnit
    from contextunity.core.sdk.identity import get_allowed_tenants
    from contextunity.core.sdk.models import SecurityScopes
    from contextunity.core.sdk.payload import get_str, get_str_list

    metadata = _bootstrap_metadata(
        project_id=project_id,
        backend=backend,
        token_id_suffix="service",
        permissions=(f"tools:register:{project_id}",),
        allowed_tenants=get_allowed_tenants() or (project_id,),
    )

    channel = create_channel_sync(router_url)
    try:
        stub = router_pb2_grpc.RouterServiceStub(channel)

        unit = ContextUnit(
            payload=payload,
            provenance=[f"{project_id}:register_manifest"],
            security=SecurityScopes(write=[f"tools:register:{project_id}"]),
        )
        pb = unit.to_protobuf(contextunit_pb2)
        response = stub.RegisterManifest(pb, metadata=metadata, wait_for_ready=True, timeout=_REGISTRATION_TIMEOUT)

        result = SdkContextUnit.from_protobuf(response).payload
        tool_list = get_str_list(result, "registered_tools")
        if not tool_list:
            single = get_str(result, "registered_tools")
            tool_list = [single] if single else []

        graph_name = get_str(result, "graph", "none")
        secret = get_str(result, "stream_secret")
        shield_url = get_str(result, "shield_url")

        logger.info(
            "Registered | tools=[%s] graph=%s shield=%s",
            ", ".join(tool_list),
            graph_name,
            shield_url or "none",
        )
        return secret, shield_url
    finally:
        channel.close()


def put_secrets_to_shield(
    project_id: str,
    secrets: dict[str, str],
    shield_url: str,
    backend: AuthBackend | None,
) -> list[str]:
    """Send API keys to Shield via PutSecret gRPC requests.

    Args:
        project_id: The identifier of the project (used as tenant namespace).
        secrets: Dictionary mapping providers/names to API key strings.
        shield_url: The Shield service gRPC URL.
        backend: The authentication backend used to sign sync tokens.

    Returns:
        list[str]: A list of provider names successfully synced to Shield.

    Raises:
        PlatformServiceError: If one or more secrets failed to sync.
    """
    from contextunity.core import ContextUnit, contextunit_pb2, shield_pb2_grpc
    from contextunity.core.exceptions import PlatformServiceError
    from contextunity.core.grpc_utils import create_channel_sync
    from contextunity.core.sdk.models import SecurityScopes

    metadata = _bootstrap_metadata(
        project_id=project_id,
        backend=backend,
        token_id_suffix="shield-sync",
        permissions=("shield:secrets:write",),
    )

    channel = create_channel_sync(shield_url)
    synced: list[str] = []
    failed: list[tuple[str, Exception]] = []
    try:
        stub = shield_pb2_grpc.ShieldServiceStub(channel)
        for provider, api_key in secrets.items():
            shield_path = f"{project_id}/api_keys/{provider}"
            try:
                unit = ContextUnit(
                    payload={
                        "path": shield_path,
                        "value": api_key,
                        "created_by": f"{project_id}:sdk_bootstrap",
                        "tags": {"type": "llm_api_key", "provider": provider},
                    },
                    provenance=[f"{project_id}:sdk_bootstrap:put_secret"],
                    security=SecurityScopes(write=["secrets:write"]),
                )
                _ = stub.PutSecret(
                    unit.to_protobuf(contextunit_pb2),
                    metadata=metadata,
                    timeout=5,
                )
                synced.append(provider)
            except Exception as e:
                failed.append((provider, e))
    finally:
        channel.close()

    if failed:
        detail = "; ".join(f"{p}: {e}" for p, e in failed)
        raise PlatformServiceError(
            f"Shield sync incomplete — {len(failed)}/{len(secrets)} provider(s) failed: {detail}"
        )

    return synced


def register_schedules(
    project_id: str,
    schedules: list[dict[str, WireValue]],
    backend: AuthBackend | None,
) -> int:
    """Sync project schedules to the contextunity.worker service.

    Args:
        project_id: The identifier of the project.
        schedules: List of dictionary representations of schedules.
        backend: The authentication backend used to sign worker sync tokens.

    Returns:
        int: The number of schedules successfully registered.
    """
    from contextunity.core import ContextUnit, contextunit_pb2, worker_pb2_grpc
    from contextunity.core.config import get_core_config
    from contextunity.core.discovery import resolve_service_endpoint
    from contextunity.core.grpc_utils import create_channel_sync
    from contextunity.core.sdk.contextunit import ContextUnit as SdkContextUnit
    from contextunity.core.sdk.identity import get_tenant_id
    from contextunity.core.sdk.models import SecurityScopes
    from contextunity.core.sdk.payload import get_int

    config = get_core_config()
    tenant_id = get_tenant_id() or project_id

    worker_url = resolve_service_endpoint(
        "worker", configured_host=config.worker_url, default_host="localhost:50052", tenant_id=tenant_id
    )

    metadata = _bootstrap_metadata(
        project_id=project_id,
        backend=backend,
        token_id_suffix="worker-sync",
        permissions=("worker:execute",),
        allowed_tenants=(tenant_id,),
    )

    channel = create_channel_sync(worker_url)
    try:
        stub = worker_pb2_grpc.WorkerServiceStub(channel)

        unit = ContextUnit(
            payload={
                "project_id": project_id,
                "schedules": schedules,
            },
            provenance=[f"{project_id}:sdk_bootstrap:register_schedules"],
            security=SecurityScopes(write=["worker:execute"]),
        )
        response = stub.RegisterSchedules(
            unit.to_protobuf(contextunit_pb2),
            metadata=metadata,
            timeout=10,
        )

        result = SdkContextUnit.from_protobuf(response).payload
        return get_int(result, "registered_count", 0)
    finally:
        channel.close()


_do_register = do_register
_put_secrets_to_shield = put_secrets_to_shield
_register_schedules = register_schedules
