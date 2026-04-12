from __future__ import annotations

import time
from typing import TYPE_CHECKING

from contextunity.core.logging import get_contextunit_logger

if TYPE_CHECKING:
    from contextunity.core.security.protocols import AuthBackend

logger = get_contextunit_logger(__name__)

_REGISTRATION_TIMEOUT = 15
_TOKEN_TTL_REGISTER = 300


def _do_register(
    router_url: str,
    project_id: str,
    payload: dict,
    backend: AuthBackend | None,
) -> tuple[str, str]:
    """Send RegisterManifest gRPC to Router."""
    from contextunity.core import ContextUnit, contextunit_pb2, router_pb2_grpc
    from contextunity.core.grpc_utils import create_channel_sync
    from contextunity.core.sdk.models import SecurityScopes
    from contextunity.core.token_utils import create_grpc_metadata_with_token
    from contextunity.core.tokens import ContextToken

    token = ContextToken(
        token_id=f"{project_id}-service",
        permissions=("tools:register", f"tools:register:{project_id}"),
        allowed_tenants=(project_id,),
        exp_unix=time.time() + _TOKEN_TTL_REGISTER,
    )
    metadata = create_grpc_metadata_with_token(token, backend=backend)

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

        result = dict(response.payload)
        raw_tools = result.get("registered_tools", [])
        if hasattr(raw_tools, "values"):
            tool_list = [v.string_value for v in raw_tools.values]
        elif isinstance(raw_tools, list):
            tool_list = [str(t) for t in raw_tools]
        else:
            tool_list = [str(raw_tools)]

        graph_name = result.get("graph", "none")
        secret = str(result.get("stream_secret", ""))
        shield_url = str(result.get("shield_url", ""))

        logger.info(
            "Registered | tools=[%s] graph=%s shield=%s",
            ", ".join(tool_list),
            graph_name,
            shield_url or "none",
        )
        return secret, shield_url
    finally:
        channel.close()


def _put_secrets_to_shield(
    project_id: str,
    secrets: dict[str, str],
    shield_url: str,
    backend: AuthBackend | None,
) -> list[str]:
    """Send API keys to Shield via PutSecret gRPC."""
    from contextunity.core import ContextUnit, contextunit_pb2, shield_pb2_grpc
    from contextunity.core.grpc_utils import create_channel_sync
    from contextunity.core.sdk.models import SecurityScopes
    from contextunity.core.token_utils import create_grpc_metadata_with_token
    from contextunity.core.tokens import ContextToken

    if backend and hasattr(backend, "sign"):
        token = ContextToken(
            token_id=f"{project_id}-shield-sync",
            permissions=("shield:put_secret", "shield:secrets:write"),
            allowed_tenants=(project_id,),
            exp_unix=time.time() + _TOKEN_TTL_REGISTER,
        )
        metadata = create_grpc_metadata_with_token(token, backend=backend)
    else:
        metadata = backend.get_auth_metadata() if backend else []

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
                        "tenant_id": project_id,
                        "created_by": f"{project_id}:sdk_bootstrap",
                        "tags": {"type": "llm_api_key", "provider": provider},
                    },
                    provenance=[f"{project_id}:sdk_bootstrap:put_secret"],
                    security=SecurityScopes(write=["secrets:write"]),
                )
                stub.PutSecret(
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
        raise RuntimeError(f"Shield sync incomplete — {len(failed)}/{len(secrets)} provider(s) failed: {detail}")

    return synced


def _register_schedules(
    project_id: str,
    schedules: list[dict],
    backend: AuthBackend | None,
) -> int:
    """Sync project schedules to cu.worker."""
    from contextunity.core import ContextUnit, contextunit_pb2, worker_pb2_grpc
    from contextunity.core.config import get_core_config
    from contextunity.core.discovery import resolve_service_endpoint
    from contextunity.core.grpc_utils import create_channel_sync
    from contextunity.core.sdk.identity import get_tenant_id
    from contextunity.core.sdk.models import SecurityScopes
    from contextunity.core.token_utils import create_grpc_metadata_with_token
    from contextunity.core.tokens import ContextToken

    config = get_core_config()
    tenant_id = get_tenant_id() or project_id

    worker_url = resolve_service_endpoint(
        "worker", configured_host=config.worker_url, default_host="localhost:50052", tenant_id=tenant_id
    )

    if backend and hasattr(backend, "sign"):
        token = ContextToken(
            token_id=f"{project_id}-worker-sync",
            permissions=("worker:execute",),
            allowed_tenants=(tenant_id,),
            exp_unix=time.time() + _TOKEN_TTL_REGISTER,
        )
        metadata = create_grpc_metadata_with_token(token, backend=backend)
    else:
        metadata = backend.get_auth_metadata() if backend else []

    channel = create_channel_sync(worker_url)
    try:
        stub = worker_pb2_grpc.WorkerServiceStub(channel)

        unit = ContextUnit(
            payload={
                "project_id": project_id,
                "tenant_id": tenant_id,
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

        result = dict(response.payload)
        return int(result.get("registered_count", 0))
    finally:
        channel.close()
