"""Shield public key fetching utilities."""

from __future__ import annotations


def fetch_project_public_key_sync(
    project_id: str,
    kid: str,
    shield_url: str,
    *,
    provenance: str,
) -> tuple[str, str]:
    """Synchronously fetch a project's public key from Shield."""
    from google.protobuf.json_format import MessageToDict

    from .. import context_unit_pb2, shield_pb2_grpc
    from ..grpc_utils import create_channel_sync
    from ..sdk.context_unit import ContextUnit as PydanticUnit

    channel = create_channel_sync(shield_url)
    try:
        stub = shield_pb2_grpc.ShieldServiceStub(channel)
        req = PydanticUnit(
            payload={"project_id": project_id},
            provenance=[provenance],
        ).to_protobuf(context_unit_pb2)
        response = stub.GetProjectPublicKey(req, timeout=10.0)
        response_dict = MessageToDict(response.payload)
        public_key_b64 = response_dict.get("publicKeyB64") or response_dict.get("public_key_b64", "")
        returned_kid = response_dict.get("kid", kid)
        if not public_key_b64:
            raise RuntimeError(f"Shield returned empty public key for project '{project_id}'")
        return public_key_b64, returned_kid
    finally:
        channel.close()


async def fetch_project_public_key_async(
    project_id: str,
    kid: str,
    shield_url: str,
    *,
    provenance: str,
) -> tuple[str, str]:
    """Asynchronously fetch a project's public key from Shield."""
    from google.protobuf.json_format import MessageToDict

    from .. import context_unit_pb2, shield_pb2_grpc
    from ..grpc_utils import create_channel
    from ..sdk.context_unit import ContextUnit as PydanticUnit

    channel = create_channel(shield_url)
    try:
        stub = shield_pb2_grpc.ShieldServiceStub(channel)
        req = PydanticUnit(
            payload={"project_id": project_id},
            provenance=[provenance],
        ).to_protobuf(context_unit_pb2)
        response = await stub.GetProjectPublicKey(req, timeout=10.0)
        response_dict = MessageToDict(response.payload)
        public_key_b64 = response_dict.get("publicKeyB64") or response_dict.get("public_key_b64", "")
        returned_kid = response_dict.get("kid", kid)
        if not public_key_b64:
            raise RuntimeError(f"Shield returned empty public key for project '{project_id}'")
        return public_key_b64, returned_kid
    finally:
        await channel.close()
