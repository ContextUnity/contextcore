"""Shield public-key fetching — synchronous retrieval of project Ed25519 keys.
Called during HTTP token verification when the verifier needs the project's
public key to validate a ``SessionTokenBackend``-signed token.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..config import SharedConfig

from ..exceptions import SecurityError


def fetch_project_public_key_sync(
    project_id: str,
    kid: str,
    shield_url: str,
    *,
    provenance: str,
    config: SharedConfig | None = None,
) -> tuple[str, str]:
    """Synchronously fetch a project's public key from Shield.

    Args:
        project_id (str): The identifier of the project.
        kid (str): The kid parameter.
        shield_url (str): The shield url parameter.

    Returns:
        tuple[str, str]: An instance of tuple[str, str].

    Raises:
        RuntimeError: If a validation error occurs.
    """
    from .. import contextunit_pb2, shield_pb2_grpc
    from ..grpc_utils import create_channel_sync
    from ..sdk.contextunit import ContextUnit as PydanticUnit
    from ..signing.shield_client import protobuf_payload_dict

    channel = create_channel_sync(shield_url, config=config)
    try:
        stub = shield_pb2_grpc.ShieldServiceStub(channel)
        req = PydanticUnit(
            payload={"project_id": project_id},
            provenance=[provenance],
        ).to_protobuf(contextunit_pb2)
        response = stub.GetProjectPublicKey(req, timeout=10.0)
        response_dict = protobuf_payload_dict(response.payload)
        public_key_raw = response_dict.get("publicKeyB64") or response_dict.get("public_key_b64", "")
        public_key_b64 = public_key_raw if isinstance(public_key_raw, str) else ""
        returned_kid_raw = response_dict.get("kid", kid)
        returned_kid = returned_kid_raw if isinstance(returned_kid_raw, str) else kid
        if not public_key_b64:
            raise SecurityError(f"Shield returned empty public key for project '{project_id}'")
        return public_key_b64, returned_kid
    finally:
        channel.close()


async def fetch_project_public_key_async(
    project_id: str,
    kid: str,
    shield_url: str,
    *,
    provenance: str,
    config: SharedConfig | None = None,
) -> tuple[str, str]:
    """Asynchronously fetch a project's public key from Shield.

    Args:
        project_id (str): The identifier of the project.
        kid (str): The kid parameter.
        shield_url (str): The shield url parameter.

    Returns:
        tuple[str, str]: An instance of tuple[str, str].

    Raises:
        RuntimeError: If a validation error occurs.
    """
    from .. import contextunit_pb2, shield_pb2_grpc
    from ..grpc_utils import create_channel
    from ..sdk.contextunit import ContextUnit as PydanticUnit
    from ..signing.shield_client import protobuf_payload_dict

    channel = create_channel(shield_url, config=config)
    try:
        stub = shield_pb2_grpc.ShieldServiceStub(channel)
        req = PydanticUnit(
            payload={"project_id": project_id},
            provenance=[provenance],
        ).to_protobuf(contextunit_pb2)
        response = await stub.GetProjectPublicKey(req, timeout=10.0)
        response_dict = protobuf_payload_dict(response.payload)
        public_key_raw = response_dict.get("publicKeyB64") or response_dict.get("public_key_b64", "")
        public_key_b64 = public_key_raw if isinstance(public_key_raw, str) else ""
        returned_kid_raw = response_dict.get("kid", kid)
        returned_kid = returned_kid_raw if isinstance(returned_kid_raw, str) else kid
        if not public_key_b64:
            raise SecurityError(f"Shield returned empty public key for project '{project_id}'")
        return public_key_b64, returned_kid
    finally:
        await channel.close()
