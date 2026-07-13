"""Shield IssueSessionToken client helpers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from contextunity.core.exceptions import SecurityError
from contextunity.core.logging import get_contextunit_logger
from contextunity.core.sdk.payload import wire_payload_from_message
from contextunity.core.types import ContextUnitPayload
from google.protobuf.message import Message

from .hmac import HmacBackend

if TYPE_CHECKING:
    from contextunity.core.tokens import ContextToken

logger = get_contextunit_logger(__name__)


def protobuf_payload_dict(payload: Message) -> ContextUnitPayload:
    """Convert a protobuf Struct payload to ``ContextUnitPayload``."""
    return wire_payload_from_message(payload)


def parse_issue_session_token_response(resp_dict: ContextUnitPayload) -> tuple[str, str, float]:
    """Extract session token fields from a Shield IssueSessionToken payload."""
    session_token_raw = resp_dict.get("session_token", "")
    kid_raw = resp_dict.get("kid", "")
    expires_at_raw = resp_dict.get("expires_at", 0.0)
    session_token = session_token_raw if isinstance(session_token_raw, str) else ""
    kid = kid_raw if isinstance(kid_raw, str) else ""
    expires_at = float(expires_at_raw) if isinstance(expires_at_raw, (int, float)) else 0.0
    return session_token, kid, expires_at


def request_session_token(
    project_id: str,
    shield_url: str,
    hmac_backend: HmacBackend | None,
    required_services: dict[str, bool] | None = None,
    requested_token: ContextToken | None = None,
    renewal_token: str | None = None,
) -> tuple[str, str, float]:
    """Request a signed session token using bootstrap HMAC or a parent session."""
    from contextunity.core import contextunit_pb2, shield_pb2_grpc
    from contextunity.core.grpc_utils import create_channel_sync
    from contextunity.core.sdk.contextunit import ContextUnit as PydanticUnit

    channel = create_channel_sync(shield_url)
    try:
        stub = shield_pb2_grpc.ShieldServiceStub(channel)
        if renewal_token:
            metadata = (("authorization", f"Bearer {renewal_token}"),)
        elif hmac_backend is not None:
            metadata = hmac_backend.get_auth_metadata()
        else:
            raise SecurityError(
                message="Shield session issuance requires bootstrap HMAC or a parent session token",
                code="SHIELD_AUTH_REQUIRED",
            )

        payload: ContextUnitPayload = {"project_id": project_id}
        if requested_token is not None:
            payload["requested_token"] = {
                "permissions": list(requested_token.permissions),
                "allowed_tenants": list(requested_token.allowed_tenants),
                "user_id": requested_token.user_id,
                "agent_id": requested_token.agent_id,
                "user_namespace": requested_token.user_namespace,
                "exp_unix": requested_token.exp_unix,
            }
        if required_services:
            known_services = {"router", "brain", "worker", "shield"}
            unknown = set(required_services.keys()) - known_services
            if unknown:
                logger.warning(
                    "Shield auto-provision: rejecting unknown services %s for project '%s'",
                    unknown,
                    project_id,
                )
                required_services = {k: v for k, v in required_services.items() if k in known_services}

            if required_services:
                payload["required_services"] = required_services
                logger.info(
                    "Shield auto-provisioning services=%s for project='%s'",
                    sorted(k for k, v in required_services.items() if v),
                    project_id,
                )

        unit = PydanticUnit(
            payload=payload,
            provenance=["core:issue_session_token"],
        )
        req = unit.to_protobuf(contextunit_pb2)

        resp = stub.IssueSessionToken(req, metadata=metadata, timeout=10.0)
        resp_dict = protobuf_payload_dict(resp.payload)
        session_token, kid, expires_at = parse_issue_session_token_response(resp_dict)
        if not session_token or not kid or not expires_at:
            error_response = resp_dict.get("error")
            error_message = resp_dict.get("message")
            error_text = error_response if isinstance(error_response, str) else ""
            message_text = error_message if isinstance(error_message, str) else ""
            if error_text:
                raise SecurityError(
                    message=f"Shield denied IssueSessionToken: [{error_text}] {message_text}",
                    code="SHIELD_DENIED_ERROR",
                )

            raise SecurityError(
                message=f"Shield returned incomplete IssueSessionToken response for project '{project_id}'",
                code="SHIELD_INVALID_RESPONSE",
            )
        return session_token, kid, expires_at
    except Exception as e:
        import grpc

        if isinstance(e, grpc.RpcError):
            code_name = e.code().name
            details = getattr(e, "details", lambda: "")() or ""

            if "failed to connect" in details.lower():
                short_details = f"cannot reach Shield at {shield_url}"
            elif ";" in details:
                short_details = details.split(";")[0].strip()
            else:
                short_details = details

            raise SecurityError(
                message=f"Shield RPC [{code_name}]: {short_details}",
                code="SHIELD_RPC_ERROR",
            ) from e
        raise
    finally:
        channel.close()
