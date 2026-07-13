from __future__ import annotations

from unittest.mock import patch

import pytest
from contextunity.core.config.models import SharedSecurityConfig
from contextunity.core.exceptions import ConfigurationError
from contextunity.core.permissions import Permissions
from contextunity.core.signing import HmacBackend, SessionTokenBackend
from contextunity.core.signing.service_auth import configure_service_signing_backend
from contextunity.core.token_utils import parse_token_string, serialize_token
from contextunity.core.tokens import ContextToken


class TestHmacBackend:
    def test_bootstrap_metadata_is_project_scoped(self):
        backend = HmacBackend("tenant_a", "secret-123")

        metadata = dict(backend.get_auth_metadata())
        token = parse_token_string(metadata["authorization"][7:])

        assert token is not None
        assert token.can_access_tenant("tenant_a")
        assert Permissions.SHIELD_SESSION_TOKEN_ISSUE in token.permissions
        assert Permissions.SHIELD_PROJECT_KEY_ROTATE in token.permissions
        assert token.agent_id == "project:tenant_a"

    def test_verify_rejects_unexpected_kid(self):
        signing_backend = HmacBackend("proj-a", "shared-secret")
        wrong_backend = HmacBackend("proj-b", "shared-secret")
        token = ContextToken(token_id="t1", permissions=("brain:read",))

        token_str = serialize_token(token, backend=signing_backend)

        assert wrong_backend.verify(token_str) is None


class TestSessionTokenBackend:
    def test_create_grpc_metadata_uses_only_shield_session_token(self):
        backend = SessionTokenBackend(
            project_id="sample_project",
            session_token="shield-session-token",
            kid="sample_project:session-001",
            expires_at=9999999999,
            shield_url="localhost:50054",
        )
        token = ContextToken(
            token_id="sample_project-client-dev",
            user_id="dev",
            allowed_tenants=("sample_project",),
        )

        with patch(
            "contextunity.core.signing._request_session_token",
            return_value=("shield-request-token", "sample_project:session-001", 9999999999),
        ) as request_session_token:
            metadata = backend.create_grpc_metadata(token)

        assert metadata == (("authorization", "Bearer shield-request-token"),)
        request_session_token.assert_called_once()
        assert request_session_token.call_args.kwargs["requested_token"] is token
        assert request_session_token.call_args.kwargs["renewal_token"] == "shield-session-token"
        assert request_session_token.call_args.args[2] is None

    def test_service_auth_bootstraps_shield_like_router(self):
        security = SharedSecurityConfig(
            project_secret="bootstrap-secret",
        )

        with (
            patch("contextunity.core.signing.service_auth.set_signing_backend"),
            patch(
                "contextunity.core.signing.shield_client.request_session_token",
                return_value=("shield-session", "sample_project:session-001", 9999999999),
            ) as request,
        ):
            backend = configure_service_signing_backend(
                security,
                project_id="sample_project",
                shield_enabled=True,
                shield_url="shield:50054",
                service_name="worker",
                allowed_tenants=("sample_project",),
            )

        assert isinstance(backend, SessionTokenBackend)
        assert request.call_args.kwargs["required_services"] == {"worker": True}
        requested = request.call_args.kwargs["requested_token"]
        assert requested.allowed_tenants == ("sample_project",)
        assert Permissions.BRAIN_EMBED in requested.permissions
        assert Permissions.SHIELD_SESSION_TOKEN_ISSUE in requested.permissions

    def test_service_auth_shield_mode_rejects_missing_bootstrap_secret(self):
        security = SharedSecurityConfig()

        with pytest.raises(ConfigurationError, match="CU_PROJECT_SECRET"):
            configure_service_signing_backend(
                security,
                project_id="sample_project",
                shield_enabled=True,
                shield_url="shield:50054",
                service_name="worker",
                allowed_tenants=("sample_project",),
            )

    def test_hmac_backend_still_signs_request_token_for_open_source_mode(self):
        backend = HmacBackend("sample_project", "open-source-secret")
        token = ContextToken(
            token_id="sample_project-client-dev",
            user_id="dev",
            allowed_tenants=("sample_project",),
        )

        metadata = backend.create_grpc_metadata(token)

        assert len(metadata) == 1
        assert metadata[0][0] == "authorization"
        assert metadata[0][1].startswith("Bearer ")
        token_str = metadata[0][1][7:]
        verified = parse_token_string(token_str)
        assert verified is not None
        assert verified.token_id == "sample_project-client-dev"
        assert backend.verify(token_str) is not None


class TestHmacGetAuthMetadata:
    """Tests for HmacBackend.get_auth_metadata — inline serialization logic.

    Kills survived mutants on payload fields, JSON structure, and signing.
    """

    def test_metadata_produces_verifiable_token(self):
        """get_auth_metadata produces a token that verifies against same backend."""
        backend = HmacBackend("proj_a", "secret-123")
        metadata = dict(backend.get_auth_metadata())
        token_str = metadata["authorization"][7:]  # strip "Bearer "
        assert backend.verify(token_str) is not None

    def test_metadata_bootstrap_payload_complete(self):
        """Bootstrap payload contains all required fields with correct values.

        Score 5: +2 protects bootstrap contract, +2 breaks if any field missing, +1 fast.
        """
        import json
        import time

        backend = HmacBackend("tenant_x", "secret-456")
        metadata = dict(backend.get_auth_metadata())
        raw = backend.verify(metadata["authorization"][7:])
        assert raw is not None
        data = json.loads(raw)

        # Structure: all required fields present
        for field in ("token_id", "permissions", "allowed_tenants", "user_id", "agent_id", "user_namespace"):
            assert field in data, f"Missing required field: {field}"

        # Values: correct defaults
        assert data["user_id"] == "system"
        assert data["agent_id"] == "project:tenant_x"
        assert "tenant_x" in data["allowed_tenants"]
        assert Permissions.SHIELD_SESSION_TOKEN_ISSUE in data["permissions"]
        assert Permissions.SHIELD_PROJECT_KEY_ROTATE in data["permissions"]
        assert "exp_unix" in data
        assert data["exp_unix"] > time.time()


class TestHmacCreateGrpcMetadata:
    """Tests for HmacBackend.create_grpc_metadata with string tokens."""

    def test_string_token_passthrough_with_bearer(self):
        """String token already with Bearer prefix is passed through."""
        backend = HmacBackend("proj", "secret")
        metadata = backend.create_grpc_metadata("Bearer my_token_123")
        assert metadata == (("authorization", "Bearer my_token_123"),)

    def test_string_token_gets_bearer_prefix(self):
        """String token without Bearer prefix gets it added."""
        backend = HmacBackend("proj", "secret")
        metadata = backend.create_grpc_metadata("raw_token_string")
        assert metadata == (("authorization", "Bearer raw_token_string"),)

    def test_contexttoken_object_signed_and_serialized(self):
        """ContextToken object gets serialized and signed via HMAC."""
        backend = HmacBackend("proj", "secret")
        token = ContextToken(
            token_id="test_token",
            permissions=("brain:read",),
            allowed_tenants=("proj",),
        )
        metadata = backend.create_grpc_metadata(token)
        assert len(metadata) == 1
        assert metadata[0][0] == "authorization"
        # Verify it's a valid signed token
        token_str = metadata[0][1][7:]
        parsed = parse_token_string(token_str)
        assert parsed is not None
        assert parsed.token_id == "test_token"


class TestHmacVerifyEdgeCases:
    """Edge cases for HmacBackend.verify.

    Score 4: +2 security behavior (reject invalid tokens), +1 edge case, +1 fast.
    """

    @pytest.mark.parametrize(
        ("token_str",),
        [
            ("",),
            ("   ",),
            ("single_part",),
            ("two.parts",),
            ("kid.payload.",),
        ],
        ids=["empty", "whitespace", "no-dots", "one-dot", "empty-sig"],
    )
    def test_malformed_input_returns_none(self, token_str) -> None:
        """Malformed/missing token formats return None (no crash)."""
        backend = HmacBackend("proj", "secret")
        assert backend.verify(token_str) is None

    def test_wrong_signature_returns_none(self):
        """Tampered signature is rejected.

        Score 5: +2 security (HMAC integrity), +2 breaks on real bug, +1 fast.
        """
        import base64

        backend = HmacBackend("proj", "secret")
        token = ContextToken(token_id="test", permissions=("brain:read",))
        token_str = serialize_token(token, backend=backend)
        parts = token_str.rsplit(".", 1)
        tampered = parts[0] + "." + base64.b64encode(b"fake_sig").decode()
        assert backend.verify(tampered) is None

    def test_constructor_rejects_empty_secret(self):
        with pytest.raises(ConfigurationError, match="project_secret"):
            HmacBackend("proj", "")

    def test_sign_verify_roundtrip(self):
        """sign → verify roundtrip returns original payload bytes."""
        backend = HmacBackend("proj", "secret")
        payload = b'{"token_id": "test_roundtrip"}'
        signed = backend.sign(payload)
        result = backend.verify(signed.serialize())
        assert result == payload

    def test_kid_format(self):
        """KID is project_id:hmac-001 by default."""
        backend = HmacBackend("my_proj", "secret")
        assert backend.active_kid == "my_proj:hmac-001"

    def test_custom_kid(self):
        """Custom KID is project_id:custom."""
        backend = HmacBackend("my_proj", "secret", kid="v2")
        assert backend.active_kid == "my_proj:v2"


pytestmark = pytest.mark.unit
