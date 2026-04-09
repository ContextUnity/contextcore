from __future__ import annotations

from contextcore.permissions import Permissions
from contextcore.signing import HmacBackend
from contextcore.token_utils import parse_token_string, serialize_token
from contextcore.tokens import ContextToken


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
