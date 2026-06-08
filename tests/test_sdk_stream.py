from __future__ import annotations

import queue
from unittest.mock import patch

import pytest
from contextunity.core.sdk.streaming.bidi import (
    FederatedToolCallContext,
    _create_stream_metadata,
    _handle_execute,
)
from contextunity.core.tokens import ContextToken
from google.protobuf.json_format import MessageToDict


class TestFederatedToolStream:
    def test_handle_execute_passes_strict_auth_context(self):
        seen: dict = {}
        response_queue: queue.Queue = queue.Queue()

        def tool_handler(tool_name: str, args: dict, auth_context: FederatedToolCallContext) -> dict:
            seen["tool_name"] = tool_name
            seen["args"] = args
            seen["auth_context"] = auth_context
            return {"row_count": 1, "rows": [{"ok": True}]}

        _handle_execute(
            payload={
                "request_id": "req-123",
                "tool": "execute_test_sql",
                "args": {"sql": "SELECT 1"},
                "caller_tenant": "tenant_a",
                "user_id": "doctor-42",
            },
            tool_handler=tool_handler,
            project_id="tenant_a",
            response_queue=response_queue,
            session=1,
        )

        assert seen["tool_name"] == "execute_test_sql"
        assert seen["args"] == {"sql": "SELECT 1"}
        assert seen["auth_context"] == FederatedToolCallContext(
            project_id="tenant_a",
            tool_name="execute_test_sql",
            request_id="req-123",
            caller_tenant="tenant_a",
            user_id="doctor-42",
        )

        response = response_queue.get_nowait()
        payload = MessageToDict(response.payload)
        assert payload["action"] == "result"
        assert payload["request_id"] == "req-123"
        assert payload["row_count"] == 1

    def test_stream_metadata_uses_session_token_only_in_shield_mode(self):
        from contextunity.core.signing import HmacBackend, SessionTokenBackend

        token = ContextToken(token_id="nszu-executor", allowed_tenants=("nszu",))
        backend = SessionTokenBackend(
            project_id="nszu",
            session_token="shield-session",
            kid="nszu:session-001",
            expires_at=9999999999,
            shield_url="localhost:50054",
            hmac_backend=HmacBackend("nszu", "bootstrap-secret"),
        )

        with patch(
            "contextunity.core.signing._request_session_token",
            return_value=("shield-stream-token", "nszu:session-001", 9999999999),
        ):
            metadata = _create_stream_metadata(token, backend)

        assert metadata == (("authorization", "Bearer shield-stream-token"),)

    def test_stream_metadata_keeps_hmac_token_in_open_source_mode(self):
        from contextunity.core.signing import HmacBackend
        from contextunity.core.token_utils import verify_token_string

        token = ContextToken(token_id="nszu-executor", allowed_tenants=("nszu",))
        backend = HmacBackend("nszu", "open-source-secret")

        metadata = _create_stream_metadata(token, backend)

        assert len(metadata) == 1
        assert metadata[0][0] == "authorization"
        assert metadata[0][1].startswith("Bearer ")
        token_str = metadata[0][1][7:]
        verified = verify_token_string(token_str, backend)
        assert verified is not None
        assert verified.token_id == "nszu-executor"
        assert verified.allowed_tenants == ("nszu",)


pytestmark = pytest.mark.unit
