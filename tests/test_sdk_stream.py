from __future__ import annotations

import queue

from contextunity.core.sdk.streaming.bidi import FederatedToolCallContext, _handle_execute
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
