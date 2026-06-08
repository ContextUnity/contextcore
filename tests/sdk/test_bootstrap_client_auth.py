"""Bootstrap client auth metadata — SessionTokenBackend attenuation."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from contextunity.core.signing import SessionTokenBackend


@pytest.mark.unit
def test_bootstrap_metadata_prefers_global_signing_backend():
    from contextunity.core.sdk.bootstrap.client import _bootstrap_metadata

    session = MagicMock(spec=SessionTokenBackend)
    session.create_grpc_metadata.return_value = (("authorization", "Bearer session-token"),)

    with patch("contextunity.core.signing.get_signing_backend", return_value=session):
        meta = _bootstrap_metadata(
            project_id="nszu",
            backend=None,
            token_id_suffix="shield-sync",
            permissions=("shield:secrets:write",),
        )

    assert meta == (("authorization", "Bearer session-token"),)
    session.create_grpc_metadata.assert_called_once()
    sent_token = session.create_grpc_metadata.call_args.args[0]
    assert sent_token.permissions == ("shield:secrets:write",)
    assert sent_token.allowed_tenants == ("nszu",)
