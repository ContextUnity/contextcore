"""Tests for contextunity.core.token_utils.http module."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from contextunity.core.token_utils.http import extract_token_string_from_http_request


class TestExtractTokenStringFromHttpRequest:
    """Strong parameterized tests for extract_token_string_from_http_request."""

    @pytest.mark.parametrize(
        ("request_data", "expected_token"),
        [
            # Django META tests
            ({"META": {"HTTP_AUTHORIZATION": "Bearer my-token"}}, "my-token"),
            (
                {"META": {"HTTP_AUTHORIZATION": "bearer my-token"}},
                "",
            ),  # Only exact 'Bearer ' match is supported natively in Django branch
            ({"META": {"HTTP_AUTHORIZATION": "Basic user:pass"}}, ""),
            ({"META": {"HTTP_AUTHORIZATION": "Bearer    "}}, ""),  # Empty after strip
            ({"META": {"HTTP_X_CONTEXT_TOKEN": "my-x-token"}}, "my-x-token"),
            # FastAPI headers tests
            ({"headers": {"authorization": "Bearer my-token"}}, "my-token"),
            ({"headers": {"authorization": "bearer my-token"}}, ""),  # Case sensitive check for 'Bearer '
            ({"headers": {"authorization": "Basic user:pass"}}, ""),
            ({"headers": {"authorization": "Bearer"}}, ""),  # Too short
            ({"headers": {"x-context-token": "my-x-token-header"}}, "my-x-token-header"),
            # Session tests
            ({"session": {"context_token": " session-token "}}, "session-token"),
            ({"session": {"context_token": "   "}}, ""),  # Empty string after strip
            ({"session": {"context_token": None}}, ""),
            ({"session": {"context_token": 123}}, ""),  # Not a string
            # Missing entirely
            ({}, ""),
            ({"META": {}}, ""),
            ({"headers": {}}, ""),
        ],
        ids=[
            "django_bearer",
            "django_bearer_lowercase",
            "django_basic",
            "django_bearer_empty",
            "django_x_header",
            "fastapi_bearer",
            "fastapi_bearer_lowercase",
            "fastapi_basic",
            "fastapi_bearer_too_short",
            "fastapi_x_header",
            "session_valid",
            "session_whitespace",
            "session_none",
            "session_int",
            "empty",
            "empty_meta",
            "empty_headers",
        ],
    )
    def test_extraction_variations(self, request_data, expected_token):
        """Test extraction matrix covering Django, FastAPI, and Session formats."""
        request = SimpleNamespace(**request_data)
        token_str = extract_token_string_from_http_request(request)
        assert token_str == expected_token


class TestBuildVerifierBackend:
    """Strong structural tests for build_verifier_backend_from_token_string."""

    @pytest.fixture
    def mock_discovery(self, monkeypatch):
        mock_get_key = MagicMock()
        mock_fetch_key = MagicMock()
        mock_update_key = MagicMock()

        monkeypatch.setattr("contextunity.core.discovery.get_project_key", mock_get_key)
        monkeypatch.setattr("contextunity.core.token_utils.http.fetch_project_public_key_sync", mock_fetch_key)
        monkeypatch.setattr("contextunity.core.discovery.update_project_public_key", mock_update_key)

        return mock_get_key, mock_fetch_key, mock_update_key

    def test_invalid_token_format_returns_none(self):
        from contextunity.core.token_utils.http import build_verifier_backend_from_token_string

        assert build_verifier_backend_from_token_string("too.few") is None
        assert build_verifier_backend_from_token_string("too.many.parts.here") is None

    def test_legacy_kid_returns_none(self):
        from contextunity.core.token_utils.http import build_verifier_backend_from_token_string

        assert build_verifier_backend_from_token_string("legacykid.payload.sig") is None

    def test_hmac_backend_success(self, mock_discovery):
        mock_get_key, _, _ = mock_discovery
        mock_get_key.return_value = {"project_secret": "my-secret"}

        from contextunity.core.token_utils.http import build_verifier_backend_from_token_string

        backend = build_verifier_backend_from_token_string("proj:v1.payload.sig")

        assert backend is not None
        assert backend.__class__.__name__ == "HmacBackend"

    def test_hmac_backend_missing_secret(self, mock_discovery):
        mock_get_key, _, _ = mock_discovery
        mock_get_key.return_value = {}

        from contextunity.core.token_utils.http import build_verifier_backend_from_token_string

        assert build_verifier_backend_from_token_string("proj:v1.payload.sig") is None

    def test_ed25519_backend_success_from_cache(self, mock_discovery, monkeypatch):
        mock_get_key, _, _ = mock_discovery
        mock_get_key.return_value = {"public_key_b64": "fake-pub-key"}

        mock_ed25519 = MagicMock()
        monkeypatch.setattr("contextunity.core.ed25519.Ed25519Backend", mock_ed25519)

        from contextunity.core.token_utils.http import build_verifier_backend_from_token_string

        backend = build_verifier_backend_from_token_string("proj:session-1.payload.sig")
        assert backend is not None

    def test_ed25519_backend_fetches_from_shield(self, mock_discovery, monkeypatch):
        mock_get_key, mock_fetch_key, mock_update_key = mock_discovery
        mock_get_key.return_value = {}
        mock_fetch_key.return_value = ("fetched-pub-key", "proj:session-1")

        mock_ed25519 = MagicMock()
        monkeypatch.setattr("contextunity.core.ed25519.Ed25519Backend", mock_ed25519)

        from contextunity.core.token_utils.http import build_verifier_backend_from_token_string

        backend = build_verifier_backend_from_token_string("proj:session-1.payload.sig", shield_url="http://shield")
        mock_fetch_key.assert_called_once_with(
            "proj", "proj:session-1", "http://shield", provenance="service:http:fetch_public_key", config=None
        )
        mock_update_key.assert_called_once_with("proj", "fetched-pub-key", "proj:session-1")
        assert backend is not None


pytestmark = pytest.mark.unit
