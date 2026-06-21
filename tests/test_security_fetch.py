"""Behavioral tests for security.fetch.fetch_safe_url — SSRF-safe fetching.

SSRF-validation tests need no network: ``validate_safe_url`` runs (and raises)
before httpx is touched. Fetch-path tests inject a fake ``httpx.AsyncClient`` so
they stay deterministic and offline while exercising the redirect / size /
status / transport branches.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator

import httpx
import pytest
from contextunity.core.exceptions import ResourceFetchError, SecurityError
from contextunity.core.security import fetch_safe_url, fetch_safe_url_sync

pytestmark = [pytest.mark.unit, pytest.mark.asyncio]


class TestSsrfValidationBlocks:
    """The SSRF policy is enforced before any socket is opened."""

    @pytest.mark.parametrize(
        "url",
        [
            "http://169.254.169.254/latest/meta-data/",
            "http://localhost/admin",
            "http://kubernetes.default.svc/api",
        ],
        ids=["aws-metadata", "localhost", "k8s"],
    )
    async def test_internal_targets_rejected(self, url: str) -> None:
        """Metadata / loopback / k8s targets raise SecurityError, never fetched."""
        with pytest.raises(SecurityError):
            await fetch_safe_url(url)

    @pytest.mark.parametrize(
        "url",
        ["file:///etc/passwd", "ftp://example.com/x", "gopher://internal"],
        ids=["file", "ftp", "gopher"],
    )
    async def test_dangerous_schemes_rejected(self, url: str) -> None:
        """Non-http(s) schemes raise SecurityError."""
        with pytest.raises(SecurityError, match="Unsafe URL scheme"):
            await fetch_safe_url(url)

    async def test_empty_url_rejected(self) -> None:
        """Empty URL raises SecurityError."""
        with pytest.raises(SecurityError, match="non-empty"):
            await fetch_safe_url("")


class _FakeResponse:
    """Minimal streaming-response stand-in for httpx.Response."""

    def __init__(self, *, status_code: int, chunks: list[bytes], is_redirect: bool = False) -> None:
        self.status_code = status_code
        self.is_redirect = is_redirect
        self._chunks = chunks

    async def aiter_bytes(self) -> AsyncIterator[bytes]:
        for chunk in self._chunks:
            yield chunk

    def iter_bytes(self) -> Iterator[bytes]:
        yield from self._chunks


class _FakeStreamCtx:
    """Async context manager returned by ``client.stream(...)``."""

    def __init__(self, response: _FakeResponse | None, error: Exception | None) -> None:
        self._response = response
        self._error = error

    async def __aenter__(self) -> _FakeResponse:
        if self._error is not None:
            raise self._error
        if self._response is None:
            raise AssertionError("fake stream needs a response or an error")
        return self._response

    async def __aexit__(self, *_exc: object) -> bool:
        return False


class _FakeSyncStreamCtx:
    """Sync context manager returned by ``client.stream(...)``."""

    def __init__(self, response: _FakeResponse | None, error: Exception | None) -> None:
        self._response = response
        self._error = error

    def __enter__(self) -> _FakeResponse:
        if self._error is not None:
            raise self._error
        if self._response is None:
            raise AssertionError("fake stream needs a response or an error")
        return self._response

    def __exit__(self, *_exc: object) -> bool:
        return False


def _install_fake_client(
    monkeypatch: pytest.MonkeyPatch,
    *,
    response: _FakeResponse | None = None,
    error: Exception | None = None,
) -> None:
    """Replace ``httpx.AsyncClient`` with a fake that yields *response* / *error*."""

    class _FakeAsyncClient:
        def __init__(self, **_kwargs: object) -> None:
            pass

        async def __aenter__(self) -> "_FakeAsyncClient":
            return self

        async def __aexit__(self, *_exc: object) -> bool:
            return False

        def stream(self, _method: str, _url: str, **_kwargs: object) -> _FakeStreamCtx:
            return _FakeStreamCtx(response, error)

    monkeypatch.setattr(httpx, "AsyncClient", _FakeAsyncClient)


def _install_fake_sync_client(
    monkeypatch: pytest.MonkeyPatch,
    *,
    response: _FakeResponse | None = None,
    error: Exception | None = None,
) -> None:
    """Replace ``httpx.Client`` with a fake that yields *response* / *error*."""

    class _FakeClient:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def __enter__(self) -> "_FakeClient":
            return self

        def __exit__(self, *_exc: object) -> bool:
            return False

        def stream(self, _method: str, _url: str, **_kwargs: object) -> _FakeSyncStreamCtx:
            return _FakeSyncStreamCtx(response, error)

    monkeypatch.setattr(httpx, "Client", _FakeClient)


class TestFetchBehavior:
    """Validated URLs are fetched with bounded redirect / size / status / transport."""

    async def test_successful_fetch_returns_joined_bytes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_fake_client(monkeypatch, response=_FakeResponse(status_code=200, chunks=[b"hello", b"-world"]))
        data = await fetch_safe_url("https://example.com/file.bin")
        assert data == b"hello-world"

    async def test_redirect_is_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_fake_client(monkeypatch, response=_FakeResponse(status_code=302, chunks=[], is_redirect=True))
        with pytest.raises(SecurityError, match="redirect"):
            await fetch_safe_url("https://example.com/redirect")

    async def test_oversize_body_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_fake_client(monkeypatch, response=_FakeResponse(status_code=200, chunks=[b"x" * 1024]))
        with pytest.raises(SecurityError, match="limit"):
            await fetch_safe_url("https://example.com/big", max_bytes=512)

    async def test_error_status_wrapped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_fake_client(monkeypatch, response=_FakeResponse(status_code=404, chunks=[]))
        with pytest.raises(ResourceFetchError, match="HTTP 404"):
            await fetch_safe_url("https://example.com/missing")

    async def test_transport_error_wrapped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_fake_client(monkeypatch, error=httpx.ConnectError("boom"))
        with pytest.raises(ResourceFetchError, match="Failed to fetch"):
            await fetch_safe_url("https://example.com/down")


class TestSyncFetchBehavior:
    """Sync helper enforces the same bounded fetch behavior."""

    async def test_successful_sync_fetch_returns_joined_bytes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_fake_sync_client(
            monkeypatch,
            response=_FakeResponse(status_code=200, chunks=[b"<html>", b"</html>"]),
        )
        data = fetch_safe_url_sync("https://example.com/page", headers={"User-Agent": "test"})
        assert data == b"<html></html>"

    async def test_sync_redirect_is_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_fake_sync_client(monkeypatch, response=_FakeResponse(status_code=302, chunks=[], is_redirect=True))
        with pytest.raises(SecurityError, match="redirect"):
            fetch_safe_url_sync("https://example.com/redirect")
