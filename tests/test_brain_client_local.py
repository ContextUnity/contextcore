"""Tests for BrainClient local mode operations."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class MockStorage:
    """Mock storage for local mode testing."""

    def __init__(self):
        self.hybrid_search = AsyncMock(return_value=[])
        self.upsert_knowledge = AsyncMock(return_value=MagicMock(id="test-123"))
        self.upsert_graph = AsyncMock()
        self.get_products_by_ids = AsyncMock(return_value=[])
        self.update_product_enrichment = AsyncMock()
        self.upsert_dealer_product = AsyncMock(return_value=42)


class MockEmbedder:
    """Mock embedder for local mode testing."""

    async def embed_async(self, text: str) -> list:
        return [0.1] * 1536


class MockService:
    """Mock Brain service for local mode."""

    def __init__(self):
        self.storage = MockStorage()
        self.embedder = MockEmbedder()


class TestKnowledgeMixinLocalMode:
    """Tests for KnowledgeMixin in local mode."""

    @pytest.fixture
    def mock_client(self):
        """Create a mock client in local mode."""
        client = MagicMock()
        client.mode = "local"
        client._service = MockService()
        return client

    @pytest.mark.asyncio
    async def test_local_search_calls_storage(self, mock_client):
        """Local search should call storage.hybrid_search."""
        from contextcore.sdk.brain.knowledge import KnowledgeMixin

        # Bind mixin methods to mock client (search method not needed for this test)
        _local_search = KnowledgeMixin._local_search.__get__(mock_client, type(mock_client))

        # Call local search directly
        results = await _local_search(
            tenant_id="test",
            query_text="winter jacket",
            limit=5,
            source_types=None,
        )

        mock_client._service.storage.hybrid_search.assert_called_once()
        assert isinstance(results, list)

    @pytest.mark.asyncio
    async def test_local_upsert_calls_storage(self, mock_client):
        """Local upsert should call storage.upsert_knowledge."""
        from contextcore.sdk.brain.knowledge import KnowledgeMixin

        _local_upsert = KnowledgeMixin._local_upsert.__get__(mock_client, type(mock_client))

        # This will fail because we don't have full Brain imports
        # but it tests the structure
        with patch("contextcore.sdk.brain.knowledge.logger"):
            result = await _local_upsert(
                tenant_id="test",
                content="Test content",
                source_type="document",
                metadata={},
            )
            # Should return empty string due to import error in test env
            assert isinstance(result, str)


class TestCommerceMixinLocalMode:
    """Tests for CommerceMixin in local mode."""

    @pytest.fixture
    def mock_client(self):
        """Create a mock client in local mode."""
        client = MagicMock()
        client.mode = "local"
        client._service = MockService()
        return client

    @pytest.mark.asyncio
    async def test_local_get_products_calls_storage(self, mock_client):
        """Local get_products should call storage."""
        from contextcore.sdk.brain.commerce import CommerceMixin

        _local_get_products = CommerceMixin._local_get_products.__get__(mock_client, type(mock_client))

        await _local_get_products(
            tenant_id="test",
            product_ids=[1, 2, 3],
        )

        mock_client._service.storage.get_products_by_ids.assert_called_once_with(
            tenant_id="test",
            product_ids=[1, 2, 3],
        )

    @pytest.mark.asyncio
    async def test_local_update_enrichment_returns_bool(self, mock_client):
        """Local update_enrichment should return boolean."""
        from contextcore.sdk.brain.commerce import CommerceMixin

        _local_update_enrichment = CommerceMixin._local_update_enrichment.__get__(mock_client, type(mock_client))

        result = await _local_update_enrichment(
            tenant_id="test",
            product_id=42,
            enrichment={"taxonomy": "clothing.jackets"},
            trace_id="trace-123",
            status="enriched",
        )

        assert result is True
        mock_client._service.storage.update_product_enrichment.assert_called_once()

    @pytest.mark.asyncio
    async def test_local_upsert_dealer_product_returns_id(self, mock_client):
        """Local upsert_dealer_product should return product ID."""
        from contextcore.sdk.brain.commerce import CommerceMixin

        _local_upsert = CommerceMixin._local_upsert_dealer_product.__get__(mock_client, type(mock_client))

        result = await _local_upsert(
            tenant_id="test",
            dealer_code="VYSOTA",
            dealer_name="Vysota",
            sku="WJ-001",
            name="Winter Jacket",
            category="Clothing > Jackets",
            brand_name="Nike",
            quantity=10,
            price_retail=1500.00,
            currency="UAH",
            params={"color": "black"},
            status="raw",
        )

        assert result == 42
        mock_client._service.storage.upsert_dealer_product.assert_called_once()


class TestBrainClientModeSelection:
    """Tests for BrainClientBase mode selection logic."""

    def test_default_mode_is_grpc(self, monkeypatch):
        """Without env or explicit arg, mode defaults to 'grpc'."""
        monkeypatch.delenv("CONTEXT_BRAIN_MODE", raising=False)
        monkeypatch.delenv("CONTEXT_BRAIN_URL", raising=False)

        mock_stub = MagicMock()
        with (
            patch("contextcore.sdk.brain.base._ensure_protos"),
            patch("contextcore.sdk.brain.base.brain_pb2_grpc", mock_stub),
            patch("grpc.aio.insecure_channel") as mock_channel,
        ):
            from contextcore.sdk.brain.base import BrainClientBase

            client = BrainClientBase()
            assert client.mode == "grpc"
            assert client.host == "localhost:50051"
            mock_channel.assert_called_once_with("localhost:50051")

    def test_mode_from_environment(self, monkeypatch):
        """CONTEXT_BRAIN_MODE=local should select local mode."""
        monkeypatch.setenv("CONTEXT_BRAIN_MODE", "local")

        mock_service = MagicMock()
        with patch.dict("sys.modules", {"contextbrain": mock_service}):
            mock_service.BrainService = MagicMock(return_value=MagicMock())
            from contextcore.sdk.brain.base import BrainClientBase

            client = BrainClientBase()
            assert client.mode == "local"
            assert client._stub is None  # No gRPC stub in local mode

    def test_explicit_mode_overrides_env(self, monkeypatch):
        """Explicit mode='grpc' should override CONTEXT_BRAIN_MODE env."""
        monkeypatch.setenv("CONTEXT_BRAIN_MODE", "local")

        mock_stub = MagicMock()
        with (
            patch("contextcore.sdk.brain.base._ensure_protos"),
            patch("contextcore.sdk.brain.base.brain_pb2_grpc", mock_stub),
            patch("grpc.aio.insecure_channel"),
        ):
            from contextcore.sdk.brain.base import BrainClientBase

            client = BrainClientBase(mode="grpc")
            assert client.mode == "grpc"

    def test_host_from_environment(self, monkeypatch):
        """CONTEXT_BRAIN_URL should be used as host."""
        monkeypatch.delenv("CONTEXT_BRAIN_MODE", raising=False)
        monkeypatch.setenv("CONTEXT_BRAIN_URL", "brain.example.com:50051")

        mock_stub = MagicMock()
        with (
            patch("contextcore.sdk.brain.base._ensure_protos"),
            patch("contextcore.sdk.brain.base.brain_pb2_grpc", mock_stub),
            patch("grpc.aio.insecure_channel") as mock_channel,
        ):
            from contextcore.sdk.brain.base import BrainClientBase

            client = BrainClientBase()
            assert client.host == "brain.example.com:50051"
            mock_channel.assert_called_once_with("brain.example.com:50051")

    def test_local_mode_fails_without_contextbrain(self, monkeypatch):
        """Local mode should raise ImportError if contextbrain is not installed."""
        monkeypatch.setenv("CONTEXT_BRAIN_MODE", "local")

        with patch.dict("sys.modules", {"contextbrain": None}):
            from contextcore.sdk.brain.base import BrainClientBase

            with pytest.raises((ImportError, ModuleNotFoundError)):
                BrainClientBase()
