"""NewsEngine methods - news items and posts."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..context_unit import ContextUnit
from .base import BrainClientBase, get_context_unit_pb2, logger

if TYPE_CHECKING:
    from typing import List


class NewsMixin:
    """Mixin with NewsEngine operations."""

    async def upsert_news_item(
        self: BrainClientBase,
        tenant_id: str,
        url: str,
        headline: str,
        summary: str = "",
        item_type: str = "raw",
        category: str = "",
        source_api: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Upsert a news item (raw or fact) to Brain.

        Args:
            tenant_id: Tenant identifier.
            url: URL of the news item (used for deduplication).
            headline: News headline.
            summary: News summary/content.
            item_type: "raw" for harvested, "fact" for processed.
            category: News category.
            source_api: Source API name (e.g., "newsapi", "gnews").
            metadata: Additional metadata.

        Returns:
            The ID of the stored news item.
        """
        unit = ContextUnit(
            payload={
                "tenant_id": tenant_id,
                "url": url,
                "headline": headline,
                "summary": summary,
                "item_type": item_type,
                "category": category,
                "source_api": source_api,
                "metadata": metadata or {},
            },
            provenance=["sdk:brain_client:upsert_news_item"],
        )

        if self.mode == "grpc":
            pb2 = get_context_unit_pb2()
            req = unit.to_protobuf(pb2)
            metadata = self._get_metadata()  # Include token in metadata
            response_pb = await self._stub.UpsertNewsItem(req, metadata=metadata)
            result = ContextUnit.from_protobuf(response_pb)
            return result.payload.get("id", "")
        else:
            logger.warning("Local mode not implemented")
            return ""

    async def upsert_news_post(
        self: BrainClientBase,
        tenant_id: str,
        headline: str,
        content: str,
        agent: str,
        emoji: str = "📰",
        fact_url: str = "",
        fact_id: str = "",
        scheduled_at: str | None = None,
    ) -> str:
        """Upsert a generated news post to Brain.

        Args:
            tenant_id: Tenant identifier.
            headline: Post headline.
            content: Post content (generated text).
            agent: Agent/persona that generated this post.
            emoji: Emoji for the post.
            fact_url: Source fact URL.
            fact_id: Source fact ID.
            scheduled_at: ISO datetime for scheduled publishing.

        Returns:
            The ID of the stored post.
        """
        unit = ContextUnit(
            payload={
                "tenant_id": tenant_id,
                "headline": headline,
                "content": content,
                "agent": agent,
                "emoji": emoji,
                "fact_url": fact_url,
                "fact_id": fact_id,
                "scheduled_at": scheduled_at or "",
            },
            provenance=["sdk:brain_client:upsert_news_post"],
        )

        if self.mode == "grpc":
            pb2 = get_context_unit_pb2()
            req = unit.to_protobuf(pb2)
            metadata = self._get_metadata()  # Include token in metadata
            response_pb = await self._stub.UpsertNewsPost(req, metadata=metadata)
            result = ContextUnit.from_protobuf(response_pb)
            return result.payload.get("id", "")
        else:
            logger.warning("Local mode not implemented")
            return ""

    async def get_news_items(
        self: BrainClientBase,
        tenant_id: str,
        item_type: str = "fact",
        limit: int = 20,
        since: str | None = None,
    ) -> "List[dict]":
        """Get news items from Brain.

        Args:
            tenant_id: Tenant identifier.
            item_type: "raw" or "fact".
            limit: Maximum number of items.
            since: ISO datetime to filter items after this time.

        Returns:
            List of news item dictionaries.
        """
        unit = ContextUnit(
            payload={
                "tenant_id": tenant_id,
                "item_type": item_type,
                "limit": limit,
                "since": since or "",
            },
            provenance=["sdk:brain_client:get_news_items"],
        )

        if self.mode == "grpc":
            pb2 = get_context_unit_pb2()
            req = unit.to_protobuf(pb2)
            metadata = self._get_metadata()  # Include token in metadata
            items = []
            async for response_pb in self._stub.GetNewsItems(req, metadata=metadata):
                result = ContextUnit.from_protobuf(response_pb)
                items.append(result.payload)
                if len(items) >= limit:
                    break
            return items
        else:
            logger.warning("Local mode not implemented")
            return []

    async def check_news_post_exists(
        self: BrainClientBase,
        tenant_id: str,
        fact_url: str,
    ) -> bool:
        """Check if a news post with this URL already exists.

        Args:
            tenant_id: Tenant identifier.
            fact_url: URL of the news post to check.

        Returns:
            True if the URL already exists, False otherwise.
        """
        unit = ContextUnit(
            payload={
                "tenant_id": tenant_id,
                "fact_url": fact_url,
            },
            provenance=["sdk:brain_client:check_news_post_exists"],
        )

        if self.mode == "grpc":
            pb2 = get_context_unit_pb2()
            req = unit.to_protobuf(pb2)
            metadata = self._get_metadata()  # Include token in metadata
            response_pb = await self._stub.CheckNewsPostExists(req, metadata=metadata)
            result = ContextUnit.from_protobuf(response_pb)
            return result.payload.get("exists", False)
        else:
            logger.warning("Local mode not implemented")
            return False


__all__ = ["NewsMixin"]
