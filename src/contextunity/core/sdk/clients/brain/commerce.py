"""Compatibility BrainClient methods for legacy Commerce RPCs.

New Commerce code should use ``contextunity.commerce.modules.matcher.brain_duckdb``.
This mixin keeps the historical ``BrainClient.match_duckdb`` surface available
while callers migrate.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, TypedDict
from uuid import UUID, uuid4

from contextunity.core.grpc_client_errors import wrap_client_error
from contextunity.core.sdk.contextunit import ContextUnit
from contextunity.core.sdk.payload import get_int, get_json_dict_list
from contextunity.core.types import JsonDict

if TYPE_CHECKING:
    from .base import BrainClientBase as _MixinBase
else:
    _MixinBase = object


class DuckDBMatchResult(TypedDict, total=False):
    """Response from Brain ``MatchDuckDB`` for the legacy SDK method."""

    duckdb_matches: list[JsonDict]
    duckdb_leftovers_count: int


class CommerceCompatMixin(_MixinBase):
    """Deprecated Commerce-specific Brain RPC compatibility methods."""

    async def match_duckdb(
        self,
        *,
        tenant_id: str,
        unmatched_url: str,
        canonical_url: str,
        leftovers_put_url: str,
        trace_id: str | None = None,
        parent_provenance: list[str] | None = None,
    ) -> DuckDBMatchResult:
        """Run legacy DuckDB matching through Brain.

        Prefer the extension-owned Commerce matcher client for new code.
        """
        provenance = list(parent_provenance) if parent_provenance else []
        provenance.append("sdk:brain_client:match_duckdb")

        unit = ContextUnit(
            payload={
                "tenant_id": tenant_id,
                "unmatched_url": unmatched_url,
                "canonical_url": canonical_url,
                "leftovers_put_url": leftovers_put_url,
            },
            provenance=provenance,
            trace_id=UUID(trace_id) if trace_id else uuid4(),
        )

        req = unit.to_protobuf(self._cu_pb2)
        with wrap_client_error("Brain", "MatchDuckDB"):
            response_pb = await self._stub.MatchDuckDB(req, metadata=self._get_metadata())
        result = ContextUnit.from_protobuf(response_pb)
        payload = result.payload
        return DuckDBMatchResult(
            duckdb_matches=get_json_dict_list(payload, "duckdb_matches"),
            duckdb_leftovers_count=get_int(payload, "duckdb_leftovers_count"),
        )


__all__ = ["CommerceCompatMixin", "DuckDBMatchResult"]
