"""Brain Admin RPC methods — cross-tenant observability via admin:read token."""

from __future__ import annotations

from typing import TYPE_CHECKING

from contextunity.core.sdk.payload import get_json_dict, get_json_dict_list
from contextunity.core.sdk.responses import MemoryLayerName
from contextunity.core.trace_inspection import (
    TraceInspection,
    TraceInspectionPage,
    TraceTerminalStatus,
    validate_trace_terminal_status,
)
from contextunity.core.types import ContextUnitPayload, JsonDict

if TYPE_CHECKING:
    from .base import BrainClientBase as _MixinBase
else:
    _MixinBase = object


class BrainAdminMixin(_MixinBase):
    """Mixin with Brain Admin observability RPCs (admin:read gated at Brain)."""

    async def _admin_call(self, rpc_name: str, payload: ContextUnitPayload) -> ContextUnitPayload:
        rpc = getattr(self._stub, rpc_name)
        return await self._call_unary(rpc, payload, rpc_name=rpc_name)

    async def list_tenants(self) -> list[JsonDict]:
        """List tenants the caller may administer."""
        result = await self._admin_call("ListTenants", {})
        return get_json_dict_list(result, "tenants")

    async def admin_search_traces(
        self,
        *,
        tenant_id: str | None = None,
        service: str | None = None,
        agent_id: str | None = None,
        status: TraceTerminalStatus | str | None = None,
        hours: int | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> ContextUnitPayload:
        """Cross-tenant trace search with only storage-backed filters."""
        if service is not None:
            raise ValueError("service filter is unsupported by canonical Trace storage")
        wire: ContextUnitPayload = {"limit": limit, "offset": offset}
        if tenant_id is not None:
            wire["tenant_id"] = tenant_id
        if agent_id is not None:
            wire["agent_id"] = agent_id
        if status is not None:
            wire["status"] = validate_trace_terminal_status(status)
        if hours is not None:
            wire["hours"] = hours
        return await self._admin_call("AdminSearchTraces", wire)

    async def search_trace_inspections(
        self,
        *,
        tenant_id: str | None = None,
        agent_id: str | None = None,
        status: TraceTerminalStatus | str | None = None,
        hours: int | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> TraceInspectionPage:
        """Search using the closed operator-safe Trace projection."""
        payload = await self.admin_search_traces(
            tenant_id=tenant_id,
            agent_id=agent_id,
            status=status,
            hours=hours,
            limit=limit,
            offset=offset,
        )
        return TraceInspectionPage.model_validate(payload)

    async def admin_get_trace_details(self, trace_id: str) -> JsonDict | None:
        """Get legacy full trace details by ID for existing admin consumers."""
        result = await self._admin_call("AdminGetTraceDetails", {"trace_id": trace_id})
        trace = get_json_dict(result, "trace")
        return trace or None

    async def get_trace_inspection(self, trace_id: str) -> TraceInspection | None:
        """Get the closed operator-safe Trace projection by ID."""
        trace = await self.admin_get_trace_details(trace_id)
        return TraceInspection.model_validate(trace) if trace is not None else None

    async def admin_get_system_analytics(
        self,
        *,
        tenant_id: str | None = None,
        hours: int | None = None,
    ) -> JsonDict:
        """Cross-tenant system analytics aggregates."""
        wire: ContextUnitPayload = {}
        if tenant_id is not None:
            wire["tenant_id"] = tenant_id
        if hours is not None:
            wire["hours"] = hours
        result = await self._admin_call("AdminGetSystemAnalytics", wire)
        return get_json_dict(result, "analytics")

    async def admin_get_memory_layer_stats(
        self,
        *,
        tenant_id: str | None = None,
        layer: MemoryLayerName | None = None,
    ) -> JsonDict:
        """Cross-tenant memory layer stats."""
        wire: ContextUnitPayload = {}
        if tenant_id is not None:
            wire["tenant_id"] = tenant_id
        if layer is not None:
            wire["layer"] = layer
        result = await self._admin_call("AdminGetMemoryLayerStats", wire)
        return get_json_dict(result, "layer_stats")

    async def get_filter_options(self, *, tenant_id: str | None = None) -> JsonDict:
        """Distinct filter values from execution traces."""
        wire: ContextUnitPayload = {}
        if tenant_id is not None:
            wire["tenant_id"] = tenant_id
        result = await self._admin_call("AdminGetFilterOptions", wire)
        return get_json_dict(result, "filter_options")

    async def get_session_traces(
        self,
        session_id: str,
        *,
        tenant_id: str | None = None,
    ) -> list[JsonDict]:
        """Fetch all traces for a session_id."""
        wire: ContextUnitPayload = {"session_id": session_id}
        if tenant_id is not None:
            wire["tenant_id"] = tenant_id
        result = await self._admin_call("AdminGetSessionTraces", wire)
        return get_json_dict_list(result, "traces")

    async def get_cells(
        self,
        *,
        tenant_id: str | None = None,
        kind: str | None = None,
        limit: int = 50,
    ) -> list[JsonDict]:
        """List cells with optional tenant/kind filter."""
        wire: ContextUnitPayload = {"limit": limit}
        if tenant_id is not None:
            wire["tenant_id"] = tenant_id
        if kind is not None:
            wire["kind"] = kind
        result = await self._admin_call("AdminGetCells", wire)
        return get_json_dict_list(result, "nodes")

    async def get_analytics_summary(
        self,
        *,
        tenant_id: str | None = None,
        hours: int | None = None,
    ) -> JsonDict:
        """Rich analytics summary with per-hour breakdown and token costs."""
        wire: ContextUnitPayload = {}
        if tenant_id is not None:
            wire["tenant_id"] = tenant_id
        if hours is not None:
            wire["hours"] = hours
        result = await self._admin_call("AdminGetAnalyticsSummary", wire)
        return get_json_dict(result, "analytics")


__all__ = ["BrainAdminMixin"]
