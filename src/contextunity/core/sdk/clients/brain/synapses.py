"""BrainSynapse methods — Flat Memory Phase B.

All operations are delegated to the Brain gRPC service.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from contextunity.core.grpc_client_errors import wrap_client_error
from contextunity.core.sdk.payload import copy_wire_payload, get_float, get_json_dict, get_str
from contextunity.core.sdk.responses import SynapseRecord
from contextunity.core.types import ContextUnitPayload, JsonDict

from ...contextunit import ContextUnit

if TYPE_CHECKING:
    from .base import BrainClientBase as _MixinBase
else:
    _MixinBase = object


class SynapseMixin(_MixinBase):
    """Mixin with BrainSynapse record/query/update-Q operations via gRPC."""

    async def record_synapse(
        self,
        *,
        tenant_id: str | None = None,
        agent_id: str,
        action_type: str,
        action_data: JsonDict | None = None,
        action_data_ref: str | None = None,
        thought_trace_ref: str | None = None,
        content_hash: str | None = None,
        graph_name: str | None = None,
        graph_run_id: str | None = None,
        node_id: str | None = None,
        node_name: str | None = None,
        node_role: str = "worker",
        scope_path: str | None = None,
        context_summary: str | None = None,
        client_id: str | None = None,
        fault_class: str | None = None,
        status: str = "active",
        q_action: float = 0.5,
        q_hypothesis: float = 0.5,
        q_relevance: float = 0.5,
        metadata: JsonDict | None = None,
    ) -> ContextUnitPayload:
        """Record one BrainSynapse learning trace.

        Args:
            tenant_id: Optional tenant override — new callers should omit it
                and let the verified token decide; a mismatch is rejected
                server-side as a policy_fault, never silently coerced.
            agent_id: Agent/actor/node owner.
            action_type: e.g. "plan", "tool_call", "llm_prompt", "route".
            action_data: Small structured action payload, stored inline.
            action_data_ref: PassByRef pointer, used instead of ``action_data`` for large payloads.
            thought_trace_ref: Optional reasoning/provenance PassByRef pointer.
            content_hash: Content hash of the referenced data, when a ref is used.
            graph_name: Graph/manifest name.
            graph_run_id: Run identifier shared by every Synapse from one execution.
            node_id: Graph node identifier that produced the trace.
            node_name: Human-readable node name.
            node_role: One of "planner", "worker", "terminal", "router".
            scope_path: Memory scope path (ltree) for later graph-first retrieval.
            context_summary: Short summary of the context that led to the action.
            client_id: Optional originating client identifier.
            fault_class: One of "agent_fault", "infra_fault", "upstream_fault",
                "policy_fault", "reference_fault", or None.
            status: Lifecycle status, defaults to "active".
            q_action: Action-quality Q-value, clamped server-side to [0.0, 1.0].
            q_hypothesis: Reasoning/plan-quality Q-value, clamped to [0.0, 1.0].
            q_relevance: Context/retrieval-relevance Q-value, clamped to [0.0, 1.0].
            metadata: Extensible metadata (phase, source, provenance, etc.).

        Returns:
            The service response payload unchanged:
            ``{id, agent_id, action_type, node_role, status, q_action, q_hypothesis,
            q_relevance, q_composite, scope_path, metadata, created_at, updated_at}``.
        """
        unit = ContextUnit(
            payload={
                "tenant_id": tenant_id,
                "agent_id": agent_id,
                "action_type": action_type,
                "action_data": action_data or {},
                "action_data_ref": action_data_ref,
                "thought_trace_ref": thought_trace_ref,
                "content_hash": content_hash,
                "graph_name": graph_name,
                "graph_run_id": graph_run_id,
                "node_id": node_id,
                "node_name": node_name,
                "node_role": node_role,
                "scope_path": scope_path,
                "context_summary": context_summary,
                "client_id": client_id,
                "fault_class": fault_class,
                "status": status,
                "q_action": q_action,
                "q_hypothesis": q_hypothesis,
                "q_relevance": q_relevance,
                "metadata": metadata or {},
            },
            provenance=["sdk:brain_client:record_synapse"],
        )

        req = unit.to_protobuf(self._cu_pb2)
        grpc_metadata = self._get_metadata()
        with wrap_client_error("Brain", "RecordSynapse"):
            response_pb = await self._stub.RecordSynapse(req, metadata=grpc_metadata)
        result = ContextUnit.from_protobuf(response_pb)
        return copy_wire_payload(result.payload)

    async def query_synapses(
        self,
        *,
        tenant_id: str | None = None,
        action_type: str | None = None,
        agent_id: str | None = None,
        node_role: str | None = None,
        status: str | None = None,
        scope_path: str | None = None,
        min_q: float = 0.6,
        limit: int = 5,
    ) -> list[SynapseRecord]:
        """Query BrainSynapses, ranked by q_composite and bounded by limit.

        Args:
            tenant_id: Optional tenant override — see ``record_synapse``.
            action_type: Optional action-type filter.
            agent_id: Optional agent filter.
            node_role: Optional node-role filter.
            status: Optional exact lifecycle-status filter. When omitted, the
                server defaults to the production-learning set
                (``active``, ``confirmed``).
            scope_path: Optional ltree scope filter (matches the path and its descendants).
            min_q: Minimum q_composite to include.
            limit: Maximum rows to return; always bounded, never a full scan.

        Returns:
            Rows ordered by q_composite descending.
        """
        unit = ContextUnit(
            payload={
                "tenant_id": tenant_id,
                "action_type": action_type,
                "agent_id": agent_id,
                "node_role": node_role,
                "status": status,
                "scope_path": scope_path,
                "min_q": min_q,
                "limit": limit,
            },
            provenance=["sdk:brain_client:query_synapses"],
        )

        req = unit.to_protobuf(self._cu_pb2)
        grpc_metadata = self._get_metadata()
        records: list[SynapseRecord] = []
        with wrap_client_error("Brain", "QuerySynapses"):
            async for response_pb in self._stub.QuerySynapses(req, metadata=grpc_metadata):
                result = ContextUnit.from_protobuf(response_pb)
                p = result.payload
                records.append(
                    SynapseRecord(
                        id=get_str(p, "id"),
                        graph_name=get_str(p, "graph_name"),
                        graph_run_id=get_str(p, "graph_run_id"),
                        node_id=get_str(p, "node_id"),
                        node_name=get_str(p, "node_name"),
                        agent_id=get_str(p, "agent_id"),
                        action_type=get_str(p, "action_type"),
                        action_data=get_json_dict(p, "action_data"),
                        action_data_ref=get_str(p, "action_data_ref"),
                        context_summary=get_str(p, "context_summary"),
                        thought_trace_ref=get_str(p, "thought_trace_ref"),
                        content_hash=get_str(p, "content_hash"),
                        node_role=get_str(p, "node_role"),
                        fault_class=get_str(p, "fault_class"),
                        status=get_str(p, "status"),
                        q_action=get_float(p, "q_action"),
                        q_hypothesis=get_float(p, "q_hypothesis"),
                        q_relevance=get_float(p, "q_relevance"),
                        q_composite=get_float(p, "q_composite"),
                        scope_path=get_str(p, "scope_path"),
                        metadata=get_json_dict(p, "metadata"),
                        created_at=get_str(p, "created_at"),
                        updated_at=get_str(p, "updated_at"),
                    )
                )
                if len(records) >= limit:
                    break
        return records

    async def update_synapse_q(
        self,
        *,
        synapse_id: str,
        q_action: float | None = None,
        q_hypothesis: float | None = None,
        q_relevance: float | None = None,
        fault_class: str | None = None,
        status: str | None = None,
        metadata: JsonDict | None = None,
        review_id: str | None = None,
        event_id: str | None = None,
        reward_source: str | None = None,
        node_role: str | None = None,
        success: bool | None = None,
        current_q_action: float | None = None,
        current_q_hypothesis: float | None = None,
        current_q_relevance: float | None = None,
    ) -> ContextUnitPayload:
        """Update Q-values/fault/status on one tenant-owned Synapse.

        Args:
            synapse_id: Target Synapse ID.
            q_action: New action-quality Q-value, or None to leave unchanged.
            q_hypothesis: New reasoning-quality Q-value, or None to leave unchanged.
            q_relevance: New relevance Q-value, or None to leave unchanged.
            fault_class: New fault classification, or None to leave unchanged.
            status: New lifecycle status, or None to leave unchanged.
            metadata: Metadata keys to shallow-merge into existing metadata.
            review_id: Explicit-review idempotency key — replaying the same
                ``review_id`` applies the update at most once.
            event_id: Automated-reward-source idempotency key (mutually
                exclusive in practice with ``review_id``; the server prefers
                ``review_id`` if both are somehow set).
            reward_source: When set to ``"node_execution"``, the server
                computes ``q_action``/``q_hypothesis``/``q_relevance``
                itself from ``current_q_*`` and ``success`` via
                ``reward_policy.apply_node_execution_reward`` instead of
                using the explicit Q-value args above (mutually exclusive
                with them).
            node_role: One of ``"planner"``, ``"worker"``, ``"terminal"``,
                ``"router"`` — required when ``reward_source`` is set.
            success: Whether the node execution succeeded — required when
                ``reward_source`` is set.
            current_q_action: Required baseline Q-value for ``reward_source``
                updates; ignored otherwise.
            current_q_hypothesis: See ``current_q_action``.
            current_q_relevance: See ``current_q_action``.

        Returns:
            The service response payload unchanged:
            ``{id, q_action, q_hypothesis, q_relevance, q_composite, updated_at}``.
        """
        unit = ContextUnit(
            payload={
                "synapse_id": synapse_id,
                "q_action": q_action,
                "q_hypothesis": q_hypothesis,
                "q_relevance": q_relevance,
                "fault_class": fault_class,
                "status": status,
                "metadata": metadata or {},
                "review_id": review_id,
                "event_id": event_id,
                "reward_source": reward_source,
                "node_role": node_role,
                "success": success,
                "current_q_action": current_q_action,
                "current_q_hypothesis": current_q_hypothesis,
                "current_q_relevance": current_q_relevance,
            },
            provenance=["sdk:brain_client:update_synapse_q"],
        )

        req = unit.to_protobuf(self._cu_pb2)
        grpc_metadata = self._get_metadata()
        with wrap_client_error("Brain", "UpdateSynapseQ"):
            response_pb = await self._stub.UpdateSynapseQ(req, metadata=grpc_metadata)
        result = ContextUnit.from_protobuf(response_pb)
        return copy_wire_payload(result.payload)


__all__ = ["SynapseMixin"]
