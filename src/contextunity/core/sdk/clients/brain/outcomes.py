"""Brain-owned delayed outcome observation SDK surface."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Literal

from contextunity.core.grpc_client_errors import wrap_client_error
from contextunity.core.sdk.payload import copy_wire_payload
from contextunity.core.types import ContextUnitPayload

from ...contextunit import ContextUnit

if TYPE_CHECKING:
    from .base import BrainClientBase as _MixinBase
else:
    _MixinBase = object


class OutcomeObservationMixin(_MixinBase):
    async def report_outcome_observation(
        self,
        *,
        trace_id: str,
        graph_run_id: str,
        verdict_digest: str,
        observation_kind: Literal["verified_success", "verified_failure", "neutral"],
        source_ref: str,
        occurred_at: datetime,
        idempotency_key: str,
    ) -> ContextUnitPayload:
        payload: ContextUnitPayload = {
            "observation": {
                "trace_id": trace_id,
                "graph_run_id": graph_run_id,
                "verdict_digest": verdict_digest,
                "observation_kind": observation_kind,
                "source_authority": "operator_review/v1",
                "source_ref": source_ref,
                "occurred_at": occurred_at.isoformat(),
                "idempotency_key": idempotency_key,
            }
        }
        unit = ContextUnit(payload=payload, provenance=["sdk:brain_client:report_outcome"])
        request = unit.to_protobuf(self._cu_pb2)
        with wrap_client_error("Brain", "ReportOutcomeObservation"):
            response = await self._stub.ReportOutcomeObservation(
                request,
                metadata=self._get_metadata(),
            )
        return copy_wire_payload(ContextUnit.from_protobuf(response).payload)


__all__ = ["OutcomeObservationMixin"]
