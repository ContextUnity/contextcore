"""UniversalDebugBus methods over the Brain ContextUnit service."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from contextunity.core.grpc_client_errors import wrap_client_error
from contextunity.core.sdk.payload import get_json_dict
from contextunity.core.types import ContextUnitPayload
from contextunity.core.udb import (
    DebugCase,
    DebugCaseDetail,
    DebugCaseQuery,
    FaultOccurrence,
    MitigationAttempt,
    RecoveryEvidence,
    ReopenDebugCase,
    ResolveDebugCase,
)

from ...contextunit import ContextUnit

if TYPE_CHECKING:
    from .base import BrainClientBase as _MixinBase
else:
    _MixinBase = object


class UdbMixin(_MixinBase):
    """Typed UDB lifecycle and bounded case-query surface."""

    async def _udb_case_call(self, rpc_name: str, payload: ContextUnitPayload) -> DebugCase:
        unit = ContextUnit(payload=payload, provenance=[f"sdk:brain_client:{rpc_name.lower()}"])
        rpc = getattr(self._stub, rpc_name)
        with wrap_client_error("Brain", rpc_name):
            response_pb = await rpc(unit.to_protobuf(self._cu_pb2), metadata=self._get_metadata())
        response = ContextUnit.from_protobuf(response_pb)
        return DebugCase.model_validate(get_json_dict(response.payload, "case"))

    async def report_fault_occurrence(self, occurrence: FaultOccurrence) -> DebugCase:
        return await self._udb_case_call("ReportFaultOccurrence", {"occurrence": occurrence.model_dump(mode="json")})

    async def report_recovery_evidence(self, evidence: RecoveryEvidence) -> DebugCase:
        return await self._udb_case_call("ReportRecoveryEvidence", {"evidence": evidence.model_dump(mode="json")})

    async def report_mitigation_attempt(self, attempt: MitigationAttempt) -> DebugCase:
        return await self._udb_case_call("ReportMitigationAttempt", {"attempt": attempt.model_dump(mode="json")})

    async def resolve_debug_case(self, command: ResolveDebugCase) -> DebugCase:
        return await self._udb_case_call("ResolveDebugCase", {"command": command.model_dump(mode="json")})

    async def reopen_debug_case(self, command: ReopenDebugCase) -> DebugCase:
        return await self._udb_case_call("ReopenDebugCase", {"command": command.model_dump(mode="json")})

    async def get_debug_case(
        self,
        case_id: UUID,
        *,
        tenant_id: str | None = None,
    ) -> DebugCase:
        payload: ContextUnitPayload = {"case_id": str(case_id)}
        if tenant_id is not None:
            payload["tenant_id"] = tenant_id
        return await self._udb_case_call("GetDebugCase", payload)

    async def get_debug_case_detail(
        self,
        case_id: UUID,
        *,
        tenant_id: str | None = None,
        history_limit: int = 20,
    ) -> DebugCaseDetail:
        """Read one case with independently bounded operator history."""
        payload: ContextUnitPayload = {
            "case_id": str(case_id),
            "include_history": True,
            "history_limit": history_limit,
        }
        if tenant_id is not None:
            payload["tenant_id"] = tenant_id
        rpc = getattr(self._stub, "GetDebugCase")
        with wrap_client_error("Brain", "GetDebugCase"):
            response_pb = await rpc(
                ContextUnit(
                    payload=payload,
                    provenance=["sdk:brain_client:getdebugcase"],
                ).to_protobuf(self._cu_pb2),
                metadata=self._get_metadata(),
            )
        response = ContextUnit.from_protobuf(response_pb)
        return DebugCaseDetail.model_validate(get_json_dict(response.payload, "detail"))

    async def _query_udb(
        self,
        rpc_name: str,
        query: DebugCaseQuery,
        *,
        tenant_id: str | None,
    ) -> list[DebugCase]:
        payload: ContextUnitPayload = {"query": query.model_dump(mode="json")}
        if tenant_id is not None:
            payload["tenant_id"] = tenant_id
        unit = ContextUnit(
            payload=payload,
            provenance=[f"sdk:brain_client:{rpc_name.lower()}"],
        )
        rpc = getattr(self._stub, rpc_name)
        cases: list[DebugCase] = []
        with wrap_client_error("Brain", rpc_name):
            async for response_pb in rpc(
                unit.to_protobuf(self._cu_pb2),
                metadata=self._get_metadata(),
            ):
                response = ContextUnit.from_protobuf(response_pb)
                cases.append(DebugCase.model_validate(get_json_dict(response.payload, "case")))
                if len(cases) >= query.limit:
                    break
        return cases

    async def query_debug_cases(
        self,
        query: DebugCaseQuery,
        *,
        tenant_id: str | None = None,
    ) -> list[DebugCase]:
        return await self._query_udb("QueryDebugCases", query, tenant_id=tenant_id)

    async def query_recurring_faults(
        self,
        query: DebugCaseQuery,
        *,
        tenant_id: str | None = None,
    ) -> list[DebugCase]:
        return await self._query_udb("QueryRecurringFaults", query, tenant_id=tenant_id)


__all__ = ["UdbMixin"]
