"""Canonical closed Router control primitives shared by config and Trace wire."""

from __future__ import annotations

from typing import Literal

ControlAction = Literal[
    "continue",
    "degrade",
    "retry",
    "request_replan",
    "abort_soft",
    "abort_hard",
    "request_human_review",
]
ControlReason = Literal[
    "evidence_missing",
    "reference_integrity_mismatch",
    "reference_integrity_stale",
    "effect_state_unknown",
    "committed_effect_requires_review",
    "compensated_effect_requires_policy",
    "replay_unsafe_effect_requires_review",
    "provider_attempt_budget_exhausted",
    "node_attempt_budget_exhausted",
    "graph_cycle_budget_exhausted",
    "side_effect_budget_exhausted",
    "input_token_budget_exhausted",
    "output_token_budget_exhausted",
    "cost_budget_exhausted",
    "wall_time_budget_exhausted",
    "stagnation_low_q_repeated_fault",
    "stagnation_detected",
    "retryable_infra_fault",
    "brain_read_degraded",
    "policy_continue",
]

__all__ = ["ControlAction", "ControlReason"]
