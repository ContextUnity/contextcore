"""Shared helpers for manifest parsing.

Reusable utilities consumed by both the Core SDK and Router service
to keep tool-ref parsing and graph validation DRY.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence

# ── Tool ref format ──────────────────────────────────────────────
# Explicit refs (used by agent tool allowlists):
#   "platform:brain_search", "federated:sql_query"
# Tool bindings additionally allow bare platform shorthand:
#   "brain_search" == "platform:brain_search"
_TOOL_NAME_RE = r"[a-z_][a-z0-9_]{0,127}"
TOOL_REF_RE = re.compile(rf"^(?:platform:|federated:){_TOOL_NAME_RE}$")
TOOL_BINDING_RE = re.compile(rf"^(?:(?:platform:|federated:)?{_TOOL_NAME_RE})$")


def parse_tool_ref(value: str) -> tuple[str, str]:
    """Parse a tool reference into (namespace, name).

    Contract:
        - ``federated:<name>`` -> project-owned BiDi tool
        - ``platform:<name>`` -> platform registry tool
        - ``<name>``          -> platform registry shorthand

    Examples:
        >>> parse_tool_ref("federated:my_sql")
        ('federated', 'my_sql')
        >>> parse_tool_ref("platform:brain_search")
        ('platform', 'brain_search')
        >>> parse_tool_ref("brain_search")
        ('platform', 'brain_search')
    """
    stripped = value.strip()
    if stripped.startswith("federated:"):
        return "federated", stripped[len("federated:") :]
    if stripped.startswith("platform:"):
        return "platform", stripped[len("platform:") :]
    return "platform", stripped


# ── Graph source shape validation ────────────────────────────────
# Shared logic used by Core RouterGraph, Router GraphEntry, and
# any future graph model to enforce exactly-one-source invariant.


def validate_graph_source_shape(
    *,
    has_inline: bool,
    has_template: bool,
    has_builtin: bool,
    template: str | None = None,
    overrides: Mapping[str, object] | None = None,
    nodes: Sequence[object] | None = None,
    edges: Sequence[object] | None = None,
    label: str = "graph",
) -> None:
    """Validate that a graph definition has exactly one source.

    Raises:
        ValueError: If source invariants are violated.
    """
    source_count = int(has_inline) + int(has_template) + int(has_builtin)

    if source_count != 1:
        raise ValueError(
            f"{label} must define exactly one graph source: "
            + "exactly one source must be set from inline nodes/edges, template, or builtin"
        )

    if has_inline:
        if nodes is None or len(nodes) == 0:
            raise ValueError(f"inline {label} requires non-empty 'nodes'")
        if edges is None or len(edges) == 0:
            raise ValueError(f"inline {label} requires non-empty 'edges'")
        if overrides:
            raise ValueError(f"inline {label} must not declare template overrides")
        return

    if has_template:
        if template == "local":
            raise ValueError("template='local' was removed in contextunity/v1alpha7; omit template for inline graphs")
        if not template or not template.startswith("yaml:"):
            raise ValueError(f"{label} template must use yaml:<template_name>")
        return

    if has_builtin:
        if overrides:
            raise ValueError(f"{label} builtin sources must not declare template overrides")


__all__ = ["TOOL_BINDING_RE", "TOOL_REF_RE", "parse_tool_ref", "validate_graph_source_shape"]
