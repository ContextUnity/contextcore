"""Dependency-neutral parsing contracts for documentation BrainCells."""

from __future__ import annotations

import ast
import hashlib
import re
import textwrap
import uuid
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Protocol

from .exceptions import ContextUnityError, register_error
from .types import JsonDict

DEFAULT_LIFECYCLE = "draft"
DEFAULT_VISIBILITY = "internal"
DOCUMENTATION_CELL_KIND = "documentation"
ALLOWED_DOC_TYPES = frozenset(
    {
        "adr",
        "agents_md",
        "api",
        "architecture",
        "changelog",
        "config",
        "config_ref",
        "phase_plan",
        "proto_rpc",
        "proto_service",
        "rpc_reference",
        "runbook",
        "test_runbook",
        "tutorial",
    }
)

_DOC_COMMENT_RE = re.compile(r"^\s*#\s*\[DOC:([A-Za-z][A-Za-z0-9_-]*)\]\s*(.+?)\s*$")
_SERVICE_RE = re.compile(r"\bservice\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{(?P<body>.*?)\n\s*\}", re.DOTALL)
_RPC_RE = re.compile(
    r"\brpc\s+([A-Za-z_][A-Za-z0-9_]*)\s*"
    r"\(\s*([A-Za-z_][A-Za-z0-9_.]*)\s*\)\s*"
    r"returns\s*\(\s*([A-Za-z_][A-Za-z0-9_.]*)\s*\)",
    re.MULTILINE,
)
_YAML_KEY_RE = re.compile(r"^(?P<indent>\s*)(?P<key>[A-Za-z_][A-Za-z0-9_-]*)\s*:")


@register_error("DOCUMENTATION_VALIDATION_ERROR")
class DocumentationValidationError(ContextUnityError):
    """Invalid documentation source or unsupported documentation type."""

    code: str = "DOCUMENTATION_VALIDATION_ERROR"
    message: str = "Documentation source is invalid"


@dataclass(frozen=True)
class DocumentationCellSource:
    """Validated source record ready for a documentation BrainCell write."""

    content: str
    source_path: str
    doc_type: str
    symbol: str
    phase: int = 3
    visibility: str = DEFAULT_VISIBILITY
    lifecycle: str = DEFAULT_LIFECYCLE
    metadata: JsonDict = field(default_factory=dict)


class _DocumentationExtractor(Protocol):
    def __call__(
        self,
        source_path: str,
        content: str,
        *,
        phase: int = 3,
        visibility: str = DEFAULT_VISIBILITY,
        lifecycle: str = DEFAULT_LIFECYCLE,
    ) -> list[DocumentationCellSource]: ...


def content_hash_of(content: str) -> str:
    """Return the stable SHA-256 identity of documentation content."""
    return f"sha256:{hashlib.sha256(content.encode('utf-8')).hexdigest()}"


def validate_documentation_type(doc_type: str) -> str:
    """Return a supported documentation type or fail closed."""
    normalized = doc_type.strip()
    if normalized not in ALLOWED_DOC_TYPES:
        allowed = ", ".join(sorted(ALLOWED_DOC_TYPES))
        raise DocumentationValidationError(f"unsupported documentation type '{doc_type}'; allowed: {allowed}")
    return normalized


def stable_document_identity(source_path: str, symbol: str | None) -> str:
    """Build the normalized path-and-symbol source identity."""
    path = PurePosixPath(source_path).as_posix()
    normalized_symbol = (symbol or "").strip()
    return f"{path}#{normalized_symbol}" if normalized_symbol else path


def deterministic_document_id(source_path: str, symbol: str | None = None) -> str:
    """Build a stable UUID for a documentation source identity."""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"contextunity.doc.{stable_document_identity(source_path, symbol)}"))


def extract_doc_comment_cells(
    source_path: str,
    content: str,
    *,
    phase: int = 3,
    visibility: str = DEFAULT_VISIBILITY,
    lifecycle: str = DEFAULT_LIFECYCLE,
) -> list[DocumentationCellSource]:
    """Extract ``[DOC:type]`` code comments."""
    cells: list[DocumentationCellSource] = []
    for line_no, line in enumerate(textwrap.dedent(content).splitlines(), start=1):
        match = _DOC_COMMENT_RE.match(line)
        if match is None:
            continue
        cells.append(
            DocumentationCellSource(
                content=match.group(2).strip(),
                source_path=source_path,
                doc_type=validate_documentation_type(match.group(1)),
                symbol=f"line:{line_no}",
                phase=phase,
                visibility=visibility,
                lifecycle=lifecycle,
                metadata={"line": line_no},
            )
        )
    return cells


def extract_proto_documentation_cells(
    source_path: str,
    content: str,
    *,
    phase: int = 3,
    visibility: str = DEFAULT_VISIBILITY,
    lifecycle: str = DEFAULT_LIFECYCLE,
) -> list[DocumentationCellSource]:
    """Extract proto services and RPCs."""
    cells: list[DocumentationCellSource] = []
    for service_match in _SERVICE_RE.finditer(textwrap.dedent(content)):
        service = service_match.group(1)
        cells.append(
            DocumentationCellSource(
                content=f"Proto service {service}.",
                source_path=source_path,
                doc_type="proto_service",
                symbol=service,
                phase=phase,
                visibility=visibility,
                lifecycle=lifecycle,
            )
        )
        for rpc_match in _RPC_RE.finditer(service_match.group("body")):
            rpc, request, response = rpc_match.groups()
            symbol = f"{service}.{rpc}"
            cells.append(
                DocumentationCellSource(
                    content=f"Proto RPC {symbol}: {request} -> {response}.",
                    source_path=source_path,
                    doc_type="rpc_reference",
                    symbol=symbol,
                    phase=phase,
                    visibility=visibility,
                    lifecycle=lifecycle,
                    metadata={"request_type": request, "response_type": response},
                )
            )
    return cells


def extract_yaml_config_cells(
    source_path: str,
    content: str,
    *,
    phase: int = 3,
    visibility: str = DEFAULT_VISIBILITY,
    lifecycle: str = DEFAULT_LIFECYCLE,
) -> list[DocumentationCellSource]:
    """Extract hierarchical YAML configuration keys."""
    cells: list[DocumentationCellSource] = []
    stack: list[tuple[int, str]] = []
    for line_no, line in enumerate(textwrap.dedent(content).splitlines(), start=1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = _YAML_KEY_RE.match(line)
        if match is None:
            continue
        indent, key = len(match.group("indent")), match.group("key")
        while stack and stack[-1][0] >= indent:
            stack.pop()
        stack.append((indent, key))
        symbol = ".".join(part for _, part in stack)
        cells.append(
            DocumentationCellSource(
                content=f"Config key {symbol} in {source_path}.",
                source_path=source_path,
                doc_type="config_ref",
                symbol=symbol,
                phase=phase,
                visibility=visibility,
                lifecycle=lifecycle,
                metadata={"line": line_no, "config_key": symbol},
            )
        )
    return cells


def extract_pydantic_config_cells(
    source_path: str,
    content: str,
    *,
    phase: int = 3,
    visibility: str = DEFAULT_VISIBILITY,
    lifecycle: str = DEFAULT_LIFECYCLE,
) -> list[DocumentationCellSource]:
    """Extract annotated fields from Pydantic-style config classes."""
    try:
        tree = ast.parse(textwrap.dedent(content))
    except SyntaxError as exc:
        raise DocumentationValidationError(f"invalid Python source for documentation ingestion: {source_path}") from exc
    cells: list[DocumentationCellSource] = []
    for node in tree.body:
        if not isinstance(node, ast.ClassDef) or not node.name.endswith(("Config", "Settings")):
            continue
        for statement in node.body:
            if not isinstance(statement, ast.AnnAssign) or not isinstance(statement.target, ast.Name):
                continue
            field_name = statement.target.id
            annotation = ast.unparse(statement.annotation)
            symbol = f"{node.name}.{field_name}"
            cells.append(
                DocumentationCellSource(
                    content=f"Pydantic config field {symbol}: {annotation}.",
                    source_path=source_path,
                    doc_type="config_ref",
                    symbol=symbol,
                    phase=phase,
                    visibility=visibility,
                    lifecycle=lifecycle,
                    metadata={"class_name": node.name, "field_name": field_name, "annotation": annotation},
                )
            )
    return cells


def build_test_generated_documentation_cell(
    *,
    source_path: str,
    test_name: str,
    content: str,
    doc_type: str,
    phase: int = 3,
    visibility: str = DEFAULT_VISIBILITY,
    lifecycle: str = DEFAULT_LIFECYCLE,
) -> DocumentationCellSource:
    """Build a changelog/runbook source record generated by a test."""
    clean_type = validate_documentation_type(doc_type)
    if clean_type not in {"changelog", "runbook", "test_runbook"}:
        raise DocumentationValidationError("test-generated documentation must be changelog, runbook, or test_runbook")
    return DocumentationCellSource(
        content=content,
        source_path=source_path,
        doc_type=clean_type,
        symbol=test_name,
        phase=phase,
        visibility=visibility,
        lifecycle=lifecycle,
        metadata={"generated_from": "test", "test_name": test_name},
    )


def extract_documentation_cells(
    source_path: str,
    content: str,
    *,
    phase: int = 3,
    visibility: str = DEFAULT_VISIBILITY,
    lifecycle: str = DEFAULT_LIFECYCLE,
) -> list[DocumentationCellSource]:
    """Extract every supported documentation record from one source file."""
    suffix = PurePosixPath(source_path).suffix.lower()
    extractors: list[_DocumentationExtractor] = []
    if suffix == ".proto":
        extractors.append(extract_proto_documentation_cells)
    if suffix in {".yml", ".yaml"}:
        extractors.append(extract_yaml_config_cells)
    if suffix == ".py":
        extractors.append(extract_pydantic_config_cells)
    extractors.append(extract_doc_comment_cells)
    cells: list[DocumentationCellSource] = []
    for extractor in extractors:
        cells.extend(extractor(source_path, content, phase=phase, visibility=visibility, lifecycle=lifecycle))
    return cells


__all__ = [
    "ALLOWED_DOC_TYPES",
    "DEFAULT_LIFECYCLE",
    "DEFAULT_VISIBILITY",
    "DOCUMENTATION_CELL_KIND",
    "DocumentationCellSource",
    "DocumentationValidationError",
    "build_test_generated_documentation_cell",
    "content_hash_of",
    "deterministic_document_id",
    "extract_doc_comment_cells",
    "extract_documentation_cells",
    "extract_proto_documentation_cells",
    "extract_pydantic_config_cells",
    "extract_yaml_config_cells",
    "stable_document_identity",
    "validate_documentation_type",
]
