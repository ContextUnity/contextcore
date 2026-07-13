# ContextCore — Agent Instructions

Kernel package of the platform containing shared types (`ContextUnit`, `ContextToken`), gRPC contracts, signing backends, authorization engine, service SDKs, and exceptions.

**Types & payloads (canonical):** [docs/architecture/type-boundaries.md](../../docs/architecture/type-boundaries.md)
**Code quality:** [docs/architecture/code-quality.md](../../docs/architecture/code-quality.md)
**Monorepo agent rules:** [AGENTS.md](../../AGENTS.md)

## Entry & verification

Run from monorepo root (`contextunity/`).

| Task | Command |
|------|---------|
| Tests | `uv run pytest packages/core/tests -q --tb=short` |
| Lint | `uv run ruff check packages/core/src packages/core/tests` |
| Types (core — strict) | `uv run basedpyright packages/core/src --warnings` |
| Monorepo gate | `uv run basedpyright --project pyrightconfig.json --warnings` |
| Architecture | `uv run pytest tests/test_architecture_conformance.py -q` |
| Runtime guards (§8.1) | `uv run pytest packages/core/tests/test_contract_boundaries.py packages/core/tests/test_security.py -q` |

Workspace: `packages/core/` (`src/contextunity/core/`).

## Always-On Invariants

1. **Pure Infrastructure (Zero Business Logic)**: Core must remain completely generic. Never reference specific project domains (e.g. nszu, traverse), tenant IDs, or product-specific schemas in code.
2. **Strict Dependency Bound**: Heavy dependencies (e.g., encryption backends, KMS clients) must be loaded lazily to keep the core package load times minimal.
3. **Protobuf Evolution Policy**: If you modify any `.proto` file in `protos/`, you MUST immediately run:
   ```bash
   uv run python scripts/build_protos.py
   ```
   Never modify generated `*_pb2.py` or `*_pb2_grpc.py` files directly.
4. **Exception Hierarchy**: All exceptions must inherit from `ContextUnityError`. Map all gRPC endpoints to standard codes using the centralized `ErrorRegistry`.
5. **Config Isolation**: All environment variables and settings must be accessed via centralized configs (`SharedConfig` or `SharedSecurityConfig`). No bare `os.getenv()` in logic files.
6. **Token & Crypto Utilities**: No inline HMAC, signing, or encryption. Use `contextunity.core.token_utils` and the centralized signing backends.
7. **Universal Envelope**: All gRPC RPC handlers must use `ContextUnit` as the universal envelope message. Domain-specific data resides in the `payload` dictionary.
8. **Type layers**: L0–L4 per [type-boundaries.md](../../docs/architecture/type-boundaries.md). Services import from `contextunity.core.types` / `contextunity.core.sdk.types` — never redefine `JsonValue`, `ContextUnitPayload`, or parallel trees. **Narrowing:** L2 guards → `types.is_json_*`; L3 payload keys → `sdk.payload.get_*`; bare `object` → `contextunity.core.narrowing` (§4.5). No `cast`, `Any`, or `# type: ignore` on boundary fixes.

## Primary Skill Routing

Choose at most **1 primary skill** based on the target task:

| Trigger | Skill |
|---------|-------|
| New platform capability / shared SDK surface / cross-service contract flow | **`acdd-feature-development`** (then `contract-boundaries` + `tdd` as needed) |
| `types.py`, `parsing.py`, SDK payloads, JSON/gRPC seams, `basedpyright` | **`contract-boundaries`** (primary) → **`type-validation`** |
| `.proto` changes | `proto-change` |
| Exceptions, registry, config schemas | `core-contract-change` (also read **`contract-boundaries`** for type touches) |
| Security interceptors / Authz | `security-implementation` |
| Implementation loop (Red-Green after ACDD or small fix) | `tdd` |
| File add/move/delete | `mempalace-files-changed` |

## Workflow Routing (Slash Commands)

| Command | Workflow |
|---------|----------|
| ACDD feature loop | [/acdd](../../.agents/workflows/acdd-feature-development.md) |
| Contract boundaries | [/contract-boundaries](../../.agents/workflows/contract-boundaries.md) |
| Documentation standards | [/documentation-standard](../../.agents/workflows/documentation-standard.md) |
| gRPC Brain Client SDK | [/brain-sdk](../../.agents/workflows/brain-sdk.md) |
