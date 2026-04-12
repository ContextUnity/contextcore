# ContextUnity Core — Agent Instructions

Kernel: shared types (`ContextUnit`, `ContextToken`), gRPC contracts (Protobufs), signing backends, authorization engine, service SDKs, and centralized exceptions.

## Entry & Execution
- **Workspace**: `packages/core/`
- **Proto compilation**: `uv run python scripts/build_protos.py` (from monorepo root). NEVER edit `*_pb2.py` files.
- **Tests**: `uv run --package contextunity-core pytest`
- **Lint**: `uv run ruff check .`

## Code Standards
You MUST adhere to [Code Standards](../../.agent/skills/code_standards/SKILL.md): 400-line limit, Pydantic strictness, `mise` sync, Ruff compliance.

## Architecture

```
src/contextunity/core/
├── manifest/                    # Declarative Layer
│   ├── models.py                # ContextUnityProject (Pydantic schema)
│   ├── generators.py            # ArtifactGenerator (manifest → bundles)
│   └── examples/                # Canonical manifest examples
│
├── sdk/                         # Runtime Layer (clients + bootstrap)
│   ├── bootstrap/               # Project bootstrap (package)
│   │   ├── api.py               # bootstrap_standalone(), bootstrap_django()
│   │   ├── client.py            # Client factory
│   │   ├── helpers.py           # Bootstrap utilities
│   │   ├── loop.py              # Event loop management
│   │   └── manifest.py          # Manifest-driven bootstrap
│   ├── clients/                 # Service clients
│   │   ├── brain/               # BrainClient (modular)
│   │   │   ├── base.py          # Connection, channel
│   │   │   ├── knowledge.py     # Search, Upsert, GraphSearch, KG
│   │   │   ├── commerce.py      # Commerce operations
│   │   │   ├── memory.py        # Episodic + entity memory
│   │   │   └── traces.py        # Agent execution traces
│   │   ├── router.py            # RouterClient (gRPC)
│   │   └── worker.py            # WorkerClient (gRPC)
│   ├── streaming/               # BiDi streaming
│   │   ├── bidi.py              # ToolExecutorStream transport
│   │   └── heartbeat.py         # Stream heartbeat
│   ├── config.py                # ProjectBootstrapConfig (validated env)
│   ├── identity.py              # get_project_id(), get_tenant_id()
│   ├── contextunit.py           # ContextUnit (Pydantic model)
│   ├── models.py                # SecurityScopes, UnitMetrics, CotStep
│   ├── prompt_integrity.py      # HMAC prompt signing/verification
│   └── tools.py                 # @federated_tool decorator
│
├── authz/                       # Unified Authorization Engine
│   ├── engine.py                # authorize(), AuthzDecision, VerifiedAuthContext
│   ├── access_manager.py        # AccessManager
│   ├── context.py               # AuthContext
│   └── __init__.py              # get_auth_context(), set_auth_context()
│
├── security/                    # Security Infrastructure
│   ├── interceptors.py          # ServicePermissionInterceptor (base)
│   └── utils.py                 # Security helpers
│
├── permissions/                 # Permission Registry
│   ├── constants.py             # Permissions class, NAMESPACE_PROFILES
│   ├── inheritance.py           # PERMISSION_INHERITANCE, expand_permissions
│   ├── access.py                # has_tool_access, has_graph_access, etc.
│   ├── policy.py                # Permission policies
│   └── validation.py            # Permission validation
│
├── token_utils/                 # Token utilities (package)
│   ├── serialization.py         # serialize_token, parse_token_string
│   ├── grpc.py                  # gRPC metadata extraction
│   ├── http.py                  # HTTP header extraction
│   ├── sdk.py                   # SDK token helpers
│   └── public_key.py            # Public key utilities
│
├── tokens.py                    # ContextToken, TokenBuilder
├── signing.py                   # SigningBackend, HmacBackend, SessionTokenBackend
├── ed25519.py                   # Ed25519Backend
├── config.py                    # SharedConfig, SharedSecurityConfig
├── logging.py                   # setup_logging, get_contextunit_logger
├── exceptions.py                # ContextUnityError hierarchy, ErrorRegistry
├── discovery.py                 # Redis-based service registration
├── grpc_utils.py                # Channel creation, TLS
├── interfaces.py                # BaseTransformer ABCs
│
├── cli/                         # CLI tools
│   ├── main.py                  # CLI entrypoint
│   ├── mint.py                  # Key generation (hmac, shield, redis, rotate)
│   └── validate.py              # Manifest validation
│
├── *_pb2.py                     # Generated: gRPC stubs (8 protos)
└── *_pb2_grpc.py                # Generated: gRPC stubs

protos/
├── brain.proto                  # BrainService (17 RPCs)
├── commerce.proto               # CommerceService (8 RPCs)
├── worker.proto                 # WorkerService (3 RPCs)
├── router.proto                 # RouterService
├── admin.proto                  # AdminService
├── shield.proto                 # ShieldService
├── zero.proto                   # ZeroService
└── contextunit.proto            # Base ContextUnit definition
```

## Strict Boundaries
- **ZERO Business Logic**: Core is purely infrastructure. No project names, tenant IDs, or domain terms.
- **Minimal Dependencies**: Only `grpcio`, `protobuf`, `pydantic`. Heavy deps (`kms`, `cryptography`) via lazy imports.
- **Proto Stability**: Proto fields MUST be appended, never deleted or renumbered.
- **Config-First**: All env vars through `SharedConfig`/`SharedSecurityConfig`. No `os.getenv()` outside config modules.
- **Exception Hierarchy**: All exceptions extend `ContextUnityError`. Use `ErrorRegistry` for gRPC mapping.
- **Import Pattern**: Services import from `contextunity.core`, never copy protos locally.

## gRPC Envelope
ALL gRPC RPCs use `ContextUnit` as the universal message type:
```protobuf
rpc Search(contextunity.core.ContextUnit) returns (stream contextunity.core.ContextUnit);
```
Domain-specific data goes in `payload` dict. This unifies the protocol across all 8 services.

## Authorization Engine
Single `authorize()` function in `authz/engine.py`:
```python
from contextunity.core.authz import authorize, get_auth_context
auth_ctx = get_auth_context()
decision = authorize(auth_ctx, permission="brain:write", tenant_id="my_project")
if decision.denied:
    context.abort(grpc.StatusCode.PERMISSION_DENIED, decision.reason)
```

## Signing Backends
Auto-detected during bootstrap — no configuration toggles:
- `SessionTokenBackend` (Enterprise): `services.shield.enabled=true` + `CU_SHIELD_GRPC_URL`
- `HmacBackend` (Open Source): `CU_PROJECT_SECRET` set
- **No UnsignedBackend. No SECURITY_ENFORCEMENT. Security is always on.**

## Configuration

| Variable | Description |
|----------|-------------|
| `LOG_LEVEL` | Logging level (INFO default) |
| `REDIS_URL` | Redis connection for discovery |
| `CU_PROJECT_SECRET` | HMAC secret (Open Source) |
| `CU_SHIELD_GRPC_URL` | Shield endpoint (Enterprise) |
| `REDIS_SECRET_KEY` | Redis encryption key (`false` for dev) |
| `OTEL_ENABLED` | OpenTelemetry toggle |

## Golden Paths

### Adding a Proto Field
1. Edit `.proto` in `protos/` — ALWAYS append, never renumber
2. Run `uv run python scripts/build_protos.py`
3. `uv sync` in consuming services
4. Update conformance tests

### Adding a New Exception
1. Create class extending `ContextUnityError` in `exceptions.py`
2. Register in `ErrorRegistry` with gRPC status mapping
3. Add to `__init__.py` public exports

### Adding a Permission
1. Add constant to `permissions/constants.py`
2. If inheritable, add to `PERMISSION_INHERITANCE` in `inheritance.py`
3. Update service `RPC_PERMISSION_MAP` where consumed
4. Update conformance tests

### Adding a CLI Command
1. Create function in `cli/` using existing patterns
2. Register in CLI entrypoint
3. Document in `mise` task runner

## Further Reading
- [Astro Docs: ContextCore](../../docs/website/src/content/docs/core/)
- [Core Skill](../../.agent/skills/contextcore/SKILL.md)
- [Namespace Vigilance Skill](../../.agent/skills/namespace_vigilance/SKILL.md)
- [Service Contracts Skill](../../.agent/skills/service_contracts/SKILL.md)
