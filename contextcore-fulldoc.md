# ContextCore — Full Documentation

**The Kernel of ContextUnity** — shared type system, gRPC contracts, ContextUnit protocol, security infrastructure, and service discovery for the entire service mesh.

---

## Overview

ContextCore is the "source of truth" for the entire ecosystem. Every service depends on it for:
- **ContextUnit** — Atomic data exchange format with provenance
- **ContextToken** — Capability-based security tokens
- **gRPC Contracts** — Proto definitions for all 8 services (via ContextUnit envelope)
- **Security Infrastructure** — Guard, token validation, signing, firewall integration
- **Service Discovery** — Redis-based registration and discovery
- **Shared Configuration** — Common settings and validation
- **Exception Hierarchy** — Unified error codes and gRPC error handling

### Design Philosophy

1. **Zero Business Logic** — Core is purely infrastructure
2. **Contract Stability** — Proto changes require ecosystem-wide review
3. **Minimal Dependencies** — Lightweight kernel
4. **Type Safety** — Pydantic validation everywhere
5. **ContextUnit Envelope** — All gRPC RPCs use `ContextUnit` as the universal message type

---

## Architecture

```
src/contextcore/
├── sdk/                     ← Modular SDK (400-Line Code Scale)
│   ├── __init__.py          ← Public re-exports
│   ├── context_unit.py      ← ContextUnit (Pydantic model)
│   ├── models.py            ← SecurityScopes, UnitMetrics, CotStep, SearchResult
│   ├── worker_client.py     ← WorkerClient (gRPC)
│   └── brain/               ← BrainClient subpackage
│       ├── base.py          ← BrainClientBase (connection, channel)
│       ├── knowledge.py     ← Search, GraphSearch, Upsert, KG relations
│       ├── commerce.py      ← Commerce operations
│       ├── news.py          ← News engine operations
│       ├── memory.py        ← Episodic + entity memory
│       └── traces.py        ← Agent execution trace logging
│
├── tokens.py                ← ContextToken, TokenBuilder
├── permissions.py           ← Permissions registry, ToolPolicy, access helpers
├── config.py                ← SharedConfig, SharedSecurityConfig, LogLevel
├── logging.py               ← setup_logging, get_context_unit_logger, safe_preview
├── interfaces.py            ← BaseTransformer, Transformer (ABC)
│
├── security.py              ← SecurityGuard, TokenValidationInterceptor
├── signing.py               ← SigningBackend protocol, SignedPayload, UnsignedBackend
├── token_utils.py           ← Token extraction (gRPC/HTTP), serialization, forwarding
├── discovery.py             ← ServiceInfo, register/deregister/discover via Redis
├── exceptions.py            ← ContextUnityError hierarchy, ErrorRegistry, gRPC handlers
│
├── brain_pb2.py             ← Generated: BrainService (17 RPCs)
├── commerce_pb2.py          ← Generated: CommerceService (8 RPCs)
├── worker_pb2.py            ← Generated: WorkerService (3 RPCs)
├── router_pb2.py            ← Generated: RouterService
├── admin_pb2.py             ← Generated: AdminService
├── shield_pb2.py            ← Generated: ShieldService
├── zero_pb2.py              ← Generated: ZeroService
└── context_unit_pb2.py      ← Generated: ContextUnit proto

protos/
├── brain.proto              ← Knowledge Store API (17 RPCs)
├── commerce.proto           ← PIM API (8 RPCs)
├── worker.proto             ← Task Runner API (3 RPCs)
├── router.proto             ← Router API
├── admin.proto              ← AdminService API
├── shield.proto             ← ShieldService API
├── zero.proto               ← ZeroService API
└── context_unit.proto       ← Base ContextUnit definition
```

---

## ContextUnit Protocol

The atomic unit of data exchange. Every piece of data flowing through ContextUnity is wrapped in a ContextUnit.

### Structure

```python
from contextcore import ContextUnit, SecurityScopes, UnitMetrics
from uuid import uuid4

unit = ContextUnit(
    unit_id=str(uuid4()),           # Unique identifier
    trace_id=str(uuid4()),          # Request lifecycle tracking
    parent_unit_id=None,            # Parent reference (for DAG)
    modality="text",                # text | audio | spatial
    payload={"query": "..."},       # Actual content
    provenance=["source:web"],      # Data journey trail
    security=SecurityScopes(        # Access control
        read=["knowledge:read"],
        write=["catalog:write"]
    ),
    metrics=UnitMetrics(            # Observability
        latency_ms=0,
        cost_usd=0.0,
        tokens_used=0
    )
)
```

### Key Properties

| Property | Type | Description |
|----------|------|-------------|
| `unit_id` | UUID | Unique identifier for this unit |
| `trace_id` | UUID | Tracks entire request lifecycle |
| `parent_unit_id` | UUID? | Links to parent for DAG traversal |
| `modality` | str | Data type: text, audio, spatial |
| `payload` | dict | The actual data content |
| `provenance` | list[str] | Ordered list of transformations |
| `security` | SecurityScopes | Read/write permissions |
| `metrics` | UnitMetrics | Latency, cost, token tracking |

### gRPC Envelope Pattern

All gRPC services use ContextUnit as the envelope:

```protobuf
// Every RPC uses ContextUnit as input and output
rpc Search(contextcore.ContextUnit) returns (stream contextcore.ContextUnit);
rpc Upsert(contextcore.ContextUnit) returns (contextcore.ContextUnit);
```

The `payload` dict carries operation-specific data. This unifies the protocol across all services.

---

## ContextToken

Capability-based access control tokens.

```python
from contextcore import ContextToken, TokenBuilder

# Create token with permissions
token = ContextToken(
    token_id="token_123",
    user_id="user@example.com",     # Identity — SPOT for user
    permissions=("knowledge:read", "catalog:read"),
    allowed_tenants=("traverse",),  # Empty = admin (all tenants)
    exp_unix=None,                  # No expiration
    revocation_id="rev-XYZ789",     # For instant invalidation
)

# Check authorization
unit = ContextUnit(
    security=SecurityScopes(read=["knowledge:read"])
)

if token.can_read(unit.security):
    print("Access granted!")
```

### Token Fields

| Field | Type | Description |
|-------|------|-------------|
| `token_id` | str | Unique identifier for audit trails |
| `user_id` | str? | User identity — SPOT for all services |
| `permissions` | tuple[str] | Capability strings (e.g., `"brain:read"`) |
| `allowed_tenants` | tuple[str] | Tenant IDs — SPOT for tenant resolution (empty = admin) |
| `exp_unix` | float? | Expiration timestamp (None = no expiration) |
| `revocation_id` | str? | For instant revocation via RevocationStore |

> **Token is SPOT (Single Point of Truth)**: `user_id` and `tenant_id` are
> derived exclusively from the token. Request payloads must NOT carry identity
> fields — services extract them from `ContextToken.user_id` and
> `ContextToken.allowed_tenants[0]`.

### Permission Format

Permissions follow the canonical pattern: `{domain}:{action}`

Defined in `contextcore.permissions.Permissions`:

| Constant | Value | Description |
|----------|-------|-------------|
| `BRAIN_READ` | `brain:read` | Read from knowledge store |
| `BRAIN_WRITE` | `brain:write` | Write to knowledge store |
| `MEMORY_READ` | `memory:read` | Read episodic/entity memory |
| `MEMORY_WRITE` | `memory:write` | Write episodic/entity memory |
| `TRACE_READ` | `trace:read` | Read agent traces |
| `TRACE_WRITE` | `trace:write` | Log agent traces |
| `GRAPH_RAG` | `graph:rag` | Access RAG retrieval graph |
| `GRAPH_DISPATCHER` | `graph:dispatcher` | Access dispatcher graph |
| `GRAPH_ALL` | `graph:*` | Access all graphs |
| `TOOL_ALL` | `tool:*` | Access all tools |
| `ADMIN_ALL` | `admin:all` | Superadmin (inherits everything) |

#### Dynamic Builders

```python
from contextcore.permissions import Permissions

Permissions.tool("sql")            # "tool:sql"
Permissions.tool("sql", "read")    # "tool:sql:read"
Permissions.graph("rag_retrieval") # "graph:rag_retrieval"
Permissions.service("brain", "read") # "brain:read"
```

#### Access Checking Helpers

```python
from contextcore.permissions import (
    has_tool_access, has_graph_access,
    extract_tool_names, check_tool_scope,
)

has_tool_access(token.permissions, "brain_search")  # bool
has_graph_access(token.permissions, "rag")          # bool
extract_tool_names(token.permissions)               # frozenset[str]
check_tool_scope(perms, "sql", "write")             # "safe" | "confirm" | "deny"
```

---

## Security Infrastructure

### SecurityGuard (`security.py`)

Unified security integration point that all gRPC services use:

```python
from contextcore import SecurityGuard, SecurityConfig

guard = get_security_guard()

# Validate token from gRPC metadata
token = guard.validate_token(context)

# Check input through AI firewall (auto-activates when contextshield is installed)
result = await guard.check_input(text, token)
if result.blocked:
    # Request rejected by firewall
    ...
```

- **Token validation** — always available via contextcore
- **Shield firewall** — auto-activates when `contextshield` is installed
- **TokenValidationInterceptor** — gRPC server interceptor for automatic token validation

### Token Utilities (`token_utils.py`)

Centralized token extraction and forwarding for cross-service calls:

```python
from contextcore import (
    extract_token_from_grpc_metadata,
    create_grpc_metadata_with_token,
    extract_token_from_http_request,
    serialize_token,
    parse_token_string,
    TokenMetadataInterceptor,
)

# gRPC: extract token from incoming request
token = extract_token_from_grpc_metadata(context)

# gRPC: forward token to downstream service
metadata = create_grpc_metadata_with_token(token)

# HTTP: extract from Django request
token = extract_token_from_http_request(request)

# Client interceptor: auto-attach token to all outgoing gRPC calls
interceptor = TokenMetadataInterceptor(token)
```

### Signing (`signing.py`)

Defines the `SigningBackend` protocol. Actual implementations are in `contextshield`:

- `UnsignedBackend` — plaintext fallback (development)
- `SignedPayload` — wire format dataclass
- Production backends: Ed25519, Cloud KMS (via contextshield)
- Open Source backend: HMAC-SHA256 (via contextcore `SIGNING_BACKEND=hmac` + `SIGNING_SHARED_SECRET`)

---

## Service Discovery (`discovery.py`)

Redis-based service registration and discovery:

```python
from contextcore import register_service, discover_services, ServiceInfo

# Register on startup (auto-heartbeat every TTL/2)
await register_service(
    service="contextbrain",
    port=50051,
    tenant_ids=["traverse", "pony"],
    redis_url="redis://localhost:6379",
)

# Discover running instances
instances: list[ServiceInfo] = discover_services(
    service="contextbrain",
    redis_url="redis://localhost:6379",
)
```

---

## Exception Hierarchy (`exceptions.py`)

Unified error codes with gRPC status code mapping:

```python
from contextcore import (
    ContextUnityError,       # Base for all errors
    ConfigurationError,      # Bad config
    RetrievalError,          # Search/RAG failures
    ProviderError,           # External provider failures
    SecurityError,           # Auth/access failures
    StorageError,            # Database failures
    DatabaseConnectionError, # Connection-level DB failures
    ErrorRegistry,           # Maps error types to gRPC codes
    grpc_error_handler,      # Decorator for gRPC handlers
)
```

All exceptions carry a `code` field for machine-readable error identification.

---

## gRPC Contracts

All proto definitions use `contextcore.ContextUnit` as the universal envelope type.

### brain.proto (17 RPCs)

```protobuf
service BrainService {
    // Knowledge
    rpc Search(contextcore.ContextUnit) returns (stream contextcore.ContextUnit);
    rpc GraphSearch(contextcore.ContextUnit) returns (contextcore.ContextUnit);
    rpc CreateKGRelation(contextcore.ContextUnit) returns (contextcore.ContextUnit);
    rpc Upsert(contextcore.ContextUnit) returns (contextcore.ContextUnit);
    // Memory
    rpc QueryMemory(contextcore.ContextUnit) returns (stream contextcore.ContextUnit);
    rpc AddEpisode(contextcore.ContextUnit) returns (contextcore.ContextUnit);
    rpc GetRecentEpisodes(contextcore.ContextUnit) returns (stream contextcore.ContextUnit);
    rpc UpsertFact(contextcore.ContextUnit) returns (contextcore.ContextUnit);
    rpc GetUserFacts(contextcore.ContextUnit) returns (stream contextcore.ContextUnit);
    // News
    rpc UpsertNewsItem(contextcore.ContextUnit) returns (contextcore.ContextUnit);
    rpc GetNewsItems(contextcore.ContextUnit) returns (stream contextcore.ContextUnit);
    rpc UpsertNewsPost(contextcore.ContextUnit) returns (contextcore.ContextUnit);
    rpc CheckNewsPostExists(contextcore.ContextUnit) returns (contextcore.ContextUnit);
    // Traces
    rpc LogTrace(contextcore.ContextUnit) returns (contextcore.ContextUnit);
    rpc GetTraces(contextcore.ContextUnit) returns (stream contextcore.ContextUnit);
    // Taxonomy
    rpc UpsertTaxonomy(contextcore.ContextUnit) returns (contextcore.ContextUnit);
    rpc GetTaxonomy(contextcore.ContextUnit) returns (stream contextcore.ContextUnit);
}
```

### commerce.proto (8 RPCs)

```protobuf
service CommerceService {
    rpc GetProduct(contextcore.ContextUnit) returns (contextcore.ContextUnit);
    rpc UpdateProduct(contextcore.ContextUnit) returns (contextcore.ContextUnit);
    rpc GetProducts(contextcore.ContextUnit) returns (stream contextcore.ContextUnit);
    rpc UpsertDealerProduct(contextcore.ContextUnit) returns (contextcore.ContextUnit);
    rpc UpdateEnrichment(contextcore.ContextUnit) returns (contextcore.ContextUnit);
    rpc TriggerHarvest(contextcore.ContextUnit) returns (contextcore.ContextUnit);
    rpc GetPendingVerifications(contextcore.ContextUnit) returns (stream contextcore.ContextUnit);
    rpc SubmitVerification(contextcore.ContextUnit) returns (contextcore.ContextUnit);
}
```

### worker.proto (3 RPCs)

```protobuf
service WorkerService {
    rpc StartWorkflow(contextcore.ContextUnit) returns (contextcore.ContextUnit);
    rpc GetTaskStatus(contextcore.ContextUnit) returns (contextcore.ContextUnit);
    rpc ExecuteCode(contextcore.ContextUnit) returns (contextcore.ContextUnit);
}
```

### Additional Protos

- **admin.proto** — AdminService for ContextView (agent management, traces, memory, health)
- **router.proto** — RouterService (dispatch, invoke graph, plugin management)
- **shield.proto** — ShieldService (firewall check, validate token)
- **zero.proto** — ZeroService (anonymize, deanonymize, session management)

### Compilation

```bash
./compile_protos.sh
# Generates *_pb2.py and *_pb2_grpc.py files for all 8 protos
```

---

## Shared Configuration

Common settings validated with Pydantic.

```python
from contextcore import SharedConfig, LogLevel, load_shared_config_from_env

# Load from environment
config = load_shared_config_from_env()

# Or create explicitly
config = SharedConfig(
    log_level=LogLevel.INFO,
    service_name="my-service",
    service_version="1.0.0",
    redis_url="redis://localhost:6379"
)
```

### Environment Variables

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `LOG_LEVEL` | str | INFO | Logging level |
| `LOG_JSON` | bool | false | Use JSON log format |
| `SERVICE_NAME` | str | None | Service identifier |
| `SERVICE_VERSION` | str | None | Semantic version |
| `REDIS_URL` | str | None | Redis connection URL |
| `OTEL_ENABLED` | bool | false | OpenTelemetry toggle |
| `OTEL_ENDPOINT` | str | None | OTLP collector URL |
| `TENANT_ID` | str | None | Default tenant identifier |

### Security Configuration (nested)

`SharedConfig.security` contains signing and token settings:

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `SECURITY_ENABLED` | bool | false | Enable token validation |
| `SIGNING_BACKEND` | str | unsigned | `unsigned`, `hmac`, `ed25519`, or `kms` |
| `TOKEN_TTL_SECONDS` | int | 3600 | Token time-to-live |
| `READ_PERMISSION` | str | brain:read | Default read permission |
| `WRITE_PERMISSION` | str | brain:write | Default write permission |

---

## Centralized Logging

Structured logging with automatic secret redaction.

```python
from contextcore import setup_logging, get_context_unit_logger, load_shared_config_from_env

# Setup at application start
config = load_shared_config_from_env()
setup_logging(config=config, service_name="myservice")

# Get logger with ContextUnit support (trace_id propagation)
logger = get_context_unit_logger(__name__)

# Log with unit (trace_id auto-included)
logger.info("Processing request", unit=context_unit)

# Safe logging of sensitive data
from contextcore import safe_log_value
logger.info("User data: %s", safe_log_value(user_data))
```

---

## Base Interfaces

Abstract interfaces for data transformers.

```python
from contextcore.interfaces import BaseTransformer, Transformer

class MyTransformer(Transformer):
    name = "my_transformer"

    async def _transform(self, unit: ContextUnit) -> ContextUnit:
        unit.payload["processed"] = True
        return unit
```

`Transformer` auto-appends its `name` to `unit.provenance` before calling `_transform`.

---

## Installation

```bash
# Using uv (recommended)
uv add contextcore

# Development
git clone https://github.com/ContextUnity/contextcore.git
cd contextcore && uv sync --dev
```

---

## Development

### Running Tests

```bash
uv run pytest
uv run pytest --cov=contextcore --cov-report=html
```

### Compiling Protos

```bash
./compile_protos.sh
```

---

## Key Files Reference

| File | Lines | Purpose |
|------|-------|---------|
| `sdk/context_unit.py` | ~100 | ContextUnit Pydantic model |
| `sdk/models.py` | ~80 | SecurityScopes, UnitMetrics, CotStep, SearchResult |
| `sdk/brain/` | ~600 | BrainClient (modular: knowledge, commerce, news, memory, traces) |
| `sdk/worker_client.py` | ~100 | WorkerClient gRPC wrapper |
| `tokens.py` | ~150 | ContextToken, TokenBuilder |
| `permissions.py` | ~300 | Permission constants, access checkers, ToolPolicy |
| `config.py` | ~180 | SharedConfig, SharedSecurityConfig, LogLevel |
| `logging.py` | ~200 | Structured logging, secret redaction |
| `security.py` | ~360 | SecurityGuard, TokenValidationInterceptor |
| `signing.py` | ~200 | SigningBackend protocol, UnsignedBackend |
| `token_utils.py` | ~450 | Token extraction/serialization for gRPC and HTTP |
| `discovery.py` | ~260 | Service registration and discovery via Redis |
| `exceptions.py` | ~320 | Error hierarchy, ErrorRegistry, gRPC error handlers |
| `interfaces.py` | ~35 | BaseTransformer, Transformer ABCs |

---

## Links

- **Documentation**: https://contextcore.dev
- **Repository**: https://github.com/ContextUnity/contextcore

---

*Last updated: February 2026*


---

