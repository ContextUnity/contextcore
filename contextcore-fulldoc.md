# ContextCore — Full Documentation

**The Kernel of ContextUnity**

ContextCore is the shared infrastructure layer. It defines the ContextUnit protocol, gRPC contracts, security tokens, and common utilities used by all ContextUnity services.

---

## Overview

ContextCore is the "source of truth" for the entire ecosystem. Every service depends on it for:
- **ContextUnit** — Atomic data exchange format with provenance
- **ContextToken** — Capability-based security tokens
- **gRPC Contracts** — Proto definitions for service boundaries
- **Shared Configuration** — Common settings and validation

### Design Philosophy

1. **Zero Business Logic** — Core is purely infrastructure
2. **Contract Stability** — Proto changes require ecosystem-wide review
3. **Minimal Dependencies** — Lightweight kernel
4. **Type Safety** — Pydantic validation everywhere

---

## Architecture

```
┌────────────────────────────────────────────────────────────────────────────┐
│                              ContextCore                                    │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│  src/contextcore/                                                          │
│  ├── sdk/                   ← Modular SDK (400-Line Code Scale)            │
│  │   ├── __init__.py        ← Public exports                               │
│  │   ├── context_unit.py    ← ContextUnit, ContextUnitBuilder              │
│  │   ├── models.py          ← Shared Pydantic models                       │
│  │   ├── worker_client.py   ← WorkerClient                                 │
│  │   └── brain/             ← BrainClient subpackage                       │
│  │       ├── base.py        ← Base client class                            │
│  │       ├── knowledge.py   ← Knowledge operations                         │
│  │       ├── commerce.py    ← Commerce operations                          │
│  │       └── news.py        ← News operations                              │
│  │                                                                         │
│  ├── tokens.py              ← ContextToken, TokenBuilder                   │
│  ├── config.py              ← SharedConfig, LogLevel                       │
│  ├── logging.py             ← setup_logging, safe_log_value                │
│  ├── interfaces.py          ← IRead, IWrite base interfaces                │
│  │                                                                         │
│  ├── brain_pb2.py           ← Generated: BrainService                      │
│  ├── commerce_pb2.py        ← Generated: CommerceService                   │
│  ├── worker_pb2.py          ← Generated: WorkerService                     │
│  ├── router_pb2.py          ← Generated: RouterService                     │
│  └── context_unit_pb2.py    ← Generated: ContextUnit proto                 │
│                                                                            │
│  protos/                                                                   │
│  ├── brain.proto            ← Knowledge Store API                          │
│  ├── commerce.proto         ← PIM API                                      │
│  ├── worker.proto           ← Task Runner API                              │
│  ├── router.proto           ← Router API                                   │
│  └── context_unit.proto     ← Base ContextUnit definition                  │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
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

### Builder Pattern

```python
from contextcore import ContextUnitBuilder

unit = (
    ContextUnitBuilder()
    .with_trace_id("abc-123")
    .with_payload({"content": "Hello"})
    .with_provenance("connector:telegram")
    .with_security(read=["chat:read"])
    .build()
)
```

---

## ContextToken

Capability-based access control tokens.

```python
from contextcore import ContextToken, SecurityScopes

# Create token with permissions
token = ContextToken(
    token_id="token_123",
    permissions=("knowledge:read", "catalog:read"),
    exp_unix=None  # No expiration
)

# Check authorization
unit = ContextUnit(
    security=SecurityScopes(read=["knowledge:read"])
)

if token.can_read(unit.security):
    print("Access granted!")
```

### Permission Format

Permissions follow the pattern: `{domain}:{action}`

| Domain | Actions | Description |
|--------|---------|-------------|
| `knowledge` | read, write, admin | Brain operations |
| `catalog` | read, write | Commerce products |
| `workflow` | trigger, cancel | Worker tasks |
| `system` | * | Admin access |

---

## gRPC Contracts

Proto definitions for service-to-service communication.

### brain.proto

```protobuf
service BrainService {
    rpc Search(SearchRequest) returns (stream SearchResult);
    rpc GraphSearch(GraphSearchRequest) returns (stream GraphSearchResult);
    rpc GetTaxonomy(TaxonomyRequest) returns (TaxonomyResponse);
    rpc IngestDocument(IngestRequest) returns (IngestResult);
}
```

### commerce.proto

```protobuf
service CommerceService {
    rpc GetProduct(ProductRequest) returns (ProductResponse);
    rpc UpdateProduct(UpdateRequest) returns (UpdateResponse);
    rpc ListProducts(ListRequest) returns (stream ProductResponse);
}
```

### worker.proto

```protobuf
service WorkerService {
    rpc TriggerWorkflow(WorkflowRequest) returns (WorkflowResponse);
    rpc GetWorkflowStatus(StatusRequest) returns (StatusResponse);
}
```

### Compilation

```bash
./compile_protos.sh
# Generates *_pb2.py and *_pb2_grpc.py files
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
| `SERVICE_NAME` | str | required | Service identifier |
| `SERVICE_VERSION` | str | 0.0.0 | Semantic version |
| `REDIS_URL` | str | - | Redis connection URL |
| `OTEL_ENABLED` | bool | false | OpenTelemetry toggle |
| `OTEL_ENDPOINT` | str | - | OTLP collector URL |

---

## Centralized Logging

Structured logging with automatic secret redaction.

```python
from contextcore import setup_logging, get_context_unit_logger, SharedConfig

# Setup at application start
config = SharedConfig(log_level="INFO")
setup_logging(config=config)

# Get logger with ContextUnit support
logger = get_context_unit_logger(__name__)

# Log with unit (trace_id auto-included)
logger.info("Processing request", unit=context_unit)

# Safe logging of sensitive data
from contextcore import safe_log_value
logger.info(f"User data: {safe_log_value(user_data)}")
```

### Secret Redaction

Automatically redacts:
- API keys matching patterns: `sk-*`, `AIza*`
- Passwords in URLs
- Token fields
- Custom patterns via config

---

## Base Interfaces

Abstract interfaces for storage implementations.

```python
from contextcore import IRead, IWrite

class MyStore(IRead, IWrite):
    async def read(self, query: str, token: ContextToken) -> list[ContextUnit]:
        ...
    
    async def write(self, units: list[ContextUnit], token: ContextToken) -> None:
        ...
```

---

## Installation

```bash
# Using uv (recommended)
uv add contextcore

# Using pip
pip install contextcore

# Development
git clone https://github.com/ContextUnity/contextcore.git
cd contextcore && uv sync --dev
```

---

## Development

### Project Structure

```
contextcore/
├── src/contextcore/      # Source code
│   ├── sdk/              # Modular SDK (400-Line Code Scale)
│   │   ├── context_unit.py    # ContextUnit, ContextUnitBuilder
│   │   ├── models.py          # Shared Pydantic models
│   │   ├── worker_client.py   # WorkerClient
│   │   └── brain/             # BrainClient subpackage
│   │       ├── base.py        # Base client class
│   │       ├── knowledge.py   # Knowledge operations
│   │       ├── commerce.py    # Commerce operations
│   │       └── news.py        # News operations
│   ├── config.py         # Shared configuration
│   ├── tokens.py         # ContextToken implementation
│   ├── logging.py        # Centralized logging
│   └── interfaces.py     # Base interfaces
├── protos/               # Protocol Buffer definitions
├── tests/                # Test suite
└── docs/                 # Documentation
```

### Running Tests

```bash
# All tests
uv run pytest

# With coverage
uv run pytest --cov=contextcore --cov-report=html

# Specific test
uv run pytest tests/test_sdk.py
```

### Compiling Protos

```bash
# Install tools
uv add grpcio-tools

# Compile
./compile_protos.sh
```

---

## Integration Examples

### Creating a Service

```python
from contextcore import ContextUnit, ContextToken, setup_logging, SharedConfig

# Initialize
config = SharedConfig(service_name="my-service")
setup_logging(config=config)

# Process request
def handle_request(payload: dict, token: ContextToken) -> ContextUnit:
    unit = ContextUnit(
        payload=payload,
        security=SecurityScopes(read=token.permissions)
    )
    unit.provenance.append("service:my-service")
    return unit
```

### gRPC Client

```python
from contextcore import BrainClient

async with BrainClient(host="localhost:50051") as client:
    async for result in client.search("query"):
        print(result)
```

---

## Links

- **Documentation**: https://contextcore.dev
- **Repository**: https://github.com/ContextUnity/contextcore
- **Proto Reference**: https://contextcore.dev/reference/protos/

---

*Last updated: January 2026*
