# ContextCore

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE.md)
[![Python 3.13+](https://img.shields.io/badge/python-3.13+-blue.svg)](https://www.python.org/downloads/)
[![GitHub](https://img.shields.io/badge/GitHub-ContextUnity-black.svg)](https://github.com/ContextUnity/contextcore)
[![Docs](https://img.shields.io/badge/docs-contextcore.dev-green.svg)](https://contextcore.dev)

> ⚠️ **Early Version**: This is an early version of ContextCore. Documentation is actively being developed, and the API may change.

## What is ContextCore?

ContextCore is the **Kernel** of the [ContextUnity](https://github.com/ContextUnity) ecosystem. It provides:

- **ContextUnit** — atomic data exchange format with provenance tracking
- **ContextToken** — capability-based security tokens for authorization
- **gRPC Contracts** — protocol definitions for service-to-service communication
- **Shared Configuration** — unified settings with Pydantic validation
- **Centralized Logging** — structured logging with automatic secret redaction

All `context*` services depend on ContextCore for shared types and contracts.

## What is it for?

ContextCore is designed for:

- **Type safety** — Pydantic models ensure data integrity across services
- **Traceability** — ContextUnit provenance tracks data journey
- **Security** — ContextToken provides capability-based authorization
- **Interoperability** — gRPC contracts ensure consistent APIs

### Core principle:

> **Zero business logic.** ContextCore is purely infrastructure.

## Key Features

- **📦 ContextUnit SDK** — atomic unit of data exchange with full observability
- **🔐 ContextToken** — capability-based access control with scope management
- **📡 gRPC Protos** — "iron-clad" contracts for inter-service communication
- **⚙️ SharedConfig** — unified settings via Pydantic validators
- **📝 Centralized Logging** — structured logs with automatic secret redaction

> **What is gRPC?** [gRPC](https://grpc.io/) is a high-performance RPC framework using Protocol Buffers. It provides type-safe, efficient service-to-service communication with built-in streaming — faster than REST APIs.

## Architecture

```
ContextCore/
├── sdk/                # ContextUnit, BrainClient, WorkerClient
│   ├── context_unit.py # ContextUnit model and serialization
│   ├── models.py       # SecurityScopes, UnitMetrics
│   ├── brain/          # BrainClient (async gRPC SDK)
│   └── worker_client.py
│
├── tokens.py           # ContextToken, TokenBuilder
├── token_utils.py      # Serialization, gRPC/HTTP extraction
├── signing.py          # SigningBackend protocol, HmacBackend, SessionTokenBackend
├── security.py         # interceptors, check_permission
├── permissions.py      # Permission registry, access tiers, tool policies
│
├── config.py           # SharedConfig, SharedSecurityConfig
├── logging.py          # setup_logging, get_context_unit_logger, safe_log_value
├── exceptions.py       # Unified exception hierarchy
├── discovery.py        # Service discovery utilities
├── grpc_utils.py       # Channel creation, TLS helpers
├── interfaces.py       # IRead, IWrite abstract interfaces
│
├── *_pb2.py            # Generated: gRPC stubs (brain, router, worker,
└── *_pb2_grpc.py       #   commerce, admin, shield, zero, context_unit)
```

## Quick Start

### ContextUnit — The Atomic Unit

```python
from contextcore import ContextUnit, SecurityScopes, UnitMetrics
from uuid import uuid4

unit = ContextUnit(
    unit_id=str(uuid4()),
    trace_id=str(uuid4()),
    modality="text",
    payload={"query": "What is RAG?"},
    provenance=["connector:telegram"],
    security=SecurityScopes(read=["knowledge:read"]),
    metrics=UnitMetrics(latency_ms=0, cost_usd=0.0, tokens_used=0)
)
```

### ContextToken — Access Control (SPOT for Identity)

```python
from contextcore import ContextToken, SecurityScopes

token = ContextToken(
    token_id="token_123",
    user_id="user@example.com",
    permissions=("knowledge:read", "catalog:read"),
    allowed_tenants=("traverse",),  # tenant resolved from token, not payload
)

# Check authorization
if token.can_read(unit.security):
    print("Access granted!")
```

### Centralized Logging

```python
from contextcore import setup_logging, get_context_unit_logger, SharedConfig

config = SharedConfig(service_name="my-service")
setup_logging(config=config)

logger = get_context_unit_logger(__name__)
logger.info("Processing request", unit=context_unit)  # trace_id auto-included
```

### gRPC Client

```python
from contextcore import BrainClient

client = BrainClient(host="localhost:50051")

results = await client.search(
    tenant_id="my_app",
    query_text="How does PostgreSQL work?",
    limit=5,
)
```

## Installation

```bash
pip install contextcore

# Using uv (recommended):
uv add contextcore
```

## Configuration

```bash
# Logging
export LOG_LEVEL=INFO
export LOG_JSON=false          # plain text (default) or true for JSON
export SERVICE_NAME=my-service

# Redis (optional)
export REDIS_URL=redis://localhost:6379

# OpenTelemetry (optional)
export OTEL_ENABLED=true
export OTEL_ENDPOINT=http://localhost:4317
```

## Development

### Prerequisites
- Python 3.13+
- `uv` package manager

### Setup

```bash
git clone https://github.com/ContextUnity/contextcore.git
cd contextcore
uv sync --dev
```

### Running Tests

```bash
uv run pytest tests/ -v
```

### Compiling Protos

```bash
./compile_protos.sh
```

## Documentation

- [Full Documentation](https://contextcore.dev) — complete guides and API reference
- [Technical Reference](./contextcore-fulldoc.md) — architecture deep-dive
- [Proto Definitions](./protos/) — gRPC contract definitions

## Testing & docs

- [Integration tests](../tests/integration/README.md) — cross-service tests (token/trace propagation, etc.)
- Doc site: [contextcore.dev](https://contextcore.dev)

## Security

ContextCore provides the security primitives used by all ContextUnity services.
See [Security Architecture](../../docs/security_architecture.md) for the full model.

### ContextToken

Capability-based access tokens with:
- **`permissions`** — capability strings (`brain:read`, `tools:register:project_id`, `admin:all`)
- **`allowed_tenants`** — tenant isolation (empty = admin access to all)
- **`user_id` / `agent_id`** — identity tracking
- **`exp_unix`** — TTL-based expiration

### Permission Model

Hierarchical permission format: `{domain}:{action}[:{resource}]`

```python
from contextcore.permissions import Permissions, has_registration_access

# Static constants
Permissions.BRAIN_READ         # "brain:read"
Permissions.TOOLS_REGISTER     # "tools:register" (any project)

# Builders
Permissions.register("acme")   # "tools:register:acme" (project-specific)
Permissions.tool("sql", "read") # "tool:sql:read"

# Checks
has_registration_access(("tools:register:acme",), "acme")  # True
has_registration_access(("tools:register:acme",), "other")  # False
has_registration_access(("tools:register",), "anything")   # True (generic)
```

### Service Discovery & Project Registry

Redis-based infrastructure in `discovery.py`:

| Function | Purpose |
|----------|---------|
| `register_service()` | Service heartbeat registration |
| `discover_services()` | Find running service instances |
| `register_project()` | Store project ownership in Redis |
| `verify_project_owner()` | Check if tenant owns a project |
| `get_registered_projects()` | List all registered projects |

All functions degrade gracefully when Redis is unavailable.

## ContextUnity Ecosystem

ContextCore is the kernel of the [ContextUnity](https://contextunity.dev) service mesh:

| Service | Role | Documentation |
|---|---|---|
| **ContextCore** | Shared kernel — types, protocols, contracts | *you are here* |
| [ContextBrain](https://contextbrain.dev) | Semantic memory — knowledge & vector storage | [contextbrain.dev](https://contextbrain.dev) |
| [ContextRouter](https://contextrouter.dev) | Agent orchestration — LangGraph + plugins | [contextrouter.dev](https://contextrouter.dev) |
| [ContextWorker](https://contextworker.dev) | Durable workflows — Temporal infrastructure | [contextworker.dev](https://contextworker.dev) |
| ContextZero | Privacy proxy — PII anonymization | — |
| ContextView | Observability dashboard — admin UI, MCP | — |

## License

This project is licensed under the terms specified in [LICENSE.md](LICENSE.md).
