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
├── sdk.py              # ContextUnit, ContextUnitBuilder, BrainClient
├── tokens.py           # ContextToken, TokenBuilder
├── config.py           # SharedConfig, LogLevel
├── logging.py          # setup_logging, safe_log_value
├── interfaces.py       # IRead, IWrite base interfaces
│
├── brain_pb2.py        # Generated: BrainService gRPC
├── commerce_pb2.py     # Generated: CommerceService gRPC
├── worker_pb2.py       # Generated: WorkerService gRPC
└── context_unit_pb2.py # Generated: ContextUnit proto
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

### ContextToken — Access Control

```python
from contextcore import ContextToken, SecurityScopes

token = ContextToken(
    token_id="token_123",
    permissions=("knowledge:read", "catalog:read")
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

## ContextUnity Ecosystem

ContextCore is part of the [ContextUnity](https://github.com/ContextUnity) platform:

| Service | Role | Documentation |
|---------|------|---------------|
| **ContextBrain** | Knowledge storage and RAG | [contextbrain.dev](https://contextbrain.dev) |
| **ContextRouter** | AI agent orchestration | [contextrouter.dev](https://contextrouter.dev) |
| **ContextWorker** | Background task execution | [contextworker.dev](https://contextworker.dev) |

## License

This project is licensed under the terms specified in [LICENSE.md](LICENSE.md).
