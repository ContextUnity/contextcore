# ContextCore

**The Kernel of ContextUnity** — shared library of types, gRPC contracts, and Telemetry SDK for the entire ContextUnity ecosystem.

[![Documentation](https://img.shields.io/badge/docs-contextcore.dev-blue)](https://contextcore.dev)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE.md)

## Overview

ContextCore is the "Source of Truth" for the entire ContextUnity ecosystem. It defines the shared language (types, interfaces, protocols), ensuring all `context*` services remain synchronized and interoperable.

### Key Features

- **ContextUnit SDK** — atomic unit of data exchange with full observability
- **Centralized Logging** — structured logging with automatic secret redaction
- **Shared Configuration** — unified settings via Pydantic validators
- **ContextToken** — capability-based access control for security
- **gRPC Protos** — "iron-clad" contracts for inter-service communication
- **Crypto Primitives** — standardized algorithms (AES-256-GCM) for compatibility

## Installation

### Using uv (Recommended)

```bash
uv add contextcore
```

### Using pip

```bash
pip install contextcore
```

### Local Development

```bash
git clone https://github.com/ContextUnity/contextcore.git
cd contextcore
uv sync --dev
```

## Quick Start

### ContextUnit — The Atomic Unit

```python
from contextcore import ContextUnit, SecurityScopes, UnitMetrics
from uuid import uuid4

# Create a ContextUnit
unit = ContextUnit(
    unit_id=str(uuid4()),
    trace_id=str(uuid4()),
    modality="text",
    payload={"query": "What is RAG?"},
    security=SecurityScopes(read=["knowledge:read"]),
    metrics=UnitMetrics(latency_ms=0, cost_usd=0.0, tokens_used=0)
)

# Access properties
print(f"Unit ID: {unit.unit_id}")
print(f"Trace ID: {unit.trace_id}")
print(f"Payload: {unit.payload}")
```

### Centralized Logging

```python
from contextcore import setup_logging, get_context_unit_logger, SharedConfig, LogLevel

# Setup logging at application startup
config = SharedConfig(log_level=LogLevel.INFO)
setup_logging(config=config)

# Get logger with ContextUnit support
logger = get_context_unit_logger(__name__)

# Log with ContextUnit (trace_id automatically included)
logger.info("Processing request", unit=context_unit)

# Safe logging of sensitive data
from contextcore import safe_log_value
logger.info(f"User data: {safe_log_value(user_data)}")
```

### Shared Configuration

```python
from contextcore import SharedConfig, LogLevel, load_shared_config_from_env

# Load from environment variables
config = load_shared_config_from_env()

# Or create explicitly
config = SharedConfig(
    log_level=LogLevel.INFO,
    service_name="my-service",
    service_version="1.0.0",
    redis_url="redis://localhost:6379"
)
```

### ContextToken — Access Control

```python
from contextcore import ContextToken, SecurityScopes

# Create a token with permissions
token = ContextToken(
    token_id="token_123",
    permissions=("knowledge:read", "catalog:read")
)

# Check permissions
unit = ContextUnit(
    security=SecurityScopes(read=["knowledge:read"])
)

if token.can_read(unit.security):
    print("Access granted!")
```

### gRPC Clients

```python
from contextcore import BrainClient, ContextUnit, ContextToken

# Create a client
client = BrainClient(host="localhost:50051")

# Query memory
unit = ContextUnit(
    payload={"query": "What is RAG?"},
    security=SecurityScopes(read=["knowledge:read"])
)
token = ContextToken(permissions=("knowledge:read",))

async for result in client.query_memory(unit, token=token):
    print(result.payload.get("content"))
```

## Core Components

### 1. ContextUnit (The Atomic Unit)

All data exchanges must adhere to the `ContextUnit` structure:

- `unit_id`: UUIDv4 unique identifier
- `trace_id`: UUIDv4 for tracking the entire request lifecycle
- `parent_unit_id`: Reference for tracing parent-child relationships
- `modality`: `text`, `audio`, or `spatial`
- `payload`: The actual message/data content
- `provenance`: List of strings showing the data's journey
- `metrics`: Latency (`ms`), cost (`usd`), and token usage
- `security`: Security Scopes for capability-based access control

### 2. Logging & Observability

**Centralized Logging** with automatic configuration:

- **Structured Logging**: JSON format with automatic inclusion of `trace_id` and `unit_id`
- **Secret Redaction**: Automatic redaction of passwords, API keys, tokens, and other secrets
- **Safe Previews**: Length-bounded previews of data to prevent log bloat
- **ContextUnit Integration**: Automatic trace_id propagation from ContextUnit instances

### 3. Shared Configuration

Pydantic validators for unified settings across all products:

- `LOG_LEVEL`: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- `REDIS_URL`: URL for Redis connection
- `SERVICE_NAME`: Service name for observability
- `SERVICE_VERSION`: Service version
- `OTEL_ENABLED`: Enable OpenTelemetry
- `OTEL_ENDPOINT`: Endpoint for OpenTelemetry collector

### 4. ContextToken

Capability-based access control for security:

- `token_id`: Unique identifier for audit trails
- `permissions`: List of capability strings (e.g., "catalog:read", "product:write")
- `exp_unix`: Expiration timestamp (None = no expiration)

### 5. gRPC Protobuf Definitions

"Iron-clad" contracts for direct inter-service communication:

- `context_unit.proto` — base ContextUnit protocol
- `brain.proto` — BrainService for RAG and knowledge management
- `commerce.proto` — CommerceService for e-commerce operations
- `worker.proto` — WorkerService for background tasks

## Documentation

- **[Full Documentation](./contextcore-fulldoc.md)** — complete documentation of all components
- **[Online Docs](https://contextcore.dev)** — documentation website
- **[Logging Guide](docs/LOGGING.md)** — detailed logging guide

## Development

### Setup

```bash
# Clone repository
git clone https://github.com/ContextUnity/contextcore.git
cd contextcore

# Install dependencies
uv sync --dev

# Run tests
uv run pytest

# Compile protobuf files
./compile_protos.sh
```

### Project Structure

```
contextcore/
├── src/contextcore/      # Source code
│   ├── sdk.py            # ContextUnit SDK
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
# Run all tests
uv run pytest

# Run with coverage
uv run pytest --cov=contextcore --cov-report=html

# Run specific test file
uv run pytest tests/test_sdk.py
```

## Integration with ContextUnity Services

ContextCore is integrated into all ContextUnity services:

- **ContextRouter** — The "Mind": AI Gateway and agent orchestration.
- **ContextBrain** — The "Memory": Centralized RAG retrieval and vector storage.
- **ContextCommerce** — The "Store": E-commerce platform with agent integration.
- **ContextWorker** — The "Hands": Background tasks and temporal workflows.
- **ContextShield** — The "Guard": Security layer validating provenance.

## License

MIT License — see [LICENSE.md](LICENSE.md) for details.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

## Links

- **Documentation**: https://contextcore.dev
- **Repository**: https://github.com/ContextUnity/contextcore
- **ContextUnity**: https://github.com/ContextUnity
