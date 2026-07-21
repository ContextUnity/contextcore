# ContextUnity Core

[![Python 3.13+](https://img.shields.io/badge/python-3.13+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE.md)

ContextUnity Core is the **Kernel** of the [ContextUnity](https://github.com/ContextUnity) ecosystem. It provides shared types, gRPC contracts, security tokens, and service SDKs used by every service in the mesh.

> **Zero business logic.** Core is purely infrastructure.

---

## What is it for?

- **ContextUnit** — atomic data exchange format with provenance tracking
- **ContextToken** — capability-based security tokens (HMAC or Shield Ed25519)
- **gRPC Contracts** — 6 proto files (`brain`, `router`, `worker`, `shield`, `admin`, `contextunit`) consumed by 5 gRPC servers + Django Admin clients
- **Service SDKs** — BrainClient, RouterClient, WorkerClient
- **Authorization Engine** — unified `authorize()` with permission inheritance
- **Centralized Logging** — structured logs with automatic secret redaction

---

## Quick Start

```bash
# Install
uv add contextunity-core

# Run tests
uv run --package contextunity-core pytest
```

### ContextUnit

```python
from contextunity.core import ContextUnit

unit = ContextUnit(
    payload={"query": "What is RAG?"},
    provenance=["connector:telegram"],
)
```

### ContextToken

```python
from contextunity.core import ContextToken

token = ContextToken(
    token_id="token_123",
    user_id="user@example.com",
    permissions=("brain:read", "catalog:read"),
    allowed_tenants=("my_project",),
)

if token.can_read(unit.security):
    print("Access granted!")
```

### BrainClient

```python
from contextunity.core import BrainClient

client = BrainClient(host="localhost:50051")
results = await client.search_cells(
    tenant_id="my_app",
    query_text="How does PostgreSQL work?",
    limit=5,
)
```

### Federated Toolkits

```python
from contextunity.core.sdk.toolkit import FederatedToolkit, tool

class DatabaseToolkit(FederatedToolkit, stateful=True):
    @tool(timeout=30, retries=2)
    async def run_query(self, query: str):
        # self.ctx is automatically injected by the BiDi stream executor!
        return {"tenant": self.ctx.tenant_id, "query": query}
```

---

## Architecture

```
src/contextunity/core/
├── manifest/               # Declarative project schema + generators
├── sdk/                    # ContextUnit, BrainClient, WorkerClient, bootstrap
├── authz/                  # Unified authorization engine
├── security/               # ServicePermissionInterceptor
├── permissions/            # Permission constants, inheritance, access helpers
├── tokens.py               # ContextToken, TokenBuilder
├── signing.py              # HmacBackend, SessionTokenBackend
├── config.py               # SharedConfig, SharedSecurityConfig
├── logging.py              # Structured logging, secret redaction
├── exceptions.py           # ContextUnityError hierarchy
├── discovery.py            # Redis-based service registration
├── cli/                    # Key minting, admin tools, validation
└── *_pb2.py                # Generated gRPC stubs (8 protos)
```

---

## Configuration

| Variable | Description |
|----------|-------------|
| `LOG_LEVEL` | Logging level (default: INFO) |
| `REDIS_URL` | Redis connection for discovery |
| `CU_PLATFORM_SECRET` | Shared HMAC root when Shield is disabled |
| `CU_PROJECT_SECRET` | Per-project Shield bootstrap secret; temporary no-Shield alias only |
| `CU_SHIELD_GRPC_URL` | Shield endpoint (Enterprise mode) |
| `OTEL_ENABLED` | OpenTelemetry toggle |

---

## Security

Security is always enforced — no toggle needed. Backend auto-detected at bootstrap:

| Backend | Mode | Trigger |
|---------|------|---------|
| `HmacBackend` | No Shield | `CU_PLATFORM_SECRET` set |
| `SessionTokenBackend` | Shield | Shield enabled in manifest |

Bootstrap computes prompt versions in both modes. No-Shield mode signs prompt
text with the platform HMAC root; Shield mode publishes canonical prompts to
Shield and registers only prompt references plus versions with Router.

---

## Further Reading

- **Full Documentation**: [ContextCore on Astro Site](../../website/src/content/docs/core/)
- **Agent Boundaries & Golden Paths**: [AGENTS.md](AGENTS.md)

## License

This project is licensed under the terms specified in [LICENSE.md](LICENSE.md).
