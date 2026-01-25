# ContextCore Full Documentation

## Overview
ContextCore is the "Source of Truth" for the entire ContextUnity ecosystem. it defines the Shared Language (types, interfaces, protocols) ensuring all `context*` services remain synchronized and interoperable.

---

## Core Components

### 1. ContextUnit (The Atomic Unit)
All data exchange MUST adhere to the `ContextUnit` structure:
- `unit_id`: UUIDv4 unique identifier.
- `trace_id`: UUIDv4 for tracking the entire request lifecycle.
- `parent_unit_id`: Reference for tracing parent-child relationships.
- `modality`: `text`, `audio`, or `spatial`.
- `payload`: The actual message/data content.
- `provenance`: A list of strings showing the data's journey.
- `metrics`: Latency (`ms`), cost (`usd`), and token usage.
- **Security Scopes**: Capability-based restrictions that enforce what a specific worker or agent can read or write.

### 2. Logging & Observability
**Centralized Logging**: `ContextCore` provides a complete logging infrastructure for all ContextUnity services.

**Key Features:**
- **Automatic Configuration**: `setup_logging()` configures logging from `SharedConfig.log_level`
- **Structured Logging**: JSON format with automatic `trace_id` and `unit_id` inclusion
- **Secret Redaction**: Automatic redaction of passwords, API keys, tokens, and other secrets
- **Safe Previews**: Length-bounded previews of data to prevent log bloat
- **ContextUnit Integration**: Automatic trace_id propagation from ContextUnit instances

**Usage:**
```python
from contextcore import setup_logging, get_context_unit_logger, SharedConfig

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

**Log Output:**
- **Handler**: `logging.StreamHandler()` writes to `sys.stderr` by default
- **Format**: JSON (default) or plain text (configurable via `json_format=False`)
- **Formatter**: `ContextUnitFormatter` automatically includes `trace_id` and `unit_id`
- **Secret Redaction**: Enabled by default, automatically redacts passwords, API keys, tokens

**Capturing Logs in Tests:**
```python
import pytest
from contextcore import setup_logging, SharedConfig, LogLevel

def test_logging_output(capsys):
    """Test that logs are written to stderr."""
    setup_logging(config=SharedConfig(log_level=LogLevel.INFO), json_format=True)
    logger = logging.getLogger("test")
    logger.info("Test message")
    
    # Capture stderr output
    captured = capsys.readouterr()
    stderr_output = captured.err.strip()
    
    # Verify JSON format
    import json
    data = json.loads(stderr_output)
    assert data["level"] == "INFO"
    assert data["message"] == "Test message"
```

**Requirements:**
- Every service MUST propagate the `trace_id`.
- Logs are derived directly from the `ContextUnit`.
- If a step isn't in the `provenance` or `chain_of_thought`, it didn't happen.
- Never log full prompts, secrets, or full retrieved context payloads.

### 3. Shared Library
- **Pydantic Validation**: All core types use Pydantic for runtime validation.
- **gRPC Contracts**: Hard service boundaries defined via `.proto` files.
- **Common Config**: Pydantic-validated `SharedConfig` model to unify settings like `LOG_LEVEL`, `REDIS_URL`, etc. (see `contextcore.config.SharedConfig`).

---

## Security & Constraints

### 1. Worker Restrictions & Authorization
The `ContextUnit` protocol includes embedded scopes that limit worker actions:
- **Read Scopes**: Defines which parts of the payload or memory a worker can access.
- **Write Scopes**: Defines which databases or fields a worker can modify.
- **ContextToken**: Authorization tokens (from `contextbrain`) validate against `ContextUnit.security` scopes for capability-based access control.
- **Enforcement**: Middleware validates tokens and scopes before execution.

### 2. General Constraints
- **Zero Business Logic**: Core only contains types, interfaces, and utilities.
- **Minimal Dependencies**: Keep the kernel lightweight.
- **Protocol Consistency**: Any change to `ContextUnit` triggers a mandatory review of all services.

---

## Documentation Mandate
Any functional change to the protocol or shared types MUST be documented here and in `docs/name` (Global) immediately.
