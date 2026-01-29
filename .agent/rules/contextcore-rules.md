---
trigger: always_on
---

# ContextCore Rules

## Role
You are working on **ContextCore** — the shared kernel of ContextUnity. This is infrastructure-only code.

## Core Principle
**Zero business logic.** ContextCore provides:
- Types and protocols (`ContextUnit`, `ContextToken`)
- gRPC contracts (`.proto` files)
- Configuration and logging utilities

## Architecture

```
src/contextcore/
├── sdk.py          # ContextUnit, ContextUnitBuilder, BrainClient, WorkerClient
├── tokens.py       # ContextToken, TokenBuilder
├── config.py       # SharedConfig, LogLevel
├── logging.py      # setup_logging, get_context_unit_logger, safe_log_value
├── interfaces.py   # IRead, IWrite abstract interfaces
│
├── *_pb2.py        # Generated gRPC stubs (DO NOT EDIT MANUALLY)
└── *_pb2_grpc.py   # Generated gRPC stubs (DO NOT EDIT MANUALLY)
```

## Critical Rules

### 1. Proto Files Are Sacred
- Proto definitions in `protos/` are shared by ALL services
- **NEVER** remove or renumber existing proto fields
- Add new fields as `optional` to maintain backward compatibility
- After editing protos, run `./compile_protos.sh`

### 2. Exports Must Be Explicit
All public API must be:
1. Defined in the appropriate module (`sdk.py`, `tokens.py`, etc.)
2. Imported in `__init__.py`
3. Listed in `__all__`

```python
# ❌ WRONG - not exported
def utility_function(): ...

# ✅ CORRECT - properly exported
# In module:
def utility_function(): ...
__all__ = ["utility_function"]

# In __init__.py:
from .module import utility_function
__all__ = [..., "utility_function"]
```

### 3. Type Safety
- Use Pydantic models for structured data
- Use `Field(...)` with `env=` for config options
- All public functions must have type hints

### 4. No Direct os.environ
```python
# ❌ FORBIDDEN
value = os.environ.get("SOME_VAR")

# ✅ CORRECT - use SharedConfig
class SharedConfig(BaseSettings):
    some_var: str = Field(default="", env="SOME_VAR")
```

### 5. Logging
- Use `get_context_unit_logger(__name__)` for loggers
- Use `safe_log_value()` for sensitive data
- Never log raw API keys, tokens, or passwords

## Golden Paths

### Adding a ContextUnit Field
1. Add to `ContextUnit` in `sdk.py`
2. Update `context_unit.proto` if gRPC-serialized
3. Run `./compile_protos.sh`
4. Add tests

### Adding a gRPC Method
1. Update proto file (`protos/brain.proto`, etc.)
2. Run `./compile_protos.sh`
3. **Notify downstream services** — they must implement the new method

### Adding Config Option
1. Add to `SharedConfig` in `config.py`
2. Document in README
3. Add tests

## Dependency Policy
ContextCore must remain lightweight:
- `grpcio` — gRPC runtime
- `protobuf` — proto serialization
- `pydantic` — validation

Do NOT add heavy dependencies. If needed, make them optional.

## Testing
```bash
uv run pytest tests/ -v
```

All new functionality must have tests.
