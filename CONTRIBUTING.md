# Contributing to ContextCore

Thanks for contributing to **ContextCore** — the kernel of ContextUnity.

## Development Setup

```bash
cd contextcore
uv sync --dev
```

## Pre-commit

```bash
pre-commit install
pre-commit run --all-files
```

## Linting & Tests

```bash
uv run ruff check . --fix
uv run ruff format .
uv run pytest tests/ -v
```

## Branching & PR Flow

### Branch naming

- **Features**: `feat/<short-topic>`
- **Fixes**: `fix/<short-topic>`
- **Chores**: `chore/<short-topic>`

### Merge strategy

- Prefer **Squash & merge** into `main`
- Use **Conventional Commits** style: `feat:`, `fix:`, `docs:`, etc.

### Releases

- Bump version in `pyproject.toml` (SemVer)
- Tag releases as `vX.Y.Z`

---

## Golden Path: Adding New Functionality

ContextCore is a **shared kernel** — changes here affect all services. Follow these paths carefully.

### Adding a New ContextUnit Field

1. **Update `sdk.py`** — add field to `ContextUnit` Pydantic model:
   ```python
   class ContextUnit(BaseModel):
       # ... existing fields ...
       new_field: str | None = None
   ```

2. **Update `context_unit.proto`** (if gRPC-serialized):
   ```protobuf
   message ContextUnit {
       // ... existing ...
       optional string new_field = N;
   }
   ```

3. **Regenerate protos**:
   ```bash
   ./compile_protos.sh
   ```

4. **Add tests**: `tests/test_sdk.py`

5. **Bump version**: patch version in `pyproject.toml`

### Adding a New gRPC Method

1. **Update the proto file** (e.g., `protos/brain.proto`):
   ```protobuf
   service BrainService {
       // ... existing ...
       rpc NewMethod(NewRequest) returns (NewResponse);
   }

   message NewRequest { ... }
   message NewResponse { ... }
   ```

2. **Regenerate protos**:
   ```bash
   ./compile_protos.sh
   ```

3. **Bump version**: minor version if new method, patch if just fields

4. **Notify downstream services** — they need to implement the new method

### Adding a New Configuration Option

1. **Update `config.py`** — add to `SharedConfig`:
   ```python
   class SharedConfig(BaseSettings):
       # ... existing ...
       new_option: str = Field(default="value", env="NEW_OPTION")
   ```

2. **Document in README** — add to Configuration section

3. **Add tests**: `tests/test_config.py`

### Adding Logging Utilities

1. **Update `logging.py`** — add new function or pattern

2. **Export from `__init__.py`**:
   ```python
   from .logging import new_function
   __all__ = [..., "new_function"]
   ```

3. **Add tests**: `tests/test_logging.py`

---

## Architecture Rules

1. **Zero business logic** — Core is purely infrastructure
2. **Minimal dependencies** — keep the kernel lightweight
3. **Backward compatibility** — don't break existing fields/methods
4. **Type safety** — use Pydantic for validation

## Proto Contract Rules

⚠️ **Proto changes require ecosystem-wide review:**

- Proto definitions are shared by all services
- Breaking changes require version bump in ALL downstream services
- Add new fields as `optional` to maintain compatibility
- Never remove or renumber existing fields

## Code Style

- Python: PEP 8, 4-space indent, strict typing
- 100% type hints on public API
- Docstrings for public functions

---

## Common Pitfalls

1. **Forgot `__all__`** — new exports won't be importable from `contextcore`
2. **Changed proto field numbers** —breaks all downstream gRPC clients
3. **Non-optional new fields** — breaks deserialization of old data
4. **Direct `os.environ`** — use `SharedConfig` with env validation
