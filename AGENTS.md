# ContextCore — Agent instructions

Kernel layer: shared types (`ContextUnit`, `ContextToken`), unified gRPC contracts (Protobufs), token verification primitives, cryptography interfaces, and service SDKs.

**License Context**: This service operates under the **Apache 2.0 Open-Source License**.

## Navigation & Entry
- **Workspace**: `services/contextcore/`
- **Proto definitions**: `services/contextcore/protos/`. After modifying `.proto` files, run `./compile_protos.sh`. DO NOT hand-edit `_pb2.py` files.
- **Tests**: run `uv run --package contextcore pytest` from the monorepo root.

## Architecture Context (Current Code State)
- **ContextUnit Protocol (`context_unit.proto`, `sdk/context_unit.py`)**: The primary payload envelope. Defines `payload`, `metadata`, `provenance`, and `security` structures.
- **ContextToken (`tokens.py`, `token_utils.py`)**: The ABAC identity model. Includes deterministic serialization and parsing functions.
- **Signing Interfaces (`signing.py`)**: Abstract layers (`SigningBackend`, `HmacBackend`, `Ed25519Backend`, `KmsBackend`) standardizing token minting and cryptographic signatures across the mesh.
- **Service SDKs (`sdk/`)**: Client stubs connecting to Router, Worker, Commerce, Voice, Zero, etc. Uses the `grpc_utils.py` interceptors automatically passing the Active token.
- **Central Exceptions (`exceptions.py`)**: Absolute registry mapping string error codes to derived `ContextUnityError` classes ensuring consistent cross-RPC tracing.
- **Service Discovery (`discovery.py`)**: gRPC DNS registry, mapping abstract targets (like `"router"`) to physical host/port resolutions.

## Documentation Strategy
When modifying or extending this service, update documentation strictly across these boundaries:
1. **Technical Specifications**: `services/contextcore/contextcore-fulldoc.md`. Update this when adding fields to `context_unit.proto`, modifying token parsers, or adding new Exception codes.
2. **Public Website**: `docs/website/src/content/docs/core/`. Keep conceptual diagrams on the Token Protocol or Security Model here.
3. **Plans & Architecture**: `plans/core/`.

## Rules specific to ContextCore
- **WARNING**: Do NOT add unnecessary external dependencies. ContextCore MUST remain lightweight (mainly `grpcio`, `protobuf`, `pydantic`). If functionality requires heavy dependencies (e.g., specific KMS clients), use lazy imports or module boundaries.
- Protocol Buffer fields MUST be appended; never delete or renumber an existing `.proto` field to maintain backward compatibility across old deployments.
- Refer strictly to the rules inside `contextcore-rules.md` in `rules/`.


## AI Agent Rules (`rules/`)
ContextUnity uses strict AI assistant rules. You **MUST** review and adhere to the following rule files before modifying this service:
- `rules/global-rules.md` (General ContextUnity architecture and boundaries)
- `rules/contextcore-rules.md` (Specific constraints for the **contextcore** domain)
