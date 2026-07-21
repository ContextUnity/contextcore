"""ContextUnity Core — shared kernel for the service mesh.

Re-exports gRPC stubs, ``ContextUnit``, ``ContextToken``, ``TokenBuilder``,
logging utilities, and the exception hierarchy.  Every service in the
ecosystem depends on this package.
"""

# Proto modules (gRPC)
# 1. Well-known types MUST load first (protobuf 5+ requires explicit dep loading)
# 2. contextunit_pb2 next (all other protos depend on it)
# 3. Service protos last
from google.protobuf import struct_pb2 as _struct_pb2  # isort:skip
from google.protobuf import timestamp_pb2 as _timestamp_pb2  # isort:skip

__proto_deps__ = (_struct_pb2, _timestamp_pb2)
from . import contextunit_pb2  # isort:skip  # noqa: F401
from . import (  # isort:skip
    admin_pb2,
    admin_pb2_grpc,
    brain_pb2,
    brain_pb2_grpc,
    router_pb2,
    router_pb2_grpc,
    shield_pb2,
    shield_pb2_grpc,
    worker_pb2,
    worker_pb2_grpc,
)
from .config import (
    LogLevel,
    ServiceConfig,
    SharedConfig,
    SharedSecurityConfig,
    get_bool_env,
    get_core_config,
    get_env,
    load_service_config,
    set_env_default,
)

# Proto enums re-exported for convenience
from .contextunit_pb2 import Modality
from .discovery import (
    ServiceInfo,
    deregister_service,
    discover_endpoints,
    discover_services,
    register_service,
    resolve_service_endpoint,
)
from .exceptions import (
    ConfigurationError,
    ContextUnityError,
    DatabaseConnectionError,
    ErrorRegistry,
    ProviderError,
    RedisConnectionError,
    SecurityError,
    StorageError,
    TamperDetectedError,
    error_registry,
    register_error,
)
from .grpc_errors import (
    get_grpc_status_code,
    grpc_error_handler,
    grpc_stream_error_handler,
    grpc_sync_error_handler,
)
from .grpc_utils import (
    bind_server_port,
    create_channel,
    create_channel_sync,
    create_server_credentials,
    graceful_shutdown,
    start_grpc_server,
    tls_enabled,
)
from .logging import (
    ContextUnitFormatter,
    ContextUnitLoggerAdapter,
    get_contextunit_logger,
    redact_secrets,
    safe_log_value,
    safe_preview,
    setup_logging,
)
from .permissions import (
    DEFAULT_TOOL_POLICIES,
    NAMESPACE_PROFILES,
    PERMISSION_INHERITANCE,
    PROJECT_PROFILES,
    Permissions,
    ToolPolicy,
    ToolRisk,
    ToolScope,
    UserNamespace,
    check_tool_scope,
    expand_permissions,
    extract_tool_names,
    has_graph_access,
    has_registration_access,
    has_tool_access,
    has_tool_scope_access,
)
from .sdk import (
    BrainClient,
    CellSearchResult,
    ContextUnit,
    CotStep,
    FederatedToolCallContext,
    RouterClient,
    SecurityScopes,
    ShieldClient,
    UnitMetrics,
    WorkerClient,
)
from .sdk.prompt_integrity import (
    compute_prompt_version,
    sign_prompt,
    verify_prompt,
)
from .security import (
    ServicePermissionInterceptor,
    check_permission,
)
from .signing import (
    AuthBackend,
    HmacBackend,
    SessionTokenBackend,
    SignedPayload,
    get_signing_backend,
)
from .token_utils import (
    TokenMetadataInterceptor,
    create_grpc_metadata_with_token,
    create_http_headers_with_token,
    extract_and_verify_token_from_http_request,
    extract_token_from_grpc_metadata,
    extract_token_from_http_request,
    extract_token_string_from_http_request,
    parse_token_string,
    serialize_token,
)
from .tokens import (
    ContextToken,
    PlatformBound,
    ProjectBinding,
    ProjectBound,
    TokenBuilder,
    get_brain_service_token,
    mint_service_token,
)

__all__ = [
    # Logging
    "setup_logging",
    "get_contextunit_logger",
    "safe_preview",
    "redact_secrets",
    "safe_log_value",
    "ContextUnitFormatter",
    "ContextUnitLoggerAdapter",
    # Config
    "load_service_config",
    "get_core_config",
    "SharedConfig",
    "SharedSecurityConfig",
    "ServiceConfig",
    "LogLevel",
    "get_env",
    "get_bool_env",
    "set_env_default",
    # SDK
    "ContextUnit",
    "BrainClient",
    "RouterClient",
    "ShieldClient",
    "WorkerClient",
    "SecurityScopes",
    "CellSearchResult",
    "CotStep",
    "UnitMetrics",
    "FederatedToolCallContext",
    # Exceptions (infrastructure)
    "ContextUnityError",
    "ConfigurationError",
    "ProviderError",
    "SecurityError",
    "TamperDetectedError",
    "StorageError",
    "DatabaseConnectionError",
    "RedisConnectionError",
    "ErrorRegistry",
    "error_registry",
    "register_error",
    "get_grpc_status_code",
    "grpc_error_handler",
    "grpc_stream_error_handler",
    "grpc_sync_error_handler",
    # Tokens
    "ContextToken",
    "PlatformBound",
    "ProjectBinding",
    "ProjectBound",
    "TokenBuilder",
    "mint_service_token",
    # Permissions
    "Permissions",
    "UserNamespace",
    "ToolScope",
    "ToolRisk",
    "ToolPolicy",
    "PERMISSION_INHERITANCE",
    "NAMESPACE_PROFILES",
    "PROJECT_PROFILES",
    "DEFAULT_TOOL_POLICIES",
    "expand_permissions",
    "has_tool_access",
    "has_graph_access",
    "extract_tool_names",
    "has_tool_scope_access",
    "has_registration_access",
    "check_tool_scope",
    # Token utilities
    "extract_token_from_grpc_metadata",
    "create_grpc_metadata_with_token",
    "extract_token_string_from_http_request",
    "extract_token_from_http_request",
    "extract_and_verify_token_from_http_request",
    "create_http_headers_with_token",
    "TokenMetadataInterceptor",
    "serialize_token",
    "parse_token_string",
    # Signing backends
    "AuthBackend",
    "SessionTokenBackend",
    "HmacBackend",
    "SignedPayload",
    "get_signing_backend",
    # Service discovery
    "ServiceInfo",
    "register_service",
    "deregister_service",
    "discover_services",
    "discover_endpoints",
    "resolve_service_endpoint",
    # Security integration
    "check_permission",
    "ServicePermissionInterceptor",
    # Proto modules (gRPC)
    "contextunit_pb2",
    "admin_pb2",
    "admin_pb2_grpc",
    "brain_pb2",
    "brain_pb2_grpc",
    "router_pb2",
    "router_pb2_grpc",
    "shield_pb2",
    "shield_pb2_grpc",
    "worker_pb2",
    "worker_pb2_grpc",
    # gRPC TLS utilities
    "tls_enabled",
    "create_channel",
    "create_channel_sync",
    "create_server_credentials",
    "bind_server_port",
    "graceful_shutdown",
    "start_grpc_server",
    "get_brain_service_token",
    # Proto enums
    "Modality",
    # Prompt integrity
    "compute_prompt_version",
    "sign_prompt",
    "verify_prompt",
]
