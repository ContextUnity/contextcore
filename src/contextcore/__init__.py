from .sdk import ContextUnit, CotStep, UnitMetrics, SecurityScopes
from .config import SharedConfig, LogLevel, load_shared_config_from_env
from .tokens import ContextToken, TokenBuilder
from .logging import (
    safe_preview,
    redact_secrets,
    safe_log_value,
    ContextUnitFormatter,
    ContextUnitLoggerAdapter,
    setup_logging,
    get_context_unit_logger,
)

# Protobuf imports - optional to avoid import errors if protos aren't generated
try:
    from .generated import context_unit_pb2, context_unit_pb2_grpc
    from .generated import commerce_pb2, commerce_pb2_grpc
    from .generated import brain_pb2, brain_pb2_grpc
    from .generated import worker_pb2, worker_pb2_grpc
except ImportError:
    context_unit_pb2 = None  # type: ignore[assignment]
    context_unit_pb2_grpc = None  # type: ignore[assignment]
    commerce_pb2 = None  # type: ignore[assignment]
    commerce_pb2_grpc = None  # type: ignore[assignment]
    brain_pb2 = None  # type: ignore[assignment]
    brain_pb2_grpc = None  # type: ignore[assignment]
    worker_pb2 = None  # type: ignore[assignment]
    worker_pb2_grpc = None  # type: ignore[assignment]

__all__ = [
    'ContextUnit',
    'CotStep',
    'UnitMetrics',
    'SecurityScopes',
    'ContextToken',
    'TokenBuilder',
    'SharedConfig',
    'LogLevel',
    'load_shared_config_from_env',
    'safe_preview',
    'redact_secrets',
    'safe_log_value',
    'ContextUnitFormatter',
    'ContextUnitLoggerAdapter',
    'setup_logging',
    'get_context_unit_logger',
    'context_unit_pb2',
    'context_unit_pb2_grpc',
    'commerce_pb2',
    'commerce_pb2_grpc',
    'brain_pb2',
    'brain_pb2_grpc',
    'worker_pb2',
    'worker_pb2_grpc',
]
