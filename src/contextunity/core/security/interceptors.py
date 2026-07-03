"""gRPC interceptors for ContextUnity service-level authentication.
Provides:
- ``check_permission`` — standalone permission + tenant check.
- ``ServicePermissionInterceptor`` — unified, parameterised server interceptor.
- ``_extract_rpc_name``, ``_should_skip`` — helper utilities.
Backend resolution (HMAC / Ed25519 / Shield key fetch) and token
revocation are delegated to ``backend_resolver``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable
from typing import TYPE_CHECKING, TypeVar, override

import grpc
from contextunity.core.grpc_metadata import invocation_metadata_as_dict
from contextunity.core.logging import get_contextunit_logger
from contextunity.core.types import GrpcServicerContext

from ..tokens import ContextToken

if TYPE_CHECKING:
    from ..config import SharedConfig

logger = get_contextunit_logger(__name__)

_RequestT = TypeVar("_RequestT")
_ResponseT = TypeVar("_ResponseT")

# Method prefixes that bypass permission checks
_SKIP_PREFIXES = (
    "grpc.health.v1",
    "grpc.reflection.v1",
)


# ── Helpers ──────────────────────────────────────────────────────


def mask_token_id(token_id: str | None) -> str:
    """Mask a token id for logs/errors — show only the first and last chars.

    Returns ``"<none>"`` for empty input. Short ids are returned as-is once
    they are too short to meaningfully mask.
    """
    if not token_id:
        return "<none>"
    tid = token_id.strip()
    if not tid:
        return "<none>"
    if len(tid) <= 12:
        return tid
    return f"{tid[:4]}…{tid[-4:]}"


def _extract_rpc_name(full_method: str) -> str:
    """Extract RPC name from fully-qualified method string.

    Args:
        full_method (str): The full method parameter.

    Returns:
        str: The resulting string value.
    """
    return full_method.rsplit("/", 1)[-1] if "/" in full_method else full_method


def _should_skip(method: str) -> bool:
    """Check if this method should skip permission checks.

    Args:
        method (str): The method parameter.

    Returns:
        bool: True if the operation was successful, False otherwise.
    """
    return any(prefix in method for prefix in _SKIP_PREFIXES)


# ── Permission check ────────────────────────────────────────────


def check_permission(
    token: ContextToken,
    required: str,
    *,
    tenant_id: str | None = None,
) -> str | None:
    """Check if token has the required permission and tenant access.

    Uses ``token.has_permission()`` which is inheritance-aware
    (``admin:all`` implies ``brain:read``, etc.).

    Args:
        token: The caller's ContextToken.
        required: The exact permission string needed (e.g. ``brain:read``).
        tenant_id: If provided, also checks tenant isolation.

    Returns:
        None if allowed, or a human-readable denial reason.
    """
    if not token.has_permission(required):
        return f"missing permission: {required}"

    if tenant_id and hasattr(token, "can_access_tenant"):
        if not token.can_access_tenant(tenant_id):
            return f"tenant access denied: {tenant_id}"

    return None


# ── Unified Interceptor ─────────────────────────────────────────


class ServicePermissionInterceptor(grpc.aio.ServerInterceptor):
    """Unified gRPC server interceptor for domain-specific permission enforcement.

    Sits before all handlers and:
    1. Logs caller identity
    2. Extracts ContextToken string from gRPC metadata
    3. Infers project_id from composite kid
    4. Dynamically builds the verification backend (from env/Shield)
    5. Validates the token cryptographically
    6. Checks permissions
    7. Aborts with ``UNAUTHENTICATED`` / ``PERMISSION_DENIED`` if any check fails
    """

    def __init__(
        self,
        rpc_permission_map: dict[str, str],
        *,
        service_name: str = "Service",
        shield_url: str | None = None,
        config: SharedConfig | None = None,
    ) -> None:
        """Initialize the unified service permission interceptor.

        Args:
            rpc_permission_map: Mapping of RPC methods to their required permission string.
            service_name: Name of the service being intercepted.
            shield_url: Optional URL to the ContextShield service for key resolution.
        """
        self._rpc_map: dict[str, str] = rpc_permission_map
        self._service_name: str = service_name
        self._shield_url: str | None = shield_url
        self._config: SharedConfig | None = config
        logger.info("%s interceptor initialized (enforce mode, shield_url=%s)", self._service_name, self._shield_url)

    async def _is_token_revoked(self, token: ContextToken) -> bool:
        """Delegate to ``backend_resolver.is_token_revoked``.

        Args:
            token (ContextToken): The security token for authentication.

        Returns:
            bool: True if the operation was successful, False otherwise.
        """
        from .backend_resolver import is_token_revoked

        return await is_token_revoked(
            token,
            service_name=self._service_name,
            config=self._config,
        )

    async def _build_verifier_backend(self, token_str: str):
        """Delegate to ``backend_resolver.build_verifier_backend``.

        Args:
            token_str (str): The raw string representation of the token.
        """
        from .backend_resolver import build_verifier_backend

        return await build_verifier_backend(
            token_str,
            shield_url=self._shield_url,
            service_name=self._service_name,
            config=self._config,
        )

    @override
    async def intercept_service(
        self,
        continuation: Callable[
            [grpc.HandlerCallDetails],
            Awaitable[grpc.RpcMethodHandler[_RequestT, _ResponseT] | None],
        ],
        handler_call_details: grpc.HandlerCallDetails,
    ) -> grpc.RpcMethodHandler[_RequestT, _ResponseT] | None:
        """Intercept incoming gRPC calls for permission validation.

        Args:
            continuation (Callable[[grpc.HandlerCallDetails], Awaitable[grpc.RpcMethodHandler[object, object]]]): The continuation parameter.
            handler_call_details (grpc.HandlerCallDetails): The handler call details parameter.

        Returns:
            grpc.RpcMethodHandler[object, object]: An instance of grpc.RpcMethodHandler[object, object].
        """
        method: str = getattr(handler_call_details, "method", "") or ""

        # Skip health checks / reflection
        if _should_skip(method):
            return await continuation(handler_call_details)

        rpc_name = _extract_rpc_name(method)
        raw_metadata = getattr(handler_call_details, "invocation_metadata", None)
        metadata = invocation_metadata_as_dict(raw_metadata)

        # ── Extract token strings ─────────────────────────────────
        # Primary: authorization header (project auth / single-header)
        auth_token_str: str = ""
        auth_raw = metadata.get("authorization", "")
        auth = auth_raw.decode("utf-8") if isinstance(auth_raw, bytes) else str(auth_raw)

        if auth.startswith("Bearer "):
            auth_token_str = auth[7:].strip()

        token_str: str = auth_token_str

        # Build Verifier Backend & Verify Token
        token: ContextToken | None = None
        caller_id = "anonymous"
        tenant_info = ""

        if token_str:
            from ..token_utils import parse_token_string, verify_token_string

            # For logging only: parse without verification
            unsafe_token = parse_token_string(token_str)
            if unsafe_token:
                caller_id = unsafe_token.agent_id or unsafe_token.token_id or "unknown"
                if unsafe_token.allowed_tenants:
                    tenant_info = f" tenants={list(unsafe_token.allowed_tenants)}"

            logger.info(
                "%s RPC %s | caller=%s%s",
                self._service_name,
                rpc_name,
                caller_id,
                tenant_info,
            )

            backend = await self._build_verifier_backend(token_str)
            if backend:
                token = verify_token_string(token_str, backend)

                # ── Key-refresh retry for session tokens ──────────
                # If verification failed, the cached public key in Redis
                # may be stale (e.g. Shield was restarted with a new keypair).
                # Fetch a fresh key from Shield and retry exactly once.
                if token is None and self._shield_url:
                    token = await self._retry_with_fresh_key(token_str)
        else:
            logger.info(
                "%s RPC %s | caller=anonymous",
                self._service_name,
                rpc_name,
            )

        # ── SECURITY ──────────────────────────────────────────────

        # Map RPC to required permission
        required_permission = self._rpc_map.get(rpc_name)
        deny_reason: str | None = None
        deny_code: grpc.StatusCode = grpc.StatusCode.PERMISSION_DENIED

        if required_permission is None:
            deny_reason = "RPC not mapped to permission"
            deny_code = grpc.StatusCode.PERMISSION_DENIED
        elif not token_str:
            deny_reason = f"no token (requires {required_permission or 'identity'})"
            deny_code = grpc.StatusCode.UNAUTHENTICATED
        elif token is None:
            deny_reason = "invalid token (cryptographic verification failed)"
            deny_code = grpc.StatusCode.UNAUTHENTICATED
        elif token.is_expired():
            deny_reason = f"token expired (token '{mask_token_id(token.token_id)}')"
            deny_code = grpc.StatusCode.UNAUTHENTICATED
        elif await self._is_token_revoked(token):
            deny_reason = f"token revoked (token '{mask_token_id(token.token_id)}')"
            deny_code = grpc.StatusCode.UNAUTHENTICATED
        elif required_permission:
            # Non-empty permission string — enforce it.
            # Empty string ("") means identity-only: the RPC handler manages
            # its own authorization (e.g. RegisterManifest).
            perm_denial = check_permission(token, required_permission)
            if perm_denial:
                deny_reason = f"{perm_denial} (token '{mask_token_id(token.token_id)}')"
                deny_code = grpc.StatusCode.PERMISSION_DENIED

        if deny_reason:
            return await self._build_denial_handler(
                rpc_name, deny_reason, deny_code, continuation, handler_call_details
            )

        logger.debug(
            "%s ALLOWED '%s' for token '%s'",
            self._service_name,
            rpc_name,
            mask_token_id(token.token_id) if token else "anonymous",
        )

        # ── Set verified auth context for downstream handlers ─────
        if token is not None and token_str:
            from ..authz.context import VerifiedAuthContext, set_auth_context

            # Extract project_id from kid
            project_id = None
            parts = token_str.rsplit(".", 2)
            if len(parts) == 3 and ":" in parts[0]:
                project_id = parts[0].split(":", 1)[0]

            auth_ctx = VerifiedAuthContext.from_token(
                token,
                token_str,
                project_id=project_id,
            )
            set_auth_context(auth_ctx)

        return await continuation(handler_call_details)

    async def _retry_with_fresh_key(self, token_str: str) -> ContextToken | None:
        """Re-fetch Ed25519 key from Shield and retry verification once.

        Args:
            token_str (str): The raw string representation of the token.

        Returns:
            ContextToken | None: An instance of ContextToken | None.
        """
        from ..token_utils import verify_token_string

        if not self._shield_url:
            return None

        parts = token_str.rsplit(".", 2)
        if len(parts) != 3:
            return None

        kid = parts[0]
        if ":" not in kid:
            return None

        _proj_id, key_ver = kid.split(":", 1)
        if "session" not in key_ver:
            return None

        try:
            from ..token_utils import fetch_project_public_key_async

            pub_b64, ret_kid = await fetch_project_public_key_async(
                _proj_id,
                kid,
                self._shield_url,
                provenance=f"{self._service_name.lower()}:key_refresh_retry",
                config=self._config,
            )

            from contextunity.core.ed25519 import Ed25519Backend as _Ed

            fresh_backend = _Ed(public_key_b64=pub_b64, kid=ret_kid)
            token = verify_token_string(token_str, fresh_backend)
            if token:
                logger.info(
                    "%s key-refresh retry succeeded for %s",
                    self._service_name,
                    kid,
                )
            return token
        except Exception as retry_exc:
            logger.debug(
                "%s key-refresh retry failed for %s: %s",
                self._service_name,
                kid,
                retry_exc,
            )
            return None

    async def _build_denial_handler(
        self,
        rpc_name: str,
        deny_reason: str,
        deny_code: grpc.StatusCode,
        continuation: Callable[
            [grpc.HandlerCallDetails],
            Awaitable[grpc.RpcMethodHandler[_RequestT, _ResponseT] | None],
        ],
        handler_call_details: grpc.HandlerCallDetails,
    ) -> grpc.RpcMethodHandler[_RequestT, _ResponseT]:
        """Construct the appropriate denial handler based on stream type.

        Args:
            rpc_name (str): The rpc name parameter.
            deny_reason (str): The deny reason parameter.
            deny_code (grpc.StatusCode): The deny code parameter.
            continuation (Any): The continuation parameter.
            handler_call_details (Any): The handler call details parameter.
        """
        logger.warning(
            "%s DENIED '%s' — %s",
            self._service_name,
            rpc_name,
            deny_reason,
        )

        _deny_msg = f"{self._service_name}: {rpc_name} denied — {deny_reason}"
        _deny_status = deny_code

        async def _denied_unary_unary(_request: object, context: GrpcServicerContext) -> None:
            await context.abort(_deny_status, _deny_msg)

        async def _denied_unary_stream(_request: object, context: GrpcServicerContext) -> AsyncIterator[object]:
            await context.abort(_deny_status, _deny_msg)
            for _ in ():
                yield _

        async def _denied_stream_unary(_request_iterator: AsyncIterator[object], context: GrpcServicerContext) -> None:
            await context.abort(_deny_status, _deny_msg)

        async def _denied_stream_stream(
            _request_iterator: AsyncIterator[object], context: GrpcServicerContext
        ) -> AsyncIterator[object]:
            await context.abort(_deny_status, _deny_msg)
            for _ in ():
                yield _

        handler = await continuation(handler_call_details)
        if not handler:
            return grpc.unary_unary_rpc_method_handler(_denied_unary_unary)

        req_stream = getattr(handler, "request_streaming", False)
        res_stream = getattr(handler, "response_streaming", False)

        if req_stream and res_stream:
            return grpc.stream_stream_rpc_method_handler(_denied_stream_stream)
        elif req_stream:
            return grpc.stream_unary_rpc_method_handler(_denied_stream_unary)
        elif res_stream:
            return grpc.unary_stream_rpc_method_handler(_denied_unary_stream)
        else:
            return grpc.unary_unary_rpc_method_handler(_denied_unary_unary)


__all__ = [
    "ServicePermissionInterceptor",
    "_extract_rpc_name",
    "_should_skip",
    "check_permission",
    "mask_token_id",
]
