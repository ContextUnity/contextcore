"""gRPC interceptors for ContextUnity service-level authentication.

Provides:
- ``check_permission`` — standalone permission + tenant check.
- ``ServicePermissionInterceptor`` — unified, parameterised server interceptor.
- ``_extract_rpc_name``, ``_should_skip`` — helper utilities.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Awaitable, Callable

if TYPE_CHECKING:
    from contextcore.signing import AuthBackend

import grpc

from contextcore.logging import get_context_unit_logger

from ..tokens import ContextToken

logger = get_context_unit_logger(__name__)


# Method prefixes that bypass permission checks
_SKIP_PREFIXES = (
    "grpc.health.v1",
    "grpc.reflection.v1",
)


# ── Helpers ──────────────────────────────────────────────────────


def _extract_rpc_name(full_method: str) -> str:
    """Extract RPC name from fully-qualified method string.

    ``/brain.BrainService/Search`` → ``Search``
    """
    return full_method.rsplit("/", 1)[-1] if "/" in full_method else full_method


def _should_skip(method: str) -> bool:
    """Check if this method should skip permission checks."""
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
    4. Dynamically builds the verification backend (from Redis/Shield)
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
    ) -> None:
        self._rpc_map = rpc_permission_map
        self._service_name = service_name
        self._shield_url = shield_url
        logger.info("%s interceptor initialized (enforce mode, shield_url=%s)", self._service_name, self._shield_url)

    async def _build_verifier_backend(self, token_str: str) -> "AuthBackend | None":
        """Parse the kid and build the appropriate verifier backend.

        Loads project_secret or public key from Redis via discovery.py.
        If kid points to a Shield session token and we don't have it,
        fetches it from Shield.
        """
        parts = token_str.split(".")
        if len(parts) != 3:
            return None

        kid = parts[0]
        if ":" not in kid:
            logger.warning("Rejecting token with legacy non-composite kid: %s", kid)
            return None

        project_id, key_version = kid.split(":", 1)

        # We need to fetch the key material from Redis
        try:
            import asyncio

            from ..discovery import get_project_key

            if asyncio.iscoroutinefunction(get_project_key):
                key_data = await get_project_key(project_id)
            else:
                key_data = get_project_key(project_id)
        except (ImportError, AttributeError):
            key_data = None

        if not key_data:
            if "session" in key_version and self._shield_url:
                try:
                    from ..discovery import update_project_public_key
                    from ..token_utils import fetch_project_public_key_async

                    pub_key_b64, returned_kid = await fetch_project_public_key_async(
                        project_id,
                        kid,
                        self._shield_url,
                        provenance=f"{self._service_name.lower()}:fetch_public_key",
                    )
                    update_project_public_key(project_id, pub_key_b64, returned_kid)
                    try:
                        from contextcore.ed25519 import Ed25519Backend

                        return Ed25519Backend(public_key_b64=pub_key_b64, kid=returned_kid)
                    except ImportError:
                        logger.error("contextshield not installed, cannot verify Ed25519 tokens")
                        return None
                except Exception as e:
                    logger.warning(
                        "Failed bootstrap public-key fetch from Shield for %s: %s",
                        kid,
                        e,
                    )
                    return None
            # Fallback: CU_PROJECT_SECRET env var (dev/testing, or single-project setup)

            from contextcore.config import get_core_config

            secret = get_core_config().security.project_secret
            if secret:
                from ..signing import HmacBackend

                return HmacBackend(project_id, project_secret=secret)
            logger.warning("No key material found in Redis for project %s", project_id)
            return None

        # Determine Algorithm
        if "session" in key_version:
            # Ed25519 Session Token
            pub_key_b64 = key_data.get("public_key_b64")
            if not pub_key_b64 and self._shield_url:
                try:
                    from ..discovery import update_project_public_key
                    from ..token_utils import fetch_project_public_key_async

                    pub_key_b64, returned_kid = await fetch_project_public_key_async(
                        project_id,
                        kid,
                        self._shield_url,
                        provenance=f"{self._service_name.lower()}:fetch_public_key",
                    )
                    update_project_public_key(project_id, pub_key_b64, returned_kid)
                except Exception as e:
                    logger.warning("Failed to fetch public key from Shield for %s: %s", kid, e)
                    return None

            if pub_key_b64:
                try:
                    from contextcore.ed25519 import Ed25519Backend

                    return Ed25519Backend(public_key_b64=pub_key_b64, kid=kid)
                except ImportError:
                    logger.error("contextshield not installed, cannot verify Ed25519 tokens")
        else:
            # HMAC Token
            secret = key_data.get("project_secret")
            if not secret:
                logger.warning(
                    "No HMAC secret found for project %s (kid=%s, key_version=%s)", project_id, kid, key_version
                )
                return None

            from ..signing import HmacBackend

            return HmacBackend(project_id, project_secret=secret)

    async def intercept_service(
        self,
        continuation: Callable[[grpc.HandlerCallDetails], Awaitable[grpc.RpcMethodHandler]],
        handler_call_details: grpc.HandlerCallDetails,
    ) -> grpc.RpcMethodHandler:
        """Intercept incoming gRPC calls for permission validation.

        Dual-header flow (Enterprise mode with SessionTokenBackend):
          - ``authorization``: Ed25519 SessionToken → project-level authn + permission check
          - ``x-context-token``: HMAC ContextToken → per-request user identity

        Single-header flow (HMAC mode):
          - ``authorization``: HMAC ContextToken → both authn and user identity
        """
        method = handler_call_details.method or ""

        # Skip health checks / reflection
        if _should_skip(method):
            return await continuation(handler_call_details)

        rpc_name = _extract_rpc_name(method)
        metadata = dict(handler_call_details.invocation_metadata or [])

        # ── Extract token strings ─────────────────────────────────
        # Primary: authorization header (project auth / single-header)
        auth_token_str = ""
        auth = metadata.get("authorization", "")
        if auth.startswith("Bearer "):
            auth_token_str = auth[7:].strip()

        # Secondary: x-context-token (user identity in dual-header mode)
        user_token_str = metadata.get("x-context-token", "").strip()

        # Pick the primary token string for auth/permission verification
        token_str = auth_token_str or user_token_str

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
            deny_reason = f"no token (requires {required_permission})"
            deny_code = grpc.StatusCode.UNAUTHENTICATED
        elif token is None:
            deny_reason = "invalid token (cryptographic verification failed)"
            deny_code = grpc.StatusCode.UNAUTHENTICATED
        elif token.is_expired():
            deny_reason = f"token expired (token '{token.token_id}')"
            deny_code = grpc.StatusCode.UNAUTHENTICATED
        else:
            perm_denial = check_permission(token, required_permission)
            if perm_denial:
                deny_reason = f"{perm_denial} (token '{token.token_id}')"
                deny_code = grpc.StatusCode.PERMISSION_DENIED

        if deny_reason:
            # ── ENFORCE mode: actually block ──────────────────────
            logger.warning(
                "%s DENIED '%s' — %s",
                self._service_name,
                rpc_name,
                deny_reason,
            )

            _deny_msg = f"{self._service_name}: {rpc_name} denied — {deny_reason}"
            _deny_status = deny_code

            async def _denied_unary_unary(request, context):
                await context.abort(_deny_status, _deny_msg)

            async def _denied_unary_stream(request, context):
                await context.abort(_deny_status, _deny_msg)
                yield

            async def _denied_stream_unary(request_iterator, context):
                await context.abort(_deny_status, _deny_msg)

            async def _denied_stream_stream(request_iterator, context):
                await context.abort(_deny_status, _deny_msg)
                yield

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

        logger.debug(
            "%s ALLOWED '%s' for token '%s'",
            self._service_name,
            rpc_name,
            token.token_id if token else "anonymous",
        )

        # ── User identity enrichment from x-context-token ─────────
        # In dual-header mode (Enterprise), the primary token (SessionToken)
        # has no user_id. If x-context-token is present and different from
        # the auth token, verify it and extract user identity.
        user_identity_token: ContextToken | None = None
        if token is not None and user_token_str and auth_token_str and user_token_str != auth_token_str:
            user_id_from_auth = getattr(token, "user_id", None)
            if not user_id_from_auth or user_id_from_auth == "system":
                # Detect Enterprise mode: primary token was Ed25519 session token.
                # In this mode, Router doesn't have the project's HMAC secret,
                # so we can't verify x-context-token cryptographically.
                # Instead, trust it transitively — project identity was already
                # proven by the Ed25519 session token, so the HMAC user token
                # it attached is trusted.
                primary_kid = auth_token_str.split(".")[0] if "." in auth_token_str else ""
                is_enterprise = "session" in primary_kid

                if is_enterprise:
                    from ..token_utils import parse_token_string

                    user_identity_token = parse_token_string(user_token_str)
                    if user_identity_token and user_identity_token.user_id:
                        logger.debug(
                            "%s: extracted user identity from x-context-token (Enterprise, transitive trust): user_id=%s",
                            self._service_name,
                            user_identity_token.user_id,
                        )
                else:
                    from ..token_utils import verify_token_string

                    user_backend = await self._build_verifier_backend(user_token_str)
                    if user_backend:
                        try:
                            user_identity_token = verify_token_string(user_token_str, user_backend)
                            if user_identity_token and user_identity_token.user_id:
                                logger.debug(
                                    "%s: enriched user identity from x-context-token: user_id=%s",
                                    self._service_name,
                                    user_identity_token.user_id,
                                )
                        except Exception as e:
                            logger.warning(
                                "%s: failed to verify x-context-token for user identity: %s",
                                self._service_name,
                                e,
                            )

        # ── Set verified auth context for downstream handlers ─────
        if token is not None and token_str:
            from ..authz.context import VerifiedAuthContext, set_auth_context

            # Extract project_id from kid
            project_id = None
            parts = token_str.split(".")
            if len(parts) == 3 and ":" in parts[0]:
                project_id = parts[0].split(":", 1)[0]

            # If we have a verified user identity token, build the auth context
            # with user_id from that token (cryptographically proven, not metadata)
            effective_token = token
            if user_identity_token and user_identity_token.user_id:
                import dataclasses

                effective_token = dataclasses.replace(
                    token,
                    user_id=user_identity_token.user_id,
                    user_namespace=user_identity_token.user_namespace,
                )

            auth_ctx = VerifiedAuthContext.from_token(
                effective_token,
                token_str,
                project_id=project_id,
            )
            set_auth_context(auth_ctx)

        return await continuation(handler_call_details)


__all__ = [
    "ServicePermissionInterceptor",
    "_extract_rpc_name",
    "_should_skip",
    "check_permission",
]
