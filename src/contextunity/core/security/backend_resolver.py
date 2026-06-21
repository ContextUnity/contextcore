"""Verifier backend resolution for ContextToken authentication.

Resolves the correct signing backend (HMAC or Ed25519) given a raw token
string.  Also provides token revocation checking against the Redis
revocation store.

Extracted from ``interceptors.py`` to keep the interceptor focused on
gRPC control flow while this module owns the "where does the key live?"
decision tree.
"""

from __future__ import annotations

from collections.abc import Awaitable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..config import SharedConfig
    from ..signing import VerifierBackend

from contextunity.core.logging import get_contextunit_logger

from ..discovery.types import ProjectKeyInfo
from ..tokens import ContextToken

logger = get_contextunit_logger(__name__)


async def is_token_revoked(
    token: ContextToken,
    *,
    service_name: str = "Service",
    config: SharedConfig | None = None,
) -> bool:
    """Check token revocation against the shared Redis revocation store.

    **Fail-closed semantics.**  When the token declares a
    ``revocation_id``, the revocation store *must* be reachable.  Any
    failure — Redis not configured, client library missing,
    connection refused, timeout, or transport error — causes the
    token to be treated as revoked.

    Tokens without ``revocation_id`` are non-revocable by design and
    always pass this check.
    """
    if not token.revocation_id:
        return False

    import asyncio

    if config is None:
        from ..config import get_core_config

        config = get_core_config()

    redis_url = config.redis.url if config.redis.enabled else ""
    if not redis_url:
        if config.local_mode:
            logger.debug(
                "%s: skipping revocation check for token '%s' in local_mode (no redis)",
                service_name,
                token.token_id,
            )
            return False
        logger.error(
            (
                "%s: token '%s' has revocation_id=%s but redis_url is not "
                "configured; failing closed (treating as revoked). Configure "
                "redis_url in the shared core config to enable revocation."
            ),
            service_name,
            token.token_id,
            token.revocation_id,
        )
        return True

    try:
        import importlib

        _ = importlib.import_module("redis.asyncio")
    except ImportError:
        logger.error(
            (
                "%s: redis[async] is not installed; cannot enforce revocation "
                "for token '%s' (revocation_id=%s); failing closed. Install "
                "with: pip install 'redis[async]'"
            ),
            service_name,
            token.token_id,
            token.revocation_id,
        )
        return True

    import redis.asyncio as aioredis

    client = aioredis.from_url(
        redis_url,
        decode_responses=True,
        socket_connect_timeout=2,
        socket_timeout=2,
    )
    try:
        key = f"contextunity:revoked:{token.revocation_id}"
        exists_awaitable: Awaitable[object] = client.exists(key)
        exists_count_raw: object = await asyncio.wait_for(exists_awaitable, timeout=3.0)
        exists_count = int(exists_count_raw) if isinstance(exists_count_raw, int) else 0
        return exists_count > 0
    except (TimeoutError, asyncio.CancelledError):
        logger.error(
            "%s: revocation check timed out for token '%s' (revocation_id=%s); failing closed (treating as revoked)",
            service_name,
            token.token_id,
            token.revocation_id,
        )
        return True
    except Exception as exc:
        logger.error(
            "%s: revocation check failed for token '%s' (revocation_id=%s): %s; failing closed (treating as revoked)",
            service_name,
            token.token_id,
            token.revocation_id,
            exc,
        )
        return True
    finally:
        try:
            close_awaitable: Awaitable[object] = client.aclose()
            _ = await close_awaitable
        except Exception:
            pass


async def build_verifier_backend(
    token_str: str,
    *,
    shield_url: str | None = None,
    service_name: str = "Service",
    config: SharedConfig | None = None,
) -> VerifierBackend | None:
    """Parse the kid and build the appropriate verifier backend.

    Loads project_secret or public key from the ProjectStore.
    If kid points to a Shield session token and we don't have it,
    fetches it from Shield.

    Resolution order:
      1. ProjectStore (Redis or InMemory) via ``get_project_key()``
      2. Shield bootstrap (Ed25519 only, when ``shield_url`` is set)
      3. ``CU_PROJECT_SECRET`` env fallback (only when no store record exists)
    """
    parts = token_str.rsplit(".", 2)
    if len(parts) != 3:
        return None

    kid = parts[0]
    if ":" not in kid:
        logger.warning("Rejecting token with legacy non-composite kid: %s", kid)
        return None

    project_id, key_version = kid.split(":", 1)

    # Fetch key material from ProjectStore
    key_data: ProjectKeyInfo | None = None
    try:
        from ..discovery import get_project_key

        key_data = get_project_key(project_id)
    except (ImportError, AttributeError):
        key_data = None

    if not key_data:
        # No record in ProjectStore — try Shield bootstrap or env fallback
        if "session" in key_version and shield_url:
            return await _bootstrap_ed25519_from_shield(
                project_id,
                kid,
                shield_url,
                service_name,
                config=config,
            )

        # Fallback: CU_PROJECT_SECRET env var (dev/testing, or single-project setup)
        from ..config import get_core_config

        secret = get_core_config().security.project_secret
        if secret:
            from ..signing import HmacBackend

            logger.warning(
                "%s: using CU_PROJECT_SECRET fallback for project %s because ProjectStore has no key material",
                service_name,
                project_id,
            )
            return HmacBackend(project_id, project_secret=secret)
        logger.warning("No key material found for project %s", project_id)
        return None

    # ── Record exists — determine algorithm from key_version ──────
    if "session" in key_version:
        return await _resolve_ed25519(
            key_data,
            project_id,
            kid,
            shield_url,
            service_name,
            config=config,
        )

    # HMAC Token — ProjectStore is the source of truth
    secret_raw: object = key_data.get("project_secret")
    secret = secret_raw if isinstance(secret_raw, str) else None
    if not secret:
        logger.warning(
            "No HMAC secret found for project %s (kid=%s, key_version=%s)",
            project_id,
            kid,
            key_version,
        )
        return None

    from ..signing import HmacBackend

    return HmacBackend(project_id, project_secret=secret)


async def _bootstrap_ed25519_from_shield(
    project_id: str,
    kid: str,
    shield_url: str,
    service_name: str,
    *,
    config: SharedConfig | None = None,
) -> VerifierBackend | None:
    """Fetch Ed25519 public key from Shield when no store record exists."""
    try:
        from ..discovery import update_project_public_key
        from ..token_utils import fetch_project_public_key_async

        pub_key_b64, returned_kid = await fetch_project_public_key_async(
            project_id,
            kid,
            shield_url,
            provenance=f"{service_name.lower()}:fetch_public_key",
            config=config,
        )
        _ = update_project_public_key(project_id, pub_key_b64, returned_kid)
        try:
            from contextunity.core.ed25519 import Ed25519Backend

            return Ed25519Backend(public_key_b64=pub_key_b64, kid=returned_kid)
        except ImportError:
            logger.error("contextunity.shield not installed, cannot verify Ed25519 tokens")
            return None
    except Exception as e:
        logger.warning("Failed bootstrap public-key fetch from Shield for %s: %s", kid, e)
        return None


async def _resolve_ed25519(
    key_data: ProjectKeyInfo,
    project_id: str,
    kid: str,
    shield_url: str | None,
    service_name: str,
    *,
    config: SharedConfig | None = None,
) -> VerifierBackend | None:
    """Resolve Ed25519 backend from stored key data, fetching from Shield if needed."""
    pub_key_raw: object = key_data.get("public_key_b64")
    pub_key_b64 = pub_key_raw if isinstance(pub_key_raw, str) else None
    if not pub_key_b64 and shield_url:
        try:
            from ..discovery import update_project_public_key
            from ..token_utils import fetch_project_public_key_async

            pub_key_b64, returned_kid = await fetch_project_public_key_async(
                project_id,
                kid,
                shield_url,
                provenance=f"{service_name.lower()}:fetch_public_key",
                config=config,
            )
            _ = update_project_public_key(project_id, pub_key_b64, returned_kid)
        except Exception as e:
            logger.warning("Failed to fetch public key from Shield for %s: %s", kid, e)
            return None

    if pub_key_b64:
        try:
            from contextunity.core.ed25519 import Ed25519Backend

            return Ed25519Backend(public_key_b64=pub_key_b64, kid=kid)
        except ImportError:
            logger.error("contextunity.shield not installed, cannot verify Ed25519 tokens")

    return None


__all__ = [
    "build_verifier_backend",
    "is_token_revoked",
]
