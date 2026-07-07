"""Verifier backend resolution for ContextToken authentication.

Resolves the correct signing backend (HMAC or Ed25519) given a raw token
string.  Also provides token revocation checking against the Redis
revocation store.

Extracted from ``interceptors.py`` to keep the interceptor focused on
gRPC control flow while this module owns the "where does the key live?"
decision tree.
"""

from __future__ import annotations

import re
from collections.abc import Awaitable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..config import SharedConfig
    from ..signing import VerifierBackend

from contextunity.core.logging import get_contextunit_logger

from ..tokens import ContextToken

logger = get_contextunit_logger(__name__)

# Shield session token_ids are minted as "session:{project_id}:{unix_ts}" (see
# contextunity.shield PKIHandler.issue_session_token). This regex identifies a
# session token and extracts its project_id (for the epoch Redis key).
#
# The precise issue time for the epoch comparison comes from ``ContextToken.iat``
# (a float, set at mint time), NOT from token_id's integer-second suffix — that
# truncation previously caused a real bug: a token issued at, say, 1000.950 got
# token_id "...1000" (via int(now)), so a revoke_all bump at 1000.900 would
# wrongly reject it (1000 < 1000.900) even though it was minted AFTER the bump.
#
# There is deliberately no fallback to the token_id timestamp when ``iat`` is
# missing: ``issue_session_token`` is the sole minter of session tokens and
# always sets ``iat``, so a session-shaped token without one cannot occur in
# practice. If it somehow did, the epoch check is skipped for that token rather
# than guessing via a known-imprecise value (see is_token_revoked below).
_SESSION_TOKEN_ID_RE = re.compile(r"^session:([a-z0-9][a-z0-9_\-]{0,62}):\d+$")

# Must match contextunity.shield.revocation.EPOCH_KEY_PREFIX. Duplicated here
# (rather than imported) because core cannot depend on the shield package —
# the same pattern already used for the "contextunity:revoked:" prefix below.
_EPOCH_KEY_PREFIX = "contextunity:epoch"


def _parse_session_project_id(token_id: str | None) -> str | None:
    """Extract the project_id from a Shield session ``token_id``, if it is one."""
    match = _SESSION_TOKEN_ID_RE.match(token_id or "")
    return match.group(1) if match else None


async def is_token_revoked(
    token: ContextToken,
    *,
    service_name: str = "Service",
    config: SharedConfig | None = None,
) -> bool:
    """Check token revocation against the shared Redis revocation store.

    Two independent checks share the same Redis round trip:

    1. **Explicit revocation** — ``revocation_id`` denylist entry
       (``contextunity:revoked:{revocation_id}``).
    2. **Project epoch (revoke-all)** — Shield session tokens are revoked if
       ``token.iat`` predates the project's ``contextunity:epoch:{project_id}``
       watermark. Requires both a session-shaped ``token_id`` (to resolve the
       project) and a non-``None`` ``iat`` (the precise issue time); the sole
       minter of session tokens always sets both, so this check is simply
       skipped — not approximated — for anything that doesn't have them.

    **Fail-closed semantics.** Once either check is needed, the revocation
    store *must* be reachable. Any failure — Redis not configured, client
    library missing, connection refused, timeout, or transport error —
    causes the token to be treated as revoked.

    Tokens with neither a ``revocation_id`` nor a session ``token_id`` +
    ``iat`` pair are non-revocable by this mechanism and always pass.
    """
    session_project_id = _parse_session_project_id(token.token_id)
    needs_explicit_check = bool(token.revocation_id)
    needs_epoch_check = session_project_id is not None and token.iat is not None

    if not needs_explicit_check and not needs_epoch_check:
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
                "%s: token '%s' requires a revocation check (revocation_id=%s, "
                "session_epoch_check=%s) but redis_url is not configured; failing "
                "closed (treating as revoked). Configure redis_url in the shared "
                "core config to enable revocation."
            ),
            service_name,
            token.token_id,
            token.revocation_id,
            needs_epoch_check,
        )
        return True

    try:
        import importlib

        _ = importlib.import_module("redis.asyncio")
    except ImportError:
        logger.error(
            (
                "%s: redis[async] is not installed; cannot enforce revocation "
                "for token '%s'; failing closed. Install with: pip install 'redis[async]'"
            ),
            service_name,
            token.token_id,
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
        if needs_explicit_check:
            key = f"contextunity:revoked:{token.revocation_id}"
            exists_awaitable: Awaitable[object] = client.exists(key)
            exists_count_raw: object = await asyncio.wait_for(exists_awaitable, timeout=3.0)
            exists_count = int(exists_count_raw) if isinstance(exists_count_raw, int) else 0
            if exists_count > 0:
                return True

        if session_project_id is not None and token.iat is not None:
            project_id = session_project_id
            issued_at = token.iat
            epoch_key = f"{_EPOCH_KEY_PREFIX}:{project_id}"
            epoch_awaitable: Awaitable[object] = client.get(epoch_key)
            epoch_raw: object = await asyncio.wait_for(epoch_awaitable, timeout=3.0)
            if epoch_raw is not None:
                try:
                    epoch_ts = float(str(epoch_raw))
                except ValueError:
                    epoch_ts = None
                if epoch_ts is not None and issued_at < epoch_ts:
                    logger.warning(
                        "%s: token '%s' issued before project '%s' epoch bump "
                        "(issued_at=%.3f < epoch=%.3f); treating as revoked",
                        service_name,
                        token.token_id,
                        project_id,
                        issued_at,
                        epoch_ts,
                    )
                    return True

        return False
    except (TimeoutError, asyncio.CancelledError):
        logger.error(
            "%s: revocation check timed out for token '%s'; failing closed (treating as revoked)",
            service_name,
            token.token_id,
        )
        return True
    except Exception as exc:
        logger.error(
            "%s: revocation check failed for token '%s': %s; failing closed (treating as revoked)",
            service_name,
            token.token_id,
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

    Session tokens resolve Ed25519 public keys from Shield. HMAC tokens use
    ``CU_PROJECT_SECRET`` directly.

    Resolution order:
      1. Shield bootstrap (Ed25519 session tokens)
      2. ``CU_PROJECT_SECRET`` env (HMAC bootstrap tokens)
    """
    parts = token_str.rsplit(".", 2)
    if len(parts) != 3:
        return None

    kid = parts[0]
    if ":" not in kid:
        logger.warning("Rejecting token with legacy non-composite kid: %s", kid)
        return None

    project_id, key_version = kid.split(":", 1)

    if "session" in key_version:
        if not shield_url:
            logger.warning("No Shield URL configured for session token project %s", project_id)
            return None
        return await _bootstrap_ed25519_from_shield(project_id, kid, shield_url, service_name, config=config)

    from ..config import get_core_config

    secret = get_core_config().security.project_secret
    if not secret:
        logger.warning(
            "No CU_PROJECT_SECRET found for project %s (kid=%s, key_version=%s)",
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
        from ..token_utils import fetch_project_public_key_async

        pub_key_b64, returned_kid = await fetch_project_public_key_async(
            project_id,
            kid,
            shield_url,
            provenance=f"{service_name.lower()}:fetch_public_key",
            config=config,
        )
        try:
            from contextunity.core.ed25519 import Ed25519Backend

            return Ed25519Backend(public_key_b64=pub_key_b64, kid=returned_kid)
        except ImportError:
            logger.error("contextunity.shield not installed, cannot verify Ed25519 tokens")
            return None
    except Exception as e:
        logger.warning("Failed bootstrap public-key fetch from Shield for %s: %s", kid, e)
        return None


__all__ = [
    "build_verifier_backend",
    "is_token_revoked",
]
