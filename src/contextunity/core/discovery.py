"""Service discovery for ContextUnity services.

Provides registration (heartbeat) and discovery of running service instances
via Redis. Used by:
- Services: register themselves on startup (call `register_service()` in server main)
- contextunity.view: discover all running instances (call `discover_services()`) — admin, no tenant filter
- Projects: discover only their tenant-scoped services via `discover_services(tenant_id=...)`

All discovery uses the SAME shared Redis that services already connect to.
contextunity.view knows Redis via REDIS_URL in settings.py — same Redis as Brain/Router/Worker.

Redis dependency is OPTIONAL — if redis is not installed, registration/discovery
are no-ops (graceful degradation).
"""

from __future__ import annotations

import asyncio
import base64
import functools
import hashlib
import hmac as hmac_mod
import json
import os
from dataclasses import dataclass, field
from typing import Optional

from .config import load_shared_config_from_env
from .logging import get_contextunit_logger

logger = get_contextunit_logger(__name__)

# Default prefix for all service discovery keys in Redis
DEFAULT_PREFIX = "contextunity:services"
DEFAULT_TTL = 30  # seconds


@dataclass
class ServiceInfo:
    """Information about a running service instance."""

    service: str  # e.g. "brain", "router", "worker"
    instance: str  # e.g. "shared", "nszu", "default"
    endpoint: str  # e.g. "localhost:50051"
    tenants: list[str] = field(default_factory=list)  # e.g. ["traverse", "pinkpony"] or [] = all
    metadata: dict = field(default_factory=dict)  # optional extra info

    def serves_tenant(self, tenant_id: str) -> bool:
        """Check if this service instance serves a given tenant.

        Empty tenants list means the service is shared (serves all tenants).
        """
        return not self.tenants or tenant_id in self.tenants


def _get_prefix() -> str:
    """Get service discovery key prefix from shared config."""
    config = load_shared_config_from_env()
    return getattr(config, "service_discovery_prefix", None) or DEFAULT_PREFIX


def _get_ttl() -> int:
    """Get service discovery TTL from shared config."""
    config = load_shared_config_from_env()
    ttl = getattr(config, "service_discovery_ttl", None)
    return int(ttl) if ttl else DEFAULT_TTL


def _get_redis_url(redis_url: str | None) -> str | None:
    """Resolve Redis URL from explicit arg or shared config."""
    if redis_url:
        return redis_url
    return load_shared_config_from_env().redis_url


def _redis_key(service: str, instance: str) -> str:
    return f"{_get_prefix()}:{service}:{instance}"


# ── Registration (called by services on startup) ────────────────────


async def register_service(
    service: str,
    instance: str,
    endpoint: str,
    redis_url: Optional[str] = None,
    tenants: Optional[list[str]] = None,
    metadata: Optional[dict] = None,
) -> Optional[asyncio.Task]:
    """Register a service instance in Redis and start heartbeat.

    Args:
        service: Service type ("brain", "router", "worker", "commerce", "view")
        instance: Instance name ("shared", "nszu", "default")
        endpoint: gRPC endpoint ("localhost:50051")
        redis_url: Redis URL (defaults to REDIS_URL env var)
        tenants: List of tenant IDs this instance serves.
                 Empty list or None = shared instance (serves all tenants).
                 Example: ["traverse", "pinkpony"] or ["nszu"]
        metadata: Optional metadata dict (port, version, etc.)

    Returns:
        Background heartbeat task, or None if Redis is unavailable.
    """
    try:
        import redis.asyncio as aioredis
    except ImportError:
        logger.warning(
            "Service registration DISABLED: 'redis' package not installed in this venv. "
            "Install it via the [redis] extra: uv pip install 'context%s[redis]'",
            service,
        )
        return None

    url = _get_redis_url(redis_url)
    if not url:
        logger.warning(
            "Service registration DISABLED: REDIS_URL is not set. Service '%s/%s' will NOT appear in the service mesh.",
            service,
            instance,
        )
        return None

    key = _redis_key(service, instance)
    value = json.dumps(
        {
            "endpoint": endpoint,
            "service": service,
            "instance": instance,
            "tenants": tenants or [],
            **(metadata or {}),
        }
    )
    ttl = _get_ttl()

    async def _heartbeat():
        """Periodically refresh the key to signal liveness."""
        r = aioredis.from_url(url, decode_responses=True)
        try:
            while True:
                try:
                    await r.setex(key, ttl, value)
                    logger.debug("Heartbeat: %s -> %s (TTL=%ds)", key, endpoint, ttl)
                except Exception as e:
                    logger.warning("Service discovery heartbeat failed: %s", e)
                # Sleep for half the TTL to ensure overlap
                await asyncio.sleep(ttl // 2 or 10)
        except asyncio.CancelledError:
            # Deregister on shutdown
            try:
                await r.delete(key)
                logger.info("Deregistered service: %s", key)
            except Exception as e:
                logger.debug("Failed to deregister service %s: %s", key, e)
            raise
        finally:
            await r.aclose()

    task = asyncio.create_task(_heartbeat())
    logger.info("Service registered: %s/%s at %s (tenants=%s)", service, instance, endpoint, tenants or "all")
    return task


async def deregister_service(
    service: str,
    instance: str,
    redis_url: Optional[str] = None,
) -> None:
    """Explicitly deregister a service instance."""
    try:
        import redis.asyncio as aioredis
    except ImportError:
        return

    url = _get_redis_url(redis_url)
    if not url:
        return

    key = _redis_key(service, instance)
    r = aioredis.from_url(url, decode_responses=True)
    try:
        await r.delete(key)
        logger.info("Deregistered service: %s", key)
    except Exception as e:
        logger.warning("Service deregistration failed: %s", e)
    finally:
        await r.aclose()


# ── Discovery (called by contextunity.view or other services) ─────────────


def discover_services(
    service_type: Optional[str] = None,
    tenant_id: Optional[str] = None,
    redis_url: Optional[str] = None,
) -> list[ServiceInfo]:
    """Discover running service instances from Redis (synchronous).

    Args:
        service_type: Filter by service type ("brain", "router", etc.)
                      If None, returns all services.
        tenant_id: Filter by tenant scope. If set, only returns services that
                   serve this tenant (or shared services with empty tenants list).
                   If None, returns ALL services (admin mode for contextunity.view).
        redis_url: Redis URL (defaults to REDIS_URL env var)

    Returns:
        List of ServiceInfo for discovered instances.
    """
    try:
        import redis as redis_sync
    except ImportError:
        logger.warning("Service discovery DISABLED: 'redis' package not installed in this venv.")
        return []

    url = _get_redis_url(redis_url)
    if not url:
        logger.warning("Service discovery DISABLED: REDIS_URL is not set.")
        return []

    prefix = _get_prefix()
    pattern = f"{prefix}:{service_type}:*" if service_type else f"{prefix}:*"

    services: list[ServiceInfo] = []
    try:
        r = redis_sync.from_url(url, decode_responses=True)
        keys = r.keys(pattern)
        for key in keys:
            raw = r.get(key)
            if not raw:
                continue
            try:
                data = json.loads(raw)
                info = ServiceInfo(
                    service=data.get("service", "unknown"),
                    instance=data.get("instance", "unknown"),
                    endpoint=data.get("endpoint", ""),
                    tenants=data.get("tenants", []),
                    metadata={k: v for k, v in data.items() if k not in ("service", "instance", "endpoint", "tenants")},
                )
                # Apply tenant filter if specified
                if tenant_id and not info.serves_tenant(tenant_id):
                    continue
                services.append(info)
            except (json.JSONDecodeError, KeyError) as e:
                logger.warning("Invalid service discovery data for %s: %s", key, e)
        r.close()
    except Exception as e:
        logger.warning("Service discovery failed: %s", e)

    return services


def discover_endpoints(
    service_type: str,
    tenant_id: Optional[str] = None,
    redis_url: Optional[str] = None,
) -> dict[str, str]:
    """Discover endpoints for a service type as {instance_name: endpoint} dict.

    Args:
        service_type: Service type to discover ("brain", "router", etc.)
        tenant_id: If set, only returns services scoped to this tenant.
                   None = return all (admin mode).
        redis_url: Redis URL override.

    Returns:
        Dict mapping instance name to endpoint.
    """
    return {
        s.instance: s.endpoint
        for s in discover_services(
            service_type=service_type,
            tenant_id=tenant_id,
            redis_url=redis_url,
        )
    }


# ── Project Registry ───────────────────────────────────────


PROJECTS_PREFIX = "contextunity:projects"


# ── Redis Encryption (stdlib-only, zero deps) ───────────────────
#
# REDIS_SECRET_KEY=false             → No encryption (dev/testing) + WARNING
# REDIS_SECRET_KEY=<32 bytes b64>    → Encrypt + integrity-protect


def _get_redis_secret_key() -> str:
    from .config import load_shared_config_from_env

    return load_shared_config_from_env().security.redis_secret_key.strip()


def _should_encrypt() -> bool:
    secret_key = _get_redis_secret_key()
    return bool(secret_key) and secret_key.lower() not in ("false", "0", "no", "")


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    """HMAC counter-mode keystream — supports arbitrary length.

    Each 32-byte block = HMAC(key, nonce || counter).
    """
    stream = b""
    ctr = 0
    while len(stream) < length:
        stream += hmac_mod.new(key, nonce + ctr.to_bytes(4, "big"), hashlib.sha256).digest()
        ctr += 1
    return stream[:length]


@functools.cache
def _log_crypto_status_once() -> None:
    if _should_encrypt():
        logger.info("Redis encryption + integrity protection enabled")
    else:
        logger.warning(
            "REDIS_SECRET_KEY not set (or 'false'). Project secrets stored UNENCRYPTED in Redis. "
            "Set REDIS_SECRET_KEY=<base64 key> for production use."
        )


def _encrypt(plaintext: str) -> str:
    """Encrypt a string for Redis storage. Returns prefixed string."""
    if not plaintext:
        return plaintext
    _log_crypto_status_once()
    if not _should_encrypt():
        return plaintext
    key = base64.b64decode(_get_redis_secret_key())
    nonce = os.urandom(16)
    data = plaintext.encode()

    # Derive separate keys for encryption and MAC
    enc_key = hmac_mod.new(key, b"encrypt" + nonce, hashlib.sha256).digest()
    mac_key = hmac_mod.new(key, b"mac" + nonce, hashlib.sha256).digest()

    # Encrypt
    ks = _keystream(enc_key, nonce, len(data))
    ct = bytes(a ^ b for a, b in zip(data, ks))

    # MAC over nonce + ciphertext (encrypt-then-MAC)
    tag = hmac_mod.new(mac_key, nonce + ct, hashlib.sha256).digest()

    return "enc:" + base64.b64encode(nonce + ct + tag).decode()


def _decrypt(ciphertext: str) -> str:
    """Decrypt a string from Redis storage."""
    if not ciphertext:
        return ciphertext
    _log_crypto_status_once()
    if not ciphertext.startswith("enc:"):
        return ciphertext  # Plaintext (dev or legacy)
    if not _should_encrypt():
        logger.error("Cannot decrypt: REDIS_SECRET_KEY not set but encrypted data found")
        return ""
    key = base64.b64decode(_get_redis_secret_key())
    raw = base64.b64decode(ciphertext[4:])
    nonce, ct, tag = raw[:16], raw[16:-32], raw[-32:]

    # Verify MAC FIRST (before decryption)
    mac_key = hmac_mod.new(key, b"mac" + nonce, hashlib.sha256).digest()
    expected_tag = hmac_mod.new(mac_key, nonce + ct, hashlib.sha256).digest()
    if not hmac_mod.compare_digest(tag, expected_tag):
        raise ValueError(
            "Redis integrity check failed — stored value was tampered. Project key binding may be compromised."
        )

    # Decrypt only after MAC verification passes
    enc_key = hmac_mod.new(key, b"encrypt" + nonce, hashlib.sha256).digest()
    ks = _keystream(enc_key, nonce, len(ct))
    return bytes(a ^ b for a, b in zip(ct, ks)).decode()


def _project_key(project_id: str) -> str:
    return f"{PROJECTS_PREFIX}:{project_id}"


def register_project(
    project_id: str,
    owner_tenant: str,
    *,
    tools: list[str] | None = None,
    redis_url: str | None = None,
    project_secret: str | None = None,
    public_key_b64: str | None = None,
    public_key_kid: str | None = None,
) -> bool:
    """Register a project in the global project registry.

    Called during RegisterManifest. Stores who owns the project so Router
    can verify ownership on subsequent requests.

    If project is already registered by a DIFFERENT owner, returns False
    (ownership conflict). Same owner re-registering is idempotent.

    Args:
        project_id: Project identifier (e.g. "nszu")
        owner_tenant: Tenant that owns this project (from token.allowed_tenants)
        tools: List of tool names being registered
        redis_url: Redis URL (defaults to REDIS_URL env var)

    Returns:
        True if registered successfully, False if ownership conflict.
    """
    try:
        import redis as redis_sync
    except ImportError:
        logger.warning(
            "Project registry: redis not installed — ownership enforcement DISABLED for '%s'. "
            "Install redis to enable project hijack protection.",
            project_id,
        )
        return True  # Graceful degradation — visible in logs

    url = _get_redis_url(redis_url)
    if not url:
        logger.warning(
            "Project registry: REDIS_URL not configured — ownership enforcement DISABLED for '%s'. "
            "Set REDIS_URL to enable project hijack protection.",
            project_id,
        )
        return True  # Graceful degradation — visible in logs

    key = _project_key(project_id)
    try:
        r = redis_sync.from_url(url, decode_responses=True)
        existing = r.get(key)

        if existing:
            data = json.loads(existing)
            existing_owner = data.get("owner_tenant", "")
            if existing_owner and existing_owner != owner_tenant:
                logger.warning(
                    "Project registry: ownership conflict for '%s' — registered owner='%s', attempted owner='%s'",
                    project_id,
                    existing_owner,
                    owner_tenant,
                )
                r.close()
                return False

        # Register or update
        value_dict = {
            "project_id": project_id,
            "owner_tenant": owner_tenant,
            "tools": tools or [],
        }

        if existing:
            try:
                data = json.loads(existing)
                # Keep old keys unless they are overwritten
                if project_secret is None and "project_secret" in data:
                    value_dict["project_secret"] = data["project_secret"]
                if public_key_b64 is None and "public_key_b64" in data:
                    value_dict["public_key_b64"] = data["public_key_b64"]
                if public_key_kid is None and "public_key_kid" in data:
                    value_dict["public_key_kid"] = data["public_key_kid"]
            except Exception:
                pass

        if project_secret is not None:
            value_dict["project_secret"] = _encrypt(project_secret)
        if public_key_b64 is not None:
            value_dict["public_key_b64"] = public_key_b64
        if public_key_kid is not None:
            value_dict["public_key_kid"] = public_key_kid

        value = json.dumps(value_dict)
        r.set(key, value)  # No TTL — projects are permanent until deregistered
        r.close()

        logger.info(
            "Project registry: registered '%s' owner='%s' tools=%s",
            project_id,
            owner_tenant,
            tools or [],
        )
        return True

    except Exception as e:
        logger.warning("Project registry failed: %s", e)
        return True  # Graceful degradation


def update_project_public_key(
    project_id: str,
    public_key_b64: str,
    public_key_kid: str,
    *,
    redis_url: str | None = None,
) -> bool:
    """Update public key for kid rotation."""
    try:
        import redis as redis_sync
    except ImportError:
        return False

    url = _get_redis_url(redis_url)
    if not url:
        return False

    try:
        r = redis_sync.from_url(url, decode_responses=True)
        key = _project_key(project_id)
        existing = r.get(key)

        if existing:
            data = json.loads(existing)
        else:
            r.close()
            return False

        data["public_key_b64"] = public_key_b64
        data["public_key_kid"] = public_key_kid

        r.set(key, json.dumps(data))
        r.close()
        return True
    except Exception as e:
        logger.warning("Project keys update failed: %s", e)
        return False


def get_project_key(
    project_id: str,
    *,
    redis_url: str | None = None,
) -> dict[str, str] | None:
    """Retrieve decrypted key material for a project.

    Returns dict with keys:
    - project_secret (decrypted)
    - public_key_b64
    - public_key_kid
    Or None if project not found.
    """
    try:
        import redis as redis_sync
    except ImportError:
        return None

    url = _get_redis_url(redis_url)
    if not url:
        return None

    try:
        r = redis_sync.from_url(url, decode_responses=True)
        raw = r.get(_project_key(project_id))
        r.close()

        if not raw:
            return None

        data = json.loads(raw)

        result = {}
        if "project_secret" in data:
            result["project_secret"] = _decrypt(data["project_secret"])
        if "public_key_b64" in data:
            result["public_key_b64"] = data["public_key_b64"]
        if "public_key_kid" in data:
            result["public_key_kid"] = data["public_key_kid"]

        return result

    except Exception as e:
        logger.warning("Project lookup failed: %s", e)
        return None


def verify_project_owner(
    project_id: str,
    claimed_tenant: str,
    *,
    redis_url: str | None = None,
) -> bool:
    """Verify that claimed_tenant owns project_id.

    Returns True if:
    - Project is registered and owned by claimed_tenant
    - Project is not registered (first-time registration allowed)
    - Redis is unavailable (graceful degradation)

    Returns False if:
    - Project is registered but owned by a DIFFERENT tenant

    Args:
        project_id: Project to verify
        claimed_tenant: Tenant claiming ownership
        redis_url: Redis URL override
    """
    try:
        import redis as redis_sync
    except ImportError:
        logger.warning(
            "Project ownership check: redis not installed — SKIPPING verification for '%s:%s'. "
            "Install redis to enable project hijack protection.",
            project_id,
            claimed_tenant,
        )
        return True  # Graceful degradation — visible in logs

    url = _get_redis_url(redis_url)
    if not url:
        logger.warning(
            "Project ownership check: REDIS_URL not configured — SKIPPING verification for '%s:%s'. "
            "Set REDIS_URL to enable project hijack protection.",
            project_id,
            claimed_tenant,
        )
        return True  # Graceful degradation — visible in logs

    try:
        r = redis_sync.from_url(url, decode_responses=True)
        raw = r.get(_project_key(project_id))
        r.close()

        if not raw:
            return True  # First-time registration allowed

        data = json.loads(raw)
        owner = data.get("owner_tenant", "")
        return not owner or owner == claimed_tenant

    except Exception as e:
        logger.warning("Project ownership verification failed: %s", e)
        return True  # Graceful degradation


def get_registered_projects(
    redis_url: str | None = None,
) -> list[dict]:
    """List all registered projects. Used by contextunity.view admin dashboard.

    Returns:
        List of project registry entries.
    """
    try:
        import redis as redis_sync
    except ImportError:
        return []

    url = _get_redis_url(redis_url)
    if not url:
        return []

    try:
        r = redis_sync.from_url(url, decode_responses=True)
        keys = r.keys(f"{PROJECTS_PREFIX}:*")
        projects = []
        for key in keys:
            raw = r.get(key)
            if raw:
                try:
                    projects.append(json.loads(raw))
                except json.JSONDecodeError:
                    pass
        r.close()
        return projects
    except Exception as e:
        logger.warning("Project registry list failed: %s", e)
        return []


__all__ = [
    "ServiceInfo",
    "register_service",
    "deregister_service",
    "discover_services",
    "discover_endpoints",
    "resolve_service_endpoint",
    "register_project",
    "get_project_key",
    "update_project_public_key",
    "verify_project_owner",
    "get_registered_projects",
]


def resolve_service_endpoint(
    service_type: str,
    *,
    configured_host: str = "",
    default_host: str = "",
    tenant_id: str | None = None,
) -> str:
    """Resolve a service endpoint using a 3-tier strategy.

    1. **Explicit config** — ``configured_host`` (from env var / config file)
    2. **Redis auto-discovery** — ``discover_services(service_type)``
    3. **Default fallback** — ``default_host`` (e.g. ``localhost:50051``)

    Logs the resolution path so that "service not found" is NEVER silent.

    Args:
        service_type: Service type key (``"brain"``, ``"worker"``, ``"zero"``, ``"shield"``)
        configured_host: Pre-configured host from env / config.  If non-empty, used directly.
        default_host: Last-resort fallback.  If empty, means the service is optional.
        tenant_id: Optional tenant filter for Redis discovery.

    Returns:
        Resolved endpoint string.  Empty string if service is unavailable
        and no default is provided.
    """
    # 1. Explicit config
    if configured_host:
        logger.debug("Service '%s': using configured host %s", service_type, configured_host)
        return configured_host

    # 2. Redis auto-discovery
    try:
        services = discover_services(service_type=service_type, tenant_id=tenant_id)
        if services:
            endpoint = services[0].endpoint
            logger.info(
                "Service '%s': auto-discovered via Redis → %s (instance=%s)",
                service_type,
                endpoint,
                services[0].instance,
            )
            return endpoint
    except Exception as e:
        logger.debug("Service '%s': Redis auto-discovery failed: %s", service_type, e)

    # 3. Default fallback
    if default_host:
        logger.debug("Service '%s': using default host %s", service_type, default_host)
        return default_host

    # No endpoint found — log clearly
    logger.warning(
        "Service '%s': NOT AVAILABLE — no configured host, Redis discovery found nothing, "
        "no default provided. Features depending on this service will be DISABLED.",
        service_type,
    )
    return ""
