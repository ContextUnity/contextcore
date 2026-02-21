"""Security utilities for ContextUnity.

Provides generic validation functions, such as SSRF-safe URL validation.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from contextcore.exceptions import SecurityError

__all__ = ["validate_safe_url"]


def validate_safe_url(url: str, allow_local: bool = False) -> str:
    """Validate a URL to prevent Server-Side Request Forgery (SSRF).

    Enforces scheme (http/https only), rejects file://, ftp://, dict://, etc.
    Optionally blocks the resolution or usage of loopback, link-local,
    and private IP addresses.

    Args:
        url: The URL string to validate.
        allow_local: If True, permits localhost/127.0.0.1 and private IPs.
                     (Useful for dev environments, but defaults to False).

    Returns:
        The validated URL string if safe.

    Raises:
        SecurityError: If the URL is determined to be unsafe or malformed.
    """
    if not url or not isinstance(url, str):
        raise SecurityError("validate_safe_url", "URL must be a non-empty string.")

    try:
        parsed = urlparse(url)
    except Exception as e:
        raise SecurityError("validate_safe_url", f"Failed to parse URL: {e}")

    # 1. Block dangerous schemes immediately
    if parsed.scheme.lower() not in ("http", "https"):
        raise SecurityError(
            "validate_safe_url", f"Unsafe URL scheme '{parsed.scheme}'. Only http and https are allowed."
        )

    # 2. Check hostname for local/private IPs (basic check)
    hostname = parsed.hostname
    if not hostname:
        raise SecurityError("validate_safe_url", "URL must include a valid hostname.")

    if not allow_local:
        # Check explicit loopback/metadata hostnames
        forbidden_hosts = {
            "localhost",
            "169.254.169.254",  # AWS/GCP metadata
            "kubernetes.default.svc",
        }
        if hostname.lower() in forbidden_hosts:
            raise SecurityError(
                "validate_safe_url", f"URL targeting protected/local hostname '{hostname}' is not allowed."
            )

        # Resolve hostname to catch integer encoded IPs, domain mappings to local IPs, etc.
        try:
            import socket

            results = socket.getaddrinfo(hostname, 80)
            for result in results:
                ip_str = result[4][0]
                ip = ipaddress.ip_address(ip_str)
                if ip.is_loopback or ip.is_private or ip.is_link_local:
                    raise SecurityError(
                        "validate_safe_url",
                        f"URL targeting private/loopback IP address '{ip_str}' is not allowed.",
                    )
        except socket.gaierror:
            pass  # Name resolution failed, safe (the request will also fail)
        except ValueError:
            pass  # Not an IP address format even after getaddrinfo, unlikely but safe

    return url
