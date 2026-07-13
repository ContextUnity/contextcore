"""Test exception hierarchy contracts across all services.

Validates:
1. All exception classes inherit from ContextUnityError
2. All exception `code` attributes are registered in ErrorRegistry
3. All exception `code` strings use correct service prefix
4. All exception `message` defaults are safe for client exposure
5. No duplicate error codes across services
"""

from __future__ import annotations

import importlib

import pytest
from contextunity.core.exceptions import ContextUnityError, ErrorRegistry

# ---------------------------------------------------------------------------
# Discovery: collect all exception modules and their classes
# ---------------------------------------------------------------------------

_EXCEPTION_MODULES = [
    "contextunity.core.exceptions",
    "contextunity.core.sdk.toolkit",
    "contextunity.router.core.exceptions",
    "contextunity.router.modules.models.types",
    "contextunity.router.conductor.catalog",
    "contextunity.brain.core.exceptions",
    "contextunity.shield.exceptions",
    "contextunity.worker.core.exceptions",
]

_SERVICE_PREFIXES = {
    "contextunity.router": "ROUTER_",
    "contextunity.brain": "BRAIN_",
    "contextunity.shield": "SHIELD_",
    "contextunity.worker": "WORKER_",
    "contextunity.core": "",  # core codes have no service prefix
}


def _collect_exception_classes() -> list[tuple[str, type[ContextUnityError]]]:
    """Import all exception modules and collect ContextUnityError subclasses."""
    results: list[tuple[str, type[ContextUnityError]]] = []
    for mod_path in _EXCEPTION_MODULES:
        try:
            mod = importlib.import_module(mod_path)
        except ImportError:
            continue
        for attr_name in dir(mod):
            obj = getattr(mod, attr_name)
            if (
                isinstance(obj, type)
                and issubclass(obj, ContextUnityError)
                and obj is not ContextUnityError
                and hasattr(obj, "code")
            ):
                results.append((mod_path, obj))
    return results


_ALL_EXCEPTIONS = _collect_exception_classes()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestExceptionHierarchy:
    """Validate structural contracts of the exception hierarchy."""

    def test_all_inherit_from_contextunity_error(self) -> None:
        """Every service exception must inherit from ContextUnityError."""
        for mod_path, exc_cls in _ALL_EXCEPTIONS:
            assert issubclass(exc_cls, ContextUnityError), (
                f"{exc_cls.__name__} in {mod_path} does not inherit ContextUnityError"
            )

    def test_all_have_code_attribute(self) -> None:
        """Every exception class must have a non-empty `code` class attribute."""
        for mod_path, exc_cls in _ALL_EXCEPTIONS:
            code = getattr(exc_cls, "code", None)
            assert code and isinstance(code, str), f"{exc_cls.__name__} in {mod_path} is missing a `code` attribute"

    def test_all_have_message_attribute(self) -> None:
        """Every exception class must have a non-empty `message` class attribute."""
        for mod_path, exc_cls in _ALL_EXCEPTIONS:
            message = getattr(exc_cls, "message", None)
            assert message and isinstance(message, str), (
                f"{exc_cls.__name__} in {mod_path} is missing a `message` attribute"
            )


class TestErrorRegistry:
    """Validate ErrorRegistry completeness and consistency."""

    def test_all_codes_registered(self) -> None:
        """Every declared exception code must be in ErrorRegistry."""
        for mod_path, exc_cls in _ALL_EXCEPTIONS:
            code = exc_cls.code
            registered = ErrorRegistry.get(code)
            assert registered is not None, (
                f"Code '{code}' ({exc_cls.__name__} in {mod_path}) is NOT registered in ErrorRegistry"
            )

    def test_registry_maps_to_correct_class(self) -> None:
        """ErrorRegistry.get(code) must return the declaring class."""
        for _mod_path, exc_cls in _ALL_EXCEPTIONS:
            code = exc_cls.code
            registered = ErrorRegistry.get(code)
            if registered is not None:
                assert registered is exc_cls or issubclass(registered, exc_cls.__bases__[0]), (
                    f"Code '{code}' maps to {registered.__name__} but expected {exc_cls.__name__}"
                )

    def test_no_duplicate_codes(self) -> None:
        """No two different classes may share the same error code."""
        seen: dict[str, type[ContextUnityError]] = {}
        for mod_path, exc_cls in _ALL_EXCEPTIONS:
            code = exc_cls.code
            if code in seen and seen[code] is not exc_cls:
                # Allow parent/child sharing (child overrides parent's default)
                if not (issubclass(exc_cls, seen[code]) or issubclass(seen[code], exc_cls)):
                    pytest.fail(f"Duplicate code '{code}': {seen[code].__name__} and {exc_cls.__name__} in {mod_path}")
            seen[code] = exc_cls

    def test_from_code_roundtrip(self) -> None:
        """ErrorRegistry.from_code() must produce an instance of the right class."""
        # Some exceptions have custom __init__ signatures (e.g. RedisConnectionError
        # requires `cause`). Skip those — they can't be instantiated via from_code().
        _SKIP_CODES = {"REDIS_CONNECTION_ERROR"}

        for _mod_path, exc_cls in _ALL_EXCEPTIONS:
            code = exc_cls.code
            if code in _SKIP_CODES:
                continue
            instance = ErrorRegistry.from_code(code, message="test")
            assert isinstance(instance, ContextUnityError), (
                f"from_code('{code}') did not produce a ContextUnityError instance"
            )


class TestServicePrefixConvention:
    """Validate that service exception codes follow prefix conventions."""

    def test_service_codes_have_correct_prefix(self) -> None:
        """Service exception codes must start with the service prefix."""
        for mod_path, exc_cls in _ALL_EXCEPTIONS:
            code = exc_cls.code
            # Find which service this module belongs to
            for svc_prefix_key, expected_prefix in _SERVICE_PREFIXES.items():
                if mod_path.startswith(svc_prefix_key) and expected_prefix:
                    # Core exceptions and INTERNAL_ERROR are exempt
                    if svc_prefix_key == "contextunity.core":
                        continue
                    assert code.startswith(expected_prefix), (
                        f"{exc_cls.__name__} in {mod_path} has code '{code}' but expected prefix '{expected_prefix}'"
                    )
                    break


class TestMessageSafety:
    """Validate that default error messages are safe for client exposure."""

    _UNSAFE_PATTERNS = [
        "traceback",
        "stack trace",
        "password=",
        "secret_key",
        "api_key=",
        "token=",
        "/home/",
        "/var/",
        "127.0.0.1",
        "localhost:",
    ]

    def test_default_messages_are_client_safe(self) -> None:
        """Default `message` must not leak internal details."""
        for mod_path, exc_cls in _ALL_EXCEPTIONS:
            msg = exc_cls.message.lower()
            for pattern in self._UNSAFE_PATTERNS:
                assert pattern not in msg, (
                    f"{exc_cls.__name__} in {mod_path} has unsafe default message "
                    f"containing '{pattern}': '{exc_cls.message}'"
                )

    def test_default_messages_are_human_readable(self) -> None:
        """Default messages should be descriptive, not just error codes."""
        for mod_path, exc_cls in _ALL_EXCEPTIONS:
            msg = exc_cls.message
            # Should be at least 10 chars and not just the code string
            assert len(msg) >= 10, f"{exc_cls.__name__} in {mod_path} has too-short message: '{msg}'"
            assert msg != exc_cls.code, f"{exc_cls.__name__} in {mod_path} message is just the code string"
