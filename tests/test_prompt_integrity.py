"""Tests for contextunity.core.prompt_integrity — signing and content-addressable versioning."""

import pytest
from contextunity.core.sdk.prompt_integrity import compute_prompt_version, sign_prompt, verify_prompt
from contextunity.core.signing import HmacBackend


@pytest.fixture
def backend() -> HmacBackend:
    return HmacBackend(project_id="test-project", project_secret="test-secret-key-123")


class TestComputePromptVersion:
    def test_deterministic(self):
        """Same text always produces the same version."""
        text = "You are a helpful analyst for medical data."
        v1 = compute_prompt_version(text)
        v2 = compute_prompt_version(text)
        assert v1 == v2

    def test_length_is_8(self):
        """Version is always 8 hex characters."""
        version = compute_prompt_version("any text")
        assert len(version) == 8
        assert all(c in "0123456789abcdef" for c in version)

    def test_different_text_different_version(self):
        """Any change in text produces a different version."""
        v1 = compute_prompt_version("You are a helpful analyst.")
        v2 = compute_prompt_version("You are a helpful analyst!")  # period → exclamation
        assert v1 != v2

    def test_unicode(self):
        """Handles non-ASCII text correctly."""
        version = compute_prompt_version("Ти — медичний аналітик.")
        assert len(version) == 8

    def test_empty_string(self):
        """Empty string is a valid input (edge case)."""
        version = compute_prompt_version("")
        assert len(version) == 8


class TestSignAndVerify:
    def test_sign_returns_serialized_string(self, backend):
        sig = sign_prompt("test prompt", backend)
        assert isinstance(sig, str)
        # kid.payload.signature format
        assert sig.count(".") == 2

    def test_verify_valid_signature(self, backend):
        text = "You are a helpful analyst for medical data."
        sig = sign_prompt(text, backend)
        assert verify_prompt(text, sig, backend) is True

    def test_verify_tampered_text(self, backend):
        """Modified text fails verification."""
        text = "You are a helpful analyst for medical data."
        sig = sign_prompt(text, backend)
        tampered = text + " INJECTED INSTRUCTION."
        assert verify_prompt(tampered, sig, backend) is False

    def test_verify_wrong_backend(self, backend):
        """Different project secret fails verification."""
        text = "You are a helpful analyst."
        sig = sign_prompt(text, backend)
        other_backend = HmacBackend(project_id="test-project", project_secret="wrong-secret")
        assert verify_prompt(text, sig, other_backend) is False

    def test_verify_corrupted_signature(self, backend):
        """Corrupted signature string fails verification."""
        text = "You are a helpful analyst."
        assert verify_prompt(text, "invalid.signature.string", backend) is False

    def test_verify_empty_signature(self, backend):
        text = "You are a helpful analyst."
        assert verify_prompt(text, "", backend) is False

    def test_roundtrip_unicode(self, backend):
        """Unicode text roundtrips correctly through sign/verify."""
        text = "Ти — медичний аналітик для НСЗУ.\nАналізуй дані пацієнтів."
        sig = sign_prompt(text, backend)
        assert verify_prompt(text, sig, backend) is True
