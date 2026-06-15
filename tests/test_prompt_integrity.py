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

    def test_signature_size_is_compact(self, backend):
        """Signature size is fixed (~120 bytes) regardless of prompt length.

        Signs SHA-256(prompt) instead of raw text, so a 5KB prompt doesn't
        produce a 7KB base64 payload in the wire format.
        """
        short_prompt = "Short."
        long_prompt = "x" * 10_000  # 10KB prompt

        sig_short = sign_prompt(short_prompt, backend)
        sig_long = sign_prompt(long_prompt, backend)

        # Both should be approximately the same size (kid + hash_b64 + sig_b64)
        assert abs(len(sig_short) - len(sig_long)) < 10
        # And both should be compact (under 200 chars)
        assert len(sig_short) < 200
        assert len(sig_long) < 200


class TestSignPromptIntegrityFailClosed:
    """WS-9: a manifest that ships LLM prompts cannot register unsigned.

    ``sign_prompt_integrity`` must refuse (fail closed) when prompts are present
    but no project secret is configured — otherwise the runtime would receive
    unsigned prompts it cannot tamper-check (infra-level prompt injection).
    """

    @staticmethod
    def _manifest_with_prompt() -> dict:
        return {
            "router": {
                "graph": {
                    "nodes": [{"name": "planner"}],
                    "config": {"planner_prompt": "You are a planner."},
                }
            }
        }

    @staticmethod
    def _patch_secret(monkeypatch, secret: str) -> None:
        from types import SimpleNamespace

        import contextunity.core.config as cfg

        monkeypatch.setattr(
            cfg,
            "get_core_config",
            lambda: SimpleNamespace(security=SimpleNamespace(project_secret=secret)),
        )

    def test_prompts_without_secret_raise(self, monkeypatch):
        from contextunity.core.exceptions import ConfigurationError
        from contextunity.core.sdk.bootstrap.manifest import sign_prompt_integrity

        self._patch_secret(monkeypatch, "")
        with pytest.raises(ConfigurationError, match="CU_PROJECT_SECRET"):
            sign_prompt_integrity(self._manifest_with_prompt(), "proj-1")

    def test_no_prompts_without_secret_is_noop(self, monkeypatch):
        from contextunity.core.sdk.bootstrap.manifest import sign_prompt_integrity

        self._patch_secret(monkeypatch, "")
        manifest = {"router": {"graph": {"nodes": [{"name": "planner"}], "config": {}}}}
        # No signable prompt present → nothing to sign, must not raise.
        sign_prompt_integrity(manifest, "proj-1")

    def test_prompts_with_secret_are_signed(self, monkeypatch):
        from contextunity.core.sdk.bootstrap.manifest import sign_prompt_integrity

        self._patch_secret(monkeypatch, "test-secret-key-123")
        manifest = self._manifest_with_prompt()
        sign_prompt_integrity(manifest, "proj-1")
        node = manifest["router"]["graph"]["nodes"][0]
        assert node.get("prompt_signature"), "prompted node must be signed when secret is present"
        assert node.get("prompt_version")


pytestmark = pytest.mark.unit
