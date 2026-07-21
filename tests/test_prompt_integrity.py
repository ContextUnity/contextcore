"""Tests for contextunity.core.prompt_integrity — signing and content-addressable versioning."""

from copy import deepcopy

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
            lambda: SimpleNamespace(
                local_mode=False,
                security=SimpleNamespace(platform_secret=secret, project_secret=""),
            ),
        )

    def test_prompts_without_secret_raise(self, monkeypatch):
        from contextunity.core.exceptions import ConfigurationError
        from contextunity.core.sdk.bootstrap.manifest import sign_prompt_integrity

        self._patch_secret(monkeypatch, "")
        with pytest.raises(ConfigurationError, match="CU_PLATFORM_SECRET"):
            sign_prompt_integrity(self._manifest_with_prompt(), "proj-1")

    def test_no_prompts_without_secret_is_noop(self, monkeypatch):
        from contextunity.core.sdk.bootstrap.manifest import sign_prompt_integrity

        self._patch_secret(monkeypatch, "")
        manifest = {"router": {"graph": {"nodes": [{"name": "planner"}], "config": {}}}}
        before = deepcopy(manifest)

        sign_prompt_integrity(manifest, "proj-1")

        assert manifest == before

    def test_prompts_with_secret_are_signed(self, monkeypatch):
        from contextunity.core.sdk.bootstrap.manifest import sign_prompt_integrity

        self._patch_secret(monkeypatch, "test-secret-key-123")
        manifest = self._manifest_with_prompt()
        sign_prompt_integrity(manifest, "proj-1")
        node = manifest["router"]["graph"]["nodes"][0]
        assert node.get("prompt_signature"), "prompted node must be signed when secret is present"
        assert node.get("prompt_version")

    def test_shield_enabled_prompts_without_secret_are_versioned_not_signed(self, monkeypatch):
        from contextunity.core.sdk.bootstrap.manifest import sign_prompt_integrity

        self._patch_secret(monkeypatch, "")
        manifest = self._manifest_with_prompt()
        manifest["services"] = {"shield": {"enabled": True}}

        sign_prompt_integrity(manifest, "proj-1")

        node = manifest["router"]["graph"]["nodes"][0]
        assert node.get("prompt_version")
        assert "prompt_signature" not in node


class TestExtractNodePrompts:
    """``extract_node_prompts`` feeds the Shield-mode prompt publisher.

    In Shield mode the canonical prompts are pushed to Shield at registration so
    the Router can verify against them (no router-local secret). This extractor
    must surface every prompted node — a regression here would silently leave a
    node's prompt unpublished, which the Router then rejects as tampering.
    """

    def test_single_graph_collects_prompts(self):
        from contextunity.core.sdk.bootstrap.manifest import extract_node_prompts

        manifest = {
            "router": {
                "graph": {
                    "nodes": [{"name": "planner"}, {"name": "verifier"}],
                    "config": {
                        "planner_prompt": "You are a planner.",
                        "verifier_prompt": "You are a verifier.",
                    },
                }
            }
        }
        assert extract_node_prompts(manifest) == {
            "planner": "You are a planner.",
            "verifier": "You are a verifier.",
        }

    def test_named_subgraphs_collected(self):
        from contextunity.core.sdk.bootstrap.manifest import extract_node_prompts

        manifest = {
            "router": {
                "graph": {
                    "default": {
                        "nodes": [{"name": "planner"}],
                        "config": {"planner_prompt": "Plan."},
                    },
                    "review": {
                        "nodes": [{"name": "verifier"}],
                        "config": {"verifier_prompt": "Verify."},
                    },
                }
            }
        }
        # Graph-scoped keys: {graph_key}/{node_name}
        assert extract_node_prompts(manifest) == {
            "default/planner": "Plan.",
            "review/verifier": "Verify.",
        }

    def test_same_node_name_in_two_graphs_does_not_collide(self):
        from contextunity.core.sdk.bootstrap.manifest import extract_node_prompts

        manifest = {
            "router": {
                "graph": {
                    "alpha": {
                        "nodes": [{"name": "planner"}],
                        "config": {"planner_prompt": "Plan A."},
                    },
                    "beta": {
                        "nodes": [{"name": "planner"}],
                        "config": {"planner_prompt": "Plan B."},
                    },
                }
            }
        }
        assert extract_node_prompts(manifest) == {
            "alpha/planner": "Plan A.",
            "beta/planner": "Plan B.",
        }

    def test_node_without_prompt_excluded(self):
        from contextunity.core.sdk.bootstrap.manifest import extract_node_prompts

        manifest = {
            "router": {
                "graph": {
                    "nodes": [{"name": "planner"}, {"name": "tool_execution"}],
                    "config": {"planner_prompt": "Plan."},
                }
            }
        }
        assert extract_node_prompts(manifest) == {"planner": "Plan."}

    def test_no_router_graph_is_empty(self):
        from contextunity.core.sdk.bootstrap.manifest import extract_node_prompts

        assert extract_node_prompts({"project": {"id": "x"}}) == {}


class TestShieldPromptBundleSanitizer:
    def test_removes_resolved_prompt_text_for_prompt_ref_nodes(self):
        from contextunity.core.manifest.models import RouterRegistrationBundle
        from contextunity.core.sdk.bootstrap.api import _strip_resolved_prompt_text

        bundle = RouterRegistrationBundle(
            project_id="sample_project",
            graph={
                "default": {
                    "nodes": [
                        {
                            "name": "planner",
                            "prompt_ref": "src/prompts.py::PLANNER",
                            "prompt_version": "1234abcd",
                        },
                        {"name": "verifier"},
                    ],
                    "config": {
                        "planner_prompt": "Shield-owned prompt text",
                        "verifier_prompt": "local non-ref prompt",
                    },
                }
            },
        )

        _strip_resolved_prompt_text(bundle)

        config = bundle.graph["default"]["config"]
        assert "planner_prompt" not in config
        assert config["verifier_prompt"] == "local non-ref prompt"


pytestmark = pytest.mark.unit
