"""Router policy contract tests."""

import pytest
from contextunity.core.manifest.router import ModelsLLMPolicy
from pydantic import ValidationError


def test_inline_model_policy_preserves_explicit_choice() -> None:
    """An inline LLM policy retains its explicitly selected catalog model."""
    policy = ModelsLLMPolicy.model_validate({"default": "openai/gpt-5-mini", "pinned_model": "mock/premium"})

    assert policy.pinned_model == "mock/premium"


def test_inline_model_policy_rejects_logical_pin_alias() -> None:
    """Pins must be directly executable by the selected provider registry."""
    with pytest.raises(ValidationError, match="provider/model"):
        ModelsLLMPolicy.model_validate({"default": "openai/gpt-5-mini", "pinned_model": "premium"})
