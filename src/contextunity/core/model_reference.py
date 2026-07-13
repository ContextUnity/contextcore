"""Canonical validation for executable model references."""

from __future__ import annotations


def validate_model_reference(value: str, *, field_name: str = "model") -> str:
    """Validate and normalize a ``provider/model`` runtime reference."""
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{field_name} must not be empty")
    if "/" not in normalized:
        raise ValueError(f"{field_name} must be an executable 'provider/model' reference")
    provider, model = normalized.split("/", 1)
    if not provider or not model or provider != provider.strip() or model != model.strip():
        raise ValueError(f"{field_name} must be an executable 'provider/model' reference")
    return normalized


__all__ = ["validate_model_reference"]
