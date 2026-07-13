"""Shared conservative detectors for high-risk personal data patterns."""

from __future__ import annotations

import re

_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_PHONE_RE = re.compile(r"\b\+?\d[\d .()/-]{7,}\d\b")
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b", re.IGNORECASE)
_CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")


def contains_pii(text: str) -> bool:
    """Return whether *text* contains a supported high-risk PII pattern."""
    return bool(
        _EMAIL_RE.search(text)
        or _PHONE_RE.search(text)
        or _SSN_RE.search(text)
        or _IBAN_RE.search(text)
        or _CARD_RE.search(text)
    )


__all__ = ["contains_pii"]
