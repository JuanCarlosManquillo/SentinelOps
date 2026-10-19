"""Redacción de datos sensibles antes de persistir (control STRIDE: divulgación)."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

REDACTED = "[REDACTED]"

_SENSITIVE_KEY = re.compile(
    r"(password|passwd|secret|token|api[_-]?key|authorization|cookie|set-cookie|credit[_-]?card)",
    re.IGNORECASE,
)
_SECRET_IN_TEXT = [
    re.compile(r"(?i)bearer\s+[a-z0-9._\-]+"),
    re.compile(r"(?i)(password|token|api[_-]?key)=([^\s&]+)"),
]


def redact_attributes(attributes: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: REDACTED if _SENSITIVE_KEY.search(key) else value for key, value in attributes.items()
    }


def redact_text(text: str) -> str:
    text = _SECRET_IN_TEXT[0].sub("Bearer " + REDACTED, text)
    return _SECRET_IN_TEXT[1].sub(lambda m: f"{m.group(1)}={REDACTED}", text)
