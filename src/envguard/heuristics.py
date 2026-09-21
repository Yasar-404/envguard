from __future__ import annotations

import math
import re
from collections import Counter

_PLACEHOLDER_MARKERS = (
    "example",
    "placeholder",
    "changeme",
    "change_me",
    "your_",
    "your-",
    "yourkey",
    "xxxx",
    "redacted",
    "dummy",
    "fixme",
    "todo",
    "${",
    "{{",
    "***",
    "...",
)

_COMMON_DUMMIES = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "admin",
        "test",
        "testing",
        "token",
        "apikey",
        "api_key",
        "null",
        "none",
        "true",
        "false",
        "undefined",
        "pass",
        "user",
        "root",
    }
)

_REFERENCE_PREFIXES = ("$", "{", "<", "%s", "%(")
_DOTTED_CHAIN = re.compile(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+")
_SNAKE_CASE = re.compile(r"[a-z_][a-z0-9_]*")


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    total = len(value)
    return -sum(n / total * math.log2(n / total) for n in Counter(value).values())


def char_classes(value: str) -> int:
    """Count how many of lowercase, uppercase, digit and other characters occur."""
    return sum(
        (
            any(c.islower() for c in value),
            any(c.isupper() for c in value),
            any(c.isdigit() for c in value),
            any(not c.isalnum() for c in value),
        )
    )


def is_placeholder(value: str) -> bool:
    """True for values that are documentation filler, template syntax or trivially repetitive."""
    lowered = value.lower()
    if lowered in _COMMON_DUMMIES or lowered.startswith(_REFERENCE_PREFIXES):
        return True
    if any(marker in lowered for marker in _PLACEHOLDER_MARKERS):
        return True
    return len(set(value)) <= 4


def looks_like_reference(value: str) -> bool:
    """True for values that read as a code identifier (`self.password`, `db_password`)."""
    if _DOTTED_CHAIN.fullmatch(value):
        return True
    return "_" in value and _SNAKE_CASE.fullmatch(value) is not None
