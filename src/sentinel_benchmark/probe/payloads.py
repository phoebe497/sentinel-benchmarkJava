"""The safe payload catalogue for agent-proposed probes.

Every value here exercises *input handling* without attempting to exploit it:
empty values, wrong types, boundary numbers, long strings, odd unicode. Nothing
in this catalogue is an attack payload, and :func:`get` re-checks that at
use-time so a careless edit fails closed instead of shipping.

The ids are deliberately the same strings the Week 4 request tool uses, so a
report saying ``payload_id=long-string`` means the same thing in both projects.
The catalogue itself is intentionally re-declared here rather than imported
across the submodule boundary: this package is what the approval gate wraps, so
it must be importable without the gateway checkout present.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

PAYLOADS: dict[str, Any] = {
    "empty-string": "",
    "empty-object": {},
    "null": None,
    "whitespace": "   \t\n\r   ",
    "long-string": "A" * 5000,
    "special-chars": "!@#$%^&*()_+-=[]{};':\",.<>/?`~\\|",
    "unicode": "こんにちは-🌐-Ωåé-\u200b\u202e",
    "wrong-type-int": 12345,
    "wrong-type-bool": True,
    "wrong-type-list-for-object": [1, 2, 3],
    "int-max": 2**63 - 1,
    "negative": -1,
    "zero": 0,
}

# Anything resembling an actual attack. Broad and case-insensitive on purpose:
# a false positive here costs one renamed payload, a false negative means this
# project attacked a target it only had permission to observe.
FORBIDDEN_PATTERNS: tuple[str, ...] = (
    r"(?i)\bunion\b\s+\bselect\b",
    r"(?i)\bselect\b.+\bfrom\b",
    r"(?i)\bdrop\s+table\b",
    r"(?i)or\s+1\s*=\s*1",
    r"--\s*$",
    r"(?i)<script",
    r"(?i)javascript:",
    r"(?i)on(error|load|click)\s*=",
    r"\.\./",
    r"(?i)\betc/passwd\b",
    r"[;&|`]\s*\w+",
    r"\$\(",
    r"(?i)\$\{jndi:",
    # The call shape, not the English words: a body may legitimately contain
    # "system prompt" while `system(` is only ever code execution.
    r"(?i)\b(exec|eval|system|popen)\s*\(",
    r"(?i)\bos\.system\b",
)

_COMPILED = tuple(re.compile(pattern) for pattern in FORBIDDEN_PATTERNS)

# The crafted prompt-injection fixture (AGENTS.md 6.1) is a catalogue entry too.
# It probes *this* system's filter rather than the target's data, and it carries
# no attack on the target, so it is vetted by the same rules as everything else.
# Registering it here keeps the invariant that the request tool can only ever
# send a named catalogue value.
INJECTION_PROBE_ID = "injection-probe"
FIXTURE_PATH = Path(
    os.getenv("SENTINEL_INJECTION_FIXTURE")
    or Path(__file__).resolve().parents[3] / "datasets/guardrails/crafted-injection-response.json"
)


def _load_injection_fixture() -> None:
    """Register the crafted fixture, if the dataset is present in this install."""
    try:
        fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    body = str(fixture.get("body") or "").strip()
    if body:
        PAYLOADS[INJECTION_PROBE_ID] = {"text": body}


_load_injection_fixture()


def _flatten(value: Any) -> list[str]:
    """Every string a value contains, keys included, so nesting cannot hide one."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        out: list[str] = []
        for key, item in value.items():
            out.append(str(key))
            out.extend(_flatten(item))
        return out
    if isinstance(value, (list, tuple)):
        return [text for item in value for text in _flatten(item)]
    return [str(value)]


def is_forbidden(value: Any) -> str | None:
    """Return the offending pattern when ``value`` looks like an attack payload."""
    for text in _flatten(value):
        for pattern in _COMPILED:
            if pattern.search(text):
                return pattern.pattern
    return None


def get(payload_id: str) -> Any:
    if payload_id not in PAYLOADS:
        raise KeyError(f"unknown payload id: {payload_id!r}; choose one of {ids()}")
    value = PAYLOADS[payload_id]
    offending = is_forbidden(value)
    if offending is not None:
        raise ValueError(f"payload {payload_id!r} matches forbidden pattern {offending!r}")
    return value


def ids() -> list[str]:
    return sorted(PAYLOADS)
