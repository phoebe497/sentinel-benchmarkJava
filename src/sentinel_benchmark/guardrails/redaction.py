"""Sensitive-data redaction (AGENTS.md 6.3).

Masks email, phone, token, API key, password and PII-shaped strings with typed
placeholders before anything reaches the LLM or a log/artifact. Detection is
*anchored* (known key prefixes, JWT/Bearer shapes, context keywords) rather than
entropy-based, so committed identifiers and hashes (``observation_id``,
``prompt_sha256``, ``checksum`` ...) are never clobbered.

The functions are pure and idempotent: ``redact(redact(x)) == redact(x)``.
"""

from __future__ import annotations

import re
from typing import Any

PLACEHOLDERS = {
    "EMAIL": "[REDACTED_EMAIL]",
    "PHONE": "[REDACTED_PHONE]",
    "API_KEY": "[REDACTED_API_KEY]",
    "TOKEN": "[REDACTED_TOKEN]",
    "PASSWORD": "[REDACTED_PASSWORD]",
    "PII": "[REDACTED_PII]",
}

# Object keys whose values are structural identifiers and must never be rewritten.
#
# This list is deliberately explicit rather than a pattern like "*_id": an
# application response may well carry a `user_id` or `customer_id` that must be
# masked, so blanket-skipping identifier-shaped names would punch a hole in the
# redaction. The cost is that a newly added identifier field must be listed
# here, and `tests/test_week5_guardrails.py` fails when one is missing —
# because a mangled identifier silently breaks the join between a probe record
# and the report it belongs to.
DEFAULT_SKIP_KEYS: frozenset[str] = frozenset(
    {
        "observation_id",
        "observation_ids",
        "analysis_group_id",
        "analysis_group_ids",
        "route_id",
        "payload_id",
        "finding_id",
        "subject_id",
        "subject_kind",
        "dataset",
        "reported_cwes",
        "verdict",
        "benchmark_test_id",
        "expected_cwe",
        "reported_cwe",
        "canonical_id",
        "document_id",
        "kb_document_ids",
        "report_id",
        "run_id",
        "request_id",
        "prompt_sha256",
        "prompt_version",
        "sha256",
        "checksum",
        "source_artifact",
        "line_start",
        "line_end",
        "provider",
        "model",
        "tool",
        "source_tools",
    }
)


# Password/secret assignments first so the value is masked before other rules can
# partially rewrite it. The key name is preserved for readability.
_PASSWORD_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|passphrase)\b(\s*[:=]\s*)(\"?)([^\s\"',;]+)",
)
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
# Anchored API-key prefixes only (never generic high-entropy blobs).
_API_KEY_RE = re.compile(
    r"\b("
    r"sk-[A-Za-z0-9\-_]{8,}"
    r"|rk_[A-Za-z0-9]{8,}"
    # Stripe-style keys carry the environment in the prefix, so the underscore
    # form must be listed separately: `[A-Za-z0-9]` stops at the underscore in
    # `sk_live_...`, which left a live key unmasked when nothing like "Bearer"
    # or "key=" preceded it.
    r"|(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{10,}"
    r"|ghp_[A-Za-z0-9]{20,}"
    r"|github_pat_[A-Za-z0-9_]{20,}"
    r"|gho_[A-Za-z0-9]{20,}"
    r"|xox[baprs]-[A-Za-z0-9\-]{8,}"
    r"|AKIA[0-9A-Z]{16}"
    r"|AIza[0-9A-Za-z\-_]{20,}"
    r")\b"
)
# JWTs and explicit bearer tokens.
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+")
_BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9\-._~+/]+=*")
# Vietnamese-shaped phone numbers with digit-boundary guards to avoid line/port hits.
_PHONE_RE = re.compile(r"(?<!\d)(?:\+?84|0)(?:[ .\-]?\d){8,9}(?!\d)")
# Narrow PII: Vietnamese national id (CMND 9 / CCCD 12) with boundary guards.
_PII_RE = re.compile(r"(?<!\d)\d{12}(?!\d)|(?<!\d)\d{9}(?!\d)")


def _sub_password(match: re.Match[str]) -> str:
    return f"{match.group(1)}{match.group(2)}{match.group(3)}{PLACEHOLDERS['PASSWORD']}"


# Order matters: passwords -> emails -> keys/tokens -> phone -> PII. Placeholders
# contain no '@', no key prefix and no digits, so later rules cannot re-match them.
_STEPS: list[tuple[str, re.Pattern[str], Any]] = [
    ("PASSWORD", _PASSWORD_RE, _sub_password),
    ("EMAIL", _EMAIL_RE, PLACEHOLDERS["EMAIL"]),
    ("API_KEY", _API_KEY_RE, PLACEHOLDERS["API_KEY"]),
    ("TOKEN", _JWT_RE, PLACEHOLDERS["TOKEN"]),
    ("TOKEN", _BEARER_RE, PLACEHOLDERS["TOKEN"]),
    ("PHONE", _PHONE_RE, PLACEHOLDERS["PHONE"]),
    ("PII", _PII_RE, PLACEHOLDERS["PII"]),
]


def redact(text: str) -> str:
    """Return ``text`` with every sensitive span replaced by a typed placeholder."""
    if not text:
        return text
    result = text
    for _kind, pattern, replacement in _STEPS:
        result = pattern.sub(replacement, result)
    return result


def redact_with_stats(text: str) -> tuple[str, dict[str, int]]:
    """Redact and report how many spans of each type were masked (for metrics)."""
    stats: dict[str, int] = {}
    if not text:
        return text, stats
    result = text
    for kind, pattern, replacement in _STEPS:
        count = len(pattern.findall(result))
        if count:
            stats[kind] = stats.get(kind, 0) + count
        result = pattern.sub(replacement, result)
    return result, stats


def redact_obj(value: Any, *, skip_keys: frozenset[str] = DEFAULT_SKIP_KEYS) -> Any:
    """Recursively redact string values in dicts/lists, preserving identifier keys."""
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {
            key: (val if key in skip_keys else redact_obj(val, skip_keys=skip_keys))
            for key, val in value.items()
        }
    if isinstance(value, (list, tuple)):
        redacted = [redact_obj(item, skip_keys=skip_keys) for item in value]
        return type(value)(redacted) if isinstance(value, tuple) else redacted
    return value
