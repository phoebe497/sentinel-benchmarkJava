"""Prompt-injection filtering (AGENTS.md 6.1).

Untrusted DATA (scanner output, application content, HTTP responses) is scanned
for known injection patterns. The filter *flags and quarantines*; it never
silently rewrites evidence. Quarantine wraps the original text in explicit
data delimiters so the model can see it is data, plus a hazard note when a
pattern matched. Team-authored knowledge documents are trusted and are not
scanned by callers.

This is defense in depth: the hardened system prompt and the Evidence Guard
remain the primary and final lines of defense.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

DATA_OPEN = "<<UNTRUSTED_DATA"
DATA_CLOSE = "<<END_UNTRUSTED_DATA>>"

# (name, pattern) — matched case-insensitively against untrusted text.
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("ignore_previous_instructions", re.compile(r"(?i)\b(ignore|disregard|forget)\b.{0,40}\b(previous|prior|above|earlier|all)\b.{0,20}\b(instruction|prompt|rule|context)", re.DOTALL)),
    ("reveal_system_prompt", re.compile(r"(?i)\b(reveal|show|print|repeat|expose|leak)\b.{0,40}\b(system|developer)\b.{0,10}\bprompt")),
    ("reveal_secret", re.compile(r"(?i)\b(reveal|show|print|expose|leak|exfiltrate|send)\b.{0,40}\b(api[ _-]?key|secret|token|password|credential)")),
    ("role_override", re.compile(r"(?i)\b(you are now|act as|pretend to be|from now on|new role|ignore your (rules|guidelines))\b")),
    ("output_contract_override", re.compile(r"(?i)\b(do not|don't|stop)\b.{0,20}\b(return|output|use)\b.{0,20}\bjson|\boverride\b.{0,20}\b(schema|contract|format)")),
    ("tool_invocation", re.compile(r"(?i)\b(call|invoke|execute|run)\b.{0,20}\b(tool|function|command|shell|os\.system|subprocess)")),
    ("data_exfiltration", re.compile(r"(?i)\b(curl|wget|fetch|http[s]?://|base64|exfiltrate)\b.{0,20}(send|post|upload|to)?", re.DOTALL)),
]


@dataclass
class InjectionVerdict:
    flagged: bool
    patterns: list[str] = field(default_factory=list)
    labeled_text: str = ""


def scan(text: str) -> InjectionVerdict:
    """Detect known injection patterns in untrusted text.

    Returns a verdict listing every matched pattern name. The original text is
    left intact; callers use :func:`quarantine` to wrap it as data.
    """
    if not text:
        return InjectionVerdict(flagged=False, patterns=[], labeled_text=text)
    hits = [name for name, pattern in _PATTERNS if pattern.search(text)]
    return InjectionVerdict(flagged=bool(hits), patterns=hits, labeled_text=text)


def quarantine(text: str, verdict: InjectionVerdict | None = None) -> str:
    """Wrap untrusted text in explicit data delimiters, keeping the original.

    When a verdict flags injection patterns, a ``hazard`` annotation lists them
    so downstream review (and the UI badge) can surface why it was quarantined.
    """
    if verdict is None:
        verdict = scan(text)
    if verdict.flagged:
        header = f'{DATA_OPEN} hazard="injection" patterns="{",".join(verdict.patterns)}">'
    else:
        header = f"{DATA_OPEN}>"
    return f"{header}\n{text}\n{DATA_CLOSE}"
