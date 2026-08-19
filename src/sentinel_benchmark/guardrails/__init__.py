"""Week 5 safety controls: prompt-injection filtering, sensitive-data redaction
and human-in-the-loop approval.

The modules are intentionally pure and importable so tests can call them
directly. Redaction and injection scanning are applied at the pipeline sinks
(prompt assembly, provider send, log writer); approval guards every outbound
request tool call.
"""

from .approval import ApprovalGate, ApprovalRejected, Decision, ProposedRequest
from .injection import InjectionVerdict, quarantine, scan
from .redaction import DEFAULT_SKIP_KEYS, redact, redact_obj, redact_with_stats

__all__ = [
    "ApprovalGate",
    "ApprovalRejected",
    "Decision",
    "ProposedRequest",
    "InjectionVerdict",
    "quarantine",
    "scan",
    "DEFAULT_SKIP_KEYS",
    "redact",
    "redact_obj",
    "redact_with_stats",
]
