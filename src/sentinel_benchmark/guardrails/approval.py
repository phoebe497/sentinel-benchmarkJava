"""Human-in-the-loop approval gate (AGENTS.md 6.2).

Before any outbound request is sent, the gate presents the endpoint, the exact
payload and a plain-language purpose, then requires an explicit Approve or
Reject. Reject means the request is not sent; there is no auto-approve and no
bypass path. Every decision is appended (redacted) to an events log.

Policy in this project: **every** request must be approved (including GET).

The gate is pure and importable: the human interaction is supplied as a
``prompter`` callable so tests can drive Approve/Reject deterministically.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

from sentinel_benchmark.guardrails.redaction import redact_obj

# prompter(request) -> (approved, reason)
Prompter = Callable[["ProposedRequest"], "tuple[bool, str]"]


class ApprovalRejected(RuntimeError):
    """Raised by :meth:`ApprovalGate.require` when a request is not approved."""

    def __init__(self, decision: "Decision") -> None:
        super().__init__(f"Request to {decision.method} {decision.endpoint} was rejected: {decision.reason or 'no reason given'}")
        self.decision = decision


@dataclass
class ProposedRequest:
    endpoint: str
    method: str = "GET"
    payload: Any = None
    purpose: str = ""

    def summary(self) -> dict[str, Any]:
        """Redacted, human-readable view shown to the approver and written to log."""
        return redact_obj(
            {
                "endpoint": self.endpoint,
                "method": self.method.upper(),
                "purpose": self.purpose,
                "payload": self.payload,
            }
        )


@dataclass
class Decision:
    approved: bool
    endpoint: str
    method: str
    timestamp: str
    reason: str = ""


@dataclass
class ApprovalGate:
    log_path: Path | None = None
    events: list[Decision] = field(default_factory=list)

    def needs_approval(self, req: ProposedRequest) -> bool:
        # Project policy: every request requires explicit human approval.
        return True

    def decide(self, req: ProposedRequest, prompter: Prompter) -> Decision:
        """Ask the prompter and record the decision. Default-deny on any error."""
        approved, reason = False, "default_deny"
        if self.needs_approval(req):
            try:
                approved, reason = prompter(req)
            except Exception as exc:  # noqa: BLE001 - any prompter failure is a reject
                approved, reason = False, f"prompter_error: {type(exc).__name__}"
        else:  # pragma: no cover - policy currently approves nothing implicitly
            approved, reason = True, "no_approval_required"
        decision = Decision(
            approved=bool(approved),
            endpoint=req.endpoint,
            method=req.method.upper(),
            timestamp=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            reason=reason or "",
        )
        self.events.append(decision)
        self._record(req, decision)
        return decision

    def require(self, req: ProposedRequest, prompter: Prompter) -> ProposedRequest:
        """Return the request only if approved; otherwise raise ApprovalRejected."""
        decision = self.decide(req, prompter)
        if not decision.approved:
            raise ApprovalRejected(decision)
        return req

    def _record(self, req: ProposedRequest, decision: Decision) -> None:
        if self.log_path is None:
            return
        row = redact_obj(
            {
                "decision": "approve" if decision.approved else "reject",
                "endpoint": decision.endpoint,
                "method": decision.method,
                "purpose": req.purpose,
                "payload": req.payload,
                "reason": decision.reason,
                "timestamp": decision.timestamp,
            }
        )
        path = Path(self.log_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
        existing = path.read_text(encoding="utf-8") if path.exists() else ""
        fd, name = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
                stream.write(existing + line)
            os.replace(name, path)
        finally:
            if os.path.exists(name):
                os.unlink(name)
