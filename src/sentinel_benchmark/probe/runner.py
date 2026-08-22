"""The one guarded path from a proposed request to a usable observation.

Order matters here, and every step is a rule from AGENTS.md:

1. Resolve the route id against the published allowlist. An unroutable
   proposal never reaches a human, because there is nothing to approve.
2. Ask the approval gate. Reject means no request is sent at all (6.2).
3. Send through the gateway, which is the only egress (7).
4. Scan the response for injection patterns *before* redacting, so detection
   sees the original text, then redact, then quarantine as labelled data. The
   response is untrusted DATA from this point on and never becomes an
   instruction (6.1, 6.3).

The result carries the redacted, quarantined response plus enough provenance
for the report to say why it believes what it believes.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

from sentinel_benchmark.guardrails import injection
from sentinel_benchmark.guardrails.approval import ApprovalGate, ApprovalRejected, Prompter
from sentinel_benchmark.guardrails.redaction import redact, redact_obj, redact_with_stats
from sentinel_benchmark.probe.client import GatewayClient, RawResponse, RouteNotAllowed
from sentinel_benchmark.probe.proposal import ProbeRequest

# Response headers worth keeping for verification: the security headers a DAST
# finding is usually *about*, plus what identifies the hop and the body.
KEPT_HEADERS = (
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "strict-transport-security",
    "referrer-policy",
    "permissions-policy",
    "feature-policy",
    "access-control-allow-origin",
    "set-cookie",
    "server",
    "x-powered-by",
    "cache-control",
    "content-type",
    "x-gateway-route",
    "x-truncated",
)


@dataclass
class ProbeResult:
    """One attempt, whatever the outcome: rejected, unroutable, failed or answered."""

    analysis_group_ids: list[str]
    route_id: str
    method: str
    endpoint: str
    purpose: str
    special_payload: bool
    payload_id: str | None
    decision: str  # approve | reject | not_routable
    reason: str
    sent: bool
    timestamp: str
    status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    body_truncated: bool = False
    reached_target: bool = False
    elapsed_ms: int = 0
    transport_error: str | None = None
    injection_flagged: bool = False
    injection_patterns: list[str] = field(default_factory=list)
    redaction_hits: dict[str, int] = field(default_factory=dict)

    def to_record(self) -> dict[str, Any]:
        """Log/report view. Redacted again at the sink: cheap, and idempotent."""
        return redact_obj(asdict(self))


def _observe(response: RawResponse) -> dict[str, Any]:
    """Make an untrusted HTTP response safe to store, log and prompt with."""
    verdict = injection.scan(response.body)
    safe_body, hits = redact_with_stats(response.body)
    headers = {key: redact(value) for key, value in response.headers.items() if key in KEPT_HEADERS}
    return {
        "status": response.status,
        "headers": headers,
        # Quarantined *after* redaction so the delimiters wrap text that is
        # already safe; the hazard note survives because the verdict came from
        # the original.
        "body": injection.quarantine(safe_body, verdict) if safe_body else "",
        "body_truncated": response.body_truncated_by_tool or response.truncated_by_gateway,
        "reached_target": response.reached_target,
        "elapsed_ms": response.elapsed_ms,
        "transport_error": response.error,
        "injection_flagged": verdict.flagged,
        "injection_patterns": verdict.patterns,
        "redaction_hits": hits,
    }


def run_probe(
    request: ProbeRequest,
    *,
    client: GatewayClient,
    gate: ApprovalGate,
    prompter: Prompter,
) -> ProbeResult:
    now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    base = {
        "analysis_group_ids": list(request.analysis_group_ids),
        "route_id": request.route_id,
        "purpose": request.purpose,
        "special_payload": request.is_special,
        "payload_id": request.payload_id,
        "timestamp": now,
    }
    try:
        route = client.route(request.route_id)
    except RouteNotAllowed as exc:
        # Not a failure of the target: a proposal the allowlist does not carry.
        return ProbeResult(**base, method="", endpoint="", decision="not_routable", reason=str(exc), sent=False)

    proposed = request.for_approval(route)
    base |= {"method": proposed.method, "endpoint": proposed.endpoint}
    try:
        gate.require(proposed, prompter)
    except ApprovalRejected as exc:
        return ProbeResult(**base, decision="reject", reason=exc.decision.reason, sent=False)

    query, body = request.materialize()
    response = client.send(request.route_id, path_params=request.path_params, query=query, body=body)
    return ProbeResult(**base, decision="approve", reason=gate.events[-1].reason, sent=True, **_observe(response))
