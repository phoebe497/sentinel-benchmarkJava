"""The second pass: let a real response revise a verdict.

This is the step that makes probing worth doing. Before it, the agent has only
the scanner's word. After it, the verdict rests on a response the system
fetched itself — and the report records both verdicts, so a reader can see
whether the probe changed the conclusion or merely confirmed it.

What Python owns and the model does not: the status code, the headers, whether
the request was sent, and whether it reached the target. Those were measured.
The model is asked for one thing only — what the response means for this
finding — and the Evidence Guard rejects an answer that asserts a measurement
instead of interpreting one.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from .guard import validate_verification
from .models import Verdict, Verification
from .prompting import VERIFICATION_PROMPT, build_verification_payload
from .providers import Provider


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def unverified(report: dict[str, Any], probe: dict[str, Any]) -> Verification:
    """Record an attempt that produced no evidence, without touching the verdict.

    A rejected or unroutable probe must not read as "checked and clean", so the
    verdict before and after are identical and the reason is stated.
    """
    verdict: Verdict = report.get("verdict") or "insufficient_evidence"
    reasons = {
        "reject": "A human rejected the request, so it was never sent.",
        "not_routable": "No allowlisted gateway route addresses this endpoint, so it cannot be probed.",
    }
    reason = reasons.get(str(probe.get("decision")), "")
    if probe.get("sent") and not probe.get("reached_target"):
        reason = f"The request was sent but never reached the target ({probe.get('transport_error') or 'gateway refused it'})."
    return Verification(
        checked_at=_now(),
        route_id=str(probe.get("route_id") or ""),
        decision=str(probe.get("decision") or "not_routable"),
        sent=bool(probe.get("sent")),
        status=probe.get("status"),
        reached_target=bool(probe.get("reached_target")),
        injection_flagged=bool(probe.get("injection_flagged")),
        observed=[],
        verdict_before=verdict,
        verdict_after=verdict,
        changed=False,
        rationale="",
        unverified_reason=reason or "The probe produced no usable response.",
    )


def verify_report(
    report: dict[str, Any],
    probe: dict[str, Any],
    *,
    provider: Provider,
) -> tuple[Verification, dict[str, Any]]:
    """Re-decide one verdict in the light of one probe response.

    Returns the verification record and the raw provider exchange, so the run
    artifacts keep the second pass as auditable as the first.
    """
    before: Verdict = report.get("verdict") or "insufficient_evidence"
    if not probe.get("sent") or not probe.get("reached_target"):
        return unverified(report, probe), {}

    payload = build_verification_payload(report=report, probe=probe)
    observation_ids = (report.get("sources") or {}).get("observation_ids") or []
    route_id = str(probe.get("route_id") or "")
    candidate, metadata = provider.analyze(system_prompt=VERIFICATION_PROMPT, user_payload=payload)
    output, guard = validate_verification(candidate, observation_ids=observation_ids, route_id=route_id)
    exchange = {
        "analysis_group_id": report.get("analysis_group_id"),
        "pass": "verification",
        "candidate": candidate,
        "guard": guard.model_dump(),
        "provider_metadata": metadata,
    }
    if output is None or not guard.passed:
        # A guard failure is not permission to keep the model's answer. The
        # verdict stands and the failure is recorded as the reason.
        record = unverified(report, probe)
        record.unverified_reason = "The verification response failed the Evidence Guard: " + "; ".join(guard.failures)[:400]
        return record, exchange

    return (
        Verification(
            checked_at=_now(),
            route_id=route_id,
            decision=str(probe.get("decision") or "approve"),
            sent=True,
            status=probe.get("status"),
            reached_target=True,
            injection_flagged=bool(probe.get("injection_flagged")),
            observed=output.observed,
            verdict_before=before,
            verdict_after=output.verdict,
            changed=output.verdict != before,
            rationale=output.verdict_rationale,
        ),
        exchange,
    )


def apply_verification(report: dict[str, Any], verification: Verification) -> dict[str, Any]:
    """Return the report with the post-probe verdict in force.

    The pre-probe verdict is not overwritten and lost: it stays inside
    ``verification.verdict_before``, which is what makes "the probe changed the
    agent's mind" a checkable claim rather than a story.
    """
    updated = {**report, "verification": verification.model_dump(mode="json")}
    updated["verdict"] = verification.verdict_after
    if verification.rationale:
        updated["verdict_rationale"] = verification.rationale
    return updated
