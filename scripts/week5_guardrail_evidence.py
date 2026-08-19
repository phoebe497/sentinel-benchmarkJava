"""Generate machine-readable Week 5 guardrail evidence into artifacts/week-5/.

Runs the three guardrails (redaction, injection scan, approval) against the
crafted fixture and writes redacted proof, an injection scan, a sample approval
event log and aggregate metrics. Raw secrets are never written: every sink goes
through the redaction-aware artifact writers, and only booleans/labels describe
the sensitive values.

Reproduce:

    python3 scripts/week5_guardrail_evidence.py
    python3 -m pytest -q tests/test_week5_guardrails.py
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import json  # noqa: E402

from sentinel_benchmark.analysis.artifacts import atomic_json, write_checksums  # noqa: E402
from sentinel_benchmark.guardrails.approval import ApprovalGate, ProposedRequest  # noqa: E402
from sentinel_benchmark.guardrails.injection import scan  # noqa: E402
from sentinel_benchmark.guardrails.redaction import redact, redact_with_stats  # noqa: E402

WEEK5 = ROOT / "artifacts" / "week-5"
FIXTURE_PATH = ROOT / "datasets" / "guardrails" / "crafted-injection-response.json"


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def main() -> int:
    fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    body = fixture["body"]
    secrets = fixture["expected"]["must_not_survive"]

    WEEK5.mkdir(parents=True, exist_ok=True)

    # --- Redaction proof (stores redacted output only) --------------------- #
    redacted_body, stats = redact_with_stats(body)
    secrets_absent = all(secret not in redacted_body for secret in secrets)
    placeholders = sorted({p for p in ("[REDACTED_EMAIL]", "[REDACTED_PHONE]", "[REDACTED_TOKEN]", "[REDACTED_API_KEY]", "[REDACTED_PASSWORD]", "[REDACTED_PII]") if p in redacted_body})
    idempotent = redact(redacted_body) == redacted_body
    redaction_proof = {
        "schema_version": "1.0",
        "fixture": str(FIXTURE_PATH.relative_to(ROOT)),
        "redacted_body": redacted_body,
        "redaction_stats": stats,
        "placeholders_present": placeholders,
        "secret_types_checked": fixture["expected"]["redacted_types"],
        "secrets_absent": secrets_absent,
        "idempotent": idempotent,
    }

    # --- Injection scan (untrusted vs benign; KB is trusted, not scanned) -- #
    untrusted = scan(body)
    benign_text = "Untrusted input flows into a SQL statement without sanitisation."
    benign = scan(benign_text)
    injection_scan = {
        "schema_version": "1.0",
        "untrusted_sample": {
            "flagged": untrusted.flagged,
            "patterns": untrusted.patterns,
            "redacted_preview": redacted_body,
        },
        "benign_sample": {
            "text": benign_text,
            "flagged": benign.flagged,
            "patterns": benign.patterns,
        },
        "note": "Knowledge-base documents are team-authored and trusted; they are not scanned.",
    }

    # --- Approval demo: one approve, one reject (log auto-redacted) -------- #
    approval_log = WEEK5 / "approval-events.jsonl"
    if approval_log.exists():
        approval_log.unlink()
    gate = ApprovalGate(log_path=approval_log)
    gate.decide(
        ProposedRequest(endpoint="/api/health", method="GET", payload=None, purpose="verify endpoint reachability"),
        prompter=lambda r: (True, "operator approved read-only check"),
    )
    gate.decide(
        ProposedRequest(
            endpoint="/api/login",
            method="POST",
            payload={"user": "admin@example.com", "pass": "password=SuperSecret123", "probe": "1' OR '1'='1"},
            purpose="SQLi probe against login (carries edge payload)",
        ),
        prompter=lambda r: (False, "operator rejected mutating probe"),
    )
    approvals = [d for d in gate.events]

    # --- Metrics ----------------------------------------------------------- #
    metrics = {
        "schema_version": "1.0",
        "generated_at": _now(),
        "redaction": {"by_type": stats, "total_masked": sum(stats.values()), "secrets_absent": secrets_absent, "idempotent": idempotent},
        "injection": {"untrusted_flagged": untrusted.flagged, "untrusted_pattern_count": len(untrusted.patterns), "benign_flagged": benign.flagged},
        "approval": {
            "total": len(approvals),
            "approve": sum(1 for d in approvals if d.approved),
            "reject": sum(1 for d in approvals if not d.approved),
            "policy": "every request requires explicit approval (default-deny)",
        },
        "test_suite": "tests/test_week5_guardrails.py",
    }

    summary = {
        "schema_version": "1.0",
        "week": 5,
        "generated_at": _now(),
        "guardrails": ["redaction", "injection", "approval"],
        "redaction_secrets_absent": secrets_absent,
        "injection_untrusted_flagged": untrusted.flagged,
        "injection_benign_flagged": benign.flagged,
        "approvals_recorded": len(approvals),
        "status": "ok" if (secrets_absent and untrusted.flagged and not benign.flagged and len(approvals) == 2) else "check_failed",
    }

    atomic_json(WEEK5 / "redaction-proof.json", redaction_proof)
    atomic_json(WEEK5 / "injection-scan.json", injection_scan)
    atomic_json(WEEK5 / "metrics.json", metrics)
    atomic_json(WEEK5 / "summary.json", summary)
    atomic_json(
        WEEK5 / "manifest.json",
        {
            "schema_version": "1.0",
            "week": 5,
            "generated_at": _now(),
            "source_fixture": str(FIXTURE_PATH.relative_to(ROOT)),
            "artifacts": ["redaction-proof.json", "injection-scan.json", "approval-events.jsonl", "metrics.json", "summary.json"],
        },
    )
    write_checksums(WEEK5)

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
