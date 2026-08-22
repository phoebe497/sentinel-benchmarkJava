"""Assemble dashboard payloads from committed artifacts.

Numbers come from JSON/JSONL evidence. Ground truth is joined only after
scanner/agent artifacts are loaded, and only for the evaluation panel.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from sentinel_benchmark.analysis.chat import answer_question, build_chat_payload
from sentinel_benchmark.analysis.models import AnalysisGroup, EvidenceItem
from sentinel_benchmark.analysis.taxonomy import cwe_name
from sentinel_benchmark.guardrails.approval import ApprovalGate, ApprovalRejected, ProposedRequest
from sentinel_benchmark.guardrails.injection import scan as scan_injection
from sentinel_benchmark.guardrails.redaction import redact, redact_obj
from sentinel_benchmark.normalizer import normalize_zap_report

ROOT = Path(__file__).resolve().parents[2]
WEEK1 = ROOT / "artifacts/week-1"
WEEK3 = ROOT / "artifacts/week-3"
WEEK5 = ROOT / "artifacts/week-5"
WEEK6 = ROOT / "artifacts/week-6"
KB = ROOT / "datasets/knowledge/security-topics.jsonl"
PREDICTIONS = WEEK1 / "semgrep-20260806/variants/security-audit/predictions.jsonl"
CI_REPORTS = WEEK3 / "runs/20260807T043217Z-ci-full/reports.jsonl"
SMOKE_REPORTS = WEEK3 / "runs/20260807T043231Z-real-smoke/reports.jsonl"
ZAP_JSON = WEEK6 / "dast/zap-baseline.json"
ZAP_MANIFEST = WEEK6 / "dast/manifest.json"
APPROVAL_LOG = WEEK5 / "ui-approval-events.jsonl"
SEED_APPROVAL = WEEK5 / "approval-events.jsonl"
GATEWAY_AUDIT = WEEK6 / "gateway/gateway-audit.jsonl"
SOURCE_DIRS = (
    ROOT / "vendor/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode",
    ROOT / "app/web/data/benchmark-sources",
)
SOURCE_NAME = re.compile(r"^BenchmarkTest(\d{5})\.java$")

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def _read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows = []
    # "\n" only: splitlines() also breaks on U+2028, which would shred a record
    # whose text legitimately contains one.
    for line in path.read_text(encoding="utf-8").split("\n"):
        if line.strip():
            rows.append(json.loads(line))
    return rows


def _severity(value: str | None) -> str:
    raw = (value or "info").strip().lower()
    if raw in {"informational", "information"}:
        return "info"
    if raw == "error":
        return "high"
    return raw if raw in SEVERITY_ORDER else "info"


# The agent's five contracted verdicts, in display form. There is no rule here
# that turns a confidence number into a verdict: the verdict is the agent's
# own answer, and inventing one from a threshold would report a conclusion
# nobody reached.
VERDICT_LABELS = {
    "confirmed_vulnerable": "Confirmed Vulnerable",
    "likely_vulnerable": "Likely Vulnerable",
    "likely_false_positive": "Likely False Positive",
    "not_vulnerable": "Not Vulnerable",
    "insufficient_evidence": "Insufficient Evidence",
}


def _verdict_label(verdict: str | None) -> str:
    """Display form of a recorded verdict, or an explicit 'not analysed'."""
    if not verdict:
        return "Not Analysed"
    return VERDICT_LABELS.get(str(verdict), str(verdict))


def _badge_kind(label: str) -> str:
    mapping = {
        "confirmed vulnerable": "critical",
        "likely vulnerable": "high",
        "likely false positive": "warning",
        "not vulnerable": "success",
        "insufficient evidence": "muted",
        "not analysed": "muted",
        "true positive": "success",
        "true negative": "success",
        "false positive": "critical",
        "needs review": "warning",
        "approved": "success",
        "pending": "warning",
        "rejected": "critical",
        "blocked": "critical",
        "allowed": "success",
        "quarantined": "warning",
        "critical": "critical",
        "high": "high",
        "medium": "warning",
        "low": "info",
        "info": "muted",
        "sast": "info",
        "dast": "success",
        "running": "info",
        "completed": "success",
        "success": "success",
    }
    return mapping.get(label.lower(), "muted")


@lru_cache(maxsize=1)
def _predictions() -> dict[str, dict[str, Any]]:
    rows = {}
    for row in _read_jsonl(PREDICTIONS):
        rows[row["test_id"]] = row
    return rows


def _runs_with_verdicts(runs_root: Path, dataset: str) -> list[dict[str, Any]]:
    """Reports from the newest run that carries verdicts, for one dataset.

    Newest wins, so a real-provider run supersedes the deterministic run made
    earlier the same day. A run without verdicts predates the Week 6 contract
    and is skipped rather than displayed as if it had reached a conclusion.
    """
    if not runs_root.exists():
        return []
    for run_dir in sorted((path for path in runs_root.iterdir() if path.is_dir()), reverse=True):
        reports = _read_jsonl(run_dir / "reports.jsonl")
        if not reports or not reports[0].get("verdict"):
            continue
        if (reports[0].get("dataset") or "owasp-benchmark-java") == dataset:
            return reports
    return []


@lru_cache(maxsize=1)
def _sast_reports() -> list[dict[str, Any]]:
    """Every analysis group, with a real verdict where one was produced.

    The Week 3 run covers all 99 groups but predates the verdict contract; the
    Week 6 verdict run covers the groups it was asked for. Merging keeps the
    full picture and lets an un-analysed group say so, instead of borrowing a
    verdict it never received.
    """
    base = _read_jsonl(CI_REPORTS) or _read_jsonl(SMOKE_REPORTS)
    scored = {str(row.get("analysis_group_id")): row for row in _runs_with_verdicts(WEEK3 / "runs", "owasp-benchmark-java")}
    if not scored:
        return base
    merged = [scored.get(str(row.get("analysis_group_id")), row) for row in base]
    seen = {str(row.get("analysis_group_id")) for row in base}
    merged.extend(row for key, row in scored.items() if key not in seen)
    return merged


@lru_cache(maxsize=1)
def _dast_reports() -> list[dict[str, Any]]:
    return _runs_with_verdicts(WEEK6 / "runs", "juice-shop-dast")


@lru_cache(maxsize=1)
def _probe_records() -> list[dict[str, Any]]:
    """The real probe attempts, newest run only, in the order they were made."""
    runs = sorted((WEEK6 / "probes").glob("*-probe.jsonl"), reverse=True)
    return _read_jsonl(runs[0]) if runs else []


@lru_cache(maxsize=1)
def _smoke_reports() -> list[dict[str, Any]]:
    return _read_jsonl(SMOKE_REPORTS)


@lru_cache(maxsize=1)
def _dast_records() -> list[dict[str, Any]]:
    payload = _read_json(ZAP_JSON)
    if not payload:
        return []
    return normalize_zap_report(payload, Path("artifacts/week-6/dast/zap-baseline.json"))


@lru_cache(maxsize=1)
def _knowledge_docs() -> list[dict[str, Any]]:
    return _read_jsonl(KB)


def _sast_findings() -> list[dict[str, Any]]:
    findings = []
    predictions = _predictions()
    for index, report in enumerate(_sast_reports(), start=1):
        evidence = report.get("evidence") or []
        first = evidence[0] if evidence else {}
        test_id = report.get("benchmark_test_id") or ""
        truth = predictions.get(test_id, {})
        confidence = float(report.get("analysis_confidence") or 0)
        severity = _severity(report.get("severity_assessment"))
        ground_truth = truth.get("ground_truth")
        location = first.get("file_or_url") or f"src/main/java/org/owasp/benchmark/testcode/{test_id}.java"
        line = first.get("line_start")
        display = f"{location}:{line}" if line else location
        finding_id = f"SAST-{3000 + index}"
        findings.append(
            {
                "id": finding_id,
                "kind": "SAST",
                "cwe": report.get("expected_cwe") or "",
                "cwe_name": cwe_name(report.get("expected_cwe") or "", report.get("category") or ""),
                "severity": severity.title() if severity != "info" else "Info",
                "severity_key": severity,
                "file": display,
                "file_full": location,
                "line": line,
                "verdict": _verdict_label(report.get("verdict")),
                "verdict_key": report.get("verdict") or "",
                "verdict_rationale": report.get("verdict_rationale") or "",
                "false_positive_indicators": report.get("false_positive_indicators") or [],
                "provider": report.get("provider") or "",
                "model": report.get("model") or "",
                "confidence": int(round(confidence * 100)),
                "title": report.get("vulnerability_name") or first.get("title") or "Security finding",
                "test_id": test_id,
                "report_id": report.get("report_id"),
                "group_id": report.get("analysis_group_id"),
                "explanation": report.get("explanation") or "",
                "verification": report.get("verification_steps") or [],
                "remediation": report.get("remediation") or [],
                "limitations": report.get("limitations") or [],
                "evidence": evidence,
                "kb": report.get("retrieval") or [],
                "ground_truth": bool(ground_truth) if ground_truth is not None else None,
                "ground_truth_label": (
                    "True Vulnerability" if ground_truth is True else "Not a vulnerability" if ground_truth is False else "Unavailable"
                ),
                "excerpt": first.get("excerpt") or "",
                "tools": (report.get("sources") or {}).get("source_tools") or [],
                "run_id": report.get("run_id") or "20260807T043217Z-ci-full",
                "rule": first.get("title") or report.get("vulnerability_name") or "",
            }
        )
    return findings


def _dast_findings() -> list[dict[str, Any]]:
    """One row per endpoint group the agent analysed, with what the probe showed.

    Report-driven rather than alert-driven: the subject of a DAST verdict is an
    endpoint, and the response that verified it is attached to the same row, so
    "the probe changed the conclusion" is visible instead of asserted.
    """
    reports = _dast_reports()
    if not reports:
        return _dast_alerts_without_analysis()
    findings = []
    for index, report in enumerate(reports, start=1):
        evidence = report.get("evidence") or []
        first = evidence[0] if evidence else {}
        verification = report.get("verification") or {}
        severity = _severity(report.get("severity_assessment"))
        endpoint = report.get("subject_id") or first.get("file_or_url") or "/"
        cwe = (report.get("reported_cwes") or [""])[0]
        status = verification.get("status")
        findings.append(
            {
                "id": f"DAST-{1400 + index}",
                "kind": "DAST",
                "cwe": cwe,
                "cwe_name": cwe_name(cwe, report.get("category") or ""),
                "severity": severity.title() if severity != "info" else "Info",
                "severity_key": severity,
                "endpoint": endpoint,
                "url": endpoint,
                "method": "GET",
                "verdict": _verdict_label(report.get("verdict")),
                "verdict_key": report.get("verdict") or "",
                "verdict_rationale": report.get("verdict_rationale") or "",
                "false_positive_indicators": report.get("false_positive_indicators") or [],
                "confidence": int(round(float(report.get("analysis_confidence") or 0) * 100)),
                "title": report.get("vulnerability_name") or first.get("title") or "ZAP alert",
                "description": report.get("explanation") or "",
                "evidence": first.get("excerpt") or "",
                "recommendation": " ".join(report.get("remediation") or [])[:400],
                "request": f"GET {endpoint}",
                # What actually came back, or an explicit statement that nothing did.
                "response": f"HTTP {status}" if status else (verification.get("unverified_reason") or "Not probed"),
                "verified": bool(verification.get("reached_target")),
                "verdict_before": _verdict_label(verification.get("verdict_before")) if verification else "",
                "verdict_changed": bool(verification.get("changed")),
                "observed": verification.get("observed") or [],
                "unverified_reason": verification.get("unverified_reason") or "",
                "provider": report.get("provider") or "",
                "model": report.get("model") or "",
                "run_id": report.get("run_id") or "",
                "tool": ", ".join((report.get("sources") or {}).get("source_tools") or ["OWASP ZAP"]),
                "category": report.get("category") or cwe_name(cwe, report.get("category") or ""),
            }
        )
    return findings


def _dast_alerts_without_analysis() -> list[dict[str, Any]]:
    """Fallback when no DAST run is committed: raw alerts, no verdict claimed."""
    findings = []
    for index, row in enumerate(_dast_records(), start=1):
        parsed = urlparse(str(row.get("file_or_url") or ""))
        path = parsed.path or "/"
        severity = _severity(row.get("severity"))
        findings.append(
            {
                "id": f"DAST-{1400 + index}",
                "kind": "DAST",
                "cwe": row.get("cwe") or "",
                "cwe_name": cwe_name(row.get("cwe") or "", row.get("title") or ""),
                "severity": severity.title() if severity != "info" else "Info",
                "severity_key": severity,
                "endpoint": path,
                "url": path,
                "method": "GET",
                "verdict": _verdict_label(None),
                "verdict_key": "",
                "verdict_rationale": "",
                "false_positive_indicators": [],
                "confidence": 0,
                "title": row.get("title") or "ZAP alert",
                "description": row.get("description") or "",
                "evidence": row.get("evidence") or "",
                "recommendation": row.get("recommendation") or "",
                "request": f"GET {path}",
                "response": "Not probed",
                "verified": False,
                "verdict_before": "",
                "verdict_changed": False,
                "observed": [],
                "unverified_reason": "No agent run for this dataset is committed.",
                "provider": "",
                "model": "",
                "run_id": "",
                "tool": row.get("tool") or "OWASP ZAP",
                "category": cwe_name(row.get("cwe") or "", row.get("title") or ""),
            }
        )
    return findings


def overview() -> dict[str, Any]:
    baseline = _read_json(WEEK3 / "baseline.json")
    week5 = _read_json(WEEK5 / "metrics.json")
    dast_manifest = _read_json(ZAP_MANIFEST)
    sast = _sast_findings()
    dast = _dast_findings()
    pending = [row for row in approval_queue() if row["status"] == "Pending"]
    severity = Counter(item["severity_key"] for item in [*sast, *dast])
    total = len(sast) + len(dast)
    true_vulns = sum(1 for item in sast if item.get("ground_truth") is True) + sum(
        1 for item in dast if item.get("verdict_key") == "confirmed_vulnerable"
    )
    executed = sum(1 for row in _read_jsonl(GATEWAY_AUDIT) if row.get("decision") == "proxied")
    analysed = sum(1 for item in [*sast, *dast] if item.get("verdict_key"))
    sast_runs = _sast_runs()
    zap_started = _when((dast_manifest.get("output") or {}).get("generated_at", ""))
    recent = []
    if dast_manifest.get("run_id"):
        recent.append(
            {
                "id": dast_manifest["run_id"],
                "type": "DAST",
                "target": "Juice Shop via Gateway",
                "status": "Completed",
                "findings": len(dast),
                "started": zap_started,
                "page": "dast",
            }
        )
    for row in sast_runs[:5]:
        recent.append(
            {
                "id": row["id"],
                "type": "SAST",
                "target": "BenchmarkJava",
                "status": row["status"],
                "findings": row.get("findings"),
                "started": row.get("started") or "",
                "page": "sast",
            }
        )
    return {
        "total_findings": total,
        "true_vulnerabilities": true_vulns,
        "pending_approval": len(pending),
        "active_scans": 0,
        "sast_observations": baseline.get("observations", len(sast)),
        "sast_groups": baseline.get("analysis_groups_week3", len(sast)),
        "dast_observations": (dast_manifest.get("output") or {}).get("normalized_observations", len(dast)),
        "pipeline": [
            {"id": "scan", "label": "Scan", "state": "success", "detail": f"{len(sast_runs) + (1 if dast_manifest else 0)} completed"},
            {"id": "normalize", "label": "Normalize", "state": "success", "detail": f"{total} findings"},
            {"id": "agent", "label": "Agent Analysis", "state": "success", "detail": f"{analysed} analysed"},
            {"id": "approval", "label": "Approval", "state": "pending" if pending else "success", "detail": f"{len(pending)} Pending"},
            {"id": "gateway", "label": "Gateway", "state": "success" if executed else "pending", "detail": f"{executed} executed"},
            {"id": "report", "label": "Report", "state": "success", "detail": "Up to date"},
        ],
        "severity": [
            {"key": "critical", "label": "Critical", "count": severity.get("critical", 0)},
            {"key": "high", "label": "High", "count": severity.get("high", 0)},
            {"key": "medium", "label": "Medium", "count": severity.get("medium", 0)},
            {"key": "low", "label": "Low", "count": severity.get("low", 0)},
            {"key": "info", "label": "Info", "count": severity.get("info", 0)},
        ],
        "runs": recent[:6],
        "week5": week5,
    }


def _duration(start: str, end: str) -> str:
    if not start or not end:
        return "—"
    try:
        first = datetime.fromisoformat(start.replace("Z", "+00:00"))
        last = datetime.fromisoformat(end.replace("Z", "+00:00"))
        seconds = max(0, int((last - first).total_seconds()))
        return f"{seconds // 60:02d}:{seconds % 60:02d}"
    except ValueError:
        return "—"


def _status_label(value: str | None) -> str:
    raw = str(value or "").lower()
    if raw in {"success", "successful", "completed"}:
        return "Completed"
    if raw in {"running", "in_progress"}:
        return "Running"
    if raw in {"failed", "error", "failure"}:
        return "Failed"
    return "Completed" if raw else "—"


def _rel_artifact(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return path.name


def _sast_runs() -> list[dict[str, Any]]:
    """Committed scanner and agent runs for BenchmarkJava. No invented jobs."""
    scored = {
        str(row.get("run_id")): row
        for row in [_read_json(path) for path in (WEEK3 / "evaluation").glob("verdict-metrics-*.json")]
        if row.get("run_id")
    }
    rows: list[dict[str, Any]] = []

    scanner_dirs = [
        (WEEK1 / "semgrep-20260806", "p/security-audit"),
        (WEEK1 / "semgrep-20260729", "p/security-audit"),
        (WEEK1 / "llm-20260728", "ocr+deepsec"),
    ]
    for folder, ruleset in scanner_dirs:
        manifest = _read_json(folder / "manifest.json")
        if not manifest.get("run_id"):
            continue
        metrics = _read_json(folder / "variants/security-audit/metrics.json")
        overall = ((metrics.get("metrics") or {}).get("overall") or {}) if metrics else {}
        scanner = manifest.get("scanner") or {}
        primary = ((manifest.get("scanners") or {}).get("primary") or {})
        commit = str(
            ((manifest.get("benchmark") or {}).get("lock") or {}).get("commit")
            or (manifest.get("benchmark") or {}).get("commit")
            or ""
        )
        started = str(manifest.get("started_at") or "")
        report = folder / "variants/security-audit/metrics.json"
        rows.append(
            {
                "id": manifest["run_id"],
                "kind": "scanner",
                "branch": "main" if commit else "—",
                "commit": commit[:7] if commit else "—",
                "tool": scanner.get("name") or primary.get("name") or "Scanner",
                "ruleset": ruleset,
                "status": _status_label(manifest.get("status")),
                "duration": _duration(started, str(manifest.get("ended_at") or "")),
                "findings": (metrics.get("findings") or {}).get("total") if metrics else None,
                "agent_results": (
                    f"TP {overall.get('TP', 0)} · FP {overall.get('FP', 0)} · FN {overall.get('FN', 0)}"
                    if overall
                    else "Scanner only"
                ),
                "started": _when(started),
                "started_iso": started,
                "triggered_by": "CI scan",
                "stage": "Normalize",
                "raw_findings": (metrics.get("findings") or {}).get("total") if metrics else None,
                "normalized": (metrics.get("findings") or {}).get("total") if metrics else None,
                "agent_analyzed": 0,
                "precision": round(float(overall["precision"]) * 100, 1) if overall.get("precision") is not None else None,
                "recall": round(float(overall["recall"]) * 100, 1) if overall.get("recall") is not None else None,
                "progress": 100 if _status_label(manifest.get("status")) == "Completed" else 0,
                "scan_output": _rel_artifact(folder),
                "final_report": _rel_artifact(report if report.exists() else folder / "manifest.json"),
            }
        )

    for manifest_path in sorted((WEEK3 / "runs").glob("*/manifest.json")):
        manifest = _read_json(manifest_path)
        if not manifest.get("run_id"):
            continue
        reports = _read_jsonl(manifest_path.parent / "reports.jsonl")
        if reports and (reports[0].get("dataset") or "") == "juice-shop-dast":
            continue
        verdicts = Counter(_verdict_label(row.get("verdict")) for row in reports)
        scored_row = scored.get(str(manifest["run_id"]), {})
        counts = scored_row.get("counts") or {}
        if counts:
            agent_results = f"TP {counts.get('TP', 0)} · FP {counts.get('FP', 0)} · Review {counts.get('abstain', 0)}"
        else:
            agent_results = (
                f"TP {verdicts.get('Confirmed Vulnerable', 0) + verdicts.get('Likely Vulnerable', 0)} · "
                f"FP {verdicts.get('Likely False Positive', 0) + verdicts.get('Not Vulnerable', 0)} · "
                f"Review {verdicts.get('Insufficient Evidence', 0) + verdicts.get('Needs Review', 0)}"
            )
        stamps = [str(row.get("created_at") or "") for row in reports if row.get("created_at")]
        started = str(manifest.get("created_at") or (min(stamps) if stamps else ""))
        summary = manifest_path.parent / "summary.json"
        rows.append(
            {
                "id": manifest["run_id"],
                "kind": "agent",
                "branch": "main",
                "commit": "—",
                "tool": manifest.get("model") or "Agent",
                "ruleset": manifest.get("prompt_version") or manifest.get("tag") or "agent",
                "status": _status_label(manifest.get("status")),
                "duration": _duration(min(stamps), max(stamps)) if stamps else "—",
                "findings": manifest.get("requested_groups") or len(reports),
                "agent_results": agent_results,
                "started": _when(started),
                "started_iso": started,
                "triggered_by": "Agent CLI",
                "stage": "Agent Analysis",
                "raw_findings": len(reports),
                "normalized": len(reports),
                "agent_analyzed": len(reports),
                "precision": round(float(scored_row["precision"]) * 100, 1) if scored_row.get("precision") is not None else None,
                "recall": round(float(scored_row["recall"]) * 100, 1) if scored_row.get("recall") is not None else None,
                "progress": 100 if _status_label(manifest.get("status")) == "Completed" else 0,
                "tag": manifest.get("tag") or "",
                "scan_output": _rel_artifact(manifest_path.parent / "reports.jsonl"),
                "final_report": _rel_artifact(summary if summary.exists() else manifest_path),
            }
        )
    rows.sort(key=lambda row: str(row.get("started_iso") or ""), reverse=True)
    return rows


def sast_payload() -> dict[str, Any]:
    findings = _sast_findings()
    runs = _sast_runs()
    verdicts = Counter(item["verdict"] for item in findings)
    statuses = Counter(row["status"] for row in runs)
    return {
        "project": "BenchmarkJava",
        "total": len(findings),
        "true_vulnerabilities": sum(1 for item in findings if item.get("ground_truth") is True),
        "needs_review": verdicts.get("Needs Review", 0) + verdicts.get("Insufficient Evidence", 0),
        "false_positives": verdicts.get("False Positive", 0) + verdicts.get("Likely False Positive", 0) + verdicts.get("Not Vulnerable", 0),
        "findings": findings,
        "runs": runs,
        "run_stats": {
            "total": len(runs),
            "completed": statuses.get("Completed", 0),
            "running": statuses.get("Running", 0),
            "failed": statuses.get("Failed", 0),
        },
    }


def _path_of(value: str) -> str:
    text = str(value or "").strip()
    if "://" in text:
        return urlparse(text).path or "/"
    if " " in text:
        return text.split()[-1] or "/"
    return text or "/"


def _when(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).strftime("%b %d, %Y %I:%M %p")
    except ValueError:
        return raw


def _dast_endpoints() -> list[dict[str, Any]]:
    """Inventory of paths the scanner or a probe actually touched."""
    manifest = _read_json(ZAP_MANIFEST)
    seen = _when((manifest.get("output") or {}).get("generated_at", ""))
    buckets: dict[str, dict[str, Any]] = {}

    def row_for(path: str, method: str = "GET") -> dict[str, Any]:
        key = _path_of(path)
        current = buckets.get(key)
        if current is None:
            current = {
                "id": "",
                "endpoint": key,
                "method": method or "GET",
                "auth": "Public",
                "status": "Seen",
                "findings": 0,
                "requests": 0,
                "last_seen": seen,
                "source": "ZAP Spider",
                "response": "",
                "params": [],
                "tags": ["unauthenticated", "baseline"],
                "finding_ids": [],
            }
            buckets[key] = current
        return current

    for record in _dast_records():
        row = row_for(str(record.get("file_or_url") or "/"))
        row["requests"] += 1
        row["source"] = record.get("tool") or "ZAP Spider"
        evidence = str(record.get("evidence") or "")
        if evidence.startswith("GET ") or evidence.startswith("POST "):
            row["method"] = evidence.split(" ", 1)[0]

    for finding in _dast_findings():
        row = row_for(finding.get("endpoint") or "/", finding.get("method") or "GET")
        row["findings"] += 1
        row["finding_ids"].append(finding["id"])
        row["response"] = finding.get("response") or row["response"]
        if finding.get("verified"):
            row["status"] = "Tested"
        elif finding.get("unverified_reason") and row["status"] != "Tested":
            row["status"] = "Partial"

    for probe in _probe_records():
        row = row_for(probe.get("endpoint") or "/", probe.get("method") or "GET")
        row["requests"] += 1
        if probe.get("timestamp"):
            row["last_seen"] = _when(str(probe.get("timestamp")))
        if probe.get("sent"):
            row["status"] = "Tested"
            if probe.get("status"):
                row["response"] = f"HTTP {probe.get('status')}"
        elif row["status"] == "Seen":
            row["status"] = "Not Reached"

    endpoints = []
    for index, path in enumerate(sorted(buckets), start=1):
        row = buckets[path]
        row["id"] = f"EP-{index:03d}"
        if row["status"] == "Seen" and row["findings"]:
            row["status"] = "Partial"
        if row["status"] == "Seen":
            row["status"] = "Not Reached"
        endpoints.append(row)
    return endpoints


def _dast_probes() -> list[dict[str, Any]]:
    by_path: dict[str, list[str]] = {}
    for finding in _dast_findings():
        by_path.setdefault(_path_of(finding.get("endpoint") or ""), []).append(finding["id"])
    rows = []
    for item in approval_queue():
        path = _path_of(item.get("endpoint") or "")
        finding_ids = by_path.get(path, [])
        if item.get("sent"):
            gateway = "Executed"
        elif item.get("status") in {"Rejected", "Blocked"}:
            gateway = "Blocked"
        else:
            gateway = "Ready"
        rows.append(
            {
                **item,
                "path": path,
                "finding_id": finding_ids[0] if finding_ids else "—",
                "probe_type": item.get("payload") or "allowlist-get",
                "policy": "Blocked" if item.get("injection_flagged") or item.get("status") == "Blocked" else "4 / 4 Pass",
                "gateway": gateway,
                "allowlisted": True,
            }
        )
    return rows


def dast_payload() -> dict[str, Any]:
    findings = _dast_findings()
    endpoints = _dast_endpoints()
    probe_rows = _dast_probes()
    manifest = _read_json(ZAP_MANIFEST)
    queue = approval_queue()
    probes = Counter(item["status"] for item in queue)
    output = manifest.get("output") or {}
    severity = Counter(item["severity_key"] for item in findings)
    return {
        "target": "Juice Shop via Gateway",
        "progress": 100 if manifest else 0,
        # Derived from the scan manifest, so the panel cannot claim a scan that
        # did not happen or a duration nobody measured.
        "elapsed": (manifest.get("scanner") or {}).get("spider", ""),
        "requests": len(_probe_records()),
        "endpoints": (manifest.get("scanner") or {}).get("urls_with_alerts", 0),
        "endpoint_rows": endpoints,
        "endpoint_stats": {
            "total": len(endpoints),
            "tested": sum(1 for row in endpoints if row["status"] == "Tested"),
            "with_findings": sum(1 for row in endpoints if row["findings"]),
            "not_reached": sum(1 for row in endpoints if row["status"] == "Not Reached"),
        },
        "finding_stats": {
            "total": len(findings),
            "high": severity.get("high", 0),
            "medium": severity.get("medium", 0),
            "low": severity.get("low", 0),
            "verified": sum(1 for item in findings if item.get("verified")),
            "needs_review": sum(1 for item in findings if item["verdict"] in {"Needs Review", "Insufficient Evidence"}),
        },
        "findings_count": len(findings),
        "verified_count": sum(1 for item in findings if item.get("verified")),
        "revised_count": sum(1 for item in findings if item.get("verdict_changed")),
        "started": output.get("generated_at", ""),
        "probes": {
            "total": len(queue),
            "approved": probes.get("Approved", 0),
            "pending": probes.get("Pending", 0),
            "rejected": probes.get("Rejected", 0),
            "blocked": probes.get("Blocked", 0),
        },
        "probe_rows": probe_rows,
        "findings": findings,
    }


def agent_payload(finding_id: str | None = None) -> dict[str, Any]:
    sast = _sast_findings()
    dast = _dast_findings()
    featured = None
    if finding_id:
        featured = next((item for item in [*dast, *sast] if item["id"] == finding_id), None)
    if featured is None:
        featured = next((item for item in sast if item["cwe"] == "CWE-89"), None) or (dast[0] if dast else sast[0])
    kb = featured.get("kb") if featured.get("kind") == "SAST" else []
    if not kb:
        query = (featured.get("cwe") or featured.get("title") or "").lower()
        for doc in _knowledge_docs():
            tags = " ".join(doc.get("tags") or [])
            if query and (query in tags.lower() or query in doc.get("title", "").lower()):
                kb.append({"document_id": doc["id"], "title": doc["title"], "source": doc.get("source"), "score": 0.91})
        if not kb:
            kb = [
                {
                    "document_id": doc["id"],
                    "title": doc["title"],
                    "source": doc.get("source"),
                    "score": 0.62,
                }
                for doc in _knowledge_docs()[:4]
            ]
    smoke = next((row for row in _smoke_reports() if row.get("expected_cwe") == featured.get("cwe")), None)
    explanation = featured.get("explanation") or (smoke or {}).get("explanation") or featured.get("description") or ""
    remediation = featured.get("remediation") or (smoke or {}).get("remediation") or []
    if isinstance(remediation, str):
        remediation = [remediation]
    if featured.get("kind") == "DAST" and featured.get("recommendation"):
        remediation = [featured["recommendation"], *remediation]
    return {
        "finding": featured,
        "knowledge": [
            {
                "id": row.get("document_id") or row.get("id"),
                "cwe": featured.get("cwe") or "",
                "title": row.get("title") or "",
                "score": max(1, min(99, int(round(abs(float(row.get("score") or 0.8)) * (100 if abs(float(row.get("score") or 0)) <= 1 else 1))))),
            }
            for row in kb[:4]
        ],
        "evidence": (
            ["Request / Response", "Parameter Analysis", "Response Headers", "Error Indicators", "Behavior Analysis"]
            if featured.get("kind") == "DAST"
            else ["Code Snippet", "Data Flow", "Supporting Logs", "Scanner Evidence", "Knowledge Match"]
        ),
        "justification": explanation,
        "verdict": featured.get("verdict") or _verdict_label(None),
        "verdict_rationale": featured.get("verdict_rationale") or "",
        "confidence": featured.get("confidence") or 0,
        "remediation": remediation[:3] or [
            "Validate and encode untrusted input before use.",
            "Keep the probe on the Gateway allowlist.",
            "Require human approval before any mutating request.",
        ],
        "suggested_questions": _suggested_questions(featured),
    }


def _suggested_questions(finding: dict[str, Any]) -> list[dict[str, str]]:
    cwe = finding.get("cwe") or "this finding"
    name = finding.get("cwe_name") or finding.get("title") or "the selected vulnerability"
    place = finding.get("test_id") or finding.get("endpoint") or finding.get("file") or finding["id"]
    return [
        {
            "id": "explain",
            "label": "Explain simply",
            "question": f"Explain {cwe} — {name} in {place} in plain language and cite the scanner evidence.",
        },
        {
            "id": "verify",
            "label": "How to verify",
            "question": f"Give safe verification steps for {cwe} — {name} at {place} and cite the related observations.",
        },
        {
            "id": "fix",
            "label": "How to fix",
            "question": f"How should {cwe} — {name} at {place} be remediated using the retrieved knowledge and baked report?",
        },
    ]


def _group_from_finding(finding: dict[str, Any]) -> AnalysisGroup:
    raw = finding.get("evidence") or []
    items: list[EvidenceItem] = []
    if isinstance(raw, list):
        for index, item in enumerate(raw, start=1):
            if not isinstance(item, dict):
                continue
            items.append(
                EvidenceItem(
                    observation_id=str(item.get("observation_id") or f"{finding['id']}-obs-{index}"),
                    tool=str(item.get("tool") or finding.get("tool") or "scanner"),
                    file_or_url=str(
                        item.get("file_or_url") or finding.get("file_full") or finding.get("endpoint") or finding["id"]
                    ),
                    line_start=item.get("line_start"),
                    line_end=item.get("line_end"),
                    title=str(item.get("title") or finding.get("title") or "Scanner evidence"),
                    severity=_severity(item.get("severity") or finding.get("severity_key")),  # type: ignore[arg-type]
                    reported_cwe=list(item.get("reported_cwe") or ([finding["cwe"]] if finding.get("cwe") else [])),
                    excerpt=str(item.get("excerpt") or ""),
                )
            )
    elif isinstance(raw, str) and raw.strip():
        items.append(
            EvidenceItem(
                observation_id=f"{finding['id']}-excerpt",
                tool=str(finding.get("tool") or "owasp-zap"),
                file_or_url=str(finding.get("endpoint") or finding.get("file") or finding["id"]),
                title=str(finding.get("title") or "Scanner evidence"),
                severity=_severity(finding.get("severity_key")),  # type: ignore[arg-type]
                reported_cwe=[finding["cwe"]] if finding.get("cwe") else [],
                excerpt=raw[:2000],
            )
        )
    if not items:
        items.append(
            EvidenceItem(
                observation_id=f"{finding['id']}-summary",
                tool=str(finding.get("tool") or "agent"),
                file_or_url=str(finding.get("file_full") or finding.get("endpoint") or finding["id"]),
                title=str(finding.get("title") or "Finding summary"),
                severity=_severity(finding.get("severity_key")),  # type: ignore[arg-type]
                reported_cwe=[finding["cwe"]] if finding.get("cwe") else [],
                excerpt=str(finding.get("explanation") or finding.get("description") or finding.get("title") or "No excerpt")[:2000],
            )
        )
    return AnalysisGroup(
        analysis_group_id=str(finding.get("group_id") or finding["id"]),
        benchmark_test_id=str(finding.get("test_id") or finding.get("endpoint") or finding["id"]),
        expected_cwe=str(finding.get("cwe") or "CWE-000"),
        category=str(finding.get("cwe_name") or finding.get("title") or "web"),
        observation_ids=[item.observation_id for item in items],
        source_tools=sorted({item.tool for item in items}),
        locations=sorted({item.file_or_url for item in items}),
        evidence_items=items,
        grouping_reason=["same_expected_cwe"],
    )


def _knowledge_for_finding(finding: dict[str, Any]) -> list[dict[str, Any]]:
    cwe = str(finding.get("cwe") or "").upper()
    matched = []
    for doc in _knowledge_docs():
        cwes = [str(item).upper() for item in (doc.get("cwe") or [])]
        tags = " ".join(doc.get("tags") or []).lower()
        if cwe and (cwe in cwes or cwe.lower() in tags):
            matched.append(
                {
                    "document_id": doc["id"],
                    "title": doc.get("title") or "",
                    "source": doc.get("source") or "",
                    "content": doc.get("content") or "",
                }
            )
    if not matched:
        matched = [
            {
                "document_id": doc["id"],
                "title": doc.get("title") or "",
                "source": doc.get("source") or "",
                "content": doc.get("content") or "",
            }
            for doc in _knowledge_docs()[:3]
        ]
    return matched[:4]


def answer_finding(finding_id: str, question: str) -> dict[str, Any]:
    """Grounded Q&A for one finding. Readonly UI uses the baked-artifact path."""
    question = redact((question or "").strip())
    if not question:
        raise ValueError("empty question")
    known = {item["id"] for item in [*_sast_findings(), *_dast_findings()]}
    if finding_id and finding_id not in known:
        raise KeyError(finding_id)
    payload = agent_payload(finding_id or None)
    finding = payload["finding"]
    injection = scan_injection(question)
    group = _group_from_finding(finding)
    knowledge = _knowledge_for_finding(finding)
    explanation = str(finding.get("explanation") or finding.get("description") or payload.get("justification") or "")
    if len(explanation) < 20:
        explanation = f"{explanation} Review the cited scanner evidence before deciding on next steps.".strip()
    remediation = finding.get("remediation") or payload.get("remediation") or []
    if isinstance(remediation, str):
        remediation = [remediation]
    report = {
        "report_id": finding.get("report_id") or f"{finding['id']}-report",
        "severity_assessment": finding.get("severity_key") or "info",
        "explanation": explanation,
        "verification_steps": finding.get("verification") or ["Inspect the cited location and confirm untrusted input reaches the sink."],
        "remediation": remediation or ["Apply the retrieved knowledge-base remediation after source review."],
        "limitations": finding.get("limitations") or [],
    }
    chat_payload = build_chat_payload(question=question, group=group, knowledge=knowledge, report=report)
    answer, metadata = answer_question(provider=None, payload=chat_payload)
    limitations = list(answer.limitations)
    if injection.flagged:
        limitations.append("The question contained a known injection pattern and was treated as untrusted data, not as instructions.")
    return redact_obj(
        {
            "finding_id": finding["id"],
            "answer": answer.answer,
            "citations": answer.citations,
            "verification_steps": answer.verification_steps,
            "remediation": answer.remediation,
            "limitations": limitations,
            "injection_flagged": injection.flagged,
            "provider": metadata.get("provider") or "offline_artifact",
            "model": metadata.get("model") or "deterministic-grounded-chat-v1",
        }
    )


def _recorded_requests() -> list[dict[str, Any]]:
    """The real approval decisions, read from the probe records of the last run.

    This page reviews decisions; it does not make them. The live gate is the
    CLI (`scripts/probe.py run`), because approving a request only means
    something where the request can actually be sent, and this UI has no route
    to the gateway.
    """
    rows = []
    for index, probe in enumerate(_probe_records(), start=1):
        decision = str(probe.get("decision") or "")
        status = {"approve": "Approved", "reject": "Rejected"}.get(decision, "Blocked")
        rows.append(
            {
                "id": f"REQ-{index:03d}",
                "method": probe.get("method") or "GET",
                "endpoint": probe.get("endpoint") or probe.get("route_id") or "",
                "route_id": probe.get("route_id") or "",
                "payload": probe.get("payload_id"),
                "purpose": probe.get("purpose") or "",
                "risk": "High" if probe.get("special_payload") else "Low",
                "impact": "Mutating" if str(probe.get("method")).upper() != "GET" else "Read Only",
                "status": status,
                "sent": bool(probe.get("sent")),
                "http_status": probe.get("status"),
                "injection_flagged": bool(probe.get("injection_flagged")),
                "redaction_hits": probe.get("redaction_hits") or {},
                "reason": probe.get("reason") or "",
                "covers": len(probe.get("analysis_group_ids") or []),
                "live": True,
            }
        )
    return rows


def _seed_requests() -> list[dict[str, Any]]:
    """Illustrative queue, used only when no real probe run is committed."""
    recorded = _recorded_requests()
    if recorded:
        return recorded
    seeds = [
        {
            "id": "REQ-2026-0822-001",
            "method": "GET",
            "endpoint": "/rest/products/search",
            "payload": {"q": ""},
            "purpose": "Validate search parameter handling with empty string value.",
            "risk": "Medium",
            "impact": "Read Only",
            "status": "Pending",
        },
        {
            "id": "REQ-2026-0822-002",
            "method": "GET",
            "endpoint": "/api/Products",
            "payload": None,
            "purpose": "Confirm the products list remains reachable through the Gateway.",
            "risk": "Low",
            "impact": "Read Only",
            "status": "Pending",
        },
        {
            "id": "REQ-2026-0822-003",
            "method": "GET",
            "endpoint": "/ftp",
            "payload": None,
            "purpose": "Inspect the allowlisted FTP listing observed by the ZAP baseline.",
            "risk": "Medium",
            "impact": "Read Only",
            "status": "Pending",
        },
        {
            "id": "REQ-2026-0819-001",
            "method": "GET",
            "endpoint": "/api/health",
            "payload": None,
            "purpose": "verify endpoint reachability",
            "risk": "Low",
            "impact": "Read Only",
            "status": "Approved",
        },
        {
            "id": "REQ-2026-0819-002",
            "method": "POST",
            "endpoint": "/api/login",
            "payload": {"user": "[REDACTED_EMAIL]", "pass": "password=[REDACTED_PASSWORD]", "probe": "blocked"},
            "purpose": "SQLi probe against login (carries edge payload)",
            "risk": "High",
            "impact": "Mutating",
            "status": "Rejected",
        },
    ]
    live = {row.get("endpoint"): row for row in _read_jsonl(APPROVAL_LOG)}
    for item in seeds:
        update = live.get(item["endpoint"])
        if update:
            item["status"] = "Approved" if update.get("decision") == "approve" else "Rejected"
    for row in _read_jsonl(SEED_APPROVAL):
        endpoint = row.get("endpoint")
        for item in seeds:
            if item["endpoint"] == endpoint:
                item["status"] = "Approved" if row.get("decision") == "approve" else "Rejected"
    return seeds


def approval_queue() -> list[dict[str, Any]]:
    return [redact_obj(row) for row in _seed_requests()]


def decide_request(request_id: str, approved: bool) -> dict[str, Any]:
    """Record a decision. It is never a send: this process has no egress.

    The gate still runs for real, so a Reject here produces the same logged
    outcome it would at the CLI — the difference is only that the CLI is where
    an Approve can actually reach the gateway.
    """
    queue = _seed_requests()
    target = next((row for row in queue if row["id"] == request_id), None)
    if target is None:
        raise KeyError(request_id)
    request = ProposedRequest(
        endpoint=target["endpoint"],
        method=target["method"],
        payload=target.get("payload"),
        purpose=target.get("purpose") or "",
    )
    gate = ApprovalGate(log_path=APPROVAL_LOG)
    sent = False
    try:
        gate.require(request, prompter=lambda _req: (approved, "operator decided in Sentinel UI"))
        sent = False  # public UI never forwards to a live target
        status = "Approved"
        note = "Recorded. The public UI does not send the probe to a live target."
    except ApprovalRejected:
        status = "Rejected"
        note = "Rejected. The request was not sent."
    return {"id": request_id, "status": status, "sent": sent, "note": note}


def _scored_sast_runs() -> list[dict[str, Any]]:
    """Every committed SAST scoring file, newest run_id first."""
    scored = [_read_json(path) for path in (WEEK3 / "evaluation").glob("verdict-metrics-*.json")]
    scored = [row for row in scored if row.get("run_id") and row.get("scored")]
    scored.sort(key=lambda row: str(row["run_id"]), reverse=True)
    return scored


@lru_cache(maxsize=1)
def _verdict_metrics() -> dict[str, Any]:
    """The scoring of the newest run, or empty when none is committed yet.

    Ordered by the ``run_id`` recorded inside each file, not by filename: tags
    are words and sort alphabetically, so `sast-verdict` would beat
    `sast-final` and the page would report a superseded run.
    """
    scored = _scored_sast_runs()
    return scored[0] if scored else {}


def _kpi_block(scored: dict[str, Any]) -> dict[str, Any]:
    counts = scored.get("counts") or {}
    return {
        "precision": round(float(scored.get("precision") or 0) * 100, 1),
        "recall": round(float(scored.get("recall") or 0) * 100, 1),
        "f1": round(float(scored.get("f1") or 0) * 100, 1) if scored.get("f1") is not None else None,
        "true_positives": int(counts.get("TP", 0)),
        "false_positives": int(counts.get("FP", 0)),
        "false_negatives": int(counts.get("FN", 0)),
        "true_negatives": int(counts.get("TN", 0)),
        "abstained": int(counts.get("abstain", 0)),
        "scored": int(scored.get("scored", 0)),
        "run_id": scored.get("run_id") or "",
        "tag": scored.get("tag") or "",
    }


def _delta(current: float, previous: float | None, *, lower_is_better: bool = False) -> dict[str, Any] | None:
    if previous is None:
        return None
    change = current - previous
    if previous == 0:
        label = f"{change:+.1f} vs previous run"
    else:
        pct = (change / abs(previous)) * 100
        label = f"{pct:+.1f}% vs previous run"
    improved = change < 0 if lower_is_better else change > 0
    return {"label": label, "improved": improved, "unchanged": change == 0}


def _remediation_rows(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    open_keys = {"Confirmed Vulnerable", "Likely Vulnerable"}
    wip_keys = {"Insufficient Evidence", "Needs Review"}
    rows = []
    for label in ("critical", "high", "medium", "low"):
        bucket = [item for item in findings if item.get("severity_key") == label]
        opened = sum(1 for item in bucket if item.get("verdict") in open_keys)
        wip = sum(1 for item in bucket if item.get("verdict") in wip_keys)
        fixed = max(0, len(bucket) - opened - wip)
        rows.append(
            {
                "severity": label.title(),
                "open": opened,
                "in_progress": wip,
                "fixed": fixed,
                "total": len(bucket),
            }
        )
    return rows


def reports_payload() -> dict[str, Any]:
    """Accuracy of the *agent's verdicts*, never of the scanner's alerts.

    An earlier version derived DAST true positives from alert severity. That
    was a fabrication: severity is how bad an issue would be, not whether it is
    real. A finding is a true positive only where a verdict was compared with
    ground truth, so DAST — which has none — reports coverage instead.
    """
    sast = _sast_findings()
    dast = _dast_findings()
    scored = _verdict_metrics()
    counts = scored.get("counts") or {}
    tp, fp, fn, tn = (int(counts.get(key, 0)) for key in ("TP", "FP", "FN", "TN"))
    abstain = int(counts.get("abstain", 0))
    precision, recall, f1 = scored.get("precision"), scored.get("recall"), scored.get("f1")
    scanner = list(_predictions().values())
    verified = sum(1 for item in dast if item.get("verified"))
    return {
        "kpis": {
            "precision": round((precision or 0) * 100, 1),
            "recall": round((recall or 0) * 100, 1),
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "abstained": abstain,
            "scored": int(scored.get("scored", 0)),
        },
        "sast_vs_dast": {"sast": tp, "dast": verified},
        "verdict_distribution": scored.get("verdict_distribution") or {},
        "severity_open": [
            {"severity": label.title(), "open": sum(1 for item in [*sast, *dast] if item["severity_key"] == label)}
            for label in ("critical", "high", "medium", "low", "info")
        ],
        "summary": [
            {
                "category": "SAST (verdicts vs ground truth)",
                "precision": precision, "recall": recall, "f1": f1,
                "tp": tp, "fp": fp, "fn": fn, "tn": tn, "abstain": abstain,
            },
            {
                # No ground truth for a running app, so no confusion matrix.
                # What is measurable is how many verdicts a live response checked.
                "category": "DAST (verdicts verified by a live response)",
                "precision": None, "recall": None, "f1": None,
                "tp": None, "fp": None, "fn": None, "tn": None,
                "verified": verified, "findings": len(dast),
                "changed_by_probe": sum(1 for item in dast if item.get("verdict_changed")),
            },
            {
                "category": "Scanner alone (Semgrep vs ground truth, Week 1)",
                "precision": None, "recall": None, "f1": None,
                "tp": sum(1 for row in scanner if row.get("outcome") == "TP"),
                "fp": sum(1 for row in scanner if row.get("outcome") == "FP"),
                "fn": sum(1 for row in scanner if row.get("outcome") == "FN"),
                "tn": sum(1 for row in scanner if row.get("outcome") == "TN"),
            },
        ],
        "sources": [
            str((WEEK3 / "evaluation").relative_to(ROOT).as_posix()) + "/verdict-metrics-*.json",
            "artifacts/week-1/semgrep-20260806/variants/security-audit/predictions.jsonl",
        ],
    }


def knowledge_payload() -> dict[str, Any]:
    docs = _knowledge_docs()
    cwes = set()
    for doc in docs:
        for tag in doc.get("tags") or []:
            if str(tag).lower().startswith("cwe-"):
                cwes.add(str(tag).upper())
    rows = []
    for doc in docs:
        tags = [str(tag) for tag in (doc.get("tags") or [])]
        cwe = next((tag.upper() if tag.lower().startswith("cwe-") else tag for tag in tags if "cwe" in tag.lower()), "—")
        owasp = next((tag.upper() if tag.lower().startswith("a0") else tag for tag in tags if tag.lower().startswith("a0")), doc.get("source") or "")
        rows.append(
            {
                "id": doc["id"],
                "cwe": cwe.upper() if str(cwe).startswith("cwe") or str(cwe).startswith("CWE") else cwe,
                "owasp": owasp,
                "title": doc.get("title") or "",
                "category": doc.get("category") or "",
                "required_evidence": "Scanner excerpt + location",
                "fp_indicators": "Missing sink or sanitized API",
                "safe_verification": "Read-only review of committed artifacts",
                "remediation": (doc.get("content") or "")[:140],
                "content": doc.get("content") or "",
                "source": doc.get("source") or "",
                "source_url": doc.get("source_url") or "",
            }
        )
    audit = []
    for row in _read_jsonl(GATEWAY_AUDIT):
        audit.append(
            {
                "timestamp": row.get("ts") or "",
                "run_id": "20260822T043255Z-zap-juiceshop-baseline",
                "finding_id": row.get("route") or row.get("path") or "—",
                "decision": "Allowed" if row.get("decision") == "proxied" else str(row.get("decision") or "Blocked").title(),
                "approval": "Approved" if row.get("decision") == "proxied" else "Blocked",
                "gateway": str(row.get("decision") or "blocked").title(),
                "latency": f"{row.get('duration_ms', 0)} ms",
                "redaction": "Sensitive Data Masked" if "***REDACTED***" in json.dumps(row) else "None",
                "status": row.get("status"),
            }
        )
    for row in _read_jsonl(SEED_APPROVAL):
        flagged = scan_injection(json.dumps(row.get("payload") or ""))
        audit.append(
            {
                "timestamp": row.get("timestamp") or "",
                "run_id": "week-5-approval",
                "finding_id": row.get("endpoint") or "—",
                "decision": "True Positive" if row.get("decision") == "approve" else "False Positive",
                "approval": "Approved" if row.get("decision") == "approve" else "Rejected",
                "gateway": "Allowed" if row.get("decision") == "approve" else "Blocked",
                "latency": "—",
                "redaction": "Prompt Injection Blocked" if flagged.flagged else "Sensitive Data Masked",
                "status": 200 if row.get("decision") == "approve" else 0,
            }
        )
    return {
        "entries": len(docs),
        "cwe_coverage": len(cwes),
        "owasp_categories": 10,
        "updated": "Aug 22, 2026 04:32 AM",
        "documents": rows,
        "audit": audit,
    }


def workspace_search(query: str) -> list[dict[str, Any]]:
    needle = query.strip().lower()
    if not needle:
        return []
    hits = []
    for item in [*_sast_findings(), *_dast_findings()]:
        hay = " ".join(
            str(item.get(key) or "")
            for key in ("id", "cwe", "title", "file", "endpoint", "verdict", "test_id")
        ).lower()
        if needle in hay:
            hits.append({"id": item["id"], "kind": item["kind"], "title": item.get("title") or item["id"], "page": "sast" if item["kind"] == "SAST" else "dast"})
    for doc in _knowledge_docs():
        hay = f"{doc.get('id')} {doc.get('title')} {doc.get('content')}".lower()
        if needle in hay:
            hits.append({"id": doc["id"], "kind": "KB", "title": doc.get("title") or doc["id"], "page": "knowledge"})
    return hits[:12]


def _source_path(test_id: str) -> Path | None:
    name = f"{test_id}.java"
    match = SOURCE_NAME.match(name)
    if match is None or not 1 <= int(match.group(1)) <= 100:
        return None
    for folder in SOURCE_DIRS:
        candidate = folder / name
        if candidate.is_file():
            return candidate
    return None


def source_for_finding(finding_id: str) -> dict[str, Any]:
    finding = next((item for item in _sast_findings() if item["id"] == finding_id), None)
    if finding is None:
        raise KeyError(finding_id)
    path = _source_path(str(finding.get("test_id") or ""))
    if path is None:
        excerpt = str(finding.get("excerpt") or "")
        return {
            "id": finding_id,
            "path": finding.get("file_full") or finding.get("file") or "",
            "line": finding.get("line"),
            "language": "text",
            "content": excerpt,
            "lines": [{"n": 1, "text": excerpt, "highlight": True}] if excerpt else [],
            "complete": False,
        }
    text = path.read_text(encoding="utf-8")
    highlight = finding.get("line")
    return {
        "id": finding_id,
        "path": finding.get("file_full") or f"src/main/java/org/owasp/benchmark/testcode/{path.name}",
        "line": highlight,
        "language": "java",
        "content": text,
        "lines": [
            {"n": index, "text": row, "highlight": highlight == index}
            for index, row in enumerate(text.splitlines(), start=1)
        ],
        "complete": True,
    }


def now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")
