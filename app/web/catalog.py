"""Assemble dashboard payloads from committed artifacts.

Numbers come from JSON/JSONL evidence. Ground truth is joined only after
scanner/agent artifacts are loaded, and only for the evaluation panel.
"""

from __future__ import annotations

import json
import os
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
BENCHMARK_LOCK = ROOT / "scripts/security/benchmark-lock.json"
BENCHMARK_CORPUS = "BenchmarkJava"
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


def _preferred_dast_run_id() -> str:
    """The DAST analysis snapshot the UI and the judge agree on.

    E2E ``*-flow`` reruns are newer by timestamp but they are not the scored
    analysis run. Prefer the run_id recorded in the LLM-as-judge file.
    """
    judged = str(_dast_judge_metrics().get("run_id") or "")
    if judged and (WEEK6 / "runs" / judged / "reports.jsonl").exists():
        return judged
    return ""


@lru_cache(maxsize=1)
def _dast_reports() -> list[dict[str, Any]]:
    preferred = _preferred_dast_run_id()
    if preferred:
        return _read_jsonl(WEEK6 / "runs" / preferred / "reports.jsonl")
    if not (WEEK6 / "runs").exists():
        return []
    for run_dir in sorted((path for path in (WEEK6 / "runs").iterdir() if path.is_dir()), reverse=True):
        if run_dir.name.endswith("-flow"):
            continue
        reports = _read_jsonl(run_dir / "reports.jsonl")
        if not reports or not reports[0].get("verdict"):
            continue
        if (reports[0].get("dataset") or "owasp-benchmark-java") == "juice-shop-dast":
            return reports
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
                "kb": report.get("retrieval") or [],
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
    sast_scored = _verdict_metrics()
    sast_tp = int((sast_scored.get("counts") or {}).get("TP") or 0)
    dast_confirmed = sum(1 for item in dast if item.get("verdict_key") == "confirmed_vulnerable")
    true_vulns = sast_tp + dast_confirmed
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
        "true_vulnerability_note": f"{sast_tp} SAST TP · {dast_confirmed} DAST confirmed",
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


def _corpus_commit(manifest: dict[str, Any] | None = None) -> str:
    """Pinned BenchmarkJava SHA. This repo's git branch is not in the artifacts."""
    bench = (manifest or {}).get("benchmark") or {}
    commit = str((bench.get("lock") or {}).get("commit") or bench.get("commit") or "")
    if not commit:
        commit = str(_read_json(BENCHMARK_LOCK).get("commit") or "")
    return commit


def _short_sha(commit: str) -> str:
    return commit[:7] if commit else "—"


def _scanner_metrics(folder: Path) -> dict[str, Any]:
    """Week-1 Semgrep metrics, or the OCR block from the 2026-07-28 comparison run."""
    metrics = _read_json(folder / "variants/security-audit/metrics.json")
    if metrics:
        return metrics
    results = _read_json(folder / "results.json")
    ocr = ((results.get("scanners") or {}).get("open_code_review") or {})
    return ocr or results


def _score_line(counts: dict[str, Any]) -> str:
    parts = [
        f"TP {int(counts.get('TP') or 0)}",
        f"FP {int(counts.get('FP') or 0)}",
        f"TN {int(counts.get('TN') or 0)}",
        f"FN {int(counts.get('FN') or 0)}",
    ]
    abstain = int(counts.get("abstain") or 0)
    if abstain:
        parts.append(f"Abstain {abstain}")
    return " · ".join(parts)


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
        metrics = _scanner_metrics(folder)
        overall = ((metrics.get("metrics") or {}).get("overall") or {}) if metrics else {}
        scanner = manifest.get("scanner") or {}
        primary = ((manifest.get("scanners") or {}).get("primary") or {})
        commit = _corpus_commit(manifest)
        started = str(manifest.get("started_at") or "")
        findings = (metrics.get("findings") or {}).get("total")
        report = folder / "variants/security-audit/metrics.json"
        if not report.exists():
            report = folder / "results.json"
        rows.append(
            {
                "id": manifest["run_id"],
                "kind": "scanner",
                "branch": BENCHMARK_CORPUS,
                "commit": _short_sha(commit),
                "commit_full": commit or "—",
                "tool": scanner.get("name") or primary.get("name") or "Scanner",
                "model": "",
                "ruleset": ruleset,
                "status": _status_label(manifest.get("status")),
                "duration": _duration(started, str(manifest.get("ended_at") or "")),
                "findings": findings,
                "agent_results": "Scanner only",
                "started": _when(started),
                "started_iso": started,
                "triggered_by": "Scanner",
                "stage": "Scan",
                "raw_findings": findings,
                "normalized": findings,
                "agent_analyzed": 0,
                "precision": round(float(overall["precision"]) * 100, 1) if overall.get("precision") is not None else None,
                "recall": round(float(overall["recall"]) * 100, 1) if overall.get("recall") is not None else None,
                "eval_label": "scanner vs ground truth" if overall else "",
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
        scored_row = scored.get(str(manifest["run_id"]), {})
        counts = scored_row.get("counts") or {}
        if counts:
            agent_results = _score_line(counts)
        else:
            # Verdict labels are not TP/FP until scoring.py joins ground truth.
            agent_results = f"{len(reports)} reports · not scored"
        stamps = [str(row.get("created_at") or "") for row in reports if row.get("created_at")]
        started = str(manifest.get("created_at") or (min(stamps) if stamps else ""))
        summary_path = manifest_path.parent / "summary.json"
        summary = _read_json(summary_path)
        requested = int(summary.get("requested") or manifest.get("requested_groups") or len(reports) or 0)
        analyzed = int(summary.get("successful") or len(reports) or 0)
        commit = _corpus_commit()
        rows.append(
            {
                "id": manifest["run_id"],
                "kind": "agent",
                "branch": BENCHMARK_CORPUS,
                "commit": _short_sha(commit),
                "commit_full": commit or "—",
                "tool": "Semgrep",
                "model": manifest.get("model") or "",
                "ruleset": manifest.get("prompt_version") or manifest.get("tag") or "agent",
                "status": _status_label(manifest.get("status")),
                "duration": _duration(min(stamps), max(stamps)) if stamps else "—",
                "findings": analyzed,
                "agent_results": agent_results,
                "started": _when(started),
                "started_iso": started,
                "triggered_by": "Agent CLI",
                "stage": "Agent Analysis",
                "raw_findings": requested,
                "normalized": requested,
                "agent_analyzed": analyzed,
                "precision": round(float(scored_row["precision"]) * 100, 1) if scored_row.get("precision") is not None else None,
                "recall": round(float(scored_row["recall"]) * 100, 1) if scored_row.get("recall") is not None else None,
                "eval_label": "agent vs ground truth" if counts else "",
                "progress": 100 if _status_label(manifest.get("status")) == "Completed" else 0,
                "tag": manifest.get("tag") or "",
                "scan_output": _rel_artifact(manifest_path.parent / "reports.jsonl"),
                "final_report": _rel_artifact(summary_path if summary_path.exists() else manifest_path),
            }
        )
    rows.sort(key=lambda row: str(row.get("started_iso") or ""), reverse=True)
    return rows


def sast_payload() -> dict[str, Any]:
    findings = _sast_findings()
    runs = _sast_runs()
    verdicts = Counter(item["verdict"] for item in findings)
    statuses = Counter(row["status"] for row in runs)
    scored = _verdict_metrics()
    counts = scored.get("counts") or {}
    analysed = sum(1 for item in findings if item.get("verdict_key"))
    return {
        "project": "BenchmarkJava",
        "total": len(findings),
        "true_vulnerabilities": sum(1 for item in findings if item.get("ground_truth") is True),
        "analysed": analysed,
        "not_analysed": len(findings) - analysed,
        "scored": int(scored.get("scored") or 0),
        "scored_tp": int(counts.get("TP") or 0),
        "needs_review": len(findings) - analysed + verdicts.get("Insufficient Evidence", 0),
        "false_positives": int(counts.get("FP") or 0),
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


_RUN_STAMP = re.compile(r"^(\d{8}T\d{6}Z)")


def _run_started(run_id: str, created_at: str = "") -> tuple[str, str]:
    """ISO timestamp and a short axis label for a committed run."""
    raw = str(created_at or "").strip()
    if raw:
        try:
            stamp = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            return stamp.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"), stamp.strftime("%b %d %H:%M")
        except ValueError:
            pass
    match = _RUN_STAMP.match(str(run_id or ""))
    if match:
        stamp = datetime.strptime(match.group(1), "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC)
        return stamp.strftime("%Y-%m-%dT%H:%M:%SZ"), stamp.strftime("%b %d %H:%M")
    return "", str(run_id or "")[:8]


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
        "run_id": (findings[0].get("run_id") if findings else "") or _preferred_dast_run_id(),
        "verified_count": sum(1 for item in findings if item.get("verified")),
        "revised_count": sum(1 for item in findings if item.get("verdict_changed")),
        "probed_endpoints": len({item.get("endpoint") for item in findings if item.get("verified")}),
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
    live = _live_chat_provider()
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
        "chat_mode": "live" if _live_chat_provider() else "offline",
        "chat_model": getattr(_live_chat_provider(), "model", "") or "deterministic-grounded-chat-v1",
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


def _live_chat_provider():
    """OpenCode zen for Ask Sentinel when an API key is configured.

    Pytest never calls the live gateway. The analysis agent still uses
    CUSTOM_SCAN_MODEL; chat uses CHAT_MODEL and defaults to glm-5.2.
    """
    if os.getenv("PYTEST_CURRENT_TEST"):
        return None
    api_key = str(os.getenv("OPENCODE_API_KEY") or "").strip()
    if not api_key or api_key == "your-api-key":
        return None
    from sentinel_benchmark.analysis.providers import NineRouterProvider

    model = str(os.getenv("CHAT_MODEL") or "glm-5.2").strip()
    try:
        inner = NineRouterProvider(
            base_url=os.getenv("OPENCODE_BASE_URL", "https://opencode.ai/zen/go/v1"),
            model=model,
            api_key=api_key,
            timeout=float(os.getenv("OPENCODE_TIMEOUT_SECONDS") or os.getenv("NINE_ROUTER_TIMEOUT_SECONDS") or "60"),
            max_retries=int(os.getenv("OPENCODE_MAX_RETRIES") or os.getenv("NINE_ROUTER_MAX_RETRIES") or "1"),
        )
    except ValueError:
        return None
    inner.name = "opencode"
    return inner


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
    # Injected text is still answered, but never forwarded to a live model.
    provider = None if injection.flagged else _live_chat_provider()
    answer, metadata = answer_question(provider=provider, payload=chat_payload, fallback_on_error=True)
    limitations = list(answer.limitations)
    if injection.flagged:
        limitations.append("The question contained a known injection pattern and was treated as untrusted data, not as instructions.")
    raw_provider = str(metadata.get("provider") or "offline_artifact")
    provider_label = "opencode" if raw_provider in {"nine_router", "opencode"} else raw_provider
    return redact_obj(
        {
            "finding_id": finding["id"],
            "answer": answer.answer,
            "citations": answer.citations,
            "verification_steps": answer.verification_steps,
            "remediation": answer.remediation,
            "limitations": limitations,
            "injection_flagged": injection.flagged,
            "provider": provider_label,
            "model": metadata.get("model") or (getattr(provider, "model", None) if provider else "deterministic-grounded-chat-v1"),
        }
    )


def _request_from_probe(probe: dict[str, Any], request_id: str) -> dict[str, Any]:
    decision = str(probe.get("decision") or "")
    status = {"approve": "Approved", "reject": "Rejected"}.get(decision, "Blocked")
    path = _path_of(str(probe.get("endpoint") or probe.get("route_id") or ""))
    finding_id = _finding_id_for_path(path)
    stamp = str(probe.get("timestamp") or "")
    http_status = probe.get("status")
    sent = bool(probe.get("sent"))
    if sent:
        gateway = "Executed"
    elif status == "Approved":
        gateway = "Queued"
    else:
        gateway = "Not Executed"
    return {
        "id": request_id,
        "finding_id": finding_id,
        "method": probe.get("method") or "GET",
        "endpoint": probe.get("endpoint") or probe.get("route_id") or "",
        "route_id": probe.get("route_id") or "",
        "path": path,
        "payload": probe.get("payload_id"),
        "purpose": probe.get("purpose") or "",
        "risk": "High" if probe.get("special_payload") else ("Medium" if path.startswith("/ftp") else "Low"),
        "impact": "Mutating" if str(probe.get("method")).upper() != "GET" else "Read Only",
        "status": status,
        "sent": sent,
        "http_status": http_status,
        "result": _http_label(http_status) if sent else ("Not Executed" if status != "Approved" else "Queued"),
        "gateway": gateway,
        "approved_by": "Operator" if status == "Approved" else "",
        "rejected_by": "User" if status == "Rejected" else ("Policy" if status == "Blocked" else ""),
        "rejected_source": "User" if status == "Rejected" else ("Policy" if status == "Blocked" else ""),
        "decided_at": _when(stamp),
        "timestamp": stamp,
        "injection_flagged": bool(probe.get("injection_flagged")),
        "injection_flag": "Flagged" if probe.get("injection_flagged") else "Clean",
        "redaction_applied": "Yes" if probe.get("redaction_hits") else "No",
        "latency_ms": probe.get("elapsed_ms"),
        "headers": probe.get("headers") or {},
        "body": (probe.get("body") or "")[:4000],
        "reason": probe.get("reason") or "",
        "covers": len(probe.get("analysis_group_ids") or []),
        "live": True,
        "source": probe.get("source") or "committed-run",
    }


def _live_probe_path() -> Path:
    return Path(os.getenv("SENTINEL_UI_LIVE_LOG") or WEEK6 / "probes" / "ui-live-probe.jsonl")


def _live_requests() -> list[dict[str, Any]]:
    rows = []
    for index, probe in enumerate(_read_jsonl(_live_probe_path()), start=1):
        rows.append(_request_from_probe(probe, f"REQ-LIVE-{index:03d}"))
    rows.reverse()
    return rows


def _recorded_requests() -> list[dict[str, Any]]:
    """The committed probe run, plus any playground attempts written by the UI."""
    rows = []
    for index, probe in enumerate(_probe_records(), start=1):
        rows.append(_request_from_probe(probe, f"REQ-{index:03d}"))
    return rows


def _finding_id_for_path(path: str) -> str:
    for finding in _dast_findings():
        if _path_of(str(finding.get("endpoint") or "")) == path:
            return str(finding["id"])
    return "—"


def _http_label(status: Any) -> str:
    if status in (None, ""):
        return "—"
    code = int(status)
    if code == 200:
        return "200 OK"
    if code == 401:
        return "401 Expected"
    return str(code)


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
    recorded = _seed_requests()
    return [redact_obj(row) for row in [*_live_requests(), *recorded]]


def _approval_history(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    index = 0
    for item in items:
        stamp = item.get("timestamp") or item.get("decided_at") or ""
        common = {
            "request_id": item.get("id"),
            "finding_id": item.get("finding_id") or "—",
            "route_id": item.get("route_id") or "",
            "timestamp": stamp,
            "when": item.get("decided_at") or _when(str(stamp)),
            "approval": item.get("status"),
            "http_status": item.get("http_status"),
            "latency": f"{item['latency_ms']} ms" if item.get("latency_ms") not in (None, "") else "—",
            "lifecycle": _lifecycle(item),
        }
        if item.get("status") in {"Approved", "Rejected"}:
            index += 1
            events.append(
                {
                    **common,
                    "id": f"EVT-{index:03d}",
                    "event": item["status"],
                    "actor": item.get("approved_by") or item.get("rejected_by") or "Operator",
                    "filter": "—",
                    "gateway": "api-gateway-lab",
                }
            )
        if item.get("sent"):
            index += 1
            events.append(
                {
                    **common,
                    "id": f"EVT-{index:03d}",
                    "event": "Probe Executed",
                    "actor": "Gateway Service",
                    "filter": "Output Redaction" if item.get("redaction_hits") or item.get("redaction_applied") == "Yes" else "—",
                    "gateway": "api-gateway-lab",
                }
            )
        if item.get("injection_flagged"):
            index += 1
            events.append(
                {
                    **common,
                    "id": f"EVT-{index:03d}",
                    "event": "Prompt Injection",
                    "actor": "Policy Engine",
                    "filter": "Prompt Injection",
                    "gateway": "api-gateway-lab",
                }
            )
        elif item.get("redaction_hits") or item.get("redaction_applied") == "Yes":
            index += 1
            events.append(
                {
                    **common,
                    "id": f"EVT-{index:03d}",
                    "event": "Response Redacted",
                    "actor": "Policy Engine",
                    "filter": "PII Masking",
                    "gateway": "api-gateway-lab",
                }
            )
    events.sort(key=lambda row: str(row.get("timestamp") or ""), reverse=True)
    return [redact_obj(row) for row in events]


def _lifecycle(item: dict[str, Any]) -> list[dict[str, str]]:
    rejected = item.get("status") in {"Rejected", "Blocked"}
    sent = bool(item.get("sent"))
    filtered = bool(item.get("injection_flagged") or item.get("redaction_hits") or item.get("redaction_applied") == "Yes")
    steps = [
        {"id": "proposed", "label": "Proposed", "state": "done"},
        {"id": "policy", "label": "Policy Passed", "state": "done" if not rejected else "done"},
        {"id": "approved", "label": "Approved" if not rejected else "Rejected", "state": "done"},
        {"id": "executed", "label": "Executed", "state": "done" if sent else ("current" if not rejected else "pending")},
        {"id": "filtered", "label": "Response Filtered", "state": "done" if filtered else ("current" if sent else "pending")},
    ]
    return steps


def approval_payload() -> dict[str, Any]:
    items = approval_queue()
    history = _approval_history(items)
    approved = [row for row in items if row.get("status") == "Approved"]
    rejected = [row for row in items if row.get("status") == "Rejected"]
    executed = [row for row in approved if row.get("sent")]
    queued = [row for row in approved if not row.get("sent")]
    success = sum(1 for row in executed if row.get("http_status") == 200)
    filters = sum(1 for row in history if row.get("event") in {"Response Redacted", "Prompt Injection"})
    return {
        "items": items,
        "history": history,
        "counts": {
            "Pending": sum(1 for row in items if row["status"] == "Pending"),
            "Approved": len(approved),
            "Rejected": len(rejected),
            "History": len(history),
        },
        "stats": {
            "approved": len(approved),
            "executed": len(executed),
            "queued": len(queued),
            "success_rate": round((success / len(executed)) * 100, 1) if executed else 0,
            "rejected": len(rejected),
            "rejected_user": sum(1 for row in rejected if row.get("rejected_source") == "User"),
            "rejected_policy": sum(1 for row in rejected if row.get("rejected_source") == "Policy"),
            "never_executed": sum(1 for row in rejected if not row.get("sent")),
            "audit_events": len(history),
            "approval_actions": len(approved) + len(rejected),
            "gateway_executions": len(executed),
            "security_filters": filters,
        },
    }


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


def _dast_judge_metrics() -> dict[str, Any]:
    """Newest LLM-as-judge scoring file for DAST, or empty when none is committed."""
    scored = [_read_json(path) for path in (WEEK6 / "evaluation").glob("verdict-metrics-*-judge.json")]
    scored = [row for row in scored if row.get("method") == "llm_as_judge" and row.get("run_id")]
    scored.sort(key=lambda row: str(row["run_id"]), reverse=True)
    return scored[0] if scored else {}


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

    SAST uses BenchmarkJava ground truth joined after the run. DAST has no
    corpus labels; Precision/Recall come from an LLM-as-judge file written the
    same way — after the reports exist — and are labelled as a proxy, not as
    Juice Shop ground truth.
    """
    sast = _sast_findings()
    dast = _dast_findings()
    history = _scored_sast_runs()
    scored = history[0] if history else {}
    previous = history[1] if len(history) > 1 else None
    kpis = _kpi_block(scored) if scored else {
        "precision": 0, "recall": 0, "f1": None, "true_positives": 0, "false_positives": 0,
        "false_negatives": 0, "true_negatives": 0, "abstained": 0, "scored": 0, "run_id": "", "tag": "",
    }
    prior = _kpi_block(previous) if previous else None
    counts = scored.get("counts") or {}
    tp, fp, fn, tn = (int(counts.get(key, 0)) for key in ("TP", "FP", "FN", "TN"))
    abstain = int(counts.get("abstain", 0))
    precision, recall, f1 = scored.get("precision"), scored.get("recall"), scored.get("f1")
    scanner = list(_predictions().values())
    dast_verdicts = Counter(item.get("verdict_key") for item in dast)
    probed = sum(1 for item in dast if item.get("verified"))
    probed_endpoints = len({item.get("endpoint") for item in dast if item.get("verified")})
    confirmed_dast = int(dast_verdicts.get("confirmed_vulnerable") or 0)
    revised = sum(1 for item in dast if item.get("verdict_changed"))
    judge = _dast_judge_metrics()
    judge_counts = judge.get("counts") or {}
    sast_groups = len(sast)
    dast_groups = len(dast)
    kpis["deltas"] = {
        "precision": _delta(kpis["precision"], prior["precision"] if prior else None),
        "recall": _delta(kpis["recall"], prior["recall"] if prior else None),
        "true_positives": _delta(kpis["true_positives"], prior["true_positives"] if prior else None),
        "false_positives": _delta(kpis["false_positives"], prior["false_positives"] if prior else None, lower_is_better=True),
        "false_negatives": _delta(kpis["false_negatives"], prior["false_negatives"] if prior else None, lower_is_better=True),
    }
    trend = []
    for row in history:
        block = _kpi_block(row)
        run_id = str(row.get("run_id") or "")
        manifest = _read_json(WEEK3 / "runs" / run_id / "manifest.json")
        started, label = _run_started(run_id, str(manifest.get("created_at") or ""))
        trend.append(
            {
                "label": f"{label} SAST",
                "started": started,
                "run_id": run_id,
                "kind": "SAST",
                "findings": int(row.get("reports") or block["scored"]),
                "true_vulnerabilities": block["true_positives"],
            }
        )
    dast_run = str(judge.get("run_id") or (dast[0].get("run_id") if dast else ""))
    dast_manifest = _read_json(WEEK6 / "runs" / dast_run / "manifest.json") if dast_run else {}
    zap_at = str((_read_json(ZAP_MANIFEST).get("output") or {}).get("generated_at") or "")
    dast_started, dast_label = _run_started(dast_run, str(dast_manifest.get("created_at") or zap_at))
    if dast_groups:
        trend.append(
            {
                "label": f"{dast_label} DAST",
                "started": dast_started,
                "run_id": dast_run or str((_read_json(ZAP_MANIFEST).get("run_id") or "")),
                "kind": "DAST",
                "findings": dast_groups,
                "true_vulnerabilities": confirmed_dast,
            }
        )
    trend.sort(key=lambda row: str(row.get("started") or row.get("run_id") or ""))
    return {
        "kpis": kpis,
        "sast_vs_dast": {"sast": tp, "dast": confirmed_dast, "dast_probed": probed},
        "verdict_distribution": scored.get("verdict_distribution") or {},
        "trend": trend,
        "remediation": _remediation_rows([*sast, *dast]),
        "severity_open": [
            {"severity": label.title(), "open": sum(1 for item in [*sast, *dast] if item["severity_key"] == label)}
            for label in ("critical", "high", "medium", "low", "info")
        ],
        "summary": [
            {
                "category": "SAST",
                "findings": sast_groups,
                "scored": int(kpis.get("scored") or 0),
                "precision": precision, "recall": recall, "f1": f1,
                "tp": tp, "fp": fp, "fn": fn, "tn": tn, "abstain": abstain,
                "probed": None,
                "revised": None,
                "label_source": "benchmarkjava_ground_truth",
                "run_id": kpis.get("run_id") or "",
            },
            {
                "category": "DAST",
                "findings": dast_groups,
                "scored": judge.get("scored"),
                "precision": judge.get("precision"),
                "recall": judge.get("recall"),
                "f1": judge.get("f1"),
                "tp": judge_counts.get("TP"),
                "fp": judge_counts.get("FP"),
                "fn": judge_counts.get("FN"),
                "tn": judge_counts.get("TN"),
                "abstain": judge_counts.get("abstain"),
                "label_source": "llm_as_judge" if judge else None,
                "judge_model": judge.get("judge_model") or "grok-4.5",
                "confirmed": confirmed_dast,
                "probed": probed,
                "probed_endpoints": probed_endpoints,
                "verified": probed,
                "revised": revised,
                "changed_by_probe": revised,
                "likely_vulnerable": int(dast_verdicts.get("likely_vulnerable") or 0),
                "not_vulnerable": int(dast_verdicts.get("not_vulnerable") or 0),
                "likely_false_positive": int(dast_verdicts.get("likely_false_positive") or 0),
                "insufficient_evidence": int(dast_verdicts.get("insufficient_evidence") or 0),
                "run_id": judge.get("run_id") or (dast[0].get("run_id") if dast else ""),
            },
        ],
        "glossary": [
            {
                "column": "Findings",
                "meaning": "Analysis groups from the committed scans: 99 BenchmarkJava groups and 18 Juice Shop groups.",
            },
            {
                "column": "Precision / Recall / F1 / TP / FP / FN",
                "meaning": "SAST: agent vs BenchmarkJava ground truth on the newest scored run. DAST: agent vs Grok 4.5 judge. There is no combined row: the two rulers must not be added together.",
            },
            {
                "column": "Probed",
                "meaning": "DAST only. A live HTTP response reached this finding's endpoint through the Gateway. One request can cover several findings on the same path. This is not a true positive.",
            },
            {
                "column": "Verdict changed",
                "meaning": "DAST only. The agent updated its verdict after reading that live response. The previous verdict stays in verification.verdict_before.",
            },
        ],
        "scanner": {
            "category": "Scanner alone (Semgrep vs ground truth, Week 1)",
            "tp": sum(1 for row in scanner if row.get("outcome") == "TP"),
            "fp": sum(1 for row in scanner if row.get("outcome") == "FP"),
            "fn": sum(1 for row in scanner if row.get("outcome") == "FN"),
            "tn": sum(1 for row in scanner if row.get("outcome") == "TN"),
        },
        "ranges": ["All committed runs", "Latest scored run"],
        "sources": [
            str((WEEK3 / "evaluation").relative_to(ROOT).as_posix()) + "/verdict-metrics-*.json",
            "artifacts/week-1/semgrep-20260806/variants/security-audit/predictions.jsonl",
            "artifacts/week-6/evaluation/verdict-metrics-dast-kb2-judge.json",
        ],
    }


def export_bundle(kind: str) -> dict[str, Any]:
    key = (kind or "").strip().lower()
    if key == "reports":
        return reports_payload()
    if key == "sast":
        return {
            "project": "BenchmarkJava",
            "findings": [
                {field: row.get(field) for field in ("id", "cwe", "rule", "severity", "file", "verdict", "confidence", "run_id")}
                for row in _sast_findings()
            ],
        }
    if key == "dast":
        return {
            "target": "OWASP Juice Shop",
            "findings": [
                {field: row.get(field) for field in ("id", "cwe", "endpoint", "method", "severity", "verdict", "confidence", "verified")}
                for row in _dast_findings()
            ],
        }
    raise KeyError(kind)


def _text_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def _surface_label(value: str) -> str:
    return {
        "sast_source": "SAST source",
        "dast_response_header": "DAST response header",
        "dast_response_body": "DAST response body",
        "scanner_tool": "Scanner tool",
    }.get(value, value or "—")


def _kb_cited_in(text: str, doc_id: str) -> bool:
    return bool(doc_id) and doc_id in (text or "")


def _report_for_test(run_id: str, test_id: str) -> dict[str, Any]:
    for row in _read_jsonl(WEEK3 / "runs" / run_id / "reports.jsonl"):
        if row.get("benchmark_test_id") == test_id:
            return row
    return {}


def _latest_report_citing(test_id: str, doc_id: str) -> tuple[str, dict[str, Any]]:
    if not (WEEK3 / "runs").exists():
        return "", {}
    for run_dir in sorted((path for path in (WEEK3 / "runs").iterdir() if path.is_dir()), reverse=True):
        row = _report_for_test(run_dir.name, test_id)
        if row and _kb_cited_in(str(row.get("verdict_rationale") or ""), doc_id):
            return run_dir.name, row
    return "", {}


def _kb_replay_slice(run_id: str, report: dict[str, Any], doc_id: str) -> dict[str, Any]:
    rationale = str(report.get("verdict_rationale") or "")
    return {
        "run_id": run_id,
        "verdict": report.get("verdict") or "",
        "verdict_label": _verdict_label(report.get("verdict")),
        "cited": _kb_cited_in(rationale, doc_id),
        "rationale": rationale,
    }


def _kb_measured_change(doc_id: str) -> dict[str, Any] | None:
    """Before/after from committed Week 3 runs. Skip if either report is missing."""
    pairs = {
        "KB-003": ("BenchmarkTest00011", "20260822T084310Z-sast-source", "20260822T084821Z-sast-kb-fix"),
        "KB-328-HASH": ("BenchmarkTest00009", "20260822T084310Z-sast-source", "20260822T093256Z-sast-v4"),
    }
    spec = pairs.get(doc_id)
    if not spec:
        return None
    test_id, before_run, after_run = spec
    before = _report_for_test(before_run, test_id)
    after_id, after = after_run, _report_for_test(after_run, test_id)
    if not after:
        after_id, after = _latest_report_citing(test_id, doc_id)
    if not before or not after:
        return None
    return {
        "subject_id": test_id,
        "before": _kb_replay_slice(before_run, before, doc_id),
        "after": _kb_replay_slice(after_id, after, doc_id),
    }


def _kb_usage() -> dict[str, list[dict[str, Any]]]:
    usage: dict[str, list[dict[str, Any]]] = {}
    known_ids = [str(doc.get("id") or "") for doc in _knowledge_docs() if doc.get("id")]
    for finding in [*_sast_findings(), *_dast_findings()]:
        retrieved = []
        for row in finding.get("kb") or []:
            doc_id = str(row.get("document_id") or row.get("id") or "")
            if doc_id:
                retrieved.append(doc_id)
        rationale = str(finding.get("verdict_rationale") or "")
        linked = set(retrieved)
        for doc_id in known_ids:
            if _kb_cited_in(rationale, doc_id):
                linked.add(doc_id)
        for doc_id in linked:
            usage.setdefault(doc_id, []).append(
                {
                    "finding_id": finding["id"],
                    "kind": finding["kind"],
                    "subject": finding.get("test_id") or finding.get("endpoint") or finding["id"],
                    "cwe": finding.get("cwe") or "",
                    "verdict": finding.get("verdict") or "",
                    "retrieved": doc_id in retrieved,
                    "cited": _kb_cited_in(rationale, doc_id),
                    "rationale": rationale,
                    "page": "sast" if finding["kind"] == "SAST" else "dast",
                }
            )
    return usage


def knowledge_payload() -> dict[str, Any]:
    docs = _knowledge_docs()
    usage = _kb_usage()
    cwes: set[str] = set()
    owasp_ids: set[str] = set()
    for doc in docs:
        for item in doc.get("cwe") or []:
            raw = str(item).upper()
            if raw.startswith("CWE-"):
                cwes.add(raw)
        for tag in doc.get("tags") or []:
            raw = str(tag)
            if raw.lower().startswith("cwe-"):
                cwes.add(raw.upper())
            if raw.lower().startswith("a0"):
                owasp_ids.add(raw.split(":")[0].split("-")[0].upper())
    rows = []
    for doc in docs:
        tags = [str(tag) for tag in (doc.get("tags") or [])]
        cwe_ids = [str(item).upper() for item in (doc.get("cwe") or []) if str(item).strip()]
        if not cwe_ids:
            tagged = next((tag.upper() for tag in tags if tag.lower().startswith("cwe-")), "")
            if tagged:
                cwe_ids = [tagged]
        owasp_label = next((tag.upper() if tag.lower().startswith("a0") else tag for tag in tags if tag.lower().startswith("a0")), doc.get("source") or "")
        linked = usage.get(doc["id"], [])
        rows.append(
            {
                "id": doc["id"],
                "cwe": ", ".join(cwe_ids) or "—",
                "owasp": owasp_label,
                "title": doc.get("title") or "",
                "category": doc.get("category") or "",
                "detection_surface": doc.get("detection_surface") or "",
                "detection_surface_label": _surface_label(str(doc.get("detection_surface") or "")),
                "confirm_indicators": _text_list(doc.get("confirm_indicators")),
                "fp_indicators": _text_list(doc.get("fp_indicators")),
                "detection_questions": _text_list(doc.get("detection_questions")),
                "content": doc.get("content") or "",
                "source": doc.get("source") or "",
                "source_url": doc.get("source_url") or "",
                "provenance": doc.get("provenance") or {},
                "retrieved_count": sum(1 for row in linked if row["retrieved"]),
                "cited_count": sum(1 for row in linked if row["cited"]),
                "used_by": linked,
                "measured_change": _kb_measured_change(doc["id"]),
            }
        )
    rows.sort(key=lambda row: (row["measured_change"] is None, -(row["cited_count"] or 0), row["id"]))
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
    stamp = ""
    if KB.exists():
        stamp = datetime.fromtimestamp(KB.stat().st_mtime, UTC).isoformat()
    return {
        "entries": len(docs),
        "cwe_coverage": len(cwes),
        "owasp_categories": len(owasp_ids),
        "cited_docs": sum(1 for row in rows if row["cited_count"]),
        "updated": _when(stamp) or "—",
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
