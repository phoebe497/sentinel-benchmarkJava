"""LLM-as-judge labels for DAST, joined only after the agent reports exist.

Juice Shop ships no corpus ground truth. A separate model reads a redacted
packet (alert + probe observations, never the agent's verdict) and emits one of
``vulnerable``, ``not_vulnerable``, ``insufficient``. Python then applies the
same confusion-matrix policy as :mod:`scoring`: abstentions stay out of
precision, and a judge abstention is ``no_ground_truth`` rather than a guess.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from sentinel_benchmark.guardrails.redaction import redact

from .models import verdict_stance
from .scoring import outcome_for

JUDGE_LABELS = ("vulnerable", "not_vulnerable", "insufficient")


def build_packets(reports: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """One judge packet per report. Agent verdicts are deliberately omitted."""
    packets = []
    for index, report in enumerate(reports, start=1):
        evidence = report.get("evidence") or []
        first = evidence[0] if evidence else {}
        verification = report.get("verification") or {}
        packets.append(
            {
                "case_id": f"DJ-{index:02d}",
                "report_id": report.get("report_id"),
                "analysis_group_id": report.get("analysis_group_id"),
                "subject_id": report.get("subject_id") or first.get("file_or_url") or "",
                "reported_cwes": list(report.get("reported_cwes") or []),
                "category": report.get("category") or "",
                "vulnerability_name": report.get("vulnerability_name") or first.get("title") or "",
                "severity_assessment": report.get("severity_assessment") or "",
                "alert_title": first.get("title") or "",
                "alert_url": first.get("file_or_url") or "",
                "alert_excerpt": redact(str(first.get("excerpt") or ""))[:500],
                "observation_id": first.get("observation_id") or "",
                "probe_reached": bool(verification.get("reached_target")),
                "probe_status": verification.get("status"),
                "probe_unverified_reason": verification.get("unverified_reason") or "",
                "probe_observed": list(verification.get("observed") or []),
            }
        )
    return packets


def load_labels(path: Path) -> list[dict[str, Any]]:
    payload = path.read_text(encoding="utf-8")
    if path.suffix == ".jsonl":
        rows = []
        for line in payload.split("\n"):
            if line.strip():
                rows.append(json.loads(line))
        if rows and "labels" in rows[0]:
            return list(rows[0]["labels"])
        return rows
    data = json.loads(payload)
    if isinstance(data, dict):
        return list(data.get("labels") or [])
    if isinstance(data, list):
        return data
    raise ValueError("Judge labels must be a JSON object with 'labels' or a JSONL of label rows")


def _truth_from_label(label: str | None) -> bool | None:
    if label == "vulnerable":
        return True
    if label == "not_vulnerable":
        return False
    return None


def score_against_labels(
    reports: Iterable[dict[str, Any]],
    labels: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    """Score agent verdicts against judge labels using the SAST outcome policy."""
    by_report = {str(row.get("report_id")): row for row in labels if row.get("report_id")}
    by_case = {str(row.get("case_id")): row for row in labels if row.get("case_id")}
    packets = {str(packet["report_id"]): packet for packet in build_packets(reports)}
    rows: list[dict[str, Any]] = []
    for packet in packets.values():
        report_id = str(packet["report_id"])
        label_row = by_report.get(report_id) or by_case.get(str(packet["case_id"])) or {}
        raw_label = str(label_row.get("label") or "").strip().lower()
        if raw_label not in JUDGE_LABELS:
            raw_label = ""
        rows.append(
            {
                "report_id": report_id,
                "analysis_group_id": packet.get("analysis_group_id"),
                "case_id": packet.get("case_id"),
                "dataset": "juice-shop-dast",
                "subject_id": packet.get("subject_id"),
                "judge_label": raw_label or None,
                "judge_confidence": label_row.get("confidence"),
                "judge_rationale": label_row.get("rationale") or "",
            }
        )
    report_by_id = {str(report.get("report_id")): report for report in reports}
    for row in rows:
        report = report_by_id.get(str(row["report_id"]), {})
        verdict = str(report.get("verdict") or "")
        row["verdict"] = verdict
        row["stance"] = verdict_stance(verdict)
        row["ground_truth"] = _truth_from_label(row["judge_label"])
        row["outcome"] = outcome_for(verdict, row["ground_truth"])
        row["verified"] = bool((report.get("verification") or {}).get("reached_target"))
        row["verdict_changed_by_probe"] = bool((report.get("verification") or {}).get("changed"))
    counts = {
        key: sum(1 for row in rows if row["outcome"] == key)
        for key in ("TP", "FP", "FN", "TN", "abstain", "no_ground_truth")
    }
    scored = counts["TP"] + counts["FP"] + counts["FN"] + counts["TN"]
    precision = counts["TP"] / (counts["TP"] + counts["FP"]) if counts["TP"] + counts["FP"] else None
    recall = counts["TP"] / (counts["TP"] + counts["FN"]) if counts["TP"] + counts["FN"] else None
    f1 = (2 * precision * recall / (precision + recall)) if precision and recall else None
    return {
        "schema_version": "1.0",
        "method": "llm_as_judge",
        "reports": len(rows),
        "scored": scored,
        "counts": counts,
        "abstention_rate": round(counts["abstain"] / (scored + counts["abstain"]), 4) if scored + counts["abstain"] else None,
        "precision": round(precision, 4) if precision is not None else None,
        "recall": round(recall, 4) if recall is not None else None,
        "f1": round(f1, 4) if f1 is not None else None,
        "accuracy": round((counts["TP"] + counts["TN"]) / scored, 4) if scored else None,
        "verdict_distribution": _distribution(rows, "verdict"),
        "judge_distribution": _distribution(rows, "judge_label"),
        "outcomes": rows,
    }


def _distribution(rows: list[dict[str, Any]], key: str) -> dict[str, int]:
    distribution: dict[str, int] = {}
    for row in rows:
        value = str(row.get(key) or "unlabelled")
        distribution[value] = distribution.get(value, 0) + 1
    return dict(sorted(distribution.items()))
