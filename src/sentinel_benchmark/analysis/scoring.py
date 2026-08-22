"""Score verdicts against BenchmarkJava ground truth.

Two rules govern this module, both from AGENTS.md:

* Ground truth is joined **after** the run. It never enters a prompt, and this
  module only ever reads reports that are already written to disk.
* Abstentions are counted separately. Folding ``insufficient_evidence`` into
  the false-positive or false-negative column would let the agent improve its
  precision by refusing to answer, which is exactly the wrong incentive.

A report is scored only when the corpus knows the answer, so DAST reports are
counted as ``no_ground_truth`` rather than being scored against a guess.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from .models import verdict_stance

Outcome = str  # TP | FP | FN | TN | abstain | no_ground_truth


def load_ground_truth(predictions_path: Path) -> dict[str, bool]:
    """Map benchmark test id to whether the corpus says it is really vulnerable."""
    truth: dict[str, bool] = {}
    for line in predictions_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        value = row.get("ground_truth")
        if isinstance(value, bool):
            truth[str(row["test_id"])] = value
    return truth


def outcome_for(verdict: str, ground_truth: bool | None) -> Outcome:
    """The confusion-matrix cell for one verdict, or why it has none."""
    if ground_truth is None:
        return "no_ground_truth"
    stance = verdict_stance(verdict)
    if stance == "abstain":
        return "abstain"
    said_vulnerable = stance == "vulnerable"
    if said_vulnerable and ground_truth:
        return "TP"
    if said_vulnerable and not ground_truth:
        return "FP"
    if not said_vulnerable and ground_truth:
        return "FN"
    return "TN"


def score_reports(reports: Iterable[dict[str, Any]], truth: dict[str, bool]) -> dict[str, Any]:
    """Per-report outcomes plus the aggregate, for one run."""
    rows: list[dict[str, Any]] = []
    for report in reports:
        test_id = str(report.get("benchmark_test_id") or "")
        ground_truth = truth.get(test_id) if test_id else None
        verdict = str(report.get("verdict") or "")
        rows.append(
            {
                "report_id": report.get("report_id"),
                "analysis_group_id": report.get("analysis_group_id"),
                "dataset": report.get("dataset") or "owasp-benchmark-java",
                "subject_id": report.get("subject_id") or test_id,
                "verdict": verdict,
                "stance": verdict_stance(verdict),
                "ground_truth": ground_truth,
                "outcome": outcome_for(verdict, ground_truth),
                # Present only when a probe ran, so a reader can tell which
                # verdicts were checked against a live response.
                "verified": bool((report.get("verification") or {}).get("reached_target")),
                "verdict_changed_by_probe": bool((report.get("verification") or {}).get("changed")),
            }
        )
    counts = {key: sum(1 for row in rows if row["outcome"] == key) for key in ("TP", "FP", "FN", "TN", "abstain", "no_ground_truth")}
    scored = counts["TP"] + counts["FP"] + counts["FN"] + counts["TN"]
    precision = counts["TP"] / (counts["TP"] + counts["FP"]) if counts["TP"] + counts["FP"] else None
    recall = counts["TP"] / (counts["TP"] + counts["FN"]) if counts["TP"] + counts["FN"] else None
    f1 = (2 * precision * recall / (precision + recall)) if precision and recall else None
    return {
        "schema_version": "1.0",
        "reports": len(rows),
        "scored": scored,
        "counts": counts,
        # Share of scoreable reports where the agent declined to conclude. High
        # abstention with high precision is not the same achievement as high
        # precision on everything, so both numbers are always reported.
        "abstention_rate": round(counts["abstain"] / (scored + counts["abstain"]), 4) if scored + counts["abstain"] else None,
        "precision": round(precision, 4) if precision is not None else None,
        "recall": round(recall, 4) if recall is not None else None,
        "f1": round(f1, 4) if f1 is not None else None,
        "accuracy": round((counts["TP"] + counts["TN"]) / scored, 4) if scored else None,
        "verdict_distribution": _distribution(rows),
        "outcomes": rows,
    }


def _distribution(rows: list[dict[str, Any]]) -> dict[str, int]:
    distribution: dict[str, int] = {}
    for row in rows:
        distribution[row["verdict"]] = distribution.get(row["verdict"], 0) + 1
    return dict(sorted(distribution.items()))


def false_cases(scored: dict[str, Any], reports: Iterable[dict[str, Any]], limit: int = 20) -> list[dict[str, Any]]:
    """The FP and FN rows with their rationale, for the improvement section.

    A count tells a mentor how well the agent did; these rows tell them why it
    was wrong, which is the part that suggests what to change.
    """
    by_id = {str(report.get("report_id")): report for report in reports}
    cases = []
    for row in scored["outcomes"]:
        if row["outcome"] not in {"FP", "FN"}:
            continue
        report = by_id.get(str(row["report_id"]), {})
        cases.append(
            {
                "outcome": row["outcome"],
                "subject_id": row["subject_id"],
                "expected_cwe": report.get("expected_cwe"),
                "verdict": row["verdict"],
                "ground_truth": row["ground_truth"],
                "verdict_rationale": report.get("verdict_rationale"),
                "false_positive_indicators": report.get("false_positive_indicators") or [],
                "limitations": report.get("limitations") or [],
            }
        )
    return cases[:limit]
