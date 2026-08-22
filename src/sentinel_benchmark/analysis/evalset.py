"""Grade the agent against expected answers written by hand.

The BenchmarkJava corpus supplies a verdict for its own 100 cases and nothing
else. It says nothing about a Juice Shop endpoint, nothing about whether an
abstention was the right call, and nothing about whether the rationale named the
detail that actually decides the case. This module covers that gap with a small
set of cases whose expected answers were written by reading the code or the
response — ``datasets/evaluation/week6-eval-cases.jsonl``.

Three things it grades, kept separate on purpose:

* **Stance** — vulnerable / not vulnerable / abstain. This is the confusion
  matrix, and abstentions stay in their own column so refusing to answer can
  never look like precision.
* **Verdict** — whether the exact label is one this case accepts. A case can be
  graded right on stance while the label is coarser than it should be.
* **Reasoning** — whether the rationale mentions the detail the case turns on.
  A right answer for the wrong reason is recorded as such rather than counted as
  a clean pass, because it will not survive the next case.

The expected answers are an opinion, held to and stated, not ground truth. When
the agent disagrees, the case file has to defend itself; ``deciding_evidence``
is there so that argument can be had with a specific line rather than a feeling.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from .models import verdict_stance


def load_cases(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").split("\n") if line.strip()]


def _matches(case: dict[str, Any], report: dict[str, Any]) -> bool:
    """Whether this report is the one the case is about.

    A CWE of ``null`` in the case means "the group with no reported CWE", which
    is a real state in the DAST data, so it is matched explicitly rather than
    treated as a wildcard.
    """
    subject = case["subject"]
    if subject["kind"] == "benchmark_test":
        if str(report.get("benchmark_test_id") or "") != subject["id"]:
            return False
        return subject.get("cwe") in (None, report.get("expected_cwe"))
    if str(report.get("subject_id") or "") != subject["id"]:
        return False
    reported = list(report.get("reported_cwes") or [])
    return not reported if subject.get("cwe") is None else subject["cwe"] in reported


def _stage_of(report: dict[str, Any]) -> str:
    verification = report.get("verification") or {}
    if not verification:
        return "static"
    return "post_probe" if verification.get("reached_target") else "pre_probe"


def find_report(case: dict[str, Any], reports: Iterable[dict[str, Any]]) -> dict[str, Any] | None:
    """The report this case grades, preferring the stage the case asks about.

    EV-06 and EV-07 are the same finding before and after a probe. When only one
    stage exists, it is still graded, and ``stage_mismatch`` records that the
    comparison was not the one the case intended.
    """
    candidates = [report for report in reports if _matches(case, report)]
    if not candidates:
        return None
    wanted = case.get("stage", "static")
    if wanted == "pre_probe":
        # The pre-probe verdict is preserved inside the verification record even
        # after a probe overwrote the top-level one, so this case stays gradable
        # on a verified run instead of silently comparing the wrong number.
        for report in candidates:
            verification = report.get("verification") or {}
            if verification.get("verdict_before"):
                restored = {**report, "verdict": verification["verdict_before"], "_graded_stage": "pre_probe"}
                return restored
    for report in candidates:
        if _stage_of(report) == wanted:
            return {**report, "_graded_stage": wanted}
    return {**candidates[0], "_graded_stage": _stage_of(candidates[0])}


def grade(case: dict[str, Any], report: dict[str, Any] | None) -> dict[str, Any]:
    """One row: what was expected, what came back, and how it is counted."""
    if report is None:
        return {
            "case_id": case["case_id"],
            "subject_id": case["subject"]["id"],
            "cwe": case["subject"].get("cwe"),
            "expected_stance": case["expected_stance"],
            "outcome": "missing_report",
            "note": "No report in this run covers the case subject.",
        }
    verdict = str(report.get("verdict") or "")
    stance = verdict_stance(verdict)
    expected = case["expected_stance"]
    rationale = " ".join(
        str(part)
        for part in (report.get("verdict_rationale"), *(report.get("false_positive_indicators") or []), *(report.get("limitations") or []))
        if part
    ).lower()
    mentioned = [term for term in case.get("expected_rationale_mentions") or [] if term.lower() in rationale]
    return {
        "case_id": case["case_id"],
        "subject_id": case["subject"]["id"],
        "cwe": case["subject"].get("cwe"),
        "graded_stage": report.get("_graded_stage"),
        "stage_mismatch": report.get("_graded_stage") != case.get("stage", "static"),
        "expected_stance": expected,
        "expected_verdict": case.get("expected_verdict") or [],
        "verdict": verdict,
        "stance": stance,
        "outcome": _outcome(expected, stance),
        "verdict_accepted": verdict in (case.get("expected_verdict") or []),
        "reasoning_matched": bool(mentioned) if case.get("expected_rationale_mentions") else None,
        "reasoning_terms_found": mentioned,
        "verdict_rationale": report.get("verdict_rationale"),
    }


def _outcome(expected: str, stance: str) -> str:
    if expected == "abstain":
        return "abstain_correct" if stance == "abstain" else "abstain_missed"
    if stance == "abstain":
        return "abstain_unexpected"
    if expected == "vulnerable":
        return "TP" if stance == "vulnerable" else "FN"
    return "TN" if stance == "not_vulnerable" else "FP"


CELLS = ("TP", "FP", "FN", "TN", "abstain_correct", "abstain_missed", "abstain_unexpected", "missing_report")


def score_cases(cases: list[dict[str, Any]], reports: list[dict[str, Any]]) -> dict[str, Any]:
    rows = [grade(case, find_report(case, reports)) for case in cases]
    counts = {cell: sum(1 for row in rows if row["outcome"] == cell) for cell in CELLS}
    decided = counts["TP"] + counts["FP"] + counts["FN"] + counts["TN"]
    precision = counts["TP"] / (counts["TP"] + counts["FP"]) if counts["TP"] + counts["FP"] else None
    recall = counts["TP"] / (counts["TP"] + counts["FN"]) if counts["TP"] + counts["FN"] else None
    graded = [row for row in rows if row["outcome"] != "missing_report"]
    return {
        "schema_version": "1.0",
        "cases": len(cases),
        "counts": counts,
        "precision": round(precision, 4) if precision is not None else None,
        "recall": round(recall, 4) if recall is not None else None,
        "f1": round(2 * precision * recall / (precision + recall), 4) if precision and recall else None,
        "stance_accuracy": round((counts["TP"] + counts["TN"] + counts["abstain_correct"]) / len(cases), 4) if cases else None,
        "verdict_exact_rate": round(sum(1 for row in graded if row["verdict_accepted"]) / len(graded), 4) if graded else None,
        # Right answer, wrong reason: the case was counted correct but the
        # rationale never named the detail it turns on.
        "right_for_the_wrong_reason": [
            row["case_id"]
            for row in graded
            if row["outcome"] in {"TP", "TN", "abstain_correct"} and row["reasoning_matched"] is False
        ],
        "decided": decided,
        "results": rows,
    }


def failures(scored: dict[str, Any], cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The rows worth a paragraph in the report, with the case's own argument."""
    by_id = {case["case_id"]: case for case in cases}
    out = []
    for row in scored["results"]:
        if row["outcome"] in {"TP", "TN", "abstain_correct"} and row.get("reasoning_matched") is not False:
            continue
        case = by_id[row["case_id"]]
        out.append(
            {
                "case_id": row["case_id"],
                "outcome": row["outcome"],
                "subject_id": row["subject_id"],
                "expected_stance": row["expected_stance"],
                "agent_verdict": row.get("verdict"),
                "agent_rationale": row.get("verdict_rationale"),
                "why_the_expected_answer": case["deciding_evidence"],
                "reasoning_matched": row.get("reasoning_matched"),
            }
        )
    return out
