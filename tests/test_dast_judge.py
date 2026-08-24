"""LLM-as-judge labels are joined after the DAST reports exist."""

from __future__ import annotations

from pathlib import Path

from sentinel_benchmark.analysis.artifacts import read_jsonl
from sentinel_benchmark.analysis.judge import build_packets, load_labels, score_against_labels

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "artifacts/week-6/runs/20260822T085445Z-dast-kb2/reports.jsonl"
LABELS = ROOT / "artifacts/week-6/evaluation/dast-llm-judge-labels.json"
METRICS = ROOT / "artifacts/week-6/evaluation/verdict-metrics-dast-kb2-judge.json"


def test_packets_omit_the_agent_verdict() -> None:
    packets = build_packets(read_jsonl(REPORTS))
    assert len(packets) == 18
    for packet in packets:
        blob = " ".join(str(value) for value in packet.values()).lower()
        assert "verdict" not in packet
        assert "confirmed_vulnerable" not in blob
        assert "likely_vulnerable" not in blob
        assert "insufficient_evidence" not in blob


def test_committed_judge_labels_cover_every_report() -> None:
    reports = read_jsonl(REPORTS)
    labels = load_labels(LABELS)
    assert {row["report_id"] for row in labels} == {row["report_id"] for row in reports}
    assert {row["label"] for row in labels} <= {"vulnerable", "not_vulnerable", "insufficient"}


def test_judge_metrics_match_the_scored_artifact() -> None:
    reports = read_jsonl(REPORTS)
    scored = score_against_labels(reports, load_labels(LABELS))
    assert scored["precision"] == 0.75
    assert scored["recall"] == 1.0
    assert scored["counts"]["TP"] == 3
    assert scored["counts"]["FP"] == 1
    assert scored["counts"]["FN"] == 0
    assert scored["scored"] == 4
    committed = METRICS.read_text(encoding="utf-8")
    assert '"precision": 0.75' in committed
    assert '"judge_model": "grok-4.5"' in committed
