from __future__ import annotations

import json
from pathlib import Path

from sentinel_benchmark.agent_reports import generate_report, reports_to_jsonl, validate_report
from sentinel_benchmark.indexer import build
from sentinel_benchmark.workspace import (
    filter_groups,
    load_analysis_groups,
    retrieval_evaluation,
    retrieve_knowledge,
)

ROOT = Path(__file__).resolve().parents[1]
PREDICTIONS = ROOT / "artifacts" / "week-1" / "semgrep-20260806" / "variants" / "security-audit" / "predictions.jsonl"


def _database(tmp_path: Path) -> Path:
    db = tmp_path / "sentinel.db"
    build(ROOT / "configs" / "sources.json", db, ROOT / "datasets" / "knowledge" / "security-topics.jsonl")
    return db


def test_analysis_projection_groups_all_observations(tmp_path: Path) -> None:
    groups = load_analysis_groups(_database(tmp_path), PREDICTIONS)
    assert len(groups) == 99
    assert sum(group["observation_count"] for group in groups) == 372
    assert len({group["canonical_id"] for group in groups}) == len(groups)
    first = next(group for group in groups if group["test_id"] == "BenchmarkTest00001")
    assert first["cwe"] == "CWE-22"
    assert first["ground_truth"] is True
    assert len(first["tools"]) == 3


def test_group_filters_and_retrieval(tmp_path: Path) -> None:
    db = _database(tmp_path)
    groups = load_analysis_groups(db, PREDICTIONS)
    result = filter_groups(groups, query="CWE-89", ground_truth="vulnerable")
    assert result
    assert all(group["cwe"] == "CWE-89" for group in result)
    documents = retrieve_knowledge(db, result[0], 3)
    assert documents
    assert any("cwe-89" in str(document["tags"]).lower() for document in documents)


def test_agent_report_contract_and_jsonl(tmp_path: Path) -> None:
    db = _database(tmp_path)
    group = next(
        group
        for group in load_analysis_groups(db, PREDICTIONS)
        if group["cwe"] == "CWE-89" and len(group["tools"]) >= 2
    )
    report = generate_report(group, retrieve_knowledge(db, group, 3), run_id="TEST-RUN")
    assert validate_report(report) == []
    assert report["sources"]["kb_document_ids"]
    assert len(report["sources"]["observation_ids"]) == group["observation_count"]
    assert report["review_status"] == "Needs review"
    assert report["model"] == "grounded-template-v1"
    exported = reports_to_jsonl([report])
    assert json.loads(exported)["report_id"] == report["report_id"]


def test_retrieval_evaluation_is_separate_from_agent_quality(tmp_path: Path) -> None:
    db = _database(tmp_path)
    groups = load_analysis_groups(db, PREDICTIONS)
    result = retrieval_evaluation(db, groups, 3)
    assert result["evaluated_groups"] > 0
    assert result["top_k"] == 3
    assert 0 <= result["hit_rate"] <= 1
