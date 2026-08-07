from __future__ import annotations

import json
from pathlib import Path

from sentinel_benchmark.indexer import build
from sentinel_benchmark.workspace import filter_groups, load_analysis_groups, retrieve_knowledge

ROOT = Path(__file__).resolve().parents[1]
PREDICTIONS = ROOT / "artifacts/week-1/semgrep-20260806/variants/security-audit/predictions.jsonl"


def database(tmp_path: Path) -> Path:
    db = tmp_path / "sentinel.db"
    build(ROOT / "configs/sources.json", db, ROOT / "datasets/knowledge/security-topics.jsonl")
    return db


def test_workspace_projection_has_no_ground_truth(tmp_path: Path) -> None:
    groups = load_analysis_groups(database(tmp_path), PREDICTIONS)
    assert len(groups) == 99
    assert sum(len(group["observation_ids"]) for group in groups) == 372
    assert all(group["analysis_group_id"].startswith("AG-") for group in groups)
    assert all(group["grouping_mode"] == "benchmark_assisted" for group in groups)
    assert "ground_truth" not in json.dumps(groups).lower()


def test_group_filters_and_cwe89_retrieval(tmp_path: Path) -> None:
    db = database(tmp_path)
    groups = load_analysis_groups(db, PREDICTIONS)
    result = filter_groups(groups, query="CWE-89")
    assert result and all(group["expected_cwe"] == "CWE-89" for group in result)
    documents = retrieve_knowledge(db, result[0], 3)
    assert any("cwe-89" in str(document["tags"]).lower() for document in documents)
