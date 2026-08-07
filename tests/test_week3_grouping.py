from __future__ import annotations

import sqlite3
from pathlib import Path

from sentinel_benchmark.analysis.grouping import group_checksum, load_groups
from sentinel_benchmark.indexer import build

ROOT = Path(__file__).resolve().parents[1]
PREDICTIONS = ROOT / "artifacts/week-1/semgrep-20260806/variants/security-audit/predictions.jsonl"


def test_deterministic_grouping_and_assignment(tmp_path: Path) -> None:
    db = tmp_path / "sentinel.db"
    build(ROOT / "configs/sources.json", db, ROOT / "datasets/knowledge/security-topics.jsonl")
    groups = load_groups(db, PREDICTIONS)
    again = load_groups(db, PREDICTIONS)
    assigned = [item for group in groups for item in group.observation_ids]
    with sqlite3.connect(db) as conn:
        ids = {row[0] for row in conn.execute("SELECT observation_id FROM findings")}
    assert len(groups) == 99
    assert len(assigned) == len(set(assigned)) == 372
    assert set(assigned) == ids
    assert group_checksum(groups) == group_checksum(again)
    assert {group.benchmark_test_id for group in groups} == {f"BenchmarkTest{i:05d}" for i in range(1, 101)} - {"BenchmarkTest00069"}
    assert all(len({item.observation_id for item in group.evidence_items}) == len(group.observation_ids) for group in groups)
    assert all(":" not in item.file_or_url[:3] for group in groups for item in group.evidence_items)
