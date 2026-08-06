from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from sentinel_benchmark.indexer import build
from sentinel_benchmark.search import search_index

ROOT = Path(__file__).resolve().parents[1]


def test_manifest_is_benchmark_only() -> None:
    sources = json.loads((ROOT / "configs" / "sources.json").read_text(encoding="utf-8"))
    assert len(sources) == 3
    assert {item["dataset"] for item in sources} == {"owasp-benchmark-java"}
    assert all("webgoat" not in json.dumps(item).lower() for item in sources)


def test_build_and_search(tmp_path: Path) -> None:
    db = tmp_path / "sentinel.db"
    result = build(ROOT / "configs" / "sources.json", db, ROOT / "datasets" / "knowledge" / "security-topics.jsonl")
    assert result == {"findings": 372, "knowledge": 12}
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 372
        assert conn.execute("SELECT COUNT(DISTINCT dataset) FROM findings").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(DISTINCT tool) FROM findings").fetchone()[0] == 3
    hits = search_index(db, "CWE-89", "findings", 10, "owasp-benchmark-java")
    assert hits
    assert all(hit["dataset"] == "owasp-benchmark-java" for hit in hits)


def test_ground_truth_manifest() -> None:
    manifest = json.loads((ROOT / "datasets" / "manifests" / "benchmarkjava-first-100.json").read_text(encoding="utf-8"))
    assert manifest["count"] == 100
    assert manifest["positive"] + manifest["negative"] == 100
    assert manifest["ground_truth_joined_after_scanning"] is True
