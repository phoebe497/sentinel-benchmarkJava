"""Pipeline invariants, including the artifact round-trip."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

from sentinel_benchmark.indexer import build
from sentinel_benchmark.search import search_index

ROOT = Path(__file__).resolve().parents[1]


ALLOWED_DATASETS = {"owasp-benchmark-java", "juice-shop-dast"}


def test_manifest_holds_only_authorized_datasets() -> None:
    sources = json.loads((ROOT / "configs" / "sources.json").read_text(encoding="utf-8"))
    assert {item["dataset"] for item in sources} <= ALLOWED_DATASETS
    assert sum(item["dataset"] == "owasp-benchmark-java" for item in sources) == 3
    assert all("webgoat" not in json.dumps(item).lower() for item in sources)
    assert all({"id", "dataset", "tool", "path", "run_id"} <= set(item) for item in sources)


def test_build_and_search(tmp_path: Path) -> None:
    db = tmp_path / "sentinel.db"
    result = build(ROOT / "configs" / "sources.json", db, ROOT / "datasets" / "knowledge" / "security-topics.jsonl")
    assert result["knowledge"] == 38
    with sqlite3.connect(db) as conn:
        counts = dict(conn.execute("SELECT dataset, COUNT(*) FROM findings GROUP BY dataset").fetchall())
        # SAST reads committed scanner artifacts, so its count is exact. DAST
        # crawls a live SPA and its alert count moves between runs, so pin only
        # that the source produced observations at all.
        assert counts["owasp-benchmark-java"] == 372
        assert counts["juice-shop-dast"] > 0
        assert set(counts) <= ALLOWED_DATASETS
        assert result["findings"] == sum(counts.values())
    hits = search_index(db, "CWE-89", "findings", 10, "owasp-benchmark-java")
    assert hits
    assert all(hit["dataset"] == "owasp-benchmark-java" for hit in hits)


def test_ground_truth_manifest() -> None:
    manifest = json.loads((ROOT / "datasets" / "manifests" / "benchmarkjava-first-100.json").read_text(encoding="utf-8"))
    assert manifest["count"] == 100
    assert manifest["positive"] + manifest["negative"] == 100
    assert manifest["ground_truth_joined_after_scanning"] is True


def test_submitted_reports_are_immutable() -> None:
    lock = json.loads((ROOT / "reports" / "locked.json").read_text(encoding="utf-8"))
    assert lock["algorithm"] == "sha256-utf8-lf"
    for relative_path, expected in lock["files"].items():
        content = (ROOT / relative_path).read_text(encoding="utf-8").replace("\r\n", "\n")
        actual = hashlib.sha256(content.encode("utf-8")).hexdigest()
        assert actual == expected, f"submitted report changed: {relative_path}"


def test_a_record_containing_an_exotic_line_separator_survives_a_round_trip(tmp_path) -> None:
    """Regression: a model emitted U+2028 and it shredded a run's reports.jsonl.

    U+2028 is legal inside a JSON string, so `json.dumps` left it raw, and
    `str.splitlines()` in the reader treated it as a newline — turning one
    record into two invalid halves and making the whole run unreadable.
    """
    from sentinel_benchmark.analysis.artifacts import read_jsonl, write_jsonl

    rows = [
        {"id": "AR-1", "explanation": "first part\u2028second part", "n": 1},
        {"id": "AR-2", "explanation": "para\u2029break and \u0085next", "n": 2},
    ]
    path = tmp_path / "reports.jsonl"
    write_jsonl(path, rows)

    raw = path.read_text(encoding="utf-8")
    assert len(raw.splitlines()) == 2, "a record must stay on one physical line for any reader"
    assert "\u2028" not in raw and "\u2029" not in raw and "\u0085" not in raw
    # The value itself is preserved exactly; only its encoding on disk changed.
    assert read_jsonl(path) == rows


def test_sse_frames_are_split_only_on_real_line_terminators() -> None:
    # Same character on the live path: the half after a U+2028 break would not
    # start with "data:" and would be silently dropped, truncating the answer.
    from sentinel_benchmark.analysis.providers import parse_chat_response

    class _Response:
        status_code = 200
        headers = {"content-type": "text/event-stream"}
        text = (
            'data: {"choices":[{"delta":{"content":"before\\u2028after"}}]}\r\n'
            "data: [DONE]\r\n"
        )

    body = parse_chat_response(_Response())
    assert "before\u2028after" in json.dumps(body, ensure_ascii=False)
