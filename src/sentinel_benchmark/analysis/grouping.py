from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

from .models import AnalysisGroup, EvidenceItem

TEST_ID = re.compile(r"BenchmarkTest\d{5}")


def load_benchmark_metadata(predictions_path: Path) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for line in predictions_path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            row = json.loads(line)
            result[row["test_id"]] = {
                "expected_cwe": f"CWE-{int(row['expected_cwe'])}",
                "category": str(row.get("category") or ""),
            }
    return result


def _test_id(row: dict[str, Any]) -> str | None:
    for key in ("file_or_url", "title", "description"):
        match = TEST_ID.search(str(row.get(key) or ""))
        if match:
            return match.group(0)
    return None


def _decode(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if item]
    try:
        value = json.loads(value or "[]")
    except (TypeError, json.JSONDecodeError):
        pass
    return [str(item) for item in value] if isinstance(value, list) else ([str(value)] if value else [])


def _public_location(value: Any) -> str:
    """Remove machine-specific scanner staging prefixes from published evidence."""
    location = str(value or "unknown").replace("\\", "/")
    for marker in ("vendor/BenchmarkJava/", "src/main/java/"):
        if marker in location:
            return location[location.rfind(marker):]
    return location.rsplit("/", 1)[-1]


def stable_group_id(test_id: str, expected_cwe: str) -> str:
    digest = hashlib.sha256(
        f"owasp-benchmark-java|{test_id}|{expected_cwe}|analysis-v1".encode()
    ).hexdigest()[:16]
    return f"AG-{digest}"


def group_observations(rows: Iterable[dict[str, Any]], metadata: dict[str, dict[str, str]]) -> list[AnalysisGroup]:
    buckets: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        test_id = _test_id(row)
        if test_id and test_id in metadata:
            buckets[(test_id, metadata[test_id]["expected_cwe"])].append(row)
    groups: list[AnalysisGroup] = []
    for (test_id, expected_cwe), items in sorted(buckets.items()):
        evidence = []
        for row in sorted(items, key=lambda value: value["observation_id"]):
            location = _public_location(row.get("file_or_url"))
            excerpt = str(row.get("evidence") or row.get("description") or "")[:1600]
            evidence.append(EvidenceItem(
                observation_id=row["observation_id"], tool=row["tool"], file_or_url=location,
                line_start=row.get("line_start"), line_end=row.get("line_end"),
                title=str(row.get("title") or "Security finding"), severity=str(row.get("severity") or "info").lower(),
                reported_cwe=_decode(row.get("cwe")), excerpt=excerpt,
            ))
        groups.append(AnalysisGroup(
            analysis_group_id=stable_group_id(test_id, expected_cwe), benchmark_test_id=test_id,
            expected_cwe=expected_cwe, category=metadata[test_id]["category"],
            observation_ids=sorted(item["observation_id"] for item in items),
            source_tools=sorted({str(item["tool"]) for item in items}),
            locations=sorted({f"{_public_location(item.get('file_or_url'))}:{item.get('line_start') or '?'}" for item in items}),
            evidence_items=evidence,
            grouping_reason=["same_benchmark_test_id", "same_expected_cwe"],
        ))
    return groups


def load_groups(db_path: Path, predictions_path: Path) -> list[AnalysisGroup]:
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = [dict(row) for row in conn.execute("SELECT * FROM findings ORDER BY observation_id")]
    return group_observations(rows, load_benchmark_metadata(predictions_path))


def canonical_bytes(groups: Iterable[AnalysisGroup]) -> bytes:
    payload = [group.model_dump(mode="json") for group in groups]
    return (json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def group_checksum(groups: Iterable[AnalysisGroup]) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(groups)).hexdigest()
