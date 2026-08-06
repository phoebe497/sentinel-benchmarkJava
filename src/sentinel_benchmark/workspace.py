"""Read-only analysis views built on top of the Week 2 findings index."""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
TEST_ID = re.compile(r"BenchmarkTest\d{5}")


def decode_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if item]
    try:
        parsed = json.loads(value or "[]")
    except (TypeError, json.JSONDecodeError):
        parsed = value
    if isinstance(parsed, list):
        return [str(item) for item in parsed if item]
    return [str(parsed)] if parsed else []


def load_ground_truth(predictions_path: Path) -> dict[str, dict[str, Any]]:
    """Load labels produced after scanning; labels never become scanner input."""
    result: dict[str, dict[str, Any]] = {}
    for line in predictions_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        result[item["test_id"]] = {
            "ground_truth": bool(item["ground_truth"]),
            "expected_cwe": f"CWE-{int(item['expected_cwe'])}",
            "category": item.get("category", ""),
        }
    return result


def _test_id(row: dict[str, Any]) -> str | None:
    for value in (row.get("file_or_url"), row.get("title"), row.get("description")):
        match = TEST_ID.search(str(value or ""))
        if match:
            return match.group(0)
    return None


def _group_id(test_id: str, cwe: str) -> str:
    digest = hashlib.sha256(f"owasp-benchmark-java|{test_id}|{cwe}".encode()).hexdigest()[:16]
    return f"CAN-{digest}"


def load_analysis_groups(db_path: Path, predictions_path: Path) -> list[dict[str, Any]]:
    """Group scanner observations by Benchmark test and expected CWE.

    Week 2 observation IDs and raw records remain unchanged. This projection is
    deliberately separate because scanner titles and line ranges differ even
    when they describe the same Benchmark test.
    """
    ground_truth = load_ground_truth(predictions_path)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        observations = [dict(row) for row in conn.execute("SELECT * FROM findings ORDER BY observation_id")]
    finally:
        conn.close()

    buckets: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in observations:
        test_id = _test_id(row)
        if not test_id or test_id not in ground_truth:
            continue
        label = ground_truth[test_id]
        row["test_id"] = test_id
        row["expected_cwe"] = label["expected_cwe"]
        row["ground_truth"] = label["ground_truth"]
        row["reported_cwe"] = decode_list(row.get("cwe"))
        buckets[(test_id, label["expected_cwe"])].append(row)

    groups: list[dict[str, Any]] = []
    for (test_id, cwe), rows in sorted(buckets.items()):
        tools = sorted({row["tool"] for row in rows})
        severities = [str(row.get("severity") or "info").lower() for row in rows]
        severity = max(severities, key=lambda value: SEVERITY_ORDER.get(value, 0))
        titles = [str(row.get("title") or "Security finding") for row in rows]
        common_title = Counter(titles).most_common(1)[0][0]
        locations = sorted(
            {
                f"{Path(str(row['file_or_url'])).name}:{row.get('line_start') or '?'}"
                for row in rows
            }
        )
        groups.append(
            {
                "canonical_id": _group_id(test_id, cwe),
                "test_id": test_id,
                "cwe": cwe,
                "title": common_title,
                "severity": severity,
                "ground_truth": rows[0]["ground_truth"],
                "category": ground_truth[test_id]["category"],
                "tools": tools,
                "observations": rows,
                "observation_count": len(rows),
                "locations": locations,
            }
        )
    return groups


def filter_groups(
    groups: Iterable[dict[str, Any]],
    query: str = "",
    severity: str = "all",
    tool: str = "all",
    ground_truth: str = "all",
) -> list[dict[str, Any]]:
    query = query.strip().lower()
    result = []
    for group in groups:
        haystack = " ".join(
            [group["test_id"], group["cwe"], group["title"], *group["tools"]]
        ).lower()
        if query and query not in haystack:
            continue
        if severity != "all" and group["severity"] != severity:
            continue
        if tool != "all" and tool not in group["tools"]:
            continue
        if ground_truth != "all" and group["ground_truth"] != (ground_truth == "vulnerable"):
            continue
        result.append(group)
    return result


def retrieve_knowledge(db_path: Path, group: dict[str, Any], limit: int = 3) -> list[dict[str, Any]]:
    from .search import search_index

    query = f"{group['cwe']} {group['title']}"
    return search_index(db_path, query, "knowledge", limit)


def retrieval_evaluation(db_path: Path, groups: Iterable[dict[str, Any]], top_k: int = 3) -> dict[str, Any]:
    evaluated = 0
    hits = 0
    for group in groups:
        documents = retrieve_knowledge(db_path, group, top_k)
        if not documents:
            continue
        evaluated += 1
        cwe = group["cwe"].lower()
        if any(cwe in " ".join(decode_list(doc.get("tags"))).lower() for doc in documents):
            hits += 1
    return {
        "evaluated_groups": evaluated,
        "top_k": top_k,
        "hits": hits,
        "hit_rate": hits / evaluated if evaluated else None,
    }
