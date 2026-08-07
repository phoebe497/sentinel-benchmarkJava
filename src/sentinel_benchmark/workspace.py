"""Read-only query facade for the Security Analysis Workspace."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Iterable

from .analysis.artifacts import list_runs, load_run
from .analysis.grouping import load_groups
from .search import hybrid_search_index, search_index, semantic_search_index


def decode_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if item]
    try:
        parsed = json.loads(value or "[]")
    except (TypeError, json.JSONDecodeError):
        parsed = value
    return [str(item) for item in parsed] if isinstance(parsed, list) else ([str(parsed)] if parsed else [])


def load_observations(db_path: Path) -> list[dict[str, Any]]:
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(row) for row in conn.execute("SELECT * FROM findings ORDER BY observation_id")]


def load_week2_groups(db_path: Path) -> list[dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for row in load_observations(db_path):
        groups.setdefault(row["canonical_id"], []).append(row)
    return [{"canonical_id": key, "observations": rows, "observation_count": len(rows), "tools": sorted({row["tool"] for row in rows})} for key, rows in sorted(groups.items())]


def load_analysis_groups(db_path: Path, predictions_path: Path) -> list[dict[str, Any]]:
    return [group.model_dump(mode="json") for group in load_groups(db_path, predictions_path)]


def filter_groups(groups: Iterable[dict[str, Any]], query: str = "", severity: str = "all", tool: str = "all", category: str = "all", **_: Any) -> list[dict[str, Any]]:
    query = query.strip().lower()
    result = []
    for group in groups:
        severities = [item.get("severity", "info") for item in group["evidence_items"]]
        haystack = " ".join([group["analysis_group_id"], group["benchmark_test_id"], group["expected_cwe"], group["category"], *group["source_tools"]]).lower()
        if query and query not in haystack: continue
        if severity != "all" and severity not in severities: continue
        if tool != "all" and tool not in group["source_tools"]: continue
        if category != "all" and category != group["category"]: continue
        result.append(group)
    return result


def retrieve_knowledge(db_path: Path, group: dict[str, Any], limit: int = 3) -> list[dict[str, Any]]:
    return search_index(db_path, f"{group['expected_cwe']} {group['category']}", "knowledge", limit)


def search_knowledge(
    db_path: Path,
    query: str,
    limit: int = 5,
    min_score: float = 0.0,
    mode: str = "keyword",
) -> list[dict[str, Any]]:
    if mode == "semantic":
        rows = semantic_search_index(db_path, query, limit)
    elif mode == "hybrid":
        rows = hybrid_search_index(db_path, query, limit)
    else:
        rows = search_index(db_path, query, "knowledge", limit)
        for position, row in enumerate(rows, start=1):
            row.update({"retrieval_mode": "keyword_bm25", "position": position})
    if mode == "keyword" or min_score <= 0:
        return rows
    return [row for row in rows if float(row.get("score") or 0) >= min_score]


def retrieval_evaluation(db_path: Path, groups: Iterable[dict[str, Any]], top_k: int = 3) -> dict[str, Any]:
    evaluated = hits = 0
    for group in groups:
        documents = retrieve_knowledge(db_path, group, top_k)
        if not documents: continue
        evaluated += 1
        cwe = group["expected_cwe"].lower()
        hits += any(cwe in " ".join(decode_list(doc.get("tags"))).lower() for doc in documents)
    return {"evaluated_groups": evaluated, "top_k": top_k, "hits": hits, "hit_rate": hits / evaluated if evaluated else None}


def available_runs(week3_root: Path) -> list[dict[str, Any]]:
    return list_runs(week3_root)


def load_run_artifact(run_dir: Path) -> dict[str, Any]:
    return load_run(run_dir)
