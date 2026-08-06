"""Small dependency-free knowledge/finding search for Week 2."""
from __future__ import annotations
import json
import re
from pathlib import Path
from typing import Any

STOP = {"the", "a", "an", "and", "or", "of", "to", "in", "via", "for", "with", "on"}
ALIASES = {"sqli": "sql injection", "cross site scripting": "xss", "cross-site scripting": "xss", "cwe 89": "cwe-89", "cwe 79": "cwe-79"}


def tokens(text: str) -> set[str]:
    return {x for x in re.findall(r"[a-z0-9]+", text.lower()) if x not in STOP}


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def search(rows: list[dict[str, Any]], query: str, limit: int = 5) -> list[dict[str, Any]]:
    query = ALIASES.get(query.lower().strip(), query)
    wanted = tokens(query)
    ranked = []
    for row in rows:
        haystack = " ".join(str(row.get(k, "")) for k in ("title", "description", "content", "tags", "cwe", "owasp", "file_or_url"))
        present = tokens(haystack)
        score = len(wanted & present)
        if query.lower() in haystack.lower():
            score += 2
        if score:
            ranked.append((score, row))
    ranked.sort(key=lambda pair: (-pair[0], str(pair[1].get("title", ""))))
    return [row for _, row in ranked[:limit]]


def search_index(db_path: Path, query: str, kind: str = "knowledge", limit: int = 10, dataset: str | None = None, severity: str | None = None) -> list[dict[str, Any]]:
    import sqlite3
    query = ALIASES.get(query.lower().strip(), query)
    terms = [x for x in re.findall(r"[a-z0-9-]+", query.lower()) if x not in STOP]
    if not terms: return []
    # Quote each token so identifiers such as CWE-89 are treated as text, not FTS operators.
    params: list[Any] = [" OR ".join('"' + x.replace('"', '') + '"' for x in terms)]
    if kind == "findings":
        base = "SELECT d.*, bm25(findings_fts) AS rank FROM findings_fts f JOIN findings d ON d.observation_id=f.observation_id WHERE findings_fts MATCH ?"
        if dataset: base += " AND d.dataset=?"; params.append(dataset)
        if severity: base += " AND d.severity=?"; params.append(severity)
        base += " ORDER BY bm25(findings_fts) LIMIT ?"
    else:
        base = "SELECT k.*, bm25(knowledge_fts) AS rank FROM knowledge_fts f JOIN knowledge k ON k.document_id=f.document_id WHERE knowledge_fts MATCH ? ORDER BY bm25(knowledge_fts) LIMIT ?"
    params.append(limit)
    conn = sqlite3.connect(db_path); conn.row_factory = sqlite3.Row
    try:
        return [dict(x) for x in conn.execute(base, params).fetchall()]
    finally:
        conn.close()
