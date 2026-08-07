"""Build a reproducible SQLite FTS5 index from scanner observations and KB."""
from __future__ import annotations
import argparse, hashlib, json, sqlite3
from pathlib import Path
from typing import Any
try:
    from .normalizer import normalize_file
except ImportError:  # `python week2/indexer.py`
    from normalizer import normalize_file

REPO_ROOT = Path(__file__).resolve().parents[2]
DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (observation_id TEXT PRIMARY KEY, canonical_id TEXT, dataset TEXT, run_id TEXT, tool TEXT, severity TEXT, file_or_url TEXT, line_start INTEGER, line_end INTEGER, title TEXT, cwe TEXT, owasp TEXT, description TEXT, evidence TEXT, recommendation TEXT, confidence REAL, source_artifact TEXT);
CREATE VIRTUAL TABLE IF NOT EXISTS findings_fts USING fts5(observation_id UNINDEXED, title, description, evidence, recommendation, cwe, owasp, file_or_url, content='findings', content_rowid='rowid');
DROP TABLE IF EXISTS knowledge_fts;
DROP TABLE IF EXISTS knowledge;
CREATE TABLE knowledge (document_id TEXT PRIMARY KEY, category TEXT, title TEXT, source TEXT, source_url TEXT, tags TEXT, content TEXT);
CREATE VIRTUAL TABLE knowledge_fts USING fts5(document_id UNINDEXED, category, title, source, tags, content, content='knowledge', content_rowid='rowid');
"""

def _stable(*parts: Any) -> str:
    return hashlib.sha256("|".join(str(x or "").strip().lower() for x in parts).encode()).hexdigest()[:16]

def build(manifest: Path, output: Path, kb_path: Path) -> dict[str, int]:
    sources = json.loads(manifest.read_text(encoding="utf-8"))
    conn = sqlite3.connect(output)
    conn.executescript(DB_SCHEMA)
    conn.execute("DELETE FROM findings")
    conn.execute("DELETE FROM findings_fts")
    total = 0
    for source in sources:
        path = REPO_ROOT / source["path"]
        if not path.exists():
            raise FileNotFoundError(path)
        for i, row in enumerate(normalize_file(path), 1):
            row.update(dataset=source["dataset"], run_id=source["run_id"], source_id=source["id"], tool=source.get("tool", row.get("tool")))
            canonical = _stable(source["dataset"], row.get("file_or_url"), row.get("line_start"), row.get("line_end"), row.get("cwe"), row.get("title"))
            # A scanner can emit multiple findings for the same BenchmarkTest ID.
            # Include the source-local ordinal so INSERT OR REPLACE cannot silently
            # collapse distinct observations that share a test/file identifier.
            obs = f"{source['id']}:{row.get('finding_id') or 'finding'}:{i:04d}"
            row["canonical_id"] = f"CAN-{canonical}"
            row["observation_id"] = obs
            conn.execute("INSERT OR REPLACE INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (obs, row["canonical_id"], row["dataset"], row["run_id"], row["tool"], row["severity"], row["file_or_url"], row["line_start"], row["line_end"], row["title"], json.dumps(row["cwe"], ensure_ascii=False), json.dumps(row["owasp"], ensure_ascii=False), row["description"], row["evidence"], row["recommendation"], row["confidence"], row["source_artifact"]))
            total += 1
    conn.execute("INSERT INTO findings_fts(rowid, observation_id, title, description, evidence, recommendation, cwe, owasp, file_or_url) SELECT rowid, observation_id, title, description, evidence, recommendation, cwe, owasp, file_or_url FROM findings")
    kb_rows = [json.loads(line) for line in kb_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    for row in kb_rows:
        conn.execute(
            "INSERT OR REPLACE INTO knowledge VALUES (?,?,?,?,?,?,?)",
            (
                row["id"],
                row.get("category", "owasp-top-10"),
                row.get("title", ""),
                row.get("source", ""),
                row.get("source_url", ""),
                json.dumps(row.get("tags", []), ensure_ascii=False),
                row.get("content", ""),
            ),
        )
    conn.execute(
        "INSERT INTO knowledge_fts(rowid, document_id, category, title, source, tags, content) "
        "SELECT rowid, document_id, category, title, source, tags, content FROM knowledge"
    )
    conn.commit(); conn.close()
    return {"findings": total, "knowledge": len(kb_rows)}

def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--manifest", type=Path, default=REPO_ROOT / "configs" / "sources.json")
    p.add_argument("--output", type=Path, default=REPO_ROOT / "datasets" / "processed" / "sentinel.db")
    p.add_argument("--knowledge", type=Path, default=REPO_ROOT / "datasets" / "knowledge" / "security-topics.jsonl")
    a = p.parse_args()
    a.output.parent.mkdir(parents=True, exist_ok=True)
    print(json.dumps(build(a.manifest, a.output, a.knowledge)))

if __name__ == "__main__": main()
