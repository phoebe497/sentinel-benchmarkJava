from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Iterable

from sentinel_benchmark.guardrails.redaction import redact_obj


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    value = redact_obj(value)
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = "".join(json.dumps(redact_obj(row), ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n" for row in rows)
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_checksums(run_dir: Path) -> None:
    lines = []
    for path in sorted(run_dir.iterdir()):
        if path.is_file() and path.name != "checksums.sha256":
            lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}")
    (run_dir / "checksums.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def verify_checksums(run_dir: Path) -> list[str]:
    failures = []
    checksum_file = run_dir / "checksums.sha256"
    if not checksum_file.exists():
        return ["missing:checksums.sha256"]
    for line in checksum_file.read_text(encoding="utf-8").splitlines():
        digest, name = line.split("  ", 1)
        path = run_dir / name
        if not path.exists() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            failures.append(name)
    return failures


def list_runs(root: Path) -> list[dict[str, Any]]:
    result = []
    for manifest in root.glob("runs/*/manifest.json"):
        try:
            row = json.loads(manifest.read_text(encoding="utf-8"))
            row["run_dir"] = str(manifest.parent)
            result.append(row)
        except (OSError, json.JSONDecodeError):
            continue
    return sorted(result, key=lambda row: row.get("created_at", ""), reverse=True)


def load_run(run_dir: Path) -> dict[str, Any]:
    failures = verify_checksums(run_dir)
    if failures:
        return {"state": "corrupt", "checksum_failures": failures, "run_dir": str(run_dir)}
    return {"state": "ready", "manifest": json.loads((run_dir / "manifest.json").read_text(encoding="utf-8")), "summary": json.loads((run_dir / "summary.json").read_text(encoding="utf-8")), "groups": read_jsonl(run_dir / "analysis-groups.jsonl"), "retrieval": read_jsonl(run_dir / "retrieval-trace.jsonl"), "reports": read_jsonl(run_dir / "reports.jsonl"), "errors": read_jsonl(run_dir / "errors.jsonl"), "reviews": read_jsonl(run_dir / "review-events.jsonl")}
