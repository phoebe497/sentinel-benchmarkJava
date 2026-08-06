"""Normalize scanner JSON/JSONL into a stable Project Sentinel finding schema."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Iterable

SEVERITY = {"critical": "critical", "high": "high", "high_bug": "high", "error": "high", "medium": "medium", "warning": "medium", "bug": "medium", "low": "low", "info": "info", "informational": "info"}


def _read_json_records(path: Path) -> Iterable[dict[str, Any]]:
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        for line in text.splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                yield item
        return
    if isinstance(payload, list):
        yield from (x for x in payload if isinstance(x, dict))
    elif isinstance(payload, dict) and isinstance(payload.get("results"), list):
        yield from (x for x in payload["results"] if isinstance(x, dict))
    elif isinstance(payload, dict) and isinstance(payload.get("findings"), list):
        yield from (x for x in payload["findings"] if isinstance(x, dict))
    elif isinstance(payload, dict):
        yield payload


def _first(item: dict[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        value = item.get(key)
        if value not in (None, "", []):
            return value
    return default


def _tool(item: dict[str, Any], source: Path) -> str:
    if item.get("check_id") or isinstance(item.get("extra"), dict):
        return "Semgrep"
    value = _first(item, "tool", "scanner", "engine_kind")
    if isinstance(value, list):
        value = value[0] if value else None
    return str(value or source.stem).replace("Vercel ", "").strip()


def normalize_record(item: dict[str, Any], index: int, source: Path) -> dict[str, Any]:
    extra = item.get("extra") if isinstance(item.get("extra"), dict) else {}
    metadata = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
    location = _first(item, "file", "path", "file_or_url", default=_first(extra, "path", default="unknown"))
    start = _first(item, "start_line", "line", default=_first(item.get("start", {}) if isinstance(item.get("start"), dict) else {}, "line", default=None))
    end = _first(item, "end_line", default=_first(item.get("end", {}) if isinstance(item.get("end"), dict) else {}, "line", default=start))
    cwe = _first(item, "cwe", default=_first(metadata, "cwe", default=None))
    if isinstance(cwe, list):
        cwe = cwe[0] if cwe else None
    owasp = _first(item, "owasp", default=_first(metadata, "owasp", default=None))
    if isinstance(owasp, list):
        owasp = owasp[0] if owasp else None
    title = _first(item, "title", default=_first(extra, "message", default=_first(item, "check_id", default="Security finding")))
    description = _first(item, "description", "content", "message", default=_first(extra, "message", default=""))
    evidence = _first(item, "evidence", "existing_code", default="")
    recommendation = _first(item, "recommendation", "suggestion_code", "fix", default="")
    severity = str(_first(item, "severity", default="info")).lower()
    severity = SEVERITY.get(severity, severity)
    return {
        "finding_id": str(_first(item, "id", "test_id", default=f"FINDING-{index:04d}")),
        "tool": _tool(item, source),
        "severity": severity,
        "file_or_url": str(location),
        "line_start": start,
        "line_end": end,
        "title": str(title),
        "cwe": cwe,
        "owasp": owasp,
        "description": str(description or ""),
        "evidence": str(evidence or ""),
        "recommendation": str(recommendation or ""),
        "confidence": _first(item, "confidence", default=None),
        "source_artifact": str(source.as_posix()),
    }


def normalize_file(source: Path) -> list[dict[str, Any]]:
    return [normalize_record(item, i, source) for i, item in enumerate(_read_json_records(source), 1)]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("-o", "--output", type=Path, default=Path("week2/data/normalized_findings.json"))
    args = parser.parse_args()
    records = normalize_file(args.input)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(records, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"input": str(args.input), "output": str(args.output), "findings": len(records)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
