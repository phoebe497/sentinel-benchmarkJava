"""Normalize scanner JSON/JSONL into a stable Project Sentinel finding schema.

Both evidence sources land in the same shape so a single agent, a single prompt
contract and a single index serve them:

- SAST (Semgrep, LLM reviewers) over BenchmarkJava source -> ``file_or_url`` is a
  file path plus line numbers.
- DAST (OWASP ZAP baseline) over the running app -> ``file_or_url`` is a URL and
  the line numbers are absent.
"""
from __future__ import annotations

import argparse
import json
import re
from html import unescape
from pathlib import Path
from typing import Any, Iterable

SEVERITY = {"critical": "critical", "high": "high", "high_bug": "high", "error": "high", "medium": "medium", "warning": "medium", "bug": "medium", "low": "low", "info": "info", "informational": "info"}

# ZAP risk/confidence are numeric strings in the JSON report.
ZAP_RISK = {"3": "high", "2": "medium", "1": "low", "0": "info"}
ZAP_CONFIDENCE = {"0": 0.0, "1": 0.25, "2": 0.5, "3": 0.75, "4": 1.0}
_TAG_RE = re.compile(r"<[^>]+>")
_SPACE_RE = re.compile(r"\s+")


def _read_json_records(path: Path) -> Iterable[dict[str, Any]]:
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        for line in text.split("\n"):
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


def _plain(html: str) -> str:
    """ZAP ships desc/solution as HTML fragments; keep the text, drop the markup."""
    return _SPACE_RE.sub(" ", unescape(_TAG_RE.sub(" ", html or ""))).strip()


def is_zap_report(payload: Any) -> bool:
    """A ZAP JSON report is a single object with a ``site`` list of alerts."""
    return isinstance(payload, dict) and isinstance(payload.get("site"), list)


def _zap_cwe(alert: dict[str, Any]) -> str | None:
    raw = str(alert.get("cweid") or "").strip()
    return f"CWE-{raw}" if raw.isdigit() and int(raw) > 0 else None


def normalize_zap_record(alert: dict[str, Any], instance: dict[str, Any], index: int, source: Path) -> dict[str, Any]:
    """One record per (alert, instance): the same alert on two URLs is two findings."""
    method = str(instance.get("method") or "GET").upper()
    uri = str(instance.get("uri") or "")
    param = str(instance.get("param") or "")
    # Everything below comes from the scanned application, so it stays untrusted
    # data: the injection filter and redaction run on it downstream.
    evidence_parts = [f"{method} {uri}"]
    if param:
        evidence_parts.append(f"param={param}")
    if instance.get("evidence"):
        evidence_parts.append(f"evidence={instance['evidence']}")
    if instance.get("otherinfo"):
        evidence_parts.append(f"otherinfo={_plain(str(instance['otherinfo']))}")
    description = _plain(str(alert.get("desc") or ""))
    total = str(alert.get("count") or "").strip()
    if total and total.isdigit() and int(total) > 1:
        description = f"{description} ZAP reported this alert on {total} URLs.".strip()
    return {
        "finding_id": f"zap-{alert.get('pluginid') or 'alert'}-{alert.get('alertRef') or index}",
        "tool": "OWASP ZAP",
        "severity": ZAP_RISK.get(str(alert.get("riskcode") or "0"), "info"),
        "file_or_url": uri,
        "line_start": None,
        "line_end": None,
        "title": str(alert.get("name") or alert.get("alert") or "ZAP alert"),
        "cwe": _zap_cwe(alert),
        "owasp": None,
        "description": description,
        "evidence": " ".join(evidence_parts),
        "recommendation": _plain(str(alert.get("solution") or "")),
        "confidence": ZAP_CONFIDENCE.get(str(alert.get("confidence") or ""), None),
        "source_artifact": str(source.as_posix()),
    }


def normalize_zap_report(payload: dict[str, Any], source: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for site in payload.get("site") or []:
        for alert in site.get("alerts") or []:
            # An alert with no instances is still an observation about the site.
            instances = alert.get("instances") or [{"uri": site.get("@name", ""), "method": "GET"}]
            for instance in instances:
                records.append(normalize_zap_record(alert, instance, len(records) + 1, source))
    return records


def normalize_file(source: Path) -> list[dict[str, Any]]:
    text = source.read_text(encoding="utf-8", errors="replace").strip()
    if text.startswith("{"):
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            payload = None
        if is_zap_report(payload):
            return normalize_zap_report(payload, source)
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
