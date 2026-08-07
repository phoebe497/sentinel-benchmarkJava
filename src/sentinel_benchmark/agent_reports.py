"""Compatibility facade for loading and exporting Week 3 report artifacts."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from pydantic import ValidationError

from .analysis.artifacts import load_run
from .analysis.models import ReportRecord
from .analysis.review import STATUSES, append_review_event

REPORT_STATUSES = tuple(sorted(STATUSES))


def validate_report(report: dict[str, Any]) -> list[str]:
    try:
        ReportRecord.model_validate(report)
        return []
    except ValidationError as exc:
        return [str(exc)]


def export_reports_jsonl(reports: Iterable[dict[str, Any]]) -> str:
    validated = [ReportRecord.model_validate(report).model_dump(mode="json") for report in reports]
    return "".join(json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n" for report in validated)


reports_to_jsonl = export_reports_jsonl


def load_reports(run_dir: Path) -> list[dict[str, Any]]:
    result = load_run(run_dir)
    return result.get("reports", []) if result.get("state") == "ready" else []


__all__ = ["REPORT_STATUSES", "append_review_event", "export_reports_jsonl", "load_reports", "validate_report"]
