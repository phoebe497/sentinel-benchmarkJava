from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

STATUSES = {"needs_review", "approved", "rejected"}


def append_review_event(path: Path, *, report_id: str, status: str, reviewer: str = "local_user", note: str = "") -> dict:
    if status not in STATUSES:
        raise ValueError(f"Invalid review status: {status}")
    event = {"schema_version": "1.0", "event_id": f"REV-{uuid.uuid4().hex[:12]}", "report_id": report_id, "status": status, "reviewer": reviewer, "note": note, "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z")}
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
    if (path.parent / "checksums.sha256").exists():
        from .artifacts import write_checksums
        write_checksums(path.parent)
    return event


def latest_status(events: list[dict], report_id: str) -> str:
    matching = [event for event in events if event.get("report_id") == report_id]
    return matching[-1]["status"] if matching else "needs_review"
