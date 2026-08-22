"""One log and one metrics file per end-to-end run.

Every stage of the Week 6 flow already writes its own artifact — a scan
manifest, a run directory, probe records, an approval log. What was missing is
the thread that ties them together: how long the whole thing took, how many
requests went out, how many a human refused, what failed. Without that, "the
flow ran" is a claim rather than a record.

Two rules shape this module:

* **Redaction is not optional here.** Logs are data, so every line goes through
  the same sink as any other artifact (AGENTS.md 4, 6.3). A caller cannot
  forget, because the writer redacts rather than the call site.
* **Timing is measured, not narrated.** A stage records its own duration from a
  monotonic clock, so a step that silently did nothing shows as such.

The log is JSONL, one object per event, appended as the run proceeds so a crash
leaves the steps that did happen on disk rather than nothing at all.
"""

from __future__ import annotations

import json
import os
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator

from sentinel_benchmark.guardrails.redaction import redact_obj


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


@dataclass
class RunLog:
    """An append-only log plus the counters the weekly report needs.

    ``counters`` is deliberately free-form: a stage increments what it knows
    about, and the metrics file is the union. Fixing the schema here would mean
    editing this class every time a stage learns to count something new.
    """

    run_id: str
    root: Path
    stage_events: list[dict[str, Any]] = field(default_factory=list)
    counters: dict[str, int] = field(default_factory=dict)
    errors: list[dict[str, Any]] = field(default_factory=list)
    started_at: str = field(default_factory=_now)
    _started: float = field(default_factory=time.perf_counter, repr=False)

    @classmethod
    def create(cls, root: Path, *, tag: str) -> "RunLog":
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        run = cls(run_id=f"{stamp}-{tag}", root=root)
        run.log_path.parent.mkdir(parents=True, exist_ok=True)
        run.event("run_started", tag=tag)
        return run

    @property
    def log_path(self) -> Path:
        return self.root / "logs" / f"{self.run_id}.jsonl"

    @property
    def metrics_path(self) -> Path:
        return self.root / "metrics" / f"{self.run_id}.json"

    def event(self, kind: str, **fields: Any) -> dict[str, Any]:
        """Append one redacted event and return it."""
        record = redact_obj({"ts": _now(), "run_id": self.run_id, "event": kind, **fields})
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
        return record

    def count(self, name: str, amount: int = 1) -> None:
        self.counters[name] = self.counters.get(name, 0) + amount

    def failure(self, stage: str, kind: str, message: str) -> None:
        """Record a failure without aborting: a broken stage is a result too."""
        self.count(f"errors.{kind}")
        entry = {"stage": stage, "error_type": kind, "message": message[:600]}
        self.errors.append(entry)
        self.event("error", **entry)

    @contextmanager
    def stage(self, name: str, **fields: Any) -> Iterator[dict[str, Any]]:
        """Time one stage. Exceptions are logged, then re-raised.

        The yielded dict is a scratchpad: whatever a stage puts in it lands in
        the completion event, so a stage reports its own outcome instead of the
        caller guessing at it.
        """
        started = time.perf_counter()
        self.event("stage_started", stage=name, **fields)
        detail: dict[str, Any] = {}
        try:
            yield detail
        except Exception as exc:  # noqa: BLE001 - recorded, then re-raised
            elapsed = round((time.perf_counter() - started) * 1000)
            self.failure(name, type(exc).__name__, str(exc))
            self.event("stage_failed", stage=name, duration_ms=elapsed, **detail)
            self.stage_events.append({"stage": name, "status": "failed", "duration_ms": elapsed, **detail})
            raise
        elapsed = round((time.perf_counter() - started) * 1000)
        self.event("stage_finished", stage=name, duration_ms=elapsed, **detail)
        self.stage_events.append({"stage": name, "status": "ok", "duration_ms": elapsed, **detail})

    def finish(self, *, status: str = "completed", **summary: Any) -> dict[str, Any]:
        """Write the metrics file and return it."""
        total = round((time.perf_counter() - self._started) * 1000)
        metrics = {
            "schema_version": "1.0",
            "run_id": self.run_id,
            "status": status,
            "started_at": self.started_at,
            "finished_at": _now(),
            "duration_ms": total,
            "stages": self.stage_events,
            "counters": dict(sorted(self.counters.items())),
            "errors": self.errors,
            "log": self.log_path.relative_to(self.root.parents[1]).as_posix() if self.root.parents[1] in self.log_path.parents else self.log_path.name,
            **summary,
        }
        metrics = redact_obj(metrics)
        self.metrics_path.parent.mkdir(parents=True, exist_ok=True)
        # Written whole, so a reader never sees a half-finished metrics file.
        tmp = self.metrics_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(metrics, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
        os.replace(tmp, self.metrics_path)
        self.event("run_finished", status=status, duration_ms=total)
        return metrics


def probe_counters(records: list[dict[str, Any]]) -> dict[str, int]:
    """Counters the approval and request stages owe the report.

    Derived from the probe records themselves rather than tallied by hand, so
    the numbers in the metrics file and the numbers in the evidence cannot
    disagree.
    """
    counters = {
        "probes.proposed": len(records),
        "probes.approved": sum(1 for row in records if row.get("decision") == "approve"),
        "probes.rejected": sum(1 for row in records if row.get("decision") == "reject"),
        "probes.not_routable": sum(1 for row in records if row.get("decision") == "not_routable"),
        "probes.sent": sum(1 for row in records if row.get("sent")),
        "probes.reached_target": sum(1 for row in records if row.get("reached_target")),
        "probes.findings_covered": sum(len(row.get("analysis_group_ids") or []) for row in records),
        "probes.injection_flagged": sum(1 for row in records if row.get("injection_flagged")),
        "probes.transport_errors": sum(1 for row in records if row.get("transport_error")),
    }
    # A rejected request that was nevertheless sent would be the single worst
    # failure this system could have, so it is counted explicitly and asserted
    # on in tests rather than left implicit in the difference of two numbers.
    counters["probes.rejected_but_sent"] = sum(1 for row in records if row.get("decision") == "reject" and row.get("sent"))
    redactions: dict[str, int] = {}
    for row in records:
        for kind, hits in (row.get("redaction_hits") or {}).items():
            redactions[kind] = redactions.get(kind, 0) + int(hits)
    for kind, hits in sorted(redactions.items()):
        counters[f"redactions.{kind}"] = hits
    return counters


def report_counters(reports: list[dict[str, Any]]) -> dict[str, int]:
    """Verdict and verification counters for one analysis run."""
    counters: dict[str, int] = {"reports.total": len(reports)}
    for report in reports:
        counters[f"verdicts.{report.get('verdict') or 'missing'}"] = counters.get(f"verdicts.{report.get('verdict') or 'missing'}", 0) + 1
        verification = report.get("verification") or {}
        if verification:
            counters["verifications.attempted"] = counters.get("verifications.attempted", 0) + 1
            if verification.get("reached_target"):
                counters["verifications.answered"] = counters.get("verifications.answered", 0) + 1
            if verification.get("changed"):
                counters["verifications.verdict_changed"] = counters.get("verifications.verdict_changed", 0) + 1
    return dict(sorted(counters.items()))
