"""What the run log must record, and what it must never let through."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel_benchmark.runlog import RunLog, probe_counters, report_counters

SECRET = "sk-abcdef0123456789ABCDEF"


def _events(run: RunLog) -> list[dict]:
    return [json.loads(line) for line in run.log_path.read_text(encoding="utf-8").split("\n") if line.strip()]


def test_a_run_records_its_stages_and_total_time(tmp_path: Path) -> None:
    run = RunLog.create(tmp_path, tag="test")
    with run.stage("normalize") as detail:
        detail["alerts"] = 18
    with run.stage("analyse"):
        run.count("reports.total", 3)
    metrics = run.finish()

    assert [stage["stage"] for stage in metrics["stages"]] == ["normalize", "analyse"]
    assert all(stage["status"] == "ok" for stage in metrics["stages"])
    assert metrics["stages"][0]["alerts"] == 18
    assert metrics["duration_ms"] >= sum(stage["duration_ms"] for stage in metrics["stages"])
    assert metrics["counters"]["reports.total"] == 3
    assert metrics["status"] == "completed"
    assert json.loads(run.metrics_path.read_text(encoding="utf-8")) == metrics
    kinds = [event["event"] for event in _events(run)]
    assert kinds == ["run_started", "stage_started", "stage_finished", "stage_started", "stage_finished", "run_finished"]


def test_a_failing_stage_is_recorded_and_re_raised(tmp_path: Path) -> None:
    run = RunLog.create(tmp_path, tag="test")
    with pytest.raises(RuntimeError):
        with run.stage("analyse"):
            raise RuntimeError("the model returned nothing")
    metrics = run.finish(status="failed")

    assert metrics["status"] == "failed"
    assert metrics["stages"][0]["status"] == "failed"
    assert metrics["errors"][0]["error_type"] == "RuntimeError"
    assert metrics["counters"]["errors.RuntimeError"] == 1
    # A crashed run must leave the steps that did happen on disk, not nothing.
    assert "stage_failed" in [event["event"] for event in _events(run)]


def test_no_secret_survives_into_the_log_or_the_metrics(tmp_path: Path) -> None:
    # AGENTS.md 4: logs are data too, so the redaction rule applies to them
    # without exception. The sink redacts so no call site can forget.
    run = RunLog.create(tmp_path, tag="test")
    run.event("probe", body=f"Authorization: Bearer {SECRET}", contact="nguyen.van.a@example.com")
    with run.stage("send") as detail:
        detail["note"] = f"password=hunter2-real-secret key={SECRET}"
    metrics = run.finish(sample=f"phone 0912345678 token {SECRET}")

    written = run.log_path.read_text(encoding="utf-8") + run.metrics_path.read_text(encoding="utf-8")
    for secret in (SECRET, "nguyen.van.a@example.com", "hunter2-real-secret", "0912345678"):
        assert secret not in written, secret
    assert "[REDACTED_" in written
    assert "[REDACTED_" in json.dumps(metrics)


def test_probe_counters_come_from_the_records_not_from_a_tally(tmp_path: Path) -> None:
    records = [
        {"decision": "approve", "sent": True, "reached_target": True, "status": 200, "analysis_group_ids": ["a", "b", "c"], "injection_flagged": True, "redaction_hits": {"token": 2}},
        {"decision": "reject", "sent": False, "reached_target": False, "analysis_group_ids": ["d"]},
        {"decision": "not_routable", "sent": False, "reached_target": False, "analysis_group_ids": ["e"]},
        {"decision": "approve", "sent": True, "reached_target": False, "analysis_group_ids": ["f"], "transport_error": "gateway refused it"},
    ]
    counters = probe_counters(records)
    assert counters["probes.proposed"] == 4
    assert counters["probes.approved"] == 2
    assert counters["probes.rejected"] == 1
    assert counters["probes.not_routable"] == 1
    assert counters["probes.sent"] == 2
    assert counters["probes.reached_target"] == 1
    assert counters["probes.findings_covered"] == 6
    assert counters["probes.injection_flagged"] == 1
    assert counters["probes.transport_errors"] == 1
    assert counters["redactions.token"] == 2
    # The single worst failure this system could have is counted explicitly.
    assert counters["probes.rejected_but_sent"] == 0


def test_a_rejected_request_that_was_sent_would_show_up_as_such() -> None:
    counters = probe_counters([{"decision": "reject", "sent": True, "analysis_group_ids": ["a"]}])
    assert counters["probes.rejected_but_sent"] == 1


def test_report_counters_separate_verdicts_from_verifications() -> None:
    counters = report_counters(
        [
            {"verdict": "confirmed_vulnerable", "verification": {"reached_target": True, "changed": True}},
            {"verdict": "insufficient_evidence", "verification": {"reached_target": False, "changed": False}},
            {"verdict": "insufficient_evidence"},
        ]
    )
    assert counters["reports.total"] == 3
    assert counters["verdicts.insufficient_evidence"] == 2
    assert counters["verdicts.confirmed_vulnerable"] == 1
    assert counters["verifications.attempted"] == 2
    assert counters["verifications.answered"] == 1
    assert counters["verifications.verdict_changed"] == 1
