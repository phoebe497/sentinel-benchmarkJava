from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .artifacts import atomic_json, list_runs, load_run, write_jsonl


def select_by_tag(root: Path, tag: str) -> dict[str, Any] | None:
    return next((run for run in list_runs(root) if run.get("tag") == tag), None)


def evaluate_runs(root: Path, *, fake_tag: str, real_tag: str | None = None) -> dict[str, Any]:
    evaluation_dir = root / "evaluation"
    evaluation_dir.mkdir(parents=True, exist_ok=True)
    fake_manifest = select_by_tag(root, fake_tag)
    if not fake_manifest:
        raise FileNotFoundError(f"No run found for tag {fake_tag!r}")
    fake = load_run(Path(fake_manifest["run_dir"]))
    real = None
    if real_tag:
        real_manifest = select_by_tag(root, real_tag)
        real = load_run(Path(real_manifest["run_dir"])) if real_manifest else None
    def metrics(run: dict[str, Any] | None) -> dict[str, Any] | None:
        if not run or run.get("state") != "ready":
            return None
        reports = run["reports"]
        requested = run["summary"]["requested"]
        observation_ids = {item for report in reports for item in report["sources"]["observation_ids"]}
        evidence_ids = {item["observation_id"] for report in reports for item in report["evidence"]}
        return {"run_id": run["summary"]["run_id"], "requested": requested, "successful": len(reports), "schema_valid_rate": len(reports) / requested if requested else 0, "guard_pass_rate": sum(row["guard"]["passed"] for row in reports) / requested if requested else 0, "evidence_reference_rate": len(observation_ids & evidence_ids) / len(observation_ids) if observation_ids else 0, "failures": len(run["errors"])}
    result = {"schema_version": "1.0", "fake": metrics(fake), "real": metrics(real)}
    atomic_json(evaluation_dir / "agent-metrics.json", result)
    failures = []
    selected_tags = {fake_tag, *([real_tag] if real_tag else [])}
    for manifest in list_runs(root):
        if manifest.get("tag") not in selected_tags:
            continue
        historical = load_run(Path(manifest["run_dir"]))
        if historical.get("state") != "ready":
            continue
        failures.extend({"run_id": manifest["run_id"], **row} for row in historical.get("errors", []))
    write_jsonl(evaluation_dir / "failure-cases.jsonl", failures)
    return result


def write_grouping_metrics(root: Path, baseline: dict[str, Any]) -> None:
    atomic_json(root / "evaluation" / "grouping-metrics.json", {key: baseline[key] for key in ("observations", "analysis_groups_week3", "covered_test_ids", "missing_test_ids", "missing_reasons", "observations_assigned_once", "duplicate_assignments", "grouping_deterministic", "group_checksum")})
