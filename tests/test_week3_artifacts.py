from __future__ import annotations

from pathlib import Path

from sentinel_benchmark.analysis.artifacts import load_run
from sentinel_benchmark.analysis.grouping import load_groups
from sentinel_benchmark.analysis.providers import FakeProvider
from sentinel_benchmark.analysis.review import append_review_event, latest_status
from sentinel_benchmark.analysis.runner import run_batch
from sentinel_benchmark.indexer import build

ROOT = Path(__file__).resolve().parents[1]
PREDICTIONS = ROOT / "artifacts/week-1/semgrep-20260806/variants/security-audit/predictions.jsonl"


def test_runner_artifacts_checksums_and_review(tmp_path: Path) -> None:
    db = tmp_path / "sentinel.db"; build(ROOT / "configs/sources.json", db, ROOT / "datasets/knowledge/security-topics.jsonl")
    run_dir = run_batch(groups=load_groups(db, PREDICTIONS), db_path=db, provider=FakeProvider(), run_root=tmp_path / "week3", tag="test", limit=3)
    loaded = load_run(run_dir)
    assert loaded["state"] == "ready"
    assert loaded["summary"]["successful"] == 3
    assert all(report["guard"]["passed"] for report in loaded["reports"])
    event = append_review_event(run_dir / "review-events.jsonl", report_id=loaded["reports"][0]["report_id"], status="approved")
    assert latest_status([event], event["report_id"]) == "approved"


def test_corrupt_artifact_is_typed_state(tmp_path: Path) -> None:
    db = tmp_path / "sentinel.db"; build(ROOT / "configs/sources.json", db, ROOT / "datasets/knowledge/security-topics.jsonl")
    run_dir = run_batch(groups=load_groups(db, PREDICTIONS), db_path=db, provider=FakeProvider(), run_root=tmp_path / "week3", tag="test", limit=1)
    (run_dir / "summary.json").write_text("{}", encoding="utf-8")
    assert load_run(run_dir)["state"] == "corrupt"


class OneBadGroupProvider(FakeProvider):
    calls: dict[str, int] = {}

    def analyze(self, *, system_prompt, user_payload):
        group_id = user_payload["analysis_group_id"]
        self.calls[group_id] = self.calls.get(group_id, 0) + 1
        if not self.calls or group_id == next(iter(self.calls)):
            raise ValueError("invalid provider JSON")
        return super().analyze(system_prompt=system_prompt, user_payload=user_payload)


def test_retry_once_and_failure_isolation(tmp_path: Path) -> None:
    db = tmp_path / "sentinel.db"; build(ROOT / "configs/sources.json", db, ROOT / "datasets/knowledge/security-topics.jsonl")
    groups = load_groups(db, PREDICTIONS)
    provider = OneBadGroupProvider(); provider.calls = {}
    run_dir = run_batch(groups=groups, db_path=db, provider=provider, run_root=tmp_path / "week3", tag="partial", limit=2)
    loaded = load_run(run_dir)
    assert loaded["summary"] == {"run_id": loaded["summary"]["run_id"], "status": "partial", "requested": 2, "successful": 1, "failed": 1, "guard_passed": 1}
    assert sorted(provider.calls.values()) == [1, 2]


def test_empty_input_produces_valid_zero_run(tmp_path: Path) -> None:
    db = tmp_path / "empty.db"; build(ROOT / "configs/sources.json", db, ROOT / "datasets/knowledge/security-topics.jsonl")
    run_dir = run_batch(groups=[], db_path=db, provider=FakeProvider(), run_root=tmp_path / "week3-empty", tag="empty")
    loaded = load_run(run_dir)
    assert loaded["state"] == "ready"
    assert loaded["summary"]["requested"] == loaded["summary"]["successful"] == 0
    assert loaded["reports"] == []
