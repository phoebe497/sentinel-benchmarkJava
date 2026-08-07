from __future__ import annotations

import json
from pathlib import Path

from sentinel_benchmark.analysis.guard import validate_candidate
from sentinel_benchmark.analysis.grouping import load_groups
from sentinel_benchmark.analysis.prompting import SYSTEM_PROMPT, build_payload
from sentinel_benchmark.analysis.providers import FakeProvider
from sentinel_benchmark.indexer import build
from sentinel_benchmark.search import search_index

ROOT = Path(__file__).resolve().parents[1]
PREDICTIONS = ROOT / "artifacts/week-1/semgrep-20260806/variants/security-audit/predictions.jsonl"


def inputs(tmp_path: Path):
    db = tmp_path / "sentinel.db"; build(ROOT / "configs/sources.json", db, ROOT / "datasets/knowledge/security-topics.jsonl")
    group = load_groups(db, PREDICTIONS)[0]
    kb = search_index(db, f"{group.expected_cwe} {group.category}", "knowledge", 3)
    return group, build_payload(group, kb)


def test_prompt_boundary_and_fake_provider(tmp_path: Path) -> None:
    group, payload = inputs(tmp_path)
    prompt = json.dumps(payload).lower()
    for token in ("ground_truth", "expected_vulnerable", "true_positive", "false_positive", '"tp"', '"tn"', '"fp"', '"fn"'):
        assert token not in prompt
    candidate, metadata = FakeProvider().analyze(system_prompt=SYSTEM_PROMPT, user_payload=payload)
    output, guard = validate_candidate(candidate, group)
    assert output is not None and guard.passed
    assert metadata["model"] == "deterministic-evidence-v1"


def test_every_group_prompt_excludes_evaluation_terms(tmp_path: Path) -> None:
    db = tmp_path / "all.db"; build(ROOT / "configs/sources.json", db, ROOT / "datasets/knowledge/security-topics.jsonl")
    for group in load_groups(db, PREDICTIONS):
        payload = build_payload(group, search_index(db, f"{group.expected_cwe} {group.category}", "knowledge", 3))
        prompt = json.dumps(payload).lower()
        for token in ("ground_truth", "expected_vulnerable", "true_positive", "false_positive"):
            assert token not in prompt
        assert "json array" in payload["output_schema"]["verification_steps"].lower()
        assert "json number" in payload["output_schema"]["analysis_confidence"].lower()


def test_guard_rejects_immutable_and_extra_fields(tmp_path: Path) -> None:
    group, payload = inputs(tmp_path)
    candidate, _ = FakeProvider().analyze(system_prompt=SYSTEM_PROMPT, user_payload=payload)
    candidate["observation_id"] = "invented"
    output, guard = validate_candidate(candidate, group)
    assert output is None and not guard.passed
    assert any("immutable_fields" in failure for failure in guard.failures)


def test_documented_system_prompt_matches_runtime_prompt() -> None:
    documented = (ROOT / "docs/prompts/week3-security-analysis-agent.md").read_text(encoding="utf-8")
    assert SYSTEM_PROMPT in documented.replace("\n", " ") or all(sentence in documented.replace("\n", " ") for sentence in SYSTEM_PROMPT.split(". "))
