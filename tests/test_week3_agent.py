from __future__ import annotations

import json
from pathlib import Path

from sentinel_benchmark.analysis.guard import validate_candidate
from sentinel_benchmark.analysis.grouping import load_groups
from sentinel_benchmark.analysis.prompting import PROMPT_VERSION, SYSTEM_PROMPT, VERIFICATION_PROMPT, build_payload
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


# Corpus and scoring vocabulary. None of this may appear anywhere in a payload:
# the agent is not told the answer and must not be able to infer the ruler.
CORPUS_TERMS = ("ground_truth", "expected_vulnerable", "true_positive", '"tp"', '"tn"', '"fp"', '"fn"')

# Analyst vocabulary. The agent is *asked* to identify a false alarm, so this
# belongs in the contract — but never in the evidence or knowledge it reads,
# because there it could only have come from a corpus label.
ANALYST_TERMS = ("false_positive",)


def _evidence_and_knowledge(payload: dict) -> str:
    """The parts of a payload that came from a scanner or the knowledge base."""
    return json.dumps({key: payload.get(key) for key in ("scanner_evidence", "knowledge", "subject", "cwe_note")}).lower()


def test_prompt_boundary_and_fake_provider(tmp_path: Path) -> None:
    group, payload = inputs(tmp_path)
    prompt = json.dumps(payload).lower()
    for token in CORPUS_TERMS:
        assert token not in prompt
    for token in ANALYST_TERMS:
        assert token not in _evidence_and_knowledge(payload)
    candidate, metadata = FakeProvider().analyze(system_prompt=SYSTEM_PROMPT, user_payload=payload)
    output, guard = validate_candidate(candidate, group, payload_kb_ids(payload))
    assert output is not None and guard.passed
    assert metadata["model"] == "deterministic-evidence-v2"


def payload_kb_ids(payload: dict) -> list[str]:
    return [row["document_id"] for row in payload.get("knowledge") or []]


def test_the_contract_names_every_verdict_the_agent_may_return(tmp_path: Path) -> None:
    # The corpus-term ban above must not be satisfiable by quietly dropping the
    # verdict vocabulary from the prompt.
    _group, payload = inputs(tmp_path)
    assert set(payload["verdict_values"]) == {
        "confirmed_vulnerable",
        "likely_vulnerable",
        "likely_false_positive",
        "not_vulnerable",
        "insufficient_evidence",
    }
    assert "observation_id" in payload["output_schema"]["verdict_rationale"]


def test_every_group_prompt_excludes_evaluation_terms(tmp_path: Path) -> None:
    db = tmp_path / "all.db"; build(ROOT / "configs/sources.json", db, ROOT / "datasets/knowledge/security-topics.jsonl")
    for group in load_groups(db, PREDICTIONS):
        payload = build_payload(group, search_index(db, f"{group.expected_cwe} {group.category}", "knowledge", 3))
        prompt = json.dumps(payload).lower()
        for token in CORPUS_TERMS:
            assert token not in prompt
        for token in ANALYST_TERMS:
            assert token not in _evidence_and_knowledge(payload)
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
    # The doc is resolved from the running version, so bumping the prompt
    # without documenting it fails instead of silently drifting.
    doc = ROOT / f"docs/prompts/{PROMPT_VERSION.split('-')[0]}-security-analysis-agent.md"
    documented = doc.read_text(encoding="utf-8").replace("\n", " ")
    assert PROMPT_VERSION in documented
    for prompt in (SYSTEM_PROMPT, VERIFICATION_PROMPT):
        assert all(sentence in documented for sentence in prompt.split(". "))
