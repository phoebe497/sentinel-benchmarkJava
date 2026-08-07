from __future__ import annotations

from pathlib import Path

import httpx

from sentinel_benchmark.analysis.chat import answer_question, build_chat_payload
from sentinel_benchmark.analysis.providers import parse_chat_response, parse_json_message
from sentinel_benchmark.analysis.grouping import load_groups
from sentinel_benchmark.indexer import build
from sentinel_benchmark.search import search_index

ROOT = Path(__file__).resolve().parents[1]
PREDICTIONS = ROOT / "artifacts/week-1/semgrep-20260806/variants/security-audit/predictions.jsonl"


def test_offline_chat_is_grounded_in_allowed_ids(tmp_path: Path) -> None:
    db = tmp_path / "sentinel.db"
    build(ROOT / "configs/sources.json", db, ROOT / "datasets/knowledge/security-topics.jsonl")
    group = load_groups(db, PREDICTIONS)[0]
    knowledge = search_index(db, f"{group.expected_cwe} {group.category}", "knowledge", 3)
    payload = build_chat_payload(question="How should I verify this vulnerability?", group=group, knowledge=knowledge, report=None)
    answer, metadata = answer_question(provider=None, payload=payload)
    assert set(answer.citations) <= set(payload["allowed_citation_ids"])
    assert answer.verification_steps
    assert metadata["provider"] == "offline_artifact"


def test_provider_json_parser_accepts_wrapped_and_reasoning_content() -> None:
    assert parse_json_message({"content": "Result:\n```json\n{\"answer\": \"ok\"}\n```"}) == {"answer": "ok"}
    assert parse_json_message({"content": "", "reasoning_content": "prefix {\"answer\": \"ok\"} suffix"}) == {"answer": "ok"}


def test_router_sse_is_normalized_when_stream_false_is_ignored() -> None:
    body = 'data: {"id":"x","model":"m","choices":[{"delta":{"content":"{\\"ok\\":"},"finish_reason":null}]}\n\ndata: {"id":"x","model":"m","choices":[{"delta":{"content":"true}"},"finish_reason":"stop"}]}\n\ndata: [DONE]\n'
    response = httpx.Response(200, headers={"content-type": "text/event-stream"}, text=body)
    parsed = parse_chat_response(response)
    assert parse_json_message(parsed["choices"][0]["message"]) == {"ok": True}
