from __future__ import annotations

from typing import Any

from pydantic import ValidationError

from .models import AgentOutput, AnalysisGroup, GuardResult

FORBIDDEN = {"observation_id", "tool", "file_or_url", "location", "expected_cwe", "benchmark_test_id", "kb_document_id", "verdict", "ground_truth", "review_status"}


def validate_candidate(candidate: dict[str, Any], group: AnalysisGroup) -> tuple[AgentOutput | None, GuardResult]:
    failures = []
    forbidden = sorted(FORBIDDEN.intersection(candidate))
    if forbidden:
        failures.append("immutable_fields:" + ",".join(forbidden))
    try:
        output = AgentOutput.model_validate(candidate)
    except ValidationError as exc:
        failures.append("schema:" + str(exc).replace("\n", " ")[:800])
        output = None
    checks = {"schema_valid": output is not None, "immutable_fields_absent": not forbidden, "evidence_preserved_by_python": True}
    return output, GuardResult(passed=not failures, checks=checks, failures=failures)
