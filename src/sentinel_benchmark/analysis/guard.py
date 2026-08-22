"""The Evidence Guard: the last line between a model's output and a report.

It answers one question — may this JSON become a report? — and it answers it in
Python, never by asking the model again. Two kinds of rule live here:

* **Contract rules.** The output matches the schema, and the model did not
  write a field that is Python's to own (identifiers, ground truth, locations).
* **Support rules.** A verdict must rest on something. The model may abstain
  freely, but it may not *conclude* without citing the evidence it concluded
  from. These are the rules that make a verdict falsifiable rather than
  decorative.
"""

from __future__ import annotations

from typing import Any, Iterable

from pydantic import ValidationError

from .models import AgentOutput, AnalysisGroup, EndpointGroup, GuardResult, VerificationOutput

# Fields Python owns. ``verdict`` is deliberately absent: since Week 6 it is a
# contracted field the model is asked for. ``ground_truth`` stays forbidden
# forever — the corpus knows the answer, the model does not.
FORBIDDEN = {
    "observation_id",
    "tool",
    "file_or_url",
    "location",
    "expected_cwe",
    "benchmark_test_id",
    "kb_document_id",
    "ground_truth",
    "review_status",
    "outcome",
}

GroupLike = AnalysisGroup | EndpointGroup


def _cites(text: str, candidates: Iterable[str]) -> bool:
    values = [value for value in candidates if value]
    return any(value in text for value in values)


def validate_candidate(
    candidate: dict[str, Any],
    group: GroupLike,
    kb_document_ids: Iterable[str] = (),
) -> tuple[AgentOutput | None, GuardResult]:
    failures: list[str] = []
    forbidden = sorted(FORBIDDEN.intersection(candidate))
    if forbidden:
        failures.append("immutable_fields:" + ",".join(forbidden))
    try:
        output = AgentOutput.model_validate(candidate)
    except ValidationError as exc:
        failures.append("schema:" + str(exc).replace("\n", " ")[:800])
        output = None

    kb_ids = list(kb_document_ids)
    checks = {
        "schema_valid": output is not None,
        "immutable_fields_absent": not forbidden,
        "evidence_preserved_by_python": True,
    }

    if output is not None:
        rationale = output.verdict_rationale
        cites_observation = _cites(rationale, group.observation_ids)
        # Only demanded when a document was actually retrieved: a verdict cannot
        # be required to cite knowledge that the search did not return.
        cites_knowledge = not kb_ids or _cites(rationale, kb_ids)
        checks["verdict_cites_observation"] = cites_observation
        checks["verdict_cites_knowledge"] = cites_knowledge
        if not cites_observation:
            failures.append("verdict_rationale_missing_observation_id")
        if not cites_knowledge:
            failures.append("verdict_rationale_missing_kb_document_id")

        # A conclusion of "confirmed" has to point at text that was actually
        # read. Without an excerpt anywhere, the strongest honest verdict is
        # "likely", and the guard says so instead of letting it through.
        has_excerpt = any(item.excerpt.strip() for item in group.evidence_items)
        confirmed_supported = output.verdict != "confirmed_vulnerable" or has_excerpt
        checks["confirmed_verdict_has_excerpt"] = confirmed_supported
        if not confirmed_supported:
            failures.append("confirmed_vulnerable_without_any_evidence_excerpt")

        # Symmetry: claiming a false positive requires naming the indicator, and
        # abstaining requires naming what was missing.
        fp_supported = output.verdict != "likely_false_positive" or bool(output.false_positive_indicators)
        checks["false_positive_names_indicator"] = fp_supported
        if not fp_supported:
            failures.append("likely_false_positive_without_indicator")

        abstain_supported = output.verdict != "insufficient_evidence" or bool(output.limitations)
        checks["abstention_states_limitation"] = abstain_supported
        if not abstain_supported:
            failures.append("insufficient_evidence_without_limitation")

    return output, GuardResult(passed=not failures, checks=checks, failures=failures)


def validate_verification(
    candidate: dict[str, Any],
    *,
    observation_ids: Iterable[str],
    route_id: str,
) -> tuple[VerificationOutput | None, GuardResult]:
    """Guard the post-probe pass. The probe's own facts are Python's, not the model's."""
    failures: list[str] = []
    forbidden = sorted(FORBIDDEN.intersection(candidate))
    if forbidden:
        failures.append("immutable_fields:" + ",".join(forbidden))
    # Status, headers and timings are recorded by the request tool. A model that
    # emits them is asserting a measurement it did not take.
    measured = sorted({"status", "headers", "reached_target", "elapsed_ms", "sent"}.intersection(candidate))
    if measured:
        failures.append("measured_fields:" + ",".join(measured))
    try:
        output = VerificationOutput.model_validate(candidate)
    except ValidationError as exc:
        failures.append("schema:" + str(exc).replace("\n", " ")[:800])
        output = None
    checks = {
        "schema_valid": output is not None,
        "immutable_fields_absent": not forbidden,
        "measured_fields_absent": not measured,
    }
    if output is not None:
        # The point of this pass is that the verdict now rests on the probe, so
        # the rationale must refer to the probe or to the observation it revised.
        grounded = _cites(output.verdict_rationale, [route_id, *observation_ids])
        checks["rationale_cites_probe_or_observation"] = grounded
        if not grounded:
            failures.append("verification_rationale_missing_route_or_observation_id")
    return output, GuardResult(passed=not failures, checks=checks, failures=failures)
