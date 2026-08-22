from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .taxonomy import cwe_name

Severity = Literal["critical", "high", "medium", "low", "info"]

# The single label answering "is this finding really a vulnerability?".
# Five values rather than a boolean, because forcing a yes/no makes the model
# guess when the evidence is thin. ``insufficient_evidence`` is the safety
# valve: it abstains instead of inventing, and it is scored separately so an
# abstention can never flatter the precision figure.
Verdict = Literal[
    "confirmed_vulnerable",
    "likely_vulnerable",
    "likely_false_positive",
    "not_vulnerable",
    "insufficient_evidence",
]

VERDICT_STANCE: dict[str, str] = {
    "confirmed_vulnerable": "vulnerable",
    "likely_vulnerable": "vulnerable",
    "likely_false_positive": "not_vulnerable",
    "not_vulnerable": "not_vulnerable",
    "insufficient_evidence": "abstain",
}


def verdict_stance(verdict: str) -> str:
    """Collapse the five verdicts onto the three positions scoring cares about.

    The mapping is fixed policy, applied identically to both evidence sources,
    so a change in the numbers is a change in the agent and not in the ruler.
    """
    return VERDICT_STANCE.get(verdict, "abstain")


class EvidenceItem(BaseModel):
    model_config = ConfigDict(extra="forbid")
    observation_id: str
    tool: str
    file_or_url: str
    line_start: int | None = None
    line_end: int | None = None
    title: str
    severity: Severity = "info"
    reported_cwe: list[str] = Field(default_factory=list)
    excerpt: str = ""


class AnalysisGroup(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["1.0"] = "1.0"
    analysis_group_id: str
    benchmark_test_id: str
    expected_cwe: str
    category: str
    grouping_mode: Literal["benchmark_assisted"] = "benchmark_assisted"
    grouping_version: Literal["1.0"] = "1.0"
    observation_ids: list[str]
    source_tools: list[str]
    locations: list[str]
    evidence_items: list[EvidenceItem]
    grouping_reason: list[Literal["same_benchmark_test_id", "same_expected_cwe"]]


class EndpointGroup(BaseModel):
    """DAST counterpart of :class:`AnalysisGroup`: the subject is an endpoint.

    Deliberately without an ``expected_cwe``: BenchmarkJava ships ground truth,
    a running app does not. Only ``reported_cwes`` (what the scanner claimed) is
    available here, so nothing downstream can mistake a scanner claim for truth.
    """

    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["1.0"] = "1.0"
    analysis_group_id: str
    endpoint: str
    methods: list[str]
    reported_cwes: list[str]
    category: str
    grouping_mode: Literal["endpoint_assisted"] = "endpoint_assisted"
    grouping_version: Literal["1.0"] = "1.0"
    observation_ids: list[str]
    source_tools: list[str]
    locations: list[str]
    evidence_items: list[EvidenceItem]
    grouping_reason: list[Literal["same_endpoint_path", "same_reported_cwe"]]


class AgentOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    severity_assessment: Severity
    verdict: Verdict
    # Must cite the evidence it rests on; the Evidence Guard enforces that a
    # real observation_id (and a knowledge document, when one was retrieved)
    # appears here, so a verdict cannot be an unsupported assertion.
    verdict_rationale: str = Field(min_length=20, max_length=1200)
    false_positive_indicators: list[str] = Field(default_factory=list, max_length=8)
    explanation: str = Field(min_length=20, max_length=4000)
    verification_steps: list[str] = Field(min_length=1, max_length=8)
    remediation: list[str] = Field(min_length=1, max_length=8)
    limitations: list[str] = Field(default_factory=list, max_length=8)
    analysis_confidence: float = Field(ge=0, le=1)


class VerificationOutput(BaseModel):
    """The second pass: what the probe response actually showed, and so what.

    Narrower than :class:`AgentOutput` on purpose. The probe adds facts about
    one endpoint; it is not a licence to rewrite the whole analysis.
    """

    model_config = ConfigDict(extra="forbid")
    verdict: Verdict
    verdict_rationale: str = Field(min_length=20, max_length=1200)
    observed: list[str] = Field(min_length=1, max_length=8)


class Verification(BaseModel):
    """Provenance for a verdict that a live request changed (or failed to change)."""

    model_config = ConfigDict(extra="forbid")
    checked_at: str
    route_id: str
    decision: str  # approve | reject | not_routable
    sent: bool
    status: int | None = None
    reached_target: bool = False
    injection_flagged: bool = False
    observed: list[str] = Field(default_factory=list)
    verdict_before: Verdict
    verdict_after: Verdict
    changed: bool
    rationale: str = ""
    # Set when no request could be made, so "unverified" is never mistaken for
    # "checked and clean".
    unverified_reason: str | None = None


class GuardResult(BaseModel):
    passed: bool
    checks: dict[str, bool]
    failures: list[str] = Field(default_factory=list)


class ReportSources(BaseModel):
    observation_ids: list[str]
    source_tools: list[str]
    kb_document_ids: list[str]


class ReportRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["1.0"] = "1.0"
    report_id: str
    analysis_group_id: str
    # Which corpus this report is about, and what its subject is. A benchmark
    # test carries ground truth; an endpoint does not, and the empty
    # ``expected_cwe`` on a DAST report is how that absence stays visible.
    dataset: str = "owasp-benchmark-java"
    subject_kind: Literal["benchmark_test", "endpoint"] = "benchmark_test"
    subject_id: str = ""
    benchmark_test_id: str = ""
    expected_cwe: str = ""
    reported_cwes: list[str] = Field(default_factory=list)
    vulnerability_name: str
    category: str
    grouping_mode: Literal["benchmark_assisted", "endpoint_assisted"]
    severity_assessment: Severity
    verdict: Verdict
    verdict_rationale: str
    false_positive_indicators: list[str] = Field(default_factory=list)
    # Filled by the post-probe pass. ``None`` means no probe was attempted yet,
    # which is different from a probe that could not be routed.
    verification: Verification | None = None
    explanation: str
    verification_steps: list[str]
    remediation: list[str]
    limitations: list[str]
    analysis_confidence: float
    evidence: list[EvidenceItem]
    sources: ReportSources
    retrieval: list[dict[str, Any]]
    guard: GuardResult
    provider: str
    model: str
    prompt_version: str
    prompt_sha256: str
    run_id: str
    created_at: str

    @model_validator(mode="before")
    @classmethod
    def populate_vulnerability_name(cls, value: Any) -> Any:
        if isinstance(value, dict) and not value.get("vulnerability_name"):
            reported = value.get("reported_cwes") or []
            cwe = str(value.get("expected_cwe") or (reported[0] if reported else ""))
            value = {**value, "vulnerability_name": cwe_name(cwe, str(value.get("category") or ""))}
        return value
