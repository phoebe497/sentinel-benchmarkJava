from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .taxonomy import cwe_name

Severity = Literal["critical", "high", "medium", "low", "info"]


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


class AgentOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    severity_assessment: Severity
    explanation: str = Field(min_length=20, max_length=4000)
    verification_steps: list[str] = Field(min_length=1, max_length=8)
    remediation: list[str] = Field(min_length=1, max_length=8)
    limitations: list[str] = Field(default_factory=list, max_length=8)
    analysis_confidence: float = Field(ge=0, le=1)


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
    benchmark_test_id: str
    expected_cwe: str
    vulnerability_name: str
    category: str
    grouping_mode: Literal["benchmark_assisted"]
    severity_assessment: Severity
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
            value = {**value, "vulnerability_name": cwe_name(str(value.get("expected_cwe") or ""), str(value.get("category") or ""))}
        return value
