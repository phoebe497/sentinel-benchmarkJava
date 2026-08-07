from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from .models import AnalysisGroup

PROMPT_VERSION = "week3-agent-v1"
SYSTEM_PROMPT = """You are a security analysis assistant. Return one JSON object matching the requested schema. Base every claim on supplied scanner evidence and knowledge. Never invent identifiers, locations, tools, CWE labels, or verdicts."""

EVALUATION_TERMS = re.compile(
    r"ground_truth|expected_vulnerable|true_positive|false_positive|\b(?:TP|TN|FP|FN)\b",
    re.IGNORECASE,
)


def _provider_safe(text: str) -> str:
    """Keep scanner evidence while removing evaluation-only vocabulary."""
    return EVALUATION_TERMS.sub("[evaluation term redacted]", text)


def build_payload(group: AnalysisGroup, knowledge: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "analysis_group_id": group.analysis_group_id,
        "benchmark_test_id": group.benchmark_test_id,
        "benchmark_assisted_cwe": group.expected_cwe,
        "cwe_note": "Metadata used to correlate scanner observations; do not claim the model inferred this CWE.",
        "scanner_evidence": [
            {**item.model_dump(mode="json"), "excerpt": _provider_safe(item.excerpt), "title": _provider_safe(item.title)}
            for item in group.evidence_items
        ],
        "knowledge": [
            {"document_id": row["document_id"], "title": _provider_safe(row.get("title", "")), "source": _provider_safe(row.get("source", "")), "content": _provider_safe(row.get("content", ""))}
            for row in knowledge
        ],
        "output_schema": {
            "severity_assessment": "exactly one lowercase value: critical, high, medium, low, info",
            "explanation": "string, 20 to 4000 characters",
            "verification_steps": "JSON array of 1 to 8 strings (never a numbered string)",
            "remediation": "JSON array of 1 to 8 strings (never a numbered string)",
            "limitations": "JSON array of 0 to 8 strings",
            "analysis_confidence": "JSON number from 0.0 to 1.0 (never a word or percentage)",
        },
        "response_rule": "Return only one JSON object. Use exactly the six keys in output_schema and no others.",
    }


def prompt_hash(payload: dict[str, Any]) -> str:
    raw = json.dumps({"system": SYSTEM_PROMPT, "payload": payload}, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()
