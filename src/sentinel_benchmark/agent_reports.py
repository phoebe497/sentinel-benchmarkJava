"""Structured, evidence-grounded Agent report contract for the Week 3 UI."""
from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any, Iterable

REPORT_STATUSES = ("Needs review", "Approved", "Rejected")
REQUIRED_FIELDS = {
    "schema_version",
    "report_id",
    "canonical_id",
    "title",
    "cwe",
    "severity",
    "verdict",
    "confidence",
    "explanation",
    "evidence",
    "verification",
    "remediation",
    "sources",
    "review_status",
    "model",
    "prompt_version",
    "run_id",
    "created_at",
}

VERIFICATION = {
    "CWE-22": "Thử các đường dẫn chứa ../ hoặc encoding tương đương và xác nhận file đích không thể thoát khỏi thư mục cho phép.",
    "CWE-78": "Dùng input chứa ký tự điều khiển shell trong môi trường cô lập và kiểm tra input có đi vào lệnh hệ điều hành hay không.",
    "CWE-79": "Dùng payload XSS vô hại trong môi trường kiểm thử và kiểm tra output encoding theo đúng HTML/JavaScript context.",
    "CWE-89": "Dùng ký tự nháy đơn và payload SQLi vô hại trong môi trường kiểm thử, sau đó kiểm tra câu lệnh có dùng tham số hóa hay không.",
    "CWE-90": "Dùng ký tự LDAP filter đặc biệt trong môi trường kiểm thử và kiểm tra dữ liệu có được escape trước khi tạo filter hay không.",
}


def _confidence(group: dict[str, Any], knowledge: list[dict[str, Any]]) -> float:
    scanner_bonus = min(max(len(group["tools"]) - 1, 0) * 0.08, 0.16)
    evidence_bonus = 0.08 if group["ground_truth"] else 0.0
    retrieval_bonus = 0.06 if knowledge else 0.0
    return round(min(0.65 + scanner_bonus + evidence_bonus + retrieval_bonus, 0.95), 2)


def _best_text(group: dict[str, Any], field: str) -> str:
    values = [str(row.get(field) or "").strip() for row in group["observations"]]
    return max(values, key=len, default="")


def generate_report(
    group: dict[str, Any],
    knowledge: list[dict[str, Any]],
    *,
    run_id: str,
    regenerate_from: str | None = None,
) -> dict[str, Any]:
    """Create the MVP report without an external model call.

    This deterministic generator proves the UI, evidence contract, review flow
    and JSONL export before the Week 3 LLM provider is connected.
    """
    confidence = _confidence(group, knowledge)
    verdict = "Likely true positive" if group["ground_truth"] else "Likely false positive"
    explanation = _best_text(group, "description") or (
        f"Các scanner ghi nhận dấu hiệu {group['title']} tại {group['test_id']}."
    )
    remediation = _best_text(group, "recommendation")
    if not remediation and knowledge:
        remediation = str(knowledge[0].get("content") or "")
    if not remediation:
        remediation = "Cần review source và áp dụng biện pháp khắc phục phù hợp với CWE trước khi đóng finding."

    evidence = []
    for row in group["observations"]:
        evidence.append(
            {
                "observation_id": row["observation_id"],
                "tool": row["tool"],
                "location": f"{PathLike.name(row['file_or_url'])}:{row.get('line_start') or '?'}",
                "excerpt": str(row.get("evidence") or row.get("description") or "")[:700],
            }
        )
    report = {
        "schema_version": "1.0",
        "report_id": f"AR-{uuid.uuid4().hex[:12]}",
        "canonical_id": group["canonical_id"],
        "title": group["title"],
        "cwe": group["cwe"],
        "severity": group["severity"],
        "verdict": verdict,
        "confidence": confidence,
        "explanation": explanation,
        "evidence": evidence,
        "verification": VERIFICATION.get(
            group["cwe"],
            "Review source-to-sink flow trong môi trường cô lập và xác nhận precondition của finding.",
        ),
        "remediation": remediation,
        "sources": {
            "kb_document_ids": [doc["document_id"] for doc in knowledge],
            "observation_ids": [row["observation_id"] for row in group["observations"]],
        },
        "retrieval": [
            {
                "document_id": doc["document_id"],
                "title": doc["title"],
                "source": doc.get("source", ""),
                "score": doc.get("rank"),
            }
            for doc in knowledge
        ],
        "review_status": "Needs review",
        "model": "grounded-template-v1",
        "prompt_version": "week3-mvp-v1",
        "run_id": run_id,
        "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }
    if regenerate_from:
        report["regenerated_from"] = regenerate_from
    errors = validate_report(report)
    if errors:
        raise ValueError("Generated report violates contract: " + ", ".join(errors))
    return report


class PathLike:
    @staticmethod
    def name(value: Any) -> str:
        return str(value or "unknown").replace("\\", "/").rsplit("/", 1)[-1]


def validate_report(report: dict[str, Any]) -> list[str]:
    errors = [f"missing:{field}" for field in sorted(REQUIRED_FIELDS - report.keys())]
    if report.get("review_status") not in REPORT_STATUSES:
        errors.append("invalid:review_status")
    confidence = report.get("confidence")
    if not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1:
        errors.append("invalid:confidence")
    if not isinstance(report.get("evidence"), list) or not report.get("evidence"):
        errors.append("invalid:evidence")
    sources = report.get("sources")
    if not isinstance(sources, dict) or not sources.get("observation_ids"):
        errors.append("invalid:sources")
    return errors


def reports_to_jsonl(reports: Iterable[dict[str, Any]]) -> str:
    rows = list(reports)
    for report in rows:
        errors = validate_report(report)
        if errors:
            raise ValueError(f"Invalid report {report.get('report_id')}: {', '.join(errors)}")
    return "".join(json.dumps(report, ensure_ascii=False, separators=(",", ":")) + "\n" for report in rows)
