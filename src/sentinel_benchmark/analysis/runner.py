from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from sentinel_benchmark.search import search_index

from .artifacts import atomic_json, write_checksums, write_jsonl
from .guard import validate_candidate
from .models import AnalysisGroup, ReportRecord, ReportSources
from .prompting import PROMPT_VERSION, SYSTEM_PROMPT, build_payload, prompt_hash
from .providers import Provider
from .taxonomy import cwe_name


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def retrieve(db_path: Path, group: AnalysisGroup, limit: int = 3) -> list[dict[str, Any]]:
    return search_index(db_path, f"{group.expected_cwe} {group.category}", "knowledge", limit)


def run_batch(*, groups: list[AnalysisGroup], db_path: Path, provider: Provider, run_root: Path, tag: str, limit: int | None = None) -> Path:
    selected = groups[:limit] if limit is not None else groups
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"{stamp}-{tag}"
    run_dir = run_root / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    reports, errors, traces, responses = [], [], [], []
    for group in selected:
        knowledge = retrieve(db_path, group)
        payload = build_payload(group, knowledge)
        traces.append({"analysis_group_id": group.analysis_group_id, "query": f"{group.expected_cwe} {group.category}", "document_ids": [row["document_id"] for row in knowledge]})
        output = guard = metadata = None
        used_payload = payload
        last_error = None
        for attempt in range(2):
            try:
                used_payload = payload if attempt == 0 else {
                    **payload,
                    "retry_correction": "The previous JSON failed validation. Correct every issue below and return only the corrected object: " + str(last_error)[:1200],
                }
                candidate, metadata = provider.analyze(system_prompt=SYSTEM_PROMPT, user_payload=used_payload)
                output, guard = validate_candidate(candidate, group)
                responses.append({"analysis_group_id": group.analysis_group_id, "candidate": candidate, "provider_metadata": {**metadata, "retry_count": attempt}})
                if output is not None and guard.passed:
                    break
                last_error = "; ".join(guard.failures)
            except (ValueError, KeyError, TypeError, ValidationError, json.JSONDecodeError) as exc:
                last_error = f"{type(exc).__name__}: {exc}"
        if output is None or guard is None or not guard.passed:
            errors.append({"analysis_group_id": group.analysis_group_id, "error_type": "provider_or_guard_failure", "message": last_error or "unknown failure"})
            continue
        created = _now()
        report_id = "AR-" + uuid.uuid5(uuid.NAMESPACE_URL, f"{run_id}|{group.analysis_group_id}").hex[:16]
        record = ReportRecord(
            report_id=report_id, analysis_group_id=group.analysis_group_id,
            benchmark_test_id=group.benchmark_test_id, expected_cwe=group.expected_cwe,
            vulnerability_name=cwe_name(group.expected_cwe, group.category), category=group.category, grouping_mode=group.grouping_mode,
            **output.model_dump(), evidence=group.evidence_items,
            sources=ReportSources(observation_ids=group.observation_ids, source_tools=group.source_tools, kb_document_ids=[row["document_id"] for row in knowledge]),
            retrieval=[{"document_id": row["document_id"], "title": row.get("title", ""), "source": row.get("source", ""), "score": row.get("rank")} for row in knowledge],
            guard=guard, provider=provider.name, model=metadata.get("model", provider.model),
            prompt_version=PROMPT_VERSION, prompt_sha256=prompt_hash(used_payload), run_id=run_id, created_at=created,
        )
        reports.append(record.model_dump(mode="json"))
    status = "successful" if len(reports) == len(selected) else ("partial" if reports else "failed")
    manifest = {"schema_version": "1.0", "run_id": run_id, "tag": tag, "provider": provider.name, "model": provider.model, "created_at": _now(), "status": status, "requested_groups": len(selected)}
    summary = {"run_id": run_id, "status": status, "requested": len(selected), "successful": len(reports), "failed": len(errors), "guard_passed": sum(row["guard"]["passed"] for row in reports)}
    atomic_json(run_dir / "manifest.json", manifest)
    write_jsonl(run_dir / "analysis-groups.jsonl", [group.model_dump(mode="json") for group in selected])
    write_jsonl(run_dir / "retrieval-trace.jsonl", traces)
    write_jsonl(run_dir / "llm-responses.jsonl", responses)
    write_jsonl(run_dir / "reports.jsonl", reports)
    write_jsonl(run_dir / "errors.jsonl", errors)
    write_jsonl(run_dir / "review-events.jsonl", [])
    atomic_json(run_dir / "summary.json", summary)
    write_checksums(run_dir)
    return run_dir
