from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

from .models import AnalysisGroup, EndpointGroup, EvidenceItem
from .taxonomy import cwe_category

TEST_ID = re.compile(r"BenchmarkTest\d{5}")


def load_benchmark_metadata(predictions_path: Path) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for line in predictions_path.read_text(encoding="utf-8").split("\n"):
        if line.strip():
            row = json.loads(line)
            result[row["test_id"]] = {
                "expected_cwe": f"CWE-{int(row['expected_cwe'])}",
                "category": str(row.get("category") or ""),
            }
    return result


def _test_id(row: dict[str, Any]) -> str | None:
    for key in ("file_or_url", "title", "description"):
        match = TEST_ID.search(str(row.get(key) or ""))
        if match:
            return match.group(0)
    return None


def _decode(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if item]
    try:
        value = json.loads(value or "[]")
    except (TypeError, json.JSONDecodeError):
        pass
    return [str(item) for item in value] if isinstance(value, list) else ([str(value)] if value else [])


def _public_location(value: Any) -> str:
    """Remove machine-specific scanner staging prefixes from published evidence."""
    location = str(value or "unknown").replace("\\", "/")
    for marker in ("vendor/BenchmarkJava/", "src/main/java/"):
        if marker in location:
            return location[location.rfind(marker):]
    return location.rsplit("/", 1)[-1]


def stable_group_id(test_id: str, expected_cwe: str) -> str:
    digest = hashlib.sha256(
        f"owasp-benchmark-java|{test_id}|{expected_cwe}|analysis-v1".encode()
    ).hexdigest()[:16]
    return f"AG-{digest}"


def group_observations(rows: Iterable[dict[str, Any]], metadata: dict[str, dict[str, str]]) -> list[AnalysisGroup]:
    buckets: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        test_id = _test_id(row)
        if test_id and test_id in metadata:
            buckets[(test_id, metadata[test_id]["expected_cwe"])].append(row)
    groups: list[AnalysisGroup] = []
    for (test_id, expected_cwe), items in sorted(buckets.items()):
        evidence = []
        for row in sorted(items, key=lambda value: value["observation_id"]):
            location = _public_location(row.get("file_or_url"))
            excerpt = str(row.get("evidence") or row.get("description") or "")[:1600]
            evidence.append(EvidenceItem(
                observation_id=row["observation_id"], tool=row["tool"], file_or_url=location,
                line_start=row.get("line_start"), line_end=row.get("line_end"),
                title=str(row.get("title") or "Security finding"), severity=str(row.get("severity") or "info").lower(),
                reported_cwe=_decode(row.get("cwe")), excerpt=excerpt,
            ))
        groups.append(AnalysisGroup(
            analysis_group_id=stable_group_id(test_id, expected_cwe), benchmark_test_id=test_id,
            expected_cwe=expected_cwe, category=metadata[test_id]["category"],
            observation_ids=sorted(item["observation_id"] for item in items),
            source_tools=sorted({str(item["tool"]) for item in items}),
            locations=sorted({f"{_public_location(item.get('file_or_url'))}:{item.get('line_start') or '?'}" for item in items}),
            evidence_items=evidence,
            grouping_reason=["same_benchmark_test_id", "same_expected_cwe"],
        ))
    return groups


def endpoint_path(uri: str) -> str:
    """Reduce a scanned URL to the endpoint the gateway allowlist speaks about.

    Host, scheme and query string drop out; numeric path segments collapse to
    ``{id}`` so ``/api/Products/1`` and ``/api/Products/2`` are one endpoint and
    line up with the ``{id}`` wildcards in the published routes.
    """
    path = urlsplit(str(uri or "")).path or "/"
    segments = ["{id}" if segment.isdigit() else segment for segment in path.split("/")]
    return "/".join(segments) or "/"


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(text or "").lower()).strip("_") or "uncategorized"


def _issue_key(row: dict[str, Any]) -> tuple[str, str]:
    """A group is one issue on one endpoint, not every issue on one endpoint.

    A single endpoint routinely carries unrelated alerts (missing CSP, a leaked
    private IP); merging them would force one verdict onto several findings.
    """
    cwes = _decode(row.get("cwe"))
    return (cwes[0] if cwes else "", _slug(row.get("title")))


def stable_endpoint_group_id(dataset: str, endpoint: str, cwe: str, issue: str) -> str:
    digest = hashlib.sha256(f"{dataset}|{endpoint}|{cwe}|{issue}|analysis-v1".encode()).hexdigest()[:16]
    return f"EG-{digest}"


def group_dast_observations(rows: Iterable[dict[str, Any]], dataset: str = "juice-shop-dast") -> list[EndpointGroup]:
    buckets: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        if row.get("dataset") != dataset:
            continue
        cwe, issue = _issue_key(row)
        buckets[(endpoint_path(row.get("file_or_url")), cwe, issue)].append(row)
    groups: list[EndpointGroup] = []
    for (endpoint, cwe, issue), items in sorted(buckets.items()):
        evidence = []
        methods: set[str] = set()
        for row in sorted(items, key=lambda value: value["observation_id"]):
            excerpt = str(row.get("evidence") or row.get("description") or "")[:1600]
            match = re.match(r"([A-Z]+) http", excerpt)
            methods.add(match.group(1) if match else "GET")
            evidence.append(EvidenceItem(
                # URLs are already publication-safe: no host filesystem paths.
                observation_id=row["observation_id"], tool=row["tool"], file_or_url=str(row.get("file_or_url") or endpoint),
                title=str(row.get("title") or "Security finding"), severity=str(row.get("severity") or "info").lower(),
                reported_cwe=_decode(row.get("cwe")), excerpt=excerpt,
            ))
        reasons: list[str] = ["same_endpoint_path"]
        if cwe:
            reasons.append("same_reported_cwe")
        groups.append(EndpointGroup(
            analysis_group_id=stable_endpoint_group_id(dataset, endpoint, cwe, issue),
            endpoint=endpoint,
            methods=sorted(methods),
            reported_cwes=[cwe] if cwe else [],
            category=cwe_category(cwe, fallback=issue),
            observation_ids=sorted(item["observation_id"] for item in items),
            source_tools=sorted({str(item["tool"]) for item in items}),
            locations=sorted({str(item.get("file_or_url") or endpoint) for item in items}),
            evidence_items=evidence,
            grouping_reason=reasons,  # type: ignore[arg-type]
        ))
    return groups


def load_dast_groups(db_path: Path, dataset: str = "juice-shop-dast") -> list[EndpointGroup]:
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = [dict(row) for row in conn.execute("SELECT * FROM findings WHERE dataset=? ORDER BY observation_id", (dataset,))]
    return group_dast_observations(rows, dataset)


def load_groups(db_path: Path, predictions_path: Path) -> list[AnalysisGroup]:
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = [dict(row) for row in conn.execute("SELECT * FROM findings ORDER BY observation_id")]
    return group_observations(rows, load_benchmark_metadata(predictions_path))


def canonical_bytes(groups: Iterable[AnalysisGroup]) -> bytes:
    payload = [group.model_dump(mode="json") for group in groups]
    return (json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def group_checksum(groups: Iterable[AnalysisGroup]) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(groups)).hexdigest()
