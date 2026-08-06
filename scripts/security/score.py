#!/usr/bin/env python3
"""Run a leakage-resistant OWASP Benchmark Java evaluation through 9Router.

The model receives Java source only. Ground-truth labels from
expectedresults-1.2.csv are loaded locally and are used only after inference.
The runner emits an immutable-style run directory containing the manifest,
per-test predictions, aggregate metrics, and a Markdown summary.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import hashlib
import json
import os
import random
import re
import sys
import time
import urllib.error
import urllib.request
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable


DEFAULT_MODEL = "gc/gemini-2.5-flash"
DEFAULT_BASE_URL = "http://127.0.0.1:20128/v1"
DEFAULT_KEY_ENV = "NINE_ROUTER_API_KEY"
DEFAULT_LOCAL_KEY = "local-router-no-auth"
HARNESS_DIR = Path(__file__).resolve().parent
PROJECT_DIR = HARNESS_DIR.parents[1]
DEFAULT_CONFIG_PATH = HARNESS_DIR / "configs" / "9router.json"
DEFAULT_BENCHMARK_DIR = PROJECT_DIR / "vendor" / "BenchmarkJava"
DEFAULT_RUNS_DIR = PROJECT_DIR / "artifacts" / "generated" / "llm"

SYSTEM_PROMPT = """\
You are a static application security testing engine for Java.
Analyze only the supplied Java source. Do not infer an answer from a filename,
test identifier, URL path, or the fact that this may be benchmark code.

Return exactly one JSON object with this schema:
{
  "vulnerable": true,
  "findings": [
    {
      "cwe": 89,
      "title": "Short vulnerability title",
      "line": 42,
      "confidence": 0.95,
      "evidence": "Concise source-level evidence"
    }
  ]
}

Use an empty findings array and vulnerable=false when there is no security
vulnerability. CWE must be an integer. Report concrete, exploitable security
issues only; do not report style, maintainability, or speculative concerns.
"""


@dataclass(frozen=True)
class BenchmarkCase:
    test_id: str
    category: str
    ground_truth: bool
    cwe: int
    source_path: Path


@dataclass
class ScanResult:
    test_id: str
    category: str
    expected_cwe: int
    ground_truth: bool
    status: str
    predicted_positive: bool | None
    vulnerable_claim: bool | None
    findings: list[dict[str, Any]]
    prompt_tokens: int | None
    completion_tokens: int | None
    total_tokens: int | None
    requests_with_usage: int
    requests_without_usage: int
    elapsed_seconds: float
    attempts: int
    error: str | None
    raw_content: str | None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate a 9Router model against OWASP Benchmark Java ground truth."
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=DEFAULT_CONFIG_PATH,
        help="9Router JSON configuration.",
    )
    parser.add_argument(
        "--benchmark-dir",
        type=Path,
        default=DEFAULT_BENCHMARK_DIR,
        help="Pinned BenchmarkJava checkout.",
    )
    parser.add_argument(
        "--lock-file",
        type=Path,
        default=Path(__file__).with_name("benchmark-lock.json"),
        help="Pinned benchmark commit and ground-truth checksum.",
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        default=DEFAULT_RUNS_DIR,
        help="Parent directory for immutable timestamped run artifacts.",
    )
    parser.add_argument("--model", default=None, help="Override config model.")
    parser.add_argument("--base-url", default=None, help="Override config endpoint.")
    parser.add_argument(
        "--api-key-env", default=None, help="Override config API-key env name."
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Balanced case count; use 0 for all cases (default: 20).",
    )
    parser.add_argument(
        "--categories",
        default="",
        help="Comma-separated Benchmark categories; empty means all.",
    )
    parser.add_argument(
        "--case-ids",
        default="",
        help="Comma-separated explicit BenchmarkTest IDs; overrides sampling.",
    )
    parser.add_argument("--seed", type=int, default=20260727)
    parser.add_argument("--concurrency", type=int, default=1)
    parser.add_argument("--timeout", type=float, default=900.0)
    parser.add_argument("--retries", type=int, default=2)
    parser.add_argument("--max-output-tokens", type=int, default=4096)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Select cases and write a manifest without calling 9Router.",
    )
    args = parser.parse_args()

    if args.limit < 0:
        parser.error("--limit must be zero or positive")
    if args.concurrency < 1:
        parser.error("--concurrency must be at least 1")
    if args.retries < 0:
        parser.error("--retries must be zero or positive")
    return args


def utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def normalize_base_url(value: str) -> str:
    return value.rstrip("/")


def load_router_config(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"9Router config not found: {path}")
    config = json.loads(path.read_text(encoding="utf-8"))
    required = ("base_url", "model", "api_key_env")
    missing = [key for key in required if not config.get(key)]
    if missing:
        raise ValueError(f"9Router config is missing: {', '.join(missing)}")
    return config


def read_git_commit(repository: Path) -> str | None:
    git_dir = repository / ".git"
    head_path = git_dir / "HEAD"
    if not head_path.is_file():
        return None
    head = head_path.read_text(encoding="utf-8").strip()
    if not head.startswith("ref: "):
        return head
    ref = head.removeprefix("ref: ").strip()
    loose_ref = git_dir / ref
    if loose_ref.is_file():
        return loose_ref.read_text(encoding="utf-8").strip()
    packed_refs = git_dir / "packed-refs"
    if packed_refs.is_file():
        for line in packed_refs.read_text(encoding="utf-8").splitlines():
            if line.startswith(("#", "^")):
                continue
            commit, _, packed_ref = line.partition(" ")
            if packed_ref == ref:
                return commit
    return None


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def validate_benchmark_lock(
    benchmark_dir: Path,
    lock_file: Path,
    case_count: int,
) -> dict[str, Any]:
    if not lock_file.is_file():
        raise FileNotFoundError(f"Benchmark lock file not found: {lock_file}")
    lock = json.loads(lock_file.read_text(encoding="utf-8"))
    actual_commit = read_git_commit(benchmark_dir)
    expected_commit = lock.get("commit")
    if actual_commit != expected_commit:
        raise RuntimeError(
            f"Benchmark commit mismatch: expected {expected_commit}, got {actual_commit}"
        )
    expected_path = benchmark_dir / lock["expected_results"]["path"]
    actual_hash = sha256_file(expected_path)
    expected_hash = lock["expected_results"]["sha256"]
    if actual_hash != expected_hash:
        raise RuntimeError(
            "Ground-truth checksum mismatch: "
            f"expected {expected_hash}, got {actual_hash}"
        )
    expected_cases = int(lock["expected_results"]["cases"])
    if case_count != expected_cases:
        raise RuntimeError(
            f"Benchmark case-count mismatch: expected {expected_cases}, got {case_count}"
        )
    return lock


def load_cases(benchmark_dir: Path) -> list[BenchmarkCase]:
    expected_path = benchmark_dir / "expectedresults-1.2.csv"
    source_dir = (
        benchmark_dir
        / "src"
        / "main"
        / "java"
        / "org"
        / "owasp"
        / "benchmark"
        / "testcode"
    )
    if not expected_path.is_file():
        raise FileNotFoundError(f"Ground-truth file not found: {expected_path}")
    if not source_dir.is_dir():
        raise FileNotFoundError(f"Benchmark source directory not found: {source_dir}")

    cases: list[BenchmarkCase] = []
    with expected_path.open("r", encoding="utf-8", newline="") as handle:
        for row in csv.reader(handle):
            if not row or row[0].lstrip().startswith("#"):
                continue
            if len(row) < 4:
                raise ValueError(f"Malformed expected-results row: {row!r}")
            test_id, category, vulnerable, cwe = (item.strip() for item in row[:4])
            source_path = source_dir / f"{test_id}.java"
            if not source_path.is_file():
                raise FileNotFoundError(f"Source file missing for {test_id}: {source_path}")
            cases.append(
                BenchmarkCase(
                    test_id=test_id,
                    category=category,
                    ground_truth=vulnerable.lower() == "true",
                    cwe=int(cwe),
                    source_path=source_path,
                )
            )
    if not cases:
        raise ValueError("No benchmark cases were loaded")
    return cases


def select_cases(cases: list[BenchmarkCase], args: argparse.Namespace) -> list[BenchmarkCase]:
    requested_categories = {
        item.strip() for item in args.categories.split(",") if item.strip()
    }
    if requested_categories:
        available = {case.category for case in cases}
        unknown = requested_categories - available
        if unknown:
            raise ValueError(f"Unknown categories: {', '.join(sorted(unknown))}")
        cases = [case for case in cases if case.category in requested_categories]

    requested_ids = {item.strip() for item in args.case_ids.split(",") if item.strip()}
    if requested_ids:
        by_id = {case.test_id: case for case in cases}
        missing = requested_ids - by_id.keys()
        if missing:
            raise ValueError(f"Unknown or filtered case IDs: {', '.join(sorted(missing))}")
        return [by_id[test_id] for test_id in sorted(requested_ids)]

    if args.limit == 0 or args.limit >= len(cases):
        return sorted(cases, key=lambda item: item.test_id)

    rng = random.Random(args.seed)
    buckets: dict[tuple[str, bool], list[BenchmarkCase]] = defaultdict(list)
    for case in cases:
        buckets[(case.category, case.ground_truth)].append(case)
    for bucket in buckets.values():
        rng.shuffle(bucket)

    selected: list[BenchmarkCase] = []
    ordered_keys = sorted(buckets, key=lambda item: (item[0], not item[1]))
    while len(selected) < args.limit:
        made_progress = False
        for key in ordered_keys:
            if buckets[key] and len(selected) < args.limit:
                selected.append(buckets[key].pop())
                made_progress = True
        if not made_progress:
            break
    return selected


def request_json(
    url: str,
    api_key: str,
    payload: dict[str, Any],
    timeout: float,
) -> dict[str, Any]:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def verify_router(
    base_url: str,
    api_key: str,
    model: str,
    timeout: float,
) -> None:
    request = urllib.request.Request(
        f"{base_url}/models",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Accept": "application/json",
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8"))
    model_ids = {
        item.get("id")
        for item in payload.get("data", [])
        if isinstance(item, dict) and item.get("id")
    }
    if model not in model_ids:
        raise RuntimeError(
            f"Required model {model!r} is not listed by {base_url}/models"
        )


def extract_json_object(content: str) -> dict[str, Any]:
    stripped = content.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?\s*", "", stripped, count=1)
        stripped = re.sub(r"\s*```$", "", stripped, count=1)
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        start = stripped.find("{")
        end = stripped.rfind("}")
        if start < 0 or end <= start:
            excerpt = stripped[:300].replace("\r", "\\r").replace("\n", "\\n")
            raise ValueError(
                f"Model response contains no JSON object; excerpt={excerpt!r}"
            )
        parsed = json.loads(stripped[start : end + 1])
    if not isinstance(parsed, dict):
        raise ValueError("Model response JSON must be an object")
    return parsed


def normalize_cwe(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        match = re.search(r"\d+", value)
        if match:
            return int(match.group())
    return None


def normalize_findings(payload: dict[str, Any]) -> list[dict[str, Any]]:
    raw = payload.get("findings", [])
    if not isinstance(raw, list):
        raise ValueError("Model response field 'findings' must be an array")
    findings: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        cwe = normalize_cwe(item.get("cwe"))
        line = item.get("line")
        confidence = item.get("confidence")
        findings.append(
            {
                "cwe": cwe,
                "title": str(item.get("title", "")).strip(),
                "line": line if isinstance(line, int) and line > 0 else None,
                "confidence": (
                    float(confidence)
                    if isinstance(confidence, (int, float))
                    else None
                ),
                "evidence": str(item.get("evidence", "")).strip(),
            }
        )
    return findings


def scan_case(
    case: BenchmarkCase,
    args: argparse.Namespace,
    api_key: str,
) -> ScanResult:
    started = time.perf_counter()
    source = case.source_path.read_text(encoding="utf-8")
    user_prompt = (
        "Analyze the following Java source. The identifier is provided only for "
        "result correlation and is not a vulnerability label.\n\n"
        f"Identifier: {case.test_id}\n"
        "```java\n"
        f"{source}\n"
        "```"
    )
    payload = {
        "model": args.model,
        "temperature": 0,
        "max_tokens": args.max_output_tokens,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
    }

    attempts = 0
    last_error: str | None = None
    prompt_tokens_reported = 0
    completion_tokens_reported = 0
    total_tokens_reported = 0
    requests_with_usage = 0
    requests_without_usage = 0
    last_content: str | None = None
    while attempts <= args.retries:
        attempts += 1
        try:
            response = request_json(
                f"{normalize_base_url(args.base_url)}/chat/completions",
                api_key,
                payload,
                args.timeout,
            )
            usage = response.get("usage") if isinstance(response.get("usage"), dict) else {}
            if isinstance(usage.get("total_tokens"), int):
                requests_with_usage += 1
                prompt_tokens_reported += int(usage.get("prompt_tokens") or 0)
                completion_tokens_reported += int(usage.get("completion_tokens") or 0)
                total_tokens_reported += int(usage["total_tokens"])
            else:
                requests_without_usage += 1
            choices = response.get("choices")
            if not isinstance(choices, list) or not choices:
                raise ValueError("9Router response has no choices")
            content = choices[0].get("message", {}).get("content")
            if not isinstance(content, str):
                raise ValueError("9Router response has no message content")
            last_content = content
            parsed = extract_json_object(content)
            findings = normalize_findings(parsed)
            vulnerable_claim = parsed.get("vulnerable")
            if not isinstance(vulnerable_claim, bool):
                vulnerable_claim = bool(findings)
            matched_cwe = any(item.get("cwe") == case.cwe for item in findings)
            return ScanResult(
                test_id=case.test_id,
                category=case.category,
                expected_cwe=case.cwe,
                ground_truth=case.ground_truth,
                status="success",
                predicted_positive=matched_cwe,
                vulnerable_claim=vulnerable_claim,
                findings=findings,
                prompt_tokens=(
                    prompt_tokens_reported if requests_with_usage else None
                ),
                completion_tokens=(
                    completion_tokens_reported if requests_with_usage else None
                ),
                total_tokens=total_tokens_reported if requests_with_usage else None,
                requests_with_usage=requests_with_usage,
                requests_without_usage=requests_without_usage,
                elapsed_seconds=round(time.perf_counter() - started, 6),
                attempts=attempts,
                error=None,
                raw_content=content,
            )
        except urllib.error.HTTPError as exc:
            requests_without_usage += 1
            response_text = exc.read().decode("utf-8", errors="replace")
            last_error = f"HTTP {exc.code}: {response_text[:500]}"
            retryable = exc.code == 429 or 500 <= exc.code < 600
            if not retryable or attempts > args.retries:
                break
        except (urllib.error.URLError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
            if not isinstance(exc, ValueError):
                requests_without_usage += 1
            last_error = f"{type(exc).__name__}: {exc}"
            if attempts > args.retries:
                break
        time.sleep(min(2 ** (attempts - 1), 8))

    return ScanResult(
        test_id=case.test_id,
        category=case.category,
        expected_cwe=case.cwe,
        ground_truth=case.ground_truth,
        status="error",
        predicted_positive=None,
        vulnerable_claim=None,
        findings=[],
        prompt_tokens=prompt_tokens_reported if requests_with_usage else None,
        completion_tokens=completion_tokens_reported if requests_with_usage else None,
        total_tokens=total_tokens_reported if requests_with_usage else None,
        requests_with_usage=requests_with_usage,
        requests_without_usage=requests_without_usage,
        elapsed_seconds=round(time.perf_counter() - started, 6),
        attempts=attempts,
        error=last_error or "Unknown scan error",
        raw_content=last_content,
    )


def safe_divide(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def confusion(results: Iterable[ScanResult]) -> dict[str, Any]:
    successful = [item for item in results if item.status == "success"]
    tp = sum(item.ground_truth and item.predicted_positive is True for item in successful)
    fn = sum(item.ground_truth and item.predicted_positive is False for item in successful)
    fp = sum(not item.ground_truth and item.predicted_positive is True for item in successful)
    tn = sum(not item.ground_truth and item.predicted_positive is False for item in successful)
    precision = safe_divide(tp, tp + fp)
    recall = safe_divide(tp, tp + fn)
    return {
        "TP": tp,
        "FP": fp,
        "FN": fn,
        "TN": tn,
        "precision": precision,
        "recall": recall,
        "f1": (
            2 * precision * recall / (precision + recall)
            if precision is not None and recall is not None and precision + recall
            else None
        ),
        "false_positive_rate": safe_divide(fp, fp + tn),
        "scored_cases": len(successful),
    }


def aggregate_metrics(
    results: list[ScanResult],
    selected_count: int,
    elapsed_seconds: float,
) -> dict[str, Any]:
    successful = [item for item in results if item.status == "success"]
    failed = [item for item in results if item.status != "success"]
    usage_complete = all(item.requests_without_usage == 0 for item in results)
    prompt_tokens = sum(item.prompt_tokens or 0 for item in results)
    completion_tokens = sum(item.completion_tokens or 0 for item in results)
    total_tokens = sum(item.total_tokens or 0 for item in results)

    categories: dict[str, list[ScanResult]] = defaultdict(list)
    cwes: dict[int, list[ScanResult]] = defaultdict(list)
    for result in results:
        categories[result.category].append(result)
        cwes[result.expected_cwe].append(result)

    return {
        "coverage": {
            "selected_cases": selected_count,
            "successful_cases": len(successful),
            "failed_cases": len(failed),
            "scoring_complete": not failed and len(successful) == selected_count,
        },
        "timing": {
            "wall_clock_seconds": round(elapsed_seconds, 6),
            "sum_case_seconds": round(sum(item.elapsed_seconds for item in results), 6),
        },
        "tokens": {
            "accounting": "API-reported usage only",
            "requests_with_usage": sum(item.requests_with_usage for item in results),
            "requests_without_usage": sum(
                item.requests_without_usage for item in results
            ),
            "prompt_tokens_reported": prompt_tokens,
            "completion_tokens_reported": completion_tokens,
            "total_tokens_reported": total_tokens,
            "total_tokens_exact": total_tokens if usage_complete else None,
        },
        "findings": {
            "raw_model_findings": sum(len(item.findings) for item in successful),
            "tests_claimed_vulnerable": sum(
                item.vulnerable_claim is True for item in successful
            ),
            "tests_with_expected_cwe_match": sum(
                item.predicted_positive is True for item in successful
            ),
        },
        "overall": confusion(results),
        "by_category": {
            category: confusion(items) for category, items in sorted(categories.items())
        },
        "by_cwe": {
            f"CWE-{cwe}": confusion(items) for cwe, items in sorted(cwes.items())
        },
    }


def json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def write_bytes(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(content)
    temporary.replace(path)


def write_json(path: Path, value: Any) -> None:
    write_bytes(path, json_bytes(value))


def write_jsonl(path: Path, values: Iterable[Any]) -> None:
    content = "".join(
        json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n"
        for value in values
    )
    write_bytes(path, content.encode("utf-8"))


def percentage(value: float | None) -> str:
    return "N/A" if value is None else f"{value * 100:.2f}%"


def render_summary(
    args: argparse.Namespace,
    manifest: dict[str, Any],
    metrics: dict[str, Any],
) -> str:
    overall = metrics["overall"]
    coverage = metrics["coverage"]
    tokens = metrics["tokens"]
    findings = metrics["findings"]
    lines = [
        "# OWASP Benchmark Java — 9Router results",
        "",
        f"- Run ID: `{manifest['run_id']}`",
        f"- Benchmark commit: `{manifest['benchmark']['commit']}`",
        f"- Model: `{args.model}`",
        f"- Cases: {coverage['successful_cases']}/{coverage['selected_cases']} successful",
        f"- Wall-clock: {metrics['timing']['wall_clock_seconds']:.3f} seconds",
        f"- Findings returned by model: {findings['raw_model_findings']}",
        f"- API-reported tokens: {tokens['total_tokens_reported']}",
        "",
        "## Ground-truth metrics",
        "",
        "| TP | FP | FN | TN | Precision | Recall | F1 | FPR |",
        "| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        (
            f"| {overall['TP']} | {overall['FP']} | {overall['FN']} | "
            f"{overall['TN']} | {percentage(overall['precision'])} | "
            f"{percentage(overall['recall'])} | {percentage(overall['f1'])} | "
            f"{percentage(overall['false_positive_rate'])} |"
        ),
        "",
        "A prediction counts as positive only when the model reports the CWE expected",
        "for that Benchmark test. Ground truth was not included in model requests.",
        "",
        "## By category",
        "",
        "| Category | Cases | TP | FP | FN | TN | Precision | Recall |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for category, values in metrics["by_category"].items():
        lines.append(
            f"| {category} | {values['scored_cases']} | {values['TP']} | "
            f"{values['FP']} | {values['FN']} | {values['TN']} | "
            f"{percentage(values['precision'])} | {percentage(values['recall'])} |"
        )
    if not coverage["scoring_complete"]:
        lines.extend(
            [
                "",
                "> **Incomplete run:** failed cases are excluded from scoring. Do not",
                "> publish these metrics until every selected case succeeds.",
            ]
        )
    return "\n".join(lines) + "\n"


def outcome(result: ScanResult) -> str:
    if result.status != "success" or result.predicted_positive is None:
        return "UNSCORED"
    if result.ground_truth and result.predicted_positive:
        return "TP"
    if result.ground_truth and not result.predicted_positive:
        return "FN"
    if not result.ground_truth and result.predicted_positive:
        return "FP"
    return "TN"


def normalized_prediction(result: ScanResult) -> dict[str, Any]:
    value = asdict(result)
    value.pop("raw_content", None)
    value["outcome"] = outcome(result)
    return value


def main() -> int:
    args = parse_args()
    args.config = args.config.resolve()
    args.benchmark_dir = args.benchmark_dir.resolve()
    args.lock_file = args.lock_file.resolve()
    args.output_root = args.output_root.resolve()
    router_config = load_router_config(args.config)
    args.model = args.model or router_config.get("model", DEFAULT_MODEL)
    args.base_url = args.base_url or router_config.get("base_url", DEFAULT_BASE_URL)
    args.api_key_env = args.api_key_env or router_config.get(
        "api_key_env", DEFAULT_KEY_ENV
    )
    args.base_url = normalize_base_url(args.base_url)

    cases = load_cases(args.benchmark_dir)
    benchmark_lock = validate_benchmark_lock(
        args.benchmark_dir, args.lock_file, len(cases)
    )
    selected = select_cases(cases, args)
    if not selected:
        raise ValueError("Selection produced no benchmark cases")

    run_started_at = utc_now()
    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + f"-{args.model.replace('/', '-')}"
    run_dir = args.output_root / run_id
    prompt_hash = hashlib.sha256(SYSTEM_PROMPT.encode("utf-8")).hexdigest()
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "run_id": run_id,
        "started_at": run_started_at,
        "status": "dry-run" if args.dry_run else "running",
        "benchmark": {
            "repository": "https://github.com/OWASP-Benchmark/BenchmarkJava.git",
            "path": str(args.benchmark_dir),
            "commit": read_git_commit(args.benchmark_dir),
            "lock_file": str(args.lock_file),
            "lock": benchmark_lock,
            "expected_results": "expectedresults-1.2.csv",
            "total_cases": len(cases),
            "selected_cases": len(selected),
        },
        "router": {
            "config": str(args.config),
            "base_url": args.base_url,
            "model": args.model,
            "api_key_source": args.api_key_env,
            "api_key_persisted": False,
        },
        "selection": {
            "limit": args.limit,
            "categories": sorted({case.category for case in selected}),
            "case_ids": [case.test_id for case in selected],
            "seed": args.seed,
        },
        "execution": {
            "concurrency": args.concurrency,
            "timeout_seconds": args.timeout,
            "retries": args.retries,
            "max_output_tokens": args.max_output_tokens,
        },
        "leakage_controls": {
            "ground_truth_sent_to_model": False,
            "metadata_xml_sent_to_model": False,
            "model_input": "Java source plus opaque BenchmarkTest identifier only",
            "system_prompt_sha256": prompt_hash,
        },
    }
    write_json(run_dir / "manifest.json", manifest)
    write_jsonl(
        run_dir / "raw" / "selected-cases.jsonl",
        (
            {
                "test_id": case.test_id,
                "category": case.category,
                "ground_truth": case.ground_truth,
                "cwe": case.cwe,
                "source_path": str(case.source_path.relative_to(args.benchmark_dir)),
            }
            for case in selected
        ),
    )

    if args.dry_run:
        print(f"Dry run created: {run_dir}")
        print(f"Selected cases: {len(selected)}")
        return 0

    api_key = os.environ.get(
        args.api_key_env,
        router_config.get("local_fallback_key", DEFAULT_LOCAL_KEY),
    )
    verify_router(args.base_url, api_key, args.model, min(args.timeout, 30.0))
    started = time.perf_counter()

    results_by_id: dict[str, ScanResult] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        future_map = {
            pool.submit(scan_case, case, args, api_key): case for case in selected
        }
        for index, future in enumerate(
            concurrent.futures.as_completed(future_map), start=1
        ):
            case = future_map[future]
            try:
                result = future.result()
            except Exception as exc:  # Preserve unexpected worker failures as evidence.
                result = ScanResult(
                    test_id=case.test_id,
                    category=case.category,
                    expected_cwe=case.cwe,
                    ground_truth=case.ground_truth,
                    status="error",
                    predicted_positive=None,
                    vulnerable_claim=None,
                    findings=[],
                    prompt_tokens=None,
                    completion_tokens=None,
                    total_tokens=None,
                    requests_with_usage=0,
                    requests_without_usage=0,
                    elapsed_seconds=0.0,
                    attempts=0,
                    error=f"{type(exc).__name__}: {exc}",
                    raw_content=None,
                )
            results_by_id[case.test_id] = result
            print(
                f"[{index}/{len(selected)}] {case.test_id}: "
                f"{result.status}, findings={len(result.findings)}, "
                f"tokens={result.total_tokens}"
            )

    elapsed = time.perf_counter() - started
    results = [results_by_id[case.test_id] for case in selected]
    metrics = aggregate_metrics(results, len(selected), elapsed)
    manifest["ended_at"] = utc_now()
    manifest["status"] = (
        "success" if metrics["coverage"]["scoring_complete"] else "incomplete"
    )
    manifest["output_files"] = [
        "manifest.json",
        "raw/selected-cases.jsonl",
        "raw/model-responses.jsonl",
        "normalized/predictions.jsonl",
        "metrics/overall.json",
        "metrics/by-cwe.json",
        "metrics/comparison.md",
        "logs/errors.jsonl",
    ]

    write_jsonl(
        run_dir / "raw" / "model-responses.jsonl",
        (
            {
                "test_id": item.test_id,
                "status": item.status,
                "raw_content": item.raw_content,
                "prompt_tokens": item.prompt_tokens,
                "completion_tokens": item.completion_tokens,
                "total_tokens": item.total_tokens,
                "attempts": item.attempts,
                "error": item.error,
            }
            for item in results
        ),
    )
    write_jsonl(
        run_dir / "normalized" / "predictions.jsonl",
        (normalized_prediction(item) for item in results),
    )
    write_json(run_dir / "metrics" / "overall.json", metrics)
    write_json(run_dir / "metrics" / "by-cwe.json", metrics["by_cwe"])
    write_bytes(
        run_dir / "metrics" / "comparison.md",
        render_summary(args, manifest, metrics).encode("utf-8"),
    )
    write_jsonl(
        run_dir / "logs" / "errors.jsonl",
        (
            {
                "test_id": item.test_id,
                "attempts": item.attempts,
                "error": item.error,
            }
            for item in results
            if item.status != "success"
        ),
    )
    write_json(run_dir / "manifest.json", manifest)

    print(f"Run artifacts: {run_dir}")
    print(
        "TP={TP} FP={FP} FN={FN} TN={TN} precision={precision} recall={recall}".format(
            **metrics["overall"]
        )
    )
    return 0 if metrics["coverage"]["scoring_complete"] else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("Interrupted", file=sys.stderr)
        raise SystemExit(130)
    except Exception as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(1)
