#!/usr/bin/env python3
"""Run Vercel DeepSec against OWASP Benchmark Java through local 9Router.

This is the scanner-harness evaluation path. DeepSec receives Java source files
only. OWASP expected results are joined after DeepSec finishes so TP/FP/FN/TN
are ground-truth metrics rather than LLM-judge labels.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from collections import Counter, defaultdict
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

import score as benchmark_core


HARNESS_DIR = Path(__file__).resolve().parent
PROJECT_DIR = HARNESS_DIR.parents[1]
DEFAULT_BENCHMARK_DIR = PROJECT_DIR / "vendor" / "BenchmarkJava"
DEFAULT_RUNS_DIR = PROJECT_DIR / "artifacts" / "generated" / "deepsec"
DEFAULT_COMPOSE_FILE = HARNESS_DIR / "configs" / "docker-compose.deepsec.yml"
DEFAULT_ROUTER_CONFIG = HARNESS_DIR / "configs" / "9router.json"
DEFAULT_LOCK_FILE = HARNESS_DIR / "benchmark-lock.json"
DEFAULT_PROJECT_ID = "owasp-benchmark"
DEEPSEC_COMMIT = "f75a16803ec5250938bacfe41571d929e8564f45"


CATEGORY_PATTERNS: dict[str, tuple[str, ...]] = {
    "pathtraver": (
        "path traversal",
        "path-traversal",
        "directory traversal",
        "directory-traversal",
        "cwe-22",
    ),
    "hash": ("weak hash", "insecure hash", "broken hash", "md5", "sha-1", "cwe-328"),
    "trustbound": ("trust boundary", "trust-boundary", "cwe-501"),
    "crypto": (
        "weak crypto",
        "weak-crypto",
        "insecure crypto",
        "insecure-crypto",
        "weak cipher",
        "insecure cipher",
        "broken cipher",
        "cwe-327",
    ),
    "cmdi": (
        "command injection",
        "command-injection",
        "os command",
        "shell injection",
        "processbuilder",
        "runtime.exec",
        "cwe-78",
    ),
    "sqli": ("sql injection", "sql-injection", "sqli", "cwe-89"),
    "ldapi": ("ldap injection", "ldap-injection", "ldapi", "cwe-90"),
    "xss": ("cross-site scripting", "cross site scripting", "xss", "cwe-79"),
    "weakrand": (
        "weak random",
        "weak-random",
        "insecure random",
        "insecure-random",
        "predictable random",
        "java.util.random",
        "cwe-330",
    ),
    "securecookie": (
        "secure cookie",
        "secure-cookie",
        "cookie secure",
        "missing secure flag",
        "insecure cookie",
        "cwe-614",
    ),
    "xpathi": ("xpath injection", "xpath-injection", "xpathi", "cwe-643"),
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Benchmark the DeepSec scanner harness through local 9Router."
    )
    parser.add_argument("--benchmark-dir", type=Path, default=DEFAULT_BENCHMARK_DIR)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_RUNS_DIR)
    parser.add_argument("--compose-file", type=Path, default=DEFAULT_COMPOSE_FILE)
    parser.add_argument("--config", type=Path, default=DEFAULT_ROUTER_CONFIG)
    parser.add_argument("--lock-file", type=Path, default=DEFAULT_LOCK_FILE)
    parser.add_argument("--project-id", default=DEFAULT_PROJECT_ID)
    parser.add_argument("--model", default=None)
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--categories", default="")
    parser.add_argument("--case-ids", default="")
    parser.add_argument("--seed", type=int, default=20260727)
    parser.add_argument("--concurrency", type=int, default=1)
    parser.add_argument("--batch-size", type=int, default=1)
    parser.add_argument("--max-turns", type=int, default=80)
    parser.add_argument(
        "--thinking-level",
        choices=("off", "minimal", "low", "medium", "high"),
        default="medium",
    )
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if args.limit < 0:
        parser.error("--limit must be zero or positive")
    if args.concurrency < 1 or args.batch_size < 1:
        parser.error("--concurrency and --batch-size must be positive")
    if args.max_turns < 1:
        parser.error("--max-turns must be positive")
    return args


def utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def write_jsonl(path: Path, values: Iterable[Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(
            json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n"
            for value in values
        ),
        encoding="utf-8",
    )


def run_logged(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    log_path: Path,
) -> tuple[int, float]:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    with log_path.open("w", encoding="utf-8", errors="replace") as log:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        assert process.stdout is not None
        for line in process.stdout:
            print(line, end="", flush=True)
            log.write(line)
        return_code = process.wait()
    return return_code, time.perf_counter() - started


def compose_command(compose_file: Path, *args: str) -> list[str]:
    return ["docker", "compose", "-f", str(compose_file), *args]


def select_cases(
    all_cases: list[benchmark_core.BenchmarkCase], args: argparse.Namespace
) -> list[benchmark_core.BenchmarkCase]:
    selection_args = argparse.Namespace(
        limit=args.limit,
        categories=args.categories,
        case_ids=args.case_ids,
        seed=args.seed,
    )
    return benchmark_core.select_cases(all_cases, selection_args)


def latest_process_run(data_root: Path, project_id: str) -> tuple[Path, dict[str, Any]]:
    runs_dir = data_root / project_id / "runs"
    candidates: list[tuple[Path, dict[str, Any]]] = []
    for path in runs_dir.glob("*.json"):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if value.get("type") == "process":
            candidates.append((path, value))
    if not candidates:
        raise RuntimeError(f"DeepSec produced no process run metadata under {runs_dir}")
    return max(candidates, key=lambda item: item[0].stat().st_mtime_ns)


def file_record_path(data_root: Path, project_id: str, relative_path: str) -> Path:
    return data_root / project_id / "files" / f"{relative_path}.json"


def finding_text(finding: dict[str, Any]) -> str:
    parts = (
        finding.get("vulnSlug"),
        finding.get("title"),
        finding.get("description"),
        finding.get("recommendation"),
    )
    return " ".join(str(part) for part in parts if part).lower()


def finding_matches_category(finding: dict[str, Any], category: str) -> bool:
    text = finding_text(finding)
    return any(pattern in text for pattern in CATEGORY_PATTERNS.get(category, ()))


def classify(ground_truth: bool, predicted_positive: bool) -> str:
    if ground_truth and predicted_positive:
        return "TP"
    if ground_truth and not predicted_positive:
        return "FN"
    if not ground_truth and predicted_positive:
        return "FP"
    return "TN"


def safe_divide(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def confusion(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    outcomes = Counter(record["outcome"] for record in records)
    tp = outcomes["TP"]
    fp = outcomes["FP"]
    fn = outcomes["FN"]
    tn = outcomes["TN"]
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
        "cases": tp + fp + fn + tn,
    }


def normalize_deepsec_results(
    selected: list[benchmark_core.BenchmarkCase],
    *,
    benchmark_dir: Path,
    data_root: Path,
    project_id: str,
    deepsec_run_id: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, int]]:
    predictions: list[dict[str, Any]] = []
    raw_findings: list[dict[str, Any]] = []
    token_totals = {
        "input_tokens": 0,
        "output_tokens": 0,
        "cache_read_input_tokens": 0,
        "cache_creation_input_tokens": 0,
    }

    for case in selected:
        relative_path = case.source_path.relative_to(benchmark_dir).as_posix()
        record_path = file_record_path(data_root, project_id, relative_path)
        if not record_path.is_file():
            raise RuntimeError(f"DeepSec file record missing: {record_path}")
        file_record = json.loads(record_path.read_text(encoding="utf-8"))
        if file_record.get("status") != "analyzed":
            raise RuntimeError(
                f"DeepSec did not analyze {case.test_id}: "
                f"status={file_record.get('status')!r}"
            )
        findings = [
            finding
            for finding in file_record.get("findings", [])
            if finding.get("producedByRunId") == deepsec_run_id
        ]
        matching = [
            finding
            for finding in findings
            if finding_matches_category(finding, case.category)
        ]
        predicted_positive = bool(matching)
        outcome = classify(case.ground_truth, predicted_positive)

        analyses = [
            analysis
            for analysis in file_record.get("analysisHistory", [])
            if analysis.get("runId") == deepsec_run_id
        ]
        if not analyses:
            raise RuntimeError(
                f"DeepSec analysis history missing for {case.test_id} "
                f"in run {deepsec_run_id}"
            )
        for analysis in analyses:
            usage = analysis.get("usage") or {}
            token_totals["input_tokens"] += int(usage.get("inputTokens") or 0)
            token_totals["output_tokens"] += int(usage.get("outputTokens") or 0)
            token_totals["cache_read_input_tokens"] += int(
                usage.get("cacheReadInputTokens") or 0
            )
            token_totals["cache_creation_input_tokens"] += int(
                usage.get("cacheCreationInputTokens") or 0
            )

        prediction = {
            "test_id": case.test_id,
            "file": relative_path,
            "category": case.category,
            "expected_cwe": case.cwe,
            "ground_truth": case.ground_truth,
            "predicted_positive": predicted_positive,
            "outcome": outcome,
            "deepsec_findings": len(findings),
            "matching_findings": len(matching),
            "deepsec_status": file_record.get("status"),
            "analysis": analyses,
        }
        predictions.append(prediction)
        for finding in findings:
            raw_findings.append(
                {
                    "test_id": case.test_id,
                    "file": relative_path,
                    "category": case.category,
                    "expected_cwe": case.cwe,
                    "matches_expected_category": finding in matching,
                    **finding,
                }
            )
    return predictions, raw_findings, token_totals


def percentage(value: float | None) -> str:
    return "N/A" if value is None else f"{value * 100:.2f}%"


def render_comparison(results: dict[str, Any]) -> str:
    overall = results["metrics"]["overall"]
    tokens = results["tokens"]
    timing = results["timing"]
    findings = results["findings"]
    lines = [
        "# DeepSec + 9Router — OWASP Benchmark results",
        "",
        f"- Run ID: `{results['run_id']}`",
        f"- DeepSec run: `{results['scanner']['deepsec_run_id']}`",
        f"- DeepSec commit: `{results['scanner']['commit']}`",
        f"- Model: `{results['router']['model']}`",
        f"- Cases: {results['coverage']['processed_cases']}/{results['coverage']['selected_cases']}",
        f"- DeepSec findings: {findings['total']}",
        f"- Findings matching expected class: {findings['matching_expected_class']}",
        f"- Input tokens: {tokens['input_tokens']}",
        f"- Output tokens: {tokens['output_tokens']}",
        f"- Total tokens: {tokens['total_tokens']}",
        f"- DeepSec process wall-clock: {timing['process_wall_clock_seconds']:.3f}s",
        f"- Total wall-clock: {timing['total_wall_clock_seconds']:.3f}s",
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
        "TP/FP/FN/TN are joined against OWASP expectedresults-1.2.csv after",
        "DeepSec finishes. No LLM judge is used for these metrics.",
        "",
        "## By CWE",
        "",
        "| CWE | Cases | TP | FP | FN | TN | Precision | Recall |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for cwe, metric in results["metrics"]["by_cwe"].items():
        lines.append(
            f"| {cwe} | {metric['cases']} | {metric['TP']} | {metric['FP']} | "
            f"{metric['FN']} | {metric['TN']} | "
            f"{percentage(metric['precision'])} | {percentage(metric['recall'])} |"
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    args = parse_args()
    args.benchmark_dir = args.benchmark_dir.resolve()
    args.output_root = args.output_root.resolve()
    args.compose_file = args.compose_file.resolve()
    args.config = args.config.resolve()
    args.lock_file = args.lock_file.resolve()

    router = benchmark_core.load_router_config(args.config)
    model = args.model or router["model"]
    cases = benchmark_core.load_cases(args.benchmark_dir)
    lock = benchmark_core.validate_benchmark_lock(
        args.benchmark_dir, args.lock_file, len(cases)
    )
    selected = select_cases(cases, args)
    if not selected:
        raise RuntimeError("No benchmark cases selected")

    run_id = (
        datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        + f"-deepsec-{model.replace('/', '-')}"
    )
    run_dir = args.output_root / run_id
    relative_paths = [
        case.source_path.relative_to(args.benchmark_dir).as_posix()
        for case in selected
    ]
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "run_id": run_id,
        "status": "dry-run" if args.dry_run else "running",
        "started_at": utc_now(),
        "benchmark": {
            "commit": lock["commit"],
            "expected_results_sha256": lock["expected_results"]["sha256"],
            "total_cases": len(cases),
            "selected_cases": len(selected),
        },
        "scanner": {
            "name": "Vercel DeepSec",
            "commit": DEEPSEC_COMMIT,
            "mode": "direct process --files-from",
        },
        "router": {
            "base_url": router["base_url"],
            "model": model,
            "api_key_env": router["api_key_env"],
            "api_key_persisted": False,
        },
        "selection": {
            "limit": args.limit,
            "seed": args.seed,
            "categories": sorted({case.category for case in selected}),
            "positive": sum(case.ground_truth for case in selected),
            "negative": sum(not case.ground_truth for case in selected),
        },
        "leakage_controls": {
            "ground_truth_sent_to_deepsec": False,
            "expected_results_mounted_in_container": False,
            "metadata_xml_sent_to_deepsec": False,
        },
    }
    write_json(run_dir / "manifest.json", manifest)
    write_jsonl(
        run_dir / "raw" / "selected-cases.jsonl",
        (
            {
                **asdict(case),
                "source_path": relative_path,
            }
            for case, relative_path in zip(selected, relative_paths, strict=True)
        ),
    )
    (run_dir / "raw").mkdir(parents=True, exist_ok=True)
    (run_dir / "raw" / "selected-files.txt").write_text(
        "\n".join(relative_paths) + "\n", encoding="utf-8"
    )
    if args.dry_run:
        print(f"Dry run created: {run_dir}")
        print(f"Selected cases: {len(selected)}")
        return 0

    api_key = os.environ.get(
        router["api_key_env"], router.get("local_fallback_key", "local-router-no-auth")
    )
    benchmark_core.verify_router(router["base_url"], api_key, model, 30.0)

    environment = os.environ.copy()
    environment["DEEPSEC_RUN_DIR"] = str(run_dir)
    environment["NINE_ROUTER_API_KEY"] = api_key
    environment["COMPOSE_PROJECT_NAME"] = "sast-benchmark-deepsec"
    total_started = time.perf_counter()
    build_seconds = 0.0
    if not args.skip_build:
        build_code, build_seconds = run_logged(
            compose_command(args.compose_file, "build", "deepsec"),
            cwd=PROJECT_DIR,
            env=environment,
            log_path=run_dir / "logs" / "deepsec-build.log",
        )
        if build_code != 0:
            raise RuntimeError(
                f"DeepSec image build failed; see {run_dir / 'logs/deepsec-build.log'}"
            )

    process_args = [
        "run",
        "--rm",
        "deepsec",
        "process",
        "--project-id",
        args.project_id,
        "--root",
        "/benchmark",
        "--files-from",
        "/run/raw/selected-files.txt",
        "--agent",
        "pi",
        "--model",
        f"openai/{model}",
        "--ai-provider",
        "openai",
        "--ai-base-url",
        "http://host.docker.internal:20128/v1",
        "--ai-api-key-env",
        "NINE_ROUTER_API_KEY",
        "--concurrency",
        str(args.concurrency),
        "--batch-size",
        str(args.batch_size),
        "--max-turns",
        str(args.max_turns),
        "--thinking-level",
        args.thinking_level,
    ]
    process_code, process_seconds = run_logged(
        compose_command(args.compose_file, *process_args),
        cwd=PROJECT_DIR,
        env=environment,
        log_path=run_dir / "logs" / "deepsec-process.log",
    )
    total_seconds = time.perf_counter() - total_started

    data_root = run_dir / "deepsec-data"
    run_meta_path, run_meta = latest_process_run(data_root, args.project_id)
    deepsec_run_id = str(run_meta["runId"])
    if run_meta.get("phase") != "done":
        raise RuntimeError(f"DeepSec run did not finish: {run_meta_path}")
    stats = run_meta.get("stats") or {}
    if int(stats.get("filesProcessed") or 0) != len(selected):
        raise RuntimeError(
            "DeepSec coverage mismatch: "
            f"processed={stats.get('filesProcessed')} selected={len(selected)}"
        )
    # Direct mode deliberately exits 1 when findings exist. Other non-zero
    # outcomes are accepted only after complete run metadata and coverage pass.
    if process_code not in (0, 1):
        raise RuntimeError(
            f"DeepSec process exited {process_code}; see "
            f"{run_dir / 'logs/deepsec-process.log'}"
        )

    predictions, raw_findings, record_tokens = normalize_deepsec_results(
        selected,
        benchmark_dir=args.benchmark_dir,
        data_root=data_root,
        project_id=args.project_id,
        deepsec_run_id=deepsec_run_id,
    )
    overall = confusion(predictions)
    by_cwe_records: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for prediction in predictions:
        by_cwe_records[f"CWE-{prediction['expected_cwe']}"].append(prediction)
    by_cwe = {
        cwe: confusion(records) for cwe, records in sorted(by_cwe_records.items())
    }

    input_tokens = int(stats.get("totalInputTokens") or record_tokens["input_tokens"])
    output_tokens = int(stats.get("totalOutputTokens") or record_tokens["output_tokens"])
    results: dict[str, Any] = {
        "schema_version": 1,
        "run_id": run_id,
        "scanner": {
            "name": "Vercel DeepSec",
            "commit": DEEPSEC_COMMIT,
            "deepsec_run_id": deepsec_run_id,
            "process_exit_code": process_code,
        },
        "router": {
            "base_url": router["base_url"],
            "model": model,
            "api_key_persisted": False,
        },
        "benchmark": {
            "commit": lock["commit"],
            "expected_results": "expectedresults-1.2.csv",
            "ground_truth_source": "OWASP Benchmark",
        },
        "coverage": {
            "selected_cases": len(selected),
            "processed_cases": int(stats.get("filesProcessed") or 0),
            "complete": int(stats.get("filesProcessed") or 0) == len(selected),
        },
        "timing": {
            "build_wall_clock_seconds": round(build_seconds, 6),
            "process_wall_clock_seconds": round(process_seconds, 6),
            "deepsec_analysis_seconds": round(
                int(stats.get("totalDurationMs") or 0) / 1000, 6
            ),
            "total_wall_clock_seconds": round(total_seconds, 6),
        },
        "tokens": {
            "source": "DeepSec run metadata",
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": input_tokens + output_tokens,
            "cache_read_input_tokens": record_tokens["cache_read_input_tokens"],
            "cache_creation_input_tokens": record_tokens[
                "cache_creation_input_tokens"
            ],
        },
        "findings": {
            "total": len(raw_findings),
            "deepsec_run_reported": int(stats.get("findingsCount") or 0),
            "matching_expected_class": sum(
                finding["matches_expected_category"] for finding in raw_findings
            ),
            "by_severity": dict(
                Counter(str(finding.get("severity", "UNKNOWN")) for finding in raw_findings)
            ),
        },
        "metrics": {
            "scoring": "OWASP ground truth; no LLM judge",
            "match_policy": "DeepSec finding text/vulnSlug mapped to expected benchmark category",
            "overall": overall,
            "by_cwe": by_cwe,
        },
    }

    write_jsonl(run_dir / "raw" / "deepsec-findings.jsonl", raw_findings)
    write_jsonl(run_dir / "normalized" / "predictions.jsonl", predictions)
    write_json(run_dir / "results.json", results)
    write_json(run_dir / "metrics" / "overall.json", results["metrics"]["overall"])
    write_json(run_dir / "metrics" / "by-cwe.json", by_cwe)
    (run_dir / "metrics" / "comparison.md").write_text(
        render_comparison(results), encoding="utf-8"
    )

    manifest["status"] = "success"
    manifest["ended_at"] = utc_now()
    manifest["scanner"]["deepsec_run_id"] = deepsec_run_id
    manifest["output_files"] = [
        "results.json",
        "raw/selected-cases.jsonl",
        "raw/selected-files.txt",
        "raw/deepsec-findings.jsonl",
        "normalized/predictions.jsonl",
        "metrics/overall.json",
        "metrics/by-cwe.json",
        "metrics/comparison.md",
        "logs/deepsec-build.log",
        "logs/deepsec-process.log",
        f"deepsec-data/{args.project_id}/runs/{deepsec_run_id}.json",
    ]
    write_json(run_dir / "manifest.json", manifest)
    print(f"Run artifacts: {run_dir}")
    print(
        f"findings={len(raw_findings)} tokens={input_tokens + output_tokens} "
        f"TP={overall['TP']} FP={overall['FP']} "
        f"FN={overall['FN']} TN={overall['TN']}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("Interrupted", file=sys.stderr)
        raise SystemExit(130)
    except Exception as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(1)
