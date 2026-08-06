#!/usr/bin/env python3
"""Run reproducible Semgrep baselines and score them on OWASP BenchmarkJava.

The scanner receives only the selected Java files. Ground truth is joined after
Semgrep exits. Each variant has its own raw JSON, terminal log, normalized
predictions, and metrics. Semgrep has no LLM token usage; token counts are
recorded as zero with an explicit non-LLM accounting label.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import deepsec_benchmark as deepsec
import score as benchmark_core


HARNESS_DIR = Path(__file__).resolve().parent
PROJECT_DIR = HARNESS_DIR.parents[1]
DEFAULT_BENCHMARK_DIR = PROJECT_DIR / "vendor" / "BenchmarkJava"
DEFAULT_RUNS_DIR = PROJECT_DIR / "artifacts" / "generated" / "semgrep"
DEFAULT_LOCK_FILE = HARNESS_DIR / "benchmark-lock.json"
DEFAULT_SEMGREP = (
    Path.home()
    / "AppData"
    / "Roaming"
    / "Python"
    / "Python313"
    / "Scripts"
    / "semgrep.exe"
)


def args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run Semgrep non-LLM baselines and configuration A/B variants."
    )
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument("--benchmark-dir", type=Path, default=DEFAULT_BENCHMARK_DIR)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_RUNS_DIR)
    parser.add_argument("--lock-file", type=Path, default=DEFAULT_LOCK_FILE)
    parser.add_argument("--semgrep", type=Path, default=DEFAULT_SEMGREP)
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument(
        "--variant",
        action="append",
        choices=("java", "security-audit", "java-plus-audit", "java-error"),
        help="Run only the named variant; may be repeated. Default: all variants.",
    )
    parser.add_argument("--dry-run", action="store_true")
    parsed = parser.parse_args()
    if parsed.count < 1:
        parser.error("--count must be positive")
    if parsed.jobs < 1:
        parser.error("--jobs must be positive")
    return parsed


def now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
    )


def first_cases(cases: list[benchmark_core.BenchmarkCase], count: int):
    selected = sorted(cases, key=lambda item: item.test_id)[:count]
    expected = [f"BenchmarkTest{index:05d}" for index in range(1, count + 1)]
    if [item.test_id for item in selected] != expected:
        raise RuntimeError("Selection is not the contiguous first Benchmark file range")
    return selected


def normalize_cwes(value: Any) -> set[int]:
    values = value if isinstance(value, list) else [value]
    cwes: set[int] = set()
    for item in values:
        for match in re.findall(r"\b(?:CWE-)?(\d{1,4})\b", str(item or ""), re.I):
            cwes.add(int(match))
    return cwes


def finding_matches_case(finding: dict[str, Any], case: benchmark_core.BenchmarkCase) -> bool:
    extra = finding.get("extra") if isinstance(finding.get("extra"), dict) else {}
    metadata = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
    cwe_values = set()
    for key in ("cwe", "cwe_id", "cwe_ids", "cwe-id"):
        cwe_values.update(normalize_cwes(metadata.get(key)))
        cwe_values.update(normalize_cwes(extra.get(key)))
    if case.cwe in cwe_values:
        return True
    text = " ".join(
        str(value or "")
        for value in (
            finding.get("check_id"),
            extra.get("message"),
            metadata.get("category"),
            metadata.get("technology"),
        )
    ).lower()
    return any(pattern in text for pattern in deepsec.CATEGORY_PATTERNS.get(case.category, ()))


def confusion(predictions: list[dict[str, Any]]) -> dict[str, Any]:
    tp = sum(row["ground_truth"] and row["predicted_positive"] for row in predictions)
    fn = sum(row["ground_truth"] and not row["predicted_positive"] for row in predictions)
    fp = sum((not row["ground_truth"]) and row["predicted_positive"] for row in predictions)
    tn = sum((not row["ground_truth"]) and not row["predicted_positive"] for row in predictions)
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and precision + recall
        else None
    )
    return {
        "TP": tp,
        "FP": fp,
        "FN": fn,
        "TN": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": fp / (fp + tn) if fp + tn else None,
        "scored_cases": len(predictions),
    }


VARIANTS = {
    "java": {
        "label": "S0-semgrep-java",
        "configs": ["p/java"],
        "description": "Semgrep Java ruleset; non-LLM baseline.",
    },
    "security-audit": {
        "label": "S1-semgrep-security-audit",
        "configs": ["p/security-audit"],
        "description": "Semgrep security-audit ruleset; broader non-LLM baseline.",
    },
    "java-plus-audit": {
        "label": "S2-semgrep-java-plus-audit",
        "configs": ["p/java", "p/security-audit"],
        "description": "Configuration ablation: union of Java and security-audit rules.",
    },
    "java-error": {
        "label": "S3-semgrep-java-error-only",
        "configs": ["p/java"],
        "severity": "ERROR",
        "description": "Configuration ablation: Java rules filtered to ERROR severity.",
    },
}


def run_variant(
    variant_name: str,
    variant: dict[str, Any],
    semgrep: Path,
    target_dir: Path,
    run_dir: Path,
    selected: list[benchmark_core.BenchmarkCase],
    jobs: int,
) -> dict[str, Any]:
    variant_dir = run_dir / "variants" / variant_name
    variant_dir.mkdir(parents=True, exist_ok=True)
    raw_path = variant_dir / "raw.json"
    log_path = variant_dir / "terminal.log"
    command = [str(semgrep), "--metrics", "off", "--disable-version-check"]
    for config in variant["configs"]:
        command.extend(["--config", config])
    if variant.get("severity"):
        command.extend(["--severity", variant["severity"]])
    command.extend(
        [
            "--json",
            "--json-output",
            str(raw_path),
            "--no-git-ignore",
            "--no-secrets-validation",
            "--jobs",
            str(jobs),
            "--time",
            str(target_dir),
        ]
    )
    print(f"\n=== Semgrep {variant['label']} ===")
    print("$ " + " ".join(command))
    started = time.perf_counter()
    env = os.environ.copy()
    env["SEMGREP_SEND_METRICS"] = "off"
    env["SEMGREP_ENABLE_VERSION_CHECK"] = "0"
    env["PATH"] = str(semgrep.parent) + os.pathsep + env.get("PATH", "")
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    with log_path.open("w", encoding="utf-8") as log:
        process = subprocess.Popen(
            command,
            cwd=PROJECT_DIR,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        assert process.stdout is not None
        for line in process.stdout:
            log.write(line)
            if len(line) > 1200:
                print(
                    f"[{variant_name}] {line[:300].rstrip()} "
                    f"... <long JSON line suppressed; full output is in {log_path}>"
                )
            else:
                print(f"[{variant_name}] {line}", end="")
        return_code = process.wait()
    elapsed = time.perf_counter() - started
    payload: dict[str, Any] = {}
    if raw_path.is_file():
        payload = json.loads(raw_path.read_text(encoding="utf-8"))
    findings = payload.get("results", []) if isinstance(payload, dict) else []
    by_file: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in findings:
        relative = str(finding.get("path", "")).replace("\\", "/")
        marker = "src/main/java/org/owasp/benchmark/testcode/"
        if marker in relative:
            relative = marker + relative.split(marker, 1)[1]
        by_file[relative].append(finding)
    predictions: list[dict[str, Any]] = []
    normalized_findings: list[dict[str, Any]] = []
    for case in selected:
        relative = f"src/main/java/org/owasp/benchmark/testcode/{case.test_id}.java"
        file_findings = by_file.get(relative, [])
        matching = [item for item in file_findings if finding_matches_case(item, case)]
        predictions.append(
            {
                "test_id": case.test_id,
                "file": relative,
                "category": case.category,
                "expected_cwe": case.cwe,
                "ground_truth": case.ground_truth,
                "predicted_positive": bool(matching),
                "outcome": "",
                "semgrep_findings": len(file_findings),
                "matching_findings": len(matching),
            }
        )
        for item in file_findings:
            extra = item.get("extra") if isinstance(item.get("extra"), dict) else {}
            normalized_findings.append(
                {
                    "test_id": case.test_id,
                    "file": relative,
                    "category": case.category,
                    "expected_cwe": case.cwe,
                    "matches_expected_category": item in matching,
                    "check_id": item.get("check_id"),
                    "start": item.get("start"),
                    "end": item.get("end"),
                    "severity": item.get("severity"),
                    "message": extra.get("message"),
                    "metadata": extra.get("metadata", {}),
                }
            )
    for row in predictions:
        if row["ground_truth"] and row["predicted_positive"]:
            row["outcome"] = "TP"
        elif row["ground_truth"]:
            row["outcome"] = "FN"
        elif row["predicted_positive"]:
            row["outcome"] = "FP"
        else:
            row["outcome"] = "TN"
    metrics = {
        "coverage": {
            "selected_cases": len(selected),
            "processed_cases": len(selected),
            "complete": return_code in (0, 1) and len(selected) == len(predictions),
        },
        "timing": {"process_wall_clock_seconds": round(elapsed, 6)},
        "tokens": {
            "accounting": "not applicable: Semgrep is a non-LLM scanner",
            "input_tokens": 0,
            "output_tokens": 0,
            "total_tokens": 0,
        },
        "findings": {
            "total": len(normalized_findings),
            "matching_expected_category": sum(
                bool(item["matches_expected_category"]) for item in normalized_findings
            ),
            "files_with_findings": len(
                {item["file"] for item in normalized_findings}
            ),
            "by_severity": dict(
                Counter(str(item.get("severity", "unknown")).lower() for item in normalized_findings)
            ),
        },
        "metrics": {
            "scoring": "OWASP ground truth; no LLM judge",
            "match_policy": "Semgrep CWE metadata or category text mapped to the expected test CWE",
            "overall": confusion(predictions),
        },
        "execution": {
            "return_code": return_code,
            "command": command,
            "terminal_log": str(log_path),
        },
    }
    write_json(variant_dir / "metrics.json", metrics)
    write_jsonl(variant_dir / "predictions.jsonl", predictions)
    write_jsonl(variant_dir / "findings.jsonl", normalized_findings)
    return {
        "variant": variant_name,
        "label": variant["label"],
        "description": variant["description"],
        "configs": variant["configs"],
        "severity": variant.get("severity"),
        "metrics": metrics,
        "predictions": predictions,
        "findings": normalized_findings,
    }


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    parsed = args()
    parsed.benchmark_dir = parsed.benchmark_dir.resolve()
    parsed.output_root = parsed.output_root.resolve()
    parsed.lock_file = parsed.lock_file.resolve()
    parsed.semgrep = parsed.semgrep.resolve()
    cases = benchmark_core.load_cases(parsed.benchmark_dir)
    lock = benchmark_core.validate_benchmark_lock(parsed.benchmark_dir, parsed.lock_file, len(cases))
    selected = first_cases(cases, parsed.count)
    selected_names = parsed.variant or list(VARIANTS)
    unknown = set(selected_names) - set(VARIANTS)
    if unknown:
        raise ValueError(f"Unknown variants: {sorted(unknown)}")
    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-semgrep-first100"
    run_dir = parsed.output_root / run_id
    target_dir = run_dir / "raw" / "targets" / "src" / "main" / "java" / "org" / "owasp" / "benchmark" / "testcode"
    target_dir.mkdir(parents=True, exist_ok=True)
    for case in selected:
        shutil.copy2(case.source_path, target_dir / f"{case.test_id}.java")
    manifest = {
        "schema_version": 1,
        "run_id": run_id,
        "started_at": now(),
        "status": "dry-run" if parsed.dry_run else "running",
        "scanner": {
            "name": "Semgrep",
            "version": None,
            "binary": str(parsed.semgrep),
            "non_llm": True,
        },
        "benchmark": {
            "path": str(parsed.benchmark_dir),
            "commit": benchmark_core.read_git_commit(parsed.benchmark_dir),
            "lock_file": str(parsed.lock_file),
            "lock": lock,
            "selected_cases": len(selected),
        },
        "selection": {
            "files": [case.test_id for case in selected],
            "source_root": str(target_dir),
        },
        "variants": {
            name: {key: value for key, value in VARIANTS[name].items()}
            for name in selected_names
        },
        "ground_truth": {
            "sent_to_scanner": False,
            "joined_after_scan": True,
            "source": "expectedresults-1.2.csv",
        },
    }
    write_json(run_dir / "manifest.json", manifest)
    write_jsonl(
        run_dir / "raw" / "selected-cases.jsonl",
        [
            {
                "test_id": case.test_id,
                "category": case.category,
                "ground_truth": case.ground_truth,
                "cwe": case.cwe,
            }
            for case in selected
        ],
    )
    if parsed.dry_run:
        print(f"Dry run created: {run_dir}")
        return 0
    if not parsed.semgrep.is_file():
        raise FileNotFoundError(f"Semgrep binary not found: {parsed.semgrep}")
    all_results: dict[str, Any] = {}
    for name in selected_names:
        all_results[name] = run_variant(
            name,
            VARIANTS[name],
            parsed.semgrep,
            run_dir / "raw" / "targets",
            run_dir,
            selected,
            parsed.jobs,
        )
    manifest["ended_at"] = now()
    manifest["status"] = "success" if all(
        item["metrics"]["coverage"]["complete"] for item in all_results.values()
    ) else "incomplete"
    manifest["output_files"] = [
        "manifest.json",
        "raw/selected-cases.jsonl",
        "raw/targets/",
        "variants/<name>/raw.json",
        "variants/<name>/terminal.log",
        "variants/<name>/findings.jsonl",
        "variants/<name>/predictions.jsonl",
        "variants/<name>/metrics.json",
        "results.json",
        "comparison.md",
    ]
    summary = {
        "schema_version": 1,
        "run_id": run_id,
        "status": manifest["status"],
        "scanner": manifest["scanner"],
        "benchmark": manifest["benchmark"],
        "variants": {
            name: {
                "label": result["label"],
                "description": result["description"],
                "metrics": result["metrics"],
            }
            for name, result in all_results.items()
        },
    }
    write_json(run_dir / "results.json", summary)
    lines = [
        f"# Semgrep baseline and A/B results — {run_id}",
        "",
        "Semgrep is a non-LLM scanner; token usage is not applicable and is recorded as zero.",
        "Ground truth was joined after scanning from OWASP BenchmarkJava.",
        "",
        "| Variant | Findings | TP | FP | FN | TN | Precision | Recall | F1 | Time (s) |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for name, result in all_results.items():
        overall = result["metrics"]["metrics"]["overall"]
        lines.append(
            f"| {result['label']} | {result['metrics']['findings']['total']} | "
            f"{overall['TP']} | {overall['FP']} | {overall['FN']} | {overall['TN']} | "
            f"{(overall['precision'] or 0) * 100:.2f}% | {(overall['recall'] or 0) * 100:.2f}% | "
            f"{(overall['f1'] or 0) * 100:.2f}% | {result['metrics']['timing']['process_wall_clock_seconds']:.3f} |"
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "- S0 is the primary Semgrep Java baseline.",
            "- S1 broadens the ruleset to `p/security-audit`.",
            "- S2 unions both rulesets to measure coverage versus noise.",
            "- S3 keeps `p/java` but reports only ERROR severity as a precision-oriented ablation.",
        ]
    )
    (run_dir / "comparison.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    write_json(run_dir / "manifest.json", manifest)
    print(f"\nSemgrep run artifacts: {run_dir}")
    for name, result in all_results.items():
        print(
            f"{result['label']}: findings={result['metrics']['findings']['total']} "
            f"TP={result['metrics']['metrics']['overall']['TP']} "
            f"FP={result['metrics']['metrics']['overall']['FP']} "
            f"FN={result['metrics']['metrics']['overall']['FN']} "
            f"TN={result['metrics']['metrics']['overall']['TN']}"
        )
    return 0 if manifest["status"] == "success" else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
    except Exception as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(1)
