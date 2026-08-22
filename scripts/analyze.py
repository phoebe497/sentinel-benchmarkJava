from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import tempfile
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dotenv import load_dotenv
from sentinel_benchmark.analysis.artifacts import atomic_json, list_runs, load_run, read_jsonl, write_checksums, write_jsonl
from sentinel_benchmark.analysis.evalset import failures, load_cases, score_cases
from sentinel_benchmark.analysis.evaluation import evaluate_runs, select_by_tag, write_grouping_metrics
from sentinel_benchmark.analysis.grouping import group_checksum, load_dast_groups, load_groups
from sentinel_benchmark.analysis.providers import FakeProvider, NineRouterProvider
from sentinel_benchmark.analysis.runner import run_batch
from sentinel_benchmark.analysis.source_context import default_roots
from sentinel_benchmark.analysis.scoring import false_cases, load_ground_truth, score_reports
from sentinel_benchmark.analysis.verification import apply_verification, verify_report
from sentinel_benchmark.indexer import build

MANIFEST = ROOT / "configs" / "sources.json"
KB = ROOT / "datasets" / "knowledge" / "security-topics.jsonl"
PREDICTIONS = ROOT / "artifacts" / "week-1" / "semgrep-20260806" / "variants" / "security-audit" / "predictions.jsonl"
WEEK3 = ROOT / "artifacts" / "week-3"
WEEK6 = ROOT / "artifacts" / "week-6"
PROBES = WEEK6 / "probes"


def indexed_groups() -> tuple[Path, list]:
    temp_dir = Path(tempfile.mkdtemp(prefix="sentinel-week3-"))
    db = temp_dir / "sentinel.db"
    build(MANIFEST, db, KB)
    return db, load_groups(db, PREDICTIONS)


def baseline() -> dict:
    db, groups = indexed_groups()
    with sqlite3.connect(db) as conn:
        rows = conn.execute("SELECT observation_id, tool, canonical_id FROM findings").fetchall()
    observation_ids = [row[0] for row in rows]
    assigned = [item for group in groups for item in group.observation_ids]
    counts = Counter(assigned)
    duplicate = sum(value - 1 for value in counts.values() if value > 1)
    covered = {group.benchmark_test_id for group in groups}
    expected = {f"BenchmarkTest{index:05d}" for index in range(1, 101)}
    checksum = group_checksum(groups)
    again = group_checksum(load_groups(db, PREDICTIONS))
    result = {
        "schema_version": "1.0", "observations": len(rows),
        "observation_ids_unique": len(set(observation_ids)) == len(observation_ids),
        "scanner_counts": dict(sorted(Counter(row[1] for row in rows).items())),
        "canonical_groups_week2": len({row[2] for row in rows}),
        "analysis_groups_week3": len(groups), "covered_test_ids": len(covered),
        "missing_test_ids": sorted(expected - covered),
        "missing_reasons": {item: "no_scanner_observation" for item in sorted(expected - covered)},
        "observations_assigned_once": len(assigned) == len(rows) and set(assigned) == set(observation_ids) and duplicate == 0,
        "duplicate_assignments": duplicate, "grouping_deterministic": checksum == again,
        "group_checksum": checksum, "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }
    expected_counts = {"Alibaba OpenCodeReview": 131, "Semgrep security-audit": 89, "Vercel DeepSec/Pi": 152}
    required = [result["observations"] == 372, result["observation_ids_unique"], result["scanner_counts"] == expected_counts, result["canonical_groups_week2"] == 371, result["analysis_groups_week3"] == 99, result["observations_assigned_once"], result["grouping_deterministic"]]
    if not all(required):
        raise RuntimeError("Baseline invariants failed: " + json.dumps(result, ensure_ascii=False))
    atomic_json(WEEK3 / "baseline.json", result)
    write_grouping_metrics(WEEK3, result)
    return result


def provider(name: str):
    if name == "fake":
        return FakeProvider()
    load_dotenv(ROOT / ".env")
    return NineRouterProvider.from_env()


def generate_report(real_tag: str, output: Path) -> None:
    base = json.loads((WEEK3 / "baseline.json").read_text(encoding="utf-8"))
    metrics_path = WEEK3 / "evaluation" / "agent-metrics.json"
    metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
    real_manifest = select_by_tag(WEEK3, real_tag)
    if not real_manifest:
        raise FileNotFoundError(f"No real run tagged {real_tag}")
    fake = metrics["fake"] or {}
    real = metrics["real"] or {}
    real_artifact = load_run(Path(real_manifest["run_dir"]))
    observed_models = sorted({row["model"] for row in real_artifact.get("reports", [])})
    observed_model_text = ", ".join(observed_models) or "not observed"
    report_date = datetime.now(UTC).strftime("%d/%m/%Y")
    text = f"""# BÁO CÁO XÂY DỰNG SECURITY ANALYSIS AGENT (WEEK 3)

**Người thực hiện:** Nguyễn Như Yến Phương  
**Ngày báo cáo:** {report_date}  
**Dự án:** Project Sentinel — Phân tích kết quả quét và sinh báo cáo bảo mật  
**Phạm vi:** 100 test case đầu tiên của OWASP BenchmarkJava

---

### 1. Mục tiêu và kết quả cần đạt

Trong Week 3, em xây dựng một Security Analysis Agent có thể đọc kết quả scan của Week 1, tra cứu kho tri thức Week 2 và tạo báo cáo dễ đọc cho từng nhóm lỗ hổng. Báo cáo giữ lại vị trí, bằng chứng và công cụ phát hiện; đồng thời bổ sung mức nghiêm trọng, giải thích đơn giản, cách xác minh, hướng khắc phục và độ tin cậy. Kết quả được lưu dưới dạng JSONL để có thể kiểm tra lại hoặc tải từ giao diện.

---

### 2. Kiến trúc và luồng xử lý

```mermaid
flowchart LR
    A[3 scanner outputs<br/>{base['observations']} observations] --> B[Normalize và group<br/>{base['analysis_groups_week3']} analysis groups]
    B --> C[Retrieve hướng dẫn<br/>từ 12 tài liệu KB]
    C --> D[Ghép evidence + KB<br/>vào prompt có schema]
    D --> E[9Router LLM<br/>phân tích lỗ hổng]
    E --> F[Pydantic + Evidence Guard<br/>kiểm tra JSON và nguồn]
    F --> G[JSONL report<br/>UI, review và export]

    classDef input fill:#E0F2FE,stroke:#0284C7,color:#0C4A6E;
    classDef process fill:#CCFBF1,stroke:#0F766E,color:#134E4A;
    classDef ai fill:#EDE9FE,stroke:#7C3AED,color:#4C1D95;
    classDef guard fill:#FEF3C7,stroke:#D97706,color:#78350F;
    classDef output fill:#DCFCE7,stroke:#16A34A,color:#14532D;
    class A input;
    class B,C,D process;
    class E ai;
    class F guard;
    class G output;
```

Python thực hiện phần có thể kiểm chứng: đọc artifact, nhóm cảnh báo, tìm tài liệu KB, gọi model, kiểm tra kết quả và ghi JSONL. LLM chỉ viết phần phân tích; model không được tự tạo hoặc thay đổi test ID, CWE, scanner, vị trí hay observation ID. Cách tách này giúp báo cáo không xuất hiện endpoint hoặc bằng chứng không có trong dữ liệu gốc.

### 3. LLM, System Prompt và tool call

Agent gọi 9Router bằng model ID `{real_manifest['model']}`; metadata của response ghi model `{observed_model_text}`. System Prompt được lưu tại `docs/prompts/week3-security-analysis-agent.md`, với hai yêu cầu chính: mọi nhận định phải dựa trên scanner evidence/KB đã cung cấp và không được bịa identifier, location, tool, CWE hoặc verdict.

Model **không tự gọi tool**. Thay vào đó, Python chủ động gọi các thành phần cần thiết theo flow cố định: grouping, keyword retrieval, provider và Evidence Guard. Nếu JSON sai schema, hệ thống phản hồi lỗi cho model và retry một lần; nếu vẫn sai, group đó được ghi vào error artifact thay vì làm dừng cả batch.

---

### 4. Kết quả và kiểm thử

| Hạng mục | Kết quả |
| :--- | ---: |
| Observations được đưa vào grouping | {base['observations']}/{base['observations']} |
| Duplicate assignment | {base['duplicate_assignments']} |
| FakeProvider — kiểm thử toàn bộ pipeline | {fake.get('successful', 0)}/{fake.get('requested', 0)} groups |
| 9Router — real smoke test | {real.get('successful', 0)}/{real.get('requested', 0)} groups |
| Schema / Guard / evidence preservation | {real.get('schema_valid_rate', 0):.0%} / {real.get('guard_pass_rate', 0):.0%} / {real.get('evidence_reference_rate', 0):.0%} |

Các test bao phủ input rỗng, JSON không hợp lệ và retry, lỗi một group không làm dừng batch, citation/field bịa bị chặn, SSE response của 9Router và checksum artifact. UI cho phép chọn lỗ hổng theo tên CWE, xem evidence/KB, tạo report, hỏi đáp và tải JSONL.

---

### 5. Deliverables và giới hạn

- `src/sentinel_benchmark/analysis/` — grouping, prompt, provider, Guard, runner và evaluation.
- `docs/prompts/week3-security-analysis-agent.md` — System Prompt và output contract.
- `artifacts/week-3/runs/` — FakeProvider full run và 9Router real run có checksum.
- `reports/week-3/week-3.md` — báo cáo tuần được sinh từ metrics thật.
- `app/streamlit_app.py` — giao diện xem evidence, Agent report và Ask Sentinel.

Real LLM hiện mới được smoke test trên {real.get('requested', 0)} groups; nội dung giải thích và khắc phục vẫn cần human review trước khi sử dụng trong môi trường thực tế.
"""
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text, encoding="utf-8", newline="\n")


def indexed_dast_groups() -> tuple[Path, list]:
    temp_dir = Path(tempfile.mkdtemp(prefix="sentinel-week6-"))
    db = temp_dir / "sentinel.db"
    build(MANIFEST, db, KB)
    return db, load_dast_groups(db)


def run_root_for(dataset: str) -> Path:
    """SAST runs stay under week-3; the DAST branch is a Week 6 artifact."""
    return WEEK3 if dataset == "sast" else WEEK6


def score_run(dataset: str, tag: str) -> dict:
    """Join ground truth onto a finished run. Never before it is on disk."""
    root = run_root_for(dataset)
    manifest = select_by_tag(root, tag)
    if not manifest:
        raise FileNotFoundError(f"No run tagged {tag!r} under {root.relative_to(ROOT)}")
    run = load_run(Path(manifest["run_dir"]))
    reports = run["reports"]
    truth = load_ground_truth(PREDICTIONS)
    scored = score_reports(reports, truth)
    out_dir = root / "evaluation"
    atomic_json(out_dir / f"verdict-metrics-{tag}.json", {**scored, "run_id": manifest["run_id"], "tag": tag, "ground_truth_source": str(PREDICTIONS.relative_to(ROOT).as_posix())})
    write_jsonl(out_dir / f"false-cases-{tag}.jsonl", false_cases(scored, reports))
    return {key: scored[key] for key in ("reports", "scored", "counts", "abstention_rate", "precision", "recall", "f1", "accuracy", "verdict_distribution")}


def verify_run(dataset: str, tag: str, provider_name: str) -> dict:
    """Re-decide the verdicts of a finished run against recorded probe responses.

    The probe records are read from artifacts, not fetched here: sending is the
    request tool's job and it requires human approval, so this step can never
    cause a request.
    """
    root = run_root_for(dataset)
    manifest = select_by_tag(root, tag)
    if not manifest:
        raise FileNotFoundError(f"No run tagged {tag!r} under {root.relative_to(ROOT)}")
    run_dir = Path(manifest["run_dir"])
    reports = load_run(run_dir)["reports"]
    probe_files = sorted(PROBES.glob("*-probe.jsonl"))
    if not probe_files:
        raise FileNotFoundError("No probe records found. Run: python scripts/probe.py run")
    probes: dict[str, dict] = {}
    for row in read_jsonl(probe_files[-1]):
        # One response can answer several findings on the same endpoint, and a
        # later attempt supersedes an earlier one.
        for group_id in row.get("analysis_group_ids") or []:
            probes[str(group_id)] = row
    chosen = provider(provider_name)
    chosen.preflight()
    updated, exchanges, tally = [], [], Counter()
    for report in reports:
        probe = probes.get(str(report.get("analysis_group_id")))
        if probe is None:
            updated.append(report)
            tally["no_probe"] += 1
            continue
        verification, exchange = verify_report(report, probe, provider=chosen)
        if exchange:
            exchanges.append(exchange)
        updated.append(apply_verification(report, verification))
        tally["changed" if verification.changed else ("verified" if verification.reached_target else "unverified")] += 1
    write_jsonl(run_dir / "reports.jsonl", updated)
    write_jsonl(run_dir / "verification-responses.jsonl", exchanges)
    write_checksums(run_dir)
    return {"run_id": manifest["run_id"], "probe_source": str(probe_files[-1].relative_to(ROOT).as_posix()), **dict(sorted(tally.items()))}


EVAL_CASES = ROOT / "datasets" / "evaluation" / "week6-eval-cases.jsonl"


def eval_cases(sast_tag: str, dast_tag: str) -> dict:
    """Grade the hand-written cases against the newest run of each branch.

    Both branches are needed because the cases span them: the corpus supplies no
    expected answer for a Juice Shop endpoint, and a live probe has nothing to
    say about a static false positive.
    """
    cases = load_cases(EVAL_CASES)
    reports: list[dict] = []
    for dataset, tag in (("sast", sast_tag), ("dast", dast_tag)):
        manifest = select_by_tag(run_root_for(dataset), tag)
        if not manifest:
            raise FileNotFoundError(f"No {dataset} run tagged {tag!r}")
        reports.extend(load_run(Path(manifest["run_dir"]))["reports"])
    scored = score_cases(cases, reports)
    out_dir = WEEK6 / "evaluation"
    atomic_json(out_dir / "eval-cases-metrics.json", {**scored, "sast_tag": sast_tag, "dast_tag": dast_tag, "cases_source": str(EVAL_CASES.relative_to(ROOT).as_posix())})
    write_jsonl(out_dir / "eval-cases-failures.jsonl", failures(scored, cases))
    return {key: scored[key] for key in ("cases", "counts", "precision", "recall", "f1", "stance_accuracy", "verdict_exact_rate", "right_for_the_wrong_reason")}


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("baseline")
    pre = sub.add_parser("preflight"); pre.add_argument("--provider", choices=["fake", "nine_router"], required=True)
    run = sub.add_parser("run"); run.add_argument("--provider", choices=["fake", "nine_router"], required=True); run.add_argument("--limit", type=int); run.add_argument("--group-id"); run.add_argument("--tag", required=True); run.add_argument("--dataset", choices=["sast", "dast"], default="sast"); run.add_argument("--no-source", action="store_true", help="omit corpus source from the payload (ablation)")
    evaluate = sub.add_parser("evaluate"); evaluate.add_argument("--fake-tag", required=True); evaluate.add_argument("--real-tag")
    score = sub.add_parser("score"); score.add_argument("--tag", required=True); score.add_argument("--dataset", choices=["sast", "dast"], default="sast")
    cases = sub.add_parser("eval-cases"); cases.add_argument("--sast-tag", default="sast-final"); cases.add_argument("--dast-tag", default="flow")
    verify = sub.add_parser("verify"); verify.add_argument("--tag", required=True); verify.add_argument("--dataset", choices=["sast", "dast"], default="dast"); verify.add_argument("--provider", choices=["fake", "nine_router"], required=True)
    report = sub.add_parser("report"); report.add_argument("--real-tag", required=True); report.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "baseline": result = baseline()
    elif args.command == "preflight": result = provider(args.provider).preflight()
    elif args.command == "run":
        db, groups = indexed_dast_groups() if args.dataset == "dast" else indexed_groups()
        if args.group_id:
            groups = [group for group in groups if group.analysis_group_id == args.group_id]
            if not groups:
                raise ValueError(f"Unknown analysis group: {args.group_id}")
        chosen = provider(args.provider); chosen.preflight()
        # Corpus source only exists for the benchmark; a live endpoint has none.
        roots = None if args.dataset == "dast" or args.no_source else default_roots(ROOT)
        path = run_batch(groups=groups, db_path=db, provider=chosen, run_root=run_root_for(args.dataset), tag=args.tag, limit=args.limit, source_roots=roots)
        result = {"run_dir": str(path.relative_to(ROOT)), "source_context": roots is not None}
    elif args.command == "evaluate": result = evaluate_runs(WEEK3, fake_tag=args.fake_tag, real_tag=args.real_tag)
    elif args.command == "score": result = score_run(args.dataset, args.tag)
    elif args.command == "verify": result = verify_run(args.dataset, args.tag, args.provider)
    elif args.command == "eval-cases": result = eval_cases(args.sast_tag, args.dast_tag)
    else: generate_report(args.real_tag, args.output); result = {"output": str(args.output)}
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
