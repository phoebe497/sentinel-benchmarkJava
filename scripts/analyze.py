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
from sentinel_benchmark.analysis.artifacts import atomic_json, list_runs, load_run
from sentinel_benchmark.analysis.evaluation import evaluate_runs, select_by_tag, write_grouping_metrics
from sentinel_benchmark.analysis.grouping import group_checksum, load_groups
from sentinel_benchmark.analysis.providers import FakeProvider, NineRouterProvider
from sentinel_benchmark.analysis.runner import run_batch
from sentinel_benchmark.indexer import build

MANIFEST = ROOT / "configs" / "sources.json"
KB = ROOT / "datasets" / "knowledge" / "security-topics.jsonl"
PREDICTIONS = ROOT / "artifacts" / "week-1" / "semgrep-20260806" / "variants" / "security-audit" / "predictions.jsonl"
WEEK3 = ROOT / "artifacts" / "week-3"


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
    return NineRouterProvider(base_url=os.getenv("NINE_ROUTER_BASE_URL", "http://127.0.0.1:20128/v1"), model=os.getenv("NINE_ROUTER_MODEL", ""), api_key=os.getenv("NINE_ROUTER_API_KEY", ""), timeout=float(os.getenv("NINE_ROUTER_TIMEOUT_SECONDS", "60")), max_retries=int(os.getenv("NINE_ROUTER_MAX_RETRIES", "1")))


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


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("baseline")
    pre = sub.add_parser("preflight"); pre.add_argument("--provider", choices=["fake", "nine_router"], required=True)
    run = sub.add_parser("run"); run.add_argument("--provider", choices=["fake", "nine_router"], required=True); run.add_argument("--limit", type=int); run.add_argument("--group-id"); run.add_argument("--tag", required=True)
    evaluate = sub.add_parser("evaluate"); evaluate.add_argument("--fake-tag", required=True); evaluate.add_argument("--real-tag")
    report = sub.add_parser("report"); report.add_argument("--real-tag", required=True); report.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "baseline": result = baseline()
    elif args.command == "preflight": result = provider(args.provider).preflight()
    elif args.command == "run":
        db, groups = indexed_groups()
        if args.group_id:
            groups = [group for group in groups if group.analysis_group_id == args.group_id]
            if not groups:
                raise ValueError(f"Unknown analysis group: {args.group_id}")
        chosen = provider(args.provider); chosen.preflight(); path = run_batch(groups=groups, db_path=db, provider=chosen, run_root=WEEK3, tag=args.tag, limit=args.limit); result = {"run_dir": str(path.relative_to(ROOT))}
    elif args.command == "evaluate": result = evaluate_runs(WEEK3, fake_tag=args.fake_tag, real_tag=args.real_tag)
    else: generate_report(args.real_tag, args.output); result = {"output": str(args.output)}
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
