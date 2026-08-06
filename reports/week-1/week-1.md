# Week 1 — SAST baseline trên OWASP BenchmarkJava

**Mục tiêu.** Thiết lập phép đo có ground truth để so sánh hai scanner dùng LLM (Alibaba OpenCodeReview, Vercel DeepSec/Pi) với baseline SAST truyền thống Semgrep.

## Quá trình

- Pin OWASP BenchmarkJava tại commit `79b9bd6` và chọn đúng 100 file đầu (`00001–00100`): 75 positive, 25 negative.
- Chỉ đưa Java source vào scanner; giữ `expectedresults-1.2.csv` ngoài input và chỉ join sau scan.
- Chạy OpenCodeReview và DeepSec/Pi qua cùng model `gc/gemini-2.5-flash`; chạy Semgrep với các cấu hình `p/java`, `p/security-audit`, union và ERROR-only.
- Chỉ chấm khi coverage đủ 100/100; lưu manifest, raw findings, normalized predictions, logs và metrics riêng.

## Kết quả

| Scanner | Findings | Thời gian | TP/FP/FN/TN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| OpenCodeReview | 131 | 2,408s | 60/6/15/19 | 90.91% | 80.00% | 85.11% |
| DeepSec/Pi | 152 | 1,909s | 64/10/11/15 | 86.49% | 85.33% | 85.91% |
| Semgrep `security-audit` (rerun 2026-08-06) | 89 | 16.97s | 57/4/18/21 | 93.44% | 76.00% | 83.82% |

DeepSec có recall cao nhất; Semgrep `security-audit` đạt precision cao nhất và nhanh hơn nhiều. Kết quả chỉ có giá trị trên first-100 sample, chưa đại diện toàn bộ 2.740 test case.

**Bằng chứng:** `artifacts/week-1/llm-20260728/results.json`, `artifacts/week-1/semgrep-20260806/results.json`, `datasets/manifests/benchmarkjava-first-100.json`. Snapshot Semgrep 2026-07-29 được giữ riêng để đối chiếu lịch sử.
