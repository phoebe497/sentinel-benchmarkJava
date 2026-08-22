# Week 1 - Đánh giá SAST trên OWASP BenchmarkJava

**Mục tiêu.** Trong tuần đầu, em xây dựng một phép thử có ground truth để so sánh hai công cụ dùng LLM là Alibaba OpenCodeReview và Vercel DeepSec/Pi với công cụ SAST truyền thống Semgrep.

## Quá trình

- Cố định OWASP BenchmarkJava tại commit `79b9bd6`, sau đó chọn 100 file đầu tiên (`00001-00100`), gồm 75 mẫu có lỗ hổng và 25 mẫu không có lỗ hổng.
- Scanner chỉ được nhận source Java. File `expectedresults-1.2.csv` được giữ riêng và chỉ dùng để đối chiếu sau khi quá trình quét kết thúc.
- OpenCodeReview và DeepSec/Pi cùng sử dụng model `gc/gemini-2.5-flash`. Semgrep được chạy với các cấu hình `p/java`, `p/security-audit`, cấu hình kết hợp và biến thể chỉ giữ mức ERROR.
- Kết quả chỉ được chấm khi cả 100 file đều đã xử lý xong. Manifest, findings gốc, predictions đã chuẩn hóa, log và metrics được lưu thành các artifact riêng.

## Kết quả

| Scanner | Findings | Thời gian | TP/FP/FN/TN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| OpenCodeReview | 131 | 2,408s | 60/6/15/19 | 90.91% | 80.00% | 85.11% |
| DeepSec/Pi | 152 | 1,909s | 64/10/11/15 | 86.49% | 85.33% | 85.91% |
| Semgrep `security-audit` (rerun 2026-08-06) | 89 | 16.97s | 57/4/18/21 | 93.44% | 76.00% | 83.82% |

DeepSec bắt được nhiều mẫu có lỗ hổng nhất, thể hiện qua recall cao nhất. Semgrep `security-audit` có precision cao nhất và hoàn thành nhanh hơn đáng kể. Tuy vậy, đây mới là kết quả trên 100 file đầu tiên nên chưa thể đại diện cho toàn bộ 2.740 test case của BenchmarkJava.

Pipeline CI `31082995915` đã chạy thành công cả automated test và Semgrep. File SARIF cũng được tải lên GitHub, tạo 89 cảnh báo trong mục **Security → Code scanning**.

**Bằng chứng:** `artifacts/week-1/llm-20260728/results.json`, `artifacts/week-1/semgrep-20260806/results.json`, `datasets/manifests/benchmarkjava-first-100.json` và [GitHub Actions run](https://github.com/phoebe497/sentinel-benchmarkJava/actions/runs/31082995915). Snapshot Semgrep ngày 2026-07-29 vẫn được giữ lại để đối chiếu khi cần.
