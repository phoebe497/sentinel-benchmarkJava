# Sentinel BenchmarkJava

Đây là repository dùng chung để theo dõi công việc từ Week 1 đến Week 6. Toàn bộ phần đánh giá hiện tại sử dụng cùng một phạm vi: **100 test case đầu tiên của OWASP BenchmarkJava**. WebGoat không còn nằm trong tập dữ liệu đang sử dụng.

## Quick start

```powershell
git submodule update --init --recursive
python -m pip install -r requirements.txt
python -m pip install -e .
python -m sentinel_benchmark.indexer
streamlit run app/streamlit_app.py
python -m pytest -q
```

**Streamlit deployment:** [sentinel-benchmarkjava.streamlit.app](https://sentinel-benchmarkjava.streamlit.app/). Kiểm tra ẩn danh ngày 2026-08-07 vẫn redirect tới `/login`; cần bật public sharing trước khi gửi mentor.

Ứng dụng dùng entrypoint `app/streamlit_app.py`. Giao diện là **Security Analysis Workspace** gồm Overview, Findings Explorer, Agent Analysis, Reports và Evaluation. Agent Analysis có grounded chat, tạo report có xác nhận và export JSONL/chat transcript. Public mode chỉ đọc baked artifacts; inference chỉ xảy ra sau thao tác gửi/xác nhận rõ ràng, không chạy trên rerun thông thường.

**GitHub Code scanning:** [89 Semgrep alerts trên phạm vi 100 file](https://github.com/phoebe497/sentinel-benchmarkJava/security/code-scanning).

> BenchmarkJava chứa mã được cố ý viết có lỗ hổng. Repository chỉ dùng phần source này để đánh giá scanner; bản thân ứng dụng BenchmarkJava không được đưa lên Internet.

## Bản đồ repo trong 5 phút

| Thư mục | Vai trò | Người đọc chính |
|---|---|---|
| `src/` | Code chuẩn hóa, lập chỉ mục và tìm kiếm | Developer |
| `app/` | Entrypoint Streamlit | Người demo |
| `vendor/BenchmarkJava/` | Upstream benchmark được pin bằng Git submodule | Scanner |
| `datasets/` | Manifest chọn mẫu và tài liệu trong knowledge base | Code/máy |
| `tests/` | Unit và integration tests | CI/reviewer |
| `reports/week-N/` | Báo cáo tuần ngắn, đóng băng sau khi nộp | Mentor |
| `artifacts/week-N/` | JSON/JSONL/log/metrics do máy sinh | Máy/reviewer sâu |
| `scripts/security/` | Harness chạy và chấm scanner | Security engineer |
| `docs/` | Phương pháp, cấu trúc và cross-review | Reviewer |

## Tiến độ

| Tuần | Quá trình | Kết quả chính |
|---|---|---|
| 1 | Quét 100 file đầu bằng OpenCodeReview, DeepSec và Semgrep | Số liệu đối chiếu ground truth và artifact gốc |
| 2 | Chuẩn hóa findings, lập chỉ mục SQLite FTS5 và xây dựng Streamlit | Knowledge base chỉ sử dụng BenchmarkJava, có live demo |
| 3 | Đã tạo khung làm việc | Chờ chốt phạm vi chi tiết với mentor |
| 4–6 | Chưa bắt đầu | Cập nhật theo từng tuần |

Chi tiết: [`docs/repository-layout.md`](docs/repository-layout.md). Báo cáo Week 1–2 đã được khóa checksum tại [`reports/locked.json`](reports/locked.json).

Thiết kế UI Week 3: [`docs/security-analysis-workspace.md`](docs/security-analysis-workspace.md).
