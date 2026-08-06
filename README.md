# Sentinel BenchmarkJava

Repository dùng chung cho tiến độ Week 1–6, với một phạm vi dữ liệu duy nhất: **100 test case đầu của OWASP BenchmarkJava**. WebGoat không thuộc active dataset của repo này.

## Quick start

```powershell
git submodule update --init --recursive
python -m pip install -r requirements.txt
python -m pip install -e .
python -m sentinel_benchmark.indexer
streamlit run app/streamlit_app.py
python -m pytest -q
```

Live demo Week 2 (legacy deployment): <https://search-feature-kb-w2.streamlit.app/>. Kiểm tra ngày 2026-08-06 cho thấy URL đang chuyển tới trang đăng nhập Streamlit, vì vậy chưa được tính là public mentor demo. Code mới đã sẵn sàng tại `app/streamlit_app.py` để repoint deployment sang repo này.

GitHub Code scanning: <https://github.com/phoebe497/sentinel-benchmarkJava/security/code-scanning> (89 Semgrep alerts từ first-100 scope).

> BenchmarkJava chứa mã cố ý có lỗ hổng. Repo chỉ dùng source để đánh giá scanner; không deploy BenchmarkJava ra Internet.

## Bản đồ repo trong 5 phút

| Thư mục | Vai trò | Người đọc chính |
|---|---|---|
| `src/` | Code chuẩn hóa, lập chỉ mục và tìm kiếm | Developer |
| `app/` | Entrypoint Streamlit | Người demo |
| `vendor/BenchmarkJava/` | Upstream benchmark được pin bằng Git submodule | Scanner |
| `datasets/` | Manifest chọn mẫu và knowledge documents | Code/máy |
| `tests/` | Unit và integration tests | CI/reviewer |
| `reports/week-N/` | Báo cáo tuần ngắn, đóng băng sau khi nộp | Mentor |
| `artifacts/week-N/` | JSON/JSONL/log/metrics do máy sinh | Máy/reviewer sâu |
| `scripts/security/` | Harness chạy và chấm scanner | Security engineer |
| `docs/` | Phương pháp, cấu trúc và cross-review | Reviewer |

## Tiến độ

| Tuần | Quá trình | Kết quả chính |
|---|---|---|
| 1 | Scan 100 file đầu bằng OpenCodeReview, DeepSec và Semgrep | Metrics ground-truth và raw artifacts |
| 2 | Chuẩn hóa findings, SQLite FTS5 và Streamlit | KB tìm kiếm BenchmarkJava-only |
| 3 | Khởi tạo | Phạm vi chi tiết chờ task mentor |
| 4–6 | Chưa bắt đầu | Cập nhật theo từng tuần |

Chi tiết: [`docs/repository-layout.md`](docs/repository-layout.md).
