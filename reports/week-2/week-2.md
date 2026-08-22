# Week 2 - Xây dựng knowledge base từ kết quả BenchmarkJava

**Mục tiêu.** Từ các kết quả quét rời rạc của Week 1, em xây dựng một bộ dữ liệu có cấu trúc thống nhất, giữ được nguồn gốc của từng finding và có thể tìm kiếm trực tiếp trên giao diện web.

## Quá trình

- Chuẩn hóa dữ liệu JSON/JSONL của OpenCodeReview, DeepSec/Pi và Semgrep về cùng một schema.
- Gắn `dataset`, `tool`, `run_id`, `source_artifact` và `canonical_id` cho mỗi record để có thể truy ngược nguồn dữ liệu.
- Lập chỉ mục SQLite FTS5/BM25 cho findings và 12 tài liệu kiến thức bảo mật.
- Xây dựng giao diện Streamlit để tìm kiếm, xem số liệu từng scanner, kiểm tra provenance và tải kết quả dưới dạng JSON.
- Loại các nguồn WebGoat khỏi manifest, index, bộ lọc và test để toàn bộ luồng dữ liệu chỉ còn BenchmarkJava.

## Kết quả

- Thu được 372 scanner observations và 371 canonical groups từ ba scanner trên cùng tập 100 file.
- Knowledge base gồm 12 tài liệu; người dùng có thể tìm theo CWE hoặc tên lỗ hổng, sau đó xem lại artifact và run đã tạo ra finding.
- Automated tests kiểm tra số lượng record, dataset đang sử dụng, số scanner, chức năng tìm kiếm và manifest ground truth.
- Giao diện đã được deploy tại [sentinel-benchmarkjava.streamlit.app](https://sentinel-benchmarkjava.streamlit.app/) từ branch `main`, entrypoint `app/streamlit_app.py`.

Mỗi observation chỉ phản ánh cảnh báo do scanner tạo ra, chưa mặc nhiên được xem là lỗ hổng đã xác nhận thủ công. `canonical_id` được dùng để gom các bản ghi có đặc điểm giống nhau; nó không phải mã CVE hay ID của ground truth.

**Bằng chứng:** `configs/sources.json`, `src/sentinel_benchmark/`, `tests/test_pipeline.py`, `datasets/knowledge/security-topics.jsonl`.
