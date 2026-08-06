# Week 2 — BenchmarkJava finding knowledge base

**Mục tiêu.** Biến raw scanner outputs Week 1 thành dữ liệu có schema thống nhất, có provenance và tìm kiếm được; cung cấp live demo nhỏ để mentor kiểm tra.

## Quá trình

- Chuẩn hóa JSON/JSONL của OpenCodeReview, DeepSec/Pi và Semgrep về cùng schema observation.
- Gắn `dataset`, `tool`, `run_id`, `source_artifact` và deterministic `canonical_id` cho từng record.
- Lập chỉ mục SQLite FTS5/BM25 cho findings và 12 knowledge documents.
- Xây Streamlit UI gồm tìm kiếm, scanner metrics và provenance; có export kết quả JSON.
- Loại toàn bộ nguồn WebGoat khỏi manifest, index, filter và test để thống nhất hướng BenchmarkJava-only.

## Kết quả

- 372 scanner observations và 371 canonical groups từ đúng 3 scanner trên cùng first-100 corpus.
- 12 knowledge documents; tìm kiếm theo CWE/tên lỗ hổng và xem được artifact/run nguồn.
- Automated tests kiểm tra số record, active dataset, số scanner, search và ground-truth manifest.
- Legacy live URL: <https://search-feature-kb-w2.streamlit.app/> hiện redirect tới Streamlit login; code mới đã local smoke-test HTTP 200 nhưng cần repoint sang repo này và bật quyền xem public trước khi gửi mentor.

Observation là cảnh báo của scanner, không đồng nghĩa lỗ hổng đã human-validate. `canonical_id` là phép gom deterministic, không phải CVE hay ground-truth ID.

**Bằng chứng:** `configs/sources.json`, `src/sentinel_benchmark/`, `tests/test_pipeline.py`, `datasets/knowledge/security-topics.jsonl`.
