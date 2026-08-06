# BÁO CÁO KẾT QUẢ CHUẨN HÓA DỮ LIỆU VÀ XÂY KHO TRI THỨC (WEEK 2)

**Người thực hiện:** Nguyễn Như Yến Phương  
**Ngày báo cáo:** 01/08/2026  
**Dự án:** Project Sentinel - Chuẩn hóa kết quả quét và xây kho tri thức  
**Live demo (URL hiện tại):** https://sentinel-benchmarkjava.streamlit.app/

---

### 1. Mục tiêu và phạm vi thực hiện

Trong tuần 2, em đã xây dựng pipeline chuyển kết quả từ các công cụ security scan về một schema thống nhất để sử dụng làm đầu vào cho Security Analysis Agent. Phạm vi sử dụng lại các artifact Week 1 đã có:

- **WebGoat:** 121 findings đã correlation tại `webgoat-src/deliverables/findings.jsonl`.
- **OWASP Benchmark:** 100 test case đầu tiên, gồm artifact của OpenCodeReview, DeepSec/Pi và Semgrep.
- **Knowledge base:** 12 tài liệu/ví dụ ngắn về các nhóm lỗ hổng web phổ biến.

Mục tiêu acceptance của Week 2 là hệ thống đọc được kết quả scan đã tạo ở Week 1 và tìm kiếm được nội dung liên quan khi nhập `SQL Injection` hoặc `XSS`.

Trong phần công việc nền của dự án V-LLM, dữ liệu thật cũng đã được crawl/thu thập theo patch diffs và PoCs; phần phân tích đã ghi nhận quan hệ source/sink/sanitizer để phục vụ truy vết luồng dữ liệu. Các artifact này là nguồn bằng chứng bổ sung cho hướng phát triển tiếp theo của kho tri thức.

---

### 2. Kiến trúc và kỹ thuật thực hiện

```text
WebGoat findings ──────────────┐
OWASP OpenCodeReview findings ├─> normalizer.py / indexer.py
OWASP DeepSec findings ───────┤             │
OWASP Semgrep JSON ───────────┘             v
                                   Common observations
                                             │
knowledge_base.jsonl ───────────────────────┤
                                             v
                                      SQLite FTS5 index
                                             │
                                             v
                                       Streamlit UI
```

#### 2.1. Chuẩn hóa dữ liệu

`week2/normalizer.py` hỗ trợ JSON array, JSON object có trường `results`/`findings` và JSONL. Mỗi record được chuyển về cấu trúc chung gồm:

```text
finding_id, tool, severity, file_or_url,
line_start, line_end, title, cwe, owasp,
description, evidence, recommendation,
confidence, source_artifact
```

Severity được map về `critical`, `high`, `medium`, `low`, `info`; các trường CWE, OWASP, evidence và recommendation được giữ lại để Agent có thể sử dụng ở tuần 3.

#### 2.2. Ingest đa nguồn và provenance

`week2/config/sources.json` là manifest khai báo dataset, scanner, run ID và đường dẫn artifact. `week2/indexer.py` dùng manifest để ingest các nguồn mà không hard-code trong UI.

Mỗi observation giữ lại dataset, tool, run ID và source artifact. Canonical ID được tạo deterministic từ:

```text
dataset + file + line range + CWE + normalized title
```

Đây là bước deduplication ban đầu; canonical group chưa phải kết luận lỗ hổng đã được xác minh.

#### 2.3. Kho tri thức và tìm kiếm

Knowledge base `week2/data/knowledge_base.jsonl` gồm 12 mục về SQL Injection, XSS, Path Traversal, Command Injection, SSRF, Broken Access Control, hardcoded secret, deserialization, cryptography, authentication, information disclosure và race condition.

SQLite FTS5 index các trường title, description, evidence, recommendation, CWE, OWASP và file. BM25 của SQLite được dùng để xếp hạng kết quả. Hệ thống có alias `SQLi → SQL Injection`, đồng thời filter theo dataset và severity.

Semantic/vector search chưa được bật trong Week 2 vì SQLite FTS5 nhẹ, chạy offline, dễ tái lập và đáp ứng acceptance criteria mà không phụ thuộc model hoặc dịch vụ bên ngoài.

#### 2.4. Giao diện và kiểm thử

`week2/app.py` cung cấp Streamlit UI với ba tab Search, Overview và Hướng dẫn. Người dùng có thể:

- tìm knowledge document và scan finding;
- lọc theo WebGoat/OWASP Benchmark và severity;
- xem evidence, recommendation, tool, run và source artifact;
- tải kết quả tìm kiếm dưới dạng JSON;
- xem thống kê observations, canonical groups, dataset, tool và severity.

Giao diện đã được deploy bằng Streamlit Community Cloud tại:

**https://sentinel-benchmarkjava.streamlit.app/**

---

### 3. Kết quả và metrics
#### 3.1. Minh chứng chức năng tìm kiếm

Hình 1 minh họa UI trả về knowledge document và các scan findings liên quan khi tìm kiếm `SQL Injection`.

![Search SQL Injection](screenshots/search-sql-injection.png)

*Hình 1. Kết quả tìm kiếm SQL Injection trên Project Sentinel Week 2.*

Hình 2 minh họa truy vấn `CWE-89` trên dataset OWASP Benchmark, trong đó kết quả giữ lại thông tin scanner, run ID và source artifact.

![Search CWE-89](screenshots/search-cwe-89.png)

*Hình 2. Kết quả tìm kiếm CWE-89 với provenance của OWASP Benchmark.*

#### 3.2 Metrics

| Nguồn | Số observations |
| :--- | ---: |
| WebGoat correlated findings | 121 |
| OWASP OpenCodeReview | 131 |
| OWASP DeepSec/Pi | 152 |
| OWASP Semgrep `security-audit` | 89 |
| **Tổng số observations trong SQLite index** | **493** |

Snapshot index tạo được **395 canonical groups** theo deterministic key. Số này không được hiểu là số lỗ hổng unique đã được xác nhận vì các scanner có thể cùng mô tả một test case.

Các acceptance query đã kiểm thử:

- `SQL Injection` trả về knowledge document và findings liên quan.
- `SQLi` hoạt động qua alias.
- `XSS` và `CWE-79` trả về nội dung Cross-Site Scripting.
- `CWE-89` với dataset `owasp-benchmark` trả về findings có provenance.
- Query không tồn tại trả về trạng thái rỗng mà không làm UI crash.

Kiểm thử tự động:

```text
4 passed
```

Streamlit smoke test trả về HTTP 200 khi khởi động ở chế độ headless.

---

### 4. Deliverables

- `week2/normalizer.py` — chương trình chuẩn hóa JSON/JSONL.
- `week2/indexer.py` — ingest đa nguồn và build SQLite FTS5 index.
- `week2/search.py` — keyword baseline, alias và FTS retrieval.
- `week2/config/sources.json` — manifest các nguồn WebGoat/OWASP Benchmark.
- `week2/data/normalized_findings.json` — 121 findings WebGoat đã chuẩn hóa.
- `week2/data/knowledge_base.jsonl` — knowledge base 12 tài liệu/ví dụ.
- `week2/data/sentinel.db` — SQLite index được sinh bởi `indexer.py`.
- `week2/app.py` — Streamlit UI.
- `week2/test_week2.py` — automated tests.
- `week2/TEST_CASES.md` — manual test cases cho demo.
- `week2/README.md` — kiến trúc, kỹ thuật, cài đặt, sử dụng và troubleshooting.

---

### 5. Hướng dẫn chạy sản phẩm

Từ root repository:

```powershell
python -m pip install -r week2/requirements.txt
python week2/normalizer.py webgoat-src/deliverables/findings.jsonl -o week2/data/normalized_findings.json
python week2/indexer.py
python -m pytest week2/test_week2.py -q
streamlit run week2/app.py
```

Trong UI, mở tab **Search**, thử `SQL Injection`, `XSS`, `CWE-89` hoặc `CWE-79`; sau đó chọn dataset và severity để kiểm tra filter. Tab **Overview** dùng để kiểm tra số lượng dữ liệu đã ingest. Tab **Hướng dẫn** mô tả luồng demo và cách đọc provenance.

---

### 6. Việc chưa làm và giới hạn

- Knowledge base hiện có 12 tài liệu ngắn; chưa crawl và chunk toàn bộ tài liệu OWASP/CWE chính thức.
- Chưa triển khai embedding, vector database hoặc hybrid semantic search.
- Correlation mới là deterministic grouping, chưa có semantic matching hoặc human review workflow.
- OWASP Benchmark mới ingest 100/2.740 test case đầu.
- Chưa đưa patch diffs, PoCs và source/sink/sanitizer của V-LLM vào cùng một index chính thức; các artifact này mới được xác định là nguồn mở rộng.
- SQLite index là artifact sinh tự động; có thể rebuild hoàn toàn bằng `python week2/indexer.py`.
