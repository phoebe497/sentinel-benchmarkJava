# Security Analysis Workspace

Giao diện Week 3 không phải chatbot gắn thêm vào trang tìm kiếm cũ. Workspace tổ chức luồng làm việc có cấu trúc:

```text
Scanner outputs → Normalize → Deduplicate → Retrieve KB
                → Agent report → Human review → JSONL export
```

## Năm khu vực chính

- **Tổng quan:** dashboard cho biết dữ liệu và Agent đã sẵn sàng đến đâu, đồng thời đưa người dùng vào một ví dụ cụ thể.
- **Phân tích lỗ hổng:** một luồng dọc gồm chọn CWE, kiểm tra evidence/KB, hỏi Sentinel và xuất report. Chi tiết kỹ thuật được mở khi cần thay vì chiếm luồng đọc chính.
- **Knowledge Base:** trang tìm kiếm độc lập với Semantic Search (TF-IDF + LSA/SVD), Hybrid Search và Keyword Search (SQLite FTS5/BM25). Semantic và Hybrid chạy local, không gọi LLM.
- **Báo cáo:** lọc theo CWE hoặc mức độ, review nội dung và xuất từng report hoặc toàn bộ JSONL.
- **Dữ liệu & kiểm định:** giữ observations, grouping, scanner metrics, Agent metrics và failure cases cho review kỹ thuật.

Analysis group được tạo theo `BenchmarkTest + expected CWE`, vì tiêu đề và vị trí do từng scanner trả về có thể khác nhau. Phép chiếu này không sửa hoặc ghi đè observations của Week 2. Các group này mang ID `AG-*` và được ghi rõ là `benchmark_assisted`.

Week 3 dùng `src/sentinel_benchmark/analysis/` cho grouping deterministic, provider, Evidence Guard, review append-only và checksummed run artifacts. Structured report luôn chạy qua `scripts/analyze.py`; grounded chat gọi domain service chỉ khi có `st.chat_input` mới. Rerun UI thông thường không gọi provider. FakeProvider và 9Router report đi qua cùng schema, Guard, runner và writer.

Ground-truth label và TP/TN/FP/FN không đi vào provider input hoặc Agent report. Evaluation join label ở lớp riêng; `expected_cwe` trong prompt luôn được chú thích là metadata dùng để correlate scanner observations.

## Hỏi đáp và tạo report

Trang Phân tích lỗ hổng giữ evidence, knowledge, hỏi đáp và report trong cùng một
luồng bốn bước. Các câu hỏi mẫu luôn chứa CWE, tên lỗ hổng và Benchmark test đang
chọn để người mới không phải tự viết prompt kỹ thuật. Ở local mode, người dùng
phải xác nhận group + provider trước khi UI gọi canonical
CLI để tạo một checksummed report artifact. Chat chỉ chạy khi người dùng gửi câu
hỏi; câu trả lời bị giới hạn vào observation ID, KB document ID và report ID đã
có. Citation ngoài allowlist bị từ chối. Public readonly mode chỉ tóm tắt baked
artifact và không kết nối local router.

WebGoat không được đưa vào active index, dashboard hoặc trang Phân tích lỗ hổng của repository BenchmarkJava.
