# Security Analysis Workspace

Giao diện Week 3 không phải chatbot gắn thêm vào trang tìm kiếm cũ. Workspace tổ chức luồng làm việc có cấu trúc:

```text
Scanner outputs → Normalize → Deduplicate → Retrieve KB
                → Agent report → Human review → JSONL export
```

## Năm khu vực chính

- **Overview:** kể lại pipeline Week 1–3 và snapshot dữ liệu.
- **Findings Explorer:** tìm kiếm và lọc theo analysis group thay vì hiển thị 372 observations rời rạc.
- **Agent Analysis:** đặt finding context, retrieved knowledge và Agent report cạnh nhau.
- **Reports:** review trạng thái và xuất từng report hoặc toàn bộ JSONL.
- **Evaluation:** tách riêng scanner, retrieval và Agent evaluation.

Analysis group được tạo theo `BenchmarkTest + expected CWE`, vì tiêu đề và vị trí do từng scanner trả về có thể khác nhau. Phép chiếu này không sửa hoặc ghi đè observations của Week 2. Các group này mang ID `AG-*` và được ghi rõ là `benchmark_assisted`.

Week 3 dùng `src/sentinel_benchmark/analysis/` cho grouping deterministic, provider, Evidence Guard, review append-only và checksummed run artifacts. Structured report luôn chạy qua `scripts/analyze.py`; grounded chat gọi domain service chỉ khi có `st.chat_input` mới. Rerun UI thông thường không gọi provider. FakeProvider và 9Router report đi qua cùng schema, Guard, runner và writer.

Ground-truth label và TP/TN/FP/FN không đi vào provider input hoặc Agent report. Evaluation join label ở lớp riêng; `expected_cwe` trong prompt luôn được chú thích là metadata dùng để correlate scanner observations.

## Grounded chat và tạo report

Agent Analysis có ba tab: scanner evidence/KB, create/view report và Ask Sentinel.
Ở local mode, người dùng phải xác nhận group + provider trước khi UI gọi canonical
CLI để tạo một checksummed report artifact. Chat chỉ chạy khi người dùng gửi câu
hỏi; câu trả lời bị giới hạn vào observation ID, KB document ID và report ID đã
có. Citation ngoài allowlist bị từ chối. Public readonly mode chỉ tóm tắt baked
artifact và không kết nối local router.

WebGoat không được đưa vào active index, Findings Explorer hoặc Agent Analysis của repository BenchmarkJava.
