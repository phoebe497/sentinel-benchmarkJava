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

Analysis group được tạo theo `BenchmarkTest + expected CWE`, vì tiêu đề và vị trí do từng scanner trả về có thể khác nhau. Phép chiếu này không sửa hoặc ghi đè observations của Week 2.

MVP dùng `grounded-template-v1` để kiểm thử report contract, evidence flow, review state và JSONL export trước khi kết nối external LLM. Mọi report luôn chứa observation IDs và KB document IDs đã dùng.

WebGoat `121 observations` chỉ là số liệu lịch sử để kể lại Week 2. Nó không được đưa vào active index, Findings Explorer hoặc Agent Analysis của repository BenchmarkJava.
