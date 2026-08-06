# Repository layout

Repo tách theo **vai trò của dữ liệu**, không tách code thành từng bản copy theo tuần:

```text
sentinel-benchmarkJava/
├── src/sentinel_benchmark/   # code dùng chung, được phép phát triển qua các tuần
├── app/                      # Streamlit entrypoint
├── vendor/BenchmarkJava/     # Git submodule upstream, pin commit
├── datasets/                 # manifest và knowledge input
├── tests/                    # automated tests
├── scripts/security/         # scanner/evaluation harness
├── reports/week-N/           # bản tóm tắt cho người đọc, đóng băng khi nộp
├── artifacts/week-N/         # raw JSON/JSONL/log/metrics cho máy và audit
└── docs/                     # phương pháp và review guide
```

`src/` trả lời “phần mềm chạy bằng gì”; `datasets/` trả lời “máy đọc đầu vào nào”; `tests/` trả lời “chứng minh code còn chạy”; `reports/` trả lời “tuần đó đã làm và đạt gì”; `artifacts/` trả lời “số liệu lấy từ đâu”.

Chỉ giữ một `DEBT.md` ngắn ở root. Chỉ chia file khi danh sách đủ lớn để có owner hoặc milestone riêng; chia sớm làm repo khó nhớ hơn.
