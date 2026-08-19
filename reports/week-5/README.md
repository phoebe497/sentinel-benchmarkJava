# Week 5 — Hướng dẫn review

Week 5 thêm guardrail cho Security Analysis Agent: **prompt-injection filter**, **human approval** trước khi gửi request, và **redaction** trước khi nội dung vào LLM hoặc log.

Review theo thứ tự dưới đây là đủ. Public demo replay artifact đã commit, không gọi API Gateway live.

## 1. Báo cáo (~1 trang)

[2026-08-19_NguyenNhuYenPhuong.md](./2026-08-19_NguyenNhuYenPhuong.md)

Đọc mục tiêu, luồng guardrail, bảng kết quả và giới hạn.

## 2. Live demo

[sentinel-benchmarkjava.streamlit.app](https://sentinel-benchmarkjava.streamlit.app/)

1. Sidebar → nhóm **KIỂM CHỨNG** → **Kiểm chứng an toàn**.
2. Xem đề xuất request (endpoint, payload, purpose).
3. Bấm **Từ chối** — request không được gửi, không có phản hồi.
4. Bấm **Duyệt và gửi** — UI hiện bản ghi đã lọc: injection bị flag/quarantine, secret đã redact (`[REDACTED_EMAIL]`, …). Không có nút xem dữ liệu gốc.

Tuỳ chọn: sidebar **Bắt đầu bản trình diễn** để được dẫn lần lượt tới đúng trang này.

## 3. Code, test và artifact

| Hạng mục | Đường dẫn |
| :--- | :--- |
| Implementation | [`src/sentinel_benchmark/guardrails/`](../../src/sentinel_benchmark/guardrails/) — `redaction.py`, `injection.py`, `approval.py` |
| Test (34 case) | [`tests/test_week5_guardrails.py`](../../tests/test_week5_guardrails.py) |
| Fixture em soạn | [`datasets/guardrails/crafted-injection-response.json`](../../datasets/guardrails/crafted-injection-response.json) |
| Evidence | [`artifacts/week-5/`](../../artifacts/week-5/) — `metrics.json`, `redaction-proof.json`, `injection-scan.json`, `approval-events.jsonl` |

Chạy test local:

```text
python -m pytest -q tests/test_week5_guardrails.py
```

Gateway vẫn là service ngoài repo (Week 4). Week 5 chốt gate trước khi gửi và sau khi nhận; live hop qua Gateway thuộc bước tiếp theo.
