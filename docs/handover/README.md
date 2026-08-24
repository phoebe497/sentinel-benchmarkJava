# Sản phẩm bàn giao cuối cùng

## 1. Mã nguồn

| Hạng mục | Ở đâu |
| :--- | :--- |
| Cấu hình CI | `.github/workflows/ci.yml` - 3 job: `test` (pytest + baseline + score + eval-cases + hygiene), `semgrep` (SARIF → GitHub Code scanning), `dast` (Juice Shop thật + ZAP baseline) |
| Công cụ chuẩn hóa dữ liệu | `src/sentinel_benchmark/normalizer.py`, `indexer.py`, `analysis/grouping.py` |
| Kho tri thức | `datasets/knowledge/security-topics.jsonl` (38 doc) + `knowledge_doc.schema.json` (draft 2020-12, strict) |
| Security Analysis Agent | `src/sentinel_benchmark/analysis/` - `prompting.py`, `providers.py`, `guard.py`, `runner.py`, `verification.py`, `scoring.py`, `judge.py`, `evalset.py`, `source_context.py` |
| Python Tool gửi request | `src/sentinel_benchmark/probe/` - `payloads.py`, `client.py`, `proposal.py`, `runner.py`; CLI ở `scripts/probe.py` |
| Guardrails | `src/sentinel_benchmark/guardrails/injection.py`, `approval.py` |
| Chức năng che dữ liệu | `src/sentinel_benchmark/guardrails/redaction.py` (chạy ở sink: prompt + log) |
| Docker Compose | `docker-compose.yml` + `configs/gateway-policy.yml`; điều khiển bằng `scripts/stack.sh` |
| Chuỗi end-to-end + log/metrics | `scripts/flow.py` + `src/sentinel_benchmark/runlog.py` |

## 2. Tài liệu kỹ thuật

| Hạng mục | Ở đâu |
| :--- | :--- |
| Kiến trúc hệ thống | [architecture.md](architecture.md) |
| Hướng dẫn cài đặt | [install.md](install.md) |
| Hướng dẫn chạy demo | [demo-guide.md](demo-guide.md) |
| Các giới hạn của hệ thống | [limitations-and-risks.md §1-§3](limitations-and-risks.md) |
| Các quyết định thiết kế chính | [architecture.md §6](architecture.md#6-những-quyết-định-đáng-giải-thích) |
| Các rủi ro bảo mật còn tồn tại | [limitations-and-risks.md §4](limitations-and-risks.md#4-rủi-ro-bảo-mật-còn-tồn-tại) |

Tài liệu phương pháp đi kèm: [verdict và cách đo](../methodology/verdict-and-scoring.md),
[DAST trên Juice Shop](../methodology/dast-juice-shop.md),
[request tool](../methodology/request-tool.md),
[System Prompt](../prompts/week6-security-analysis-agent.md),
[DAST LLM-as-judge](../prompts/dast-llm-judge.md).

## 3. Báo cáo kết quả

[results.md](results.md) - lỗ hổng phát hiện, case đúng, case sai, FP/FN, đề xuất
cải tiến. Mọi số đều có đường dẫn tới file JSON/JSONL đã commit.

## 4. Bản trình diễn

[demo-script.md](demo-script.md) - kịch bản 10-15 phút, có bảng đối chiếu 7 điểm
bắt buộc (một lần quét, agent tạo báo cáo, agent đề xuất request, Approve/Reject,
request qua Gateway, prompt injection bị chặn, dữ liệu nhạy cảm bị che) với bước
tương ứng.

## 5. Bản mô tả sản phẩm ngắn

[product-brief.md](product-brief.md) - vấn đề, người dùng, giá trị, phạm vi hiện
tại, hạn chế, hướng phát triển.

---

## Chạy nhanh để kiểm chứng

```bash
python -m pytest -q                                    # 140 test
python scripts/flow.py --provider nine_router          # cả chuỗi, có người duyệt
python scripts/analyze.py eval-cases                   # chấm 10 case tự viết
python scripts/security/artifact_hygiene.py            # không secret, không abs path
```
