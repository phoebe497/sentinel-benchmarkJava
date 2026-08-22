# Kịch bản demo (10-15 phút)

Bảy điểm bắt buộc phải thể hiện, và chỗ mỗi điểm xuất hiện:

| # | Phải thể hiện | Ở bước nào |
| :--- | :--- | :--- |
| 1 | Một lần chạy công cụ quét | [§2](#2-2-phút--một-lần-quét-thật) |
| 2 | Agent tạo báo cáo | [§3](#3-3-phút--agent-ra-verdict-không-phải-viết-văn) |
| 3 | Agent đề xuất request kiểm tra | [§4](#4-2-phút--agent-đề-xuất-request-python-chọn-route) |
| 4 | Người dùng Approve hoặc Reject | [§4](#4-2-phút--agent-đề-xuất-request-python-chọn-route) |
| 5 | Request đi qua API Gateway | [§4](#4-2-phút--agent-đề-xuất-request-python-chọn-route) |
| 6 | Prompt Injection bị chặn | [§6](#6-2-phút--prompt-injection-bị-chặn-trên-http-thật) |
| 7 | Dữ liệu nhạy cảm bị che | [§6](#6-2-phút--prompt-injection-bị-chặn-trên-http-thật) và [§7](#7-1-phút--log-và-metrics) |

Chuẩn bị trước khi bắt đầu (đừng làm trong lúc demo, mất 3-5 phút):

```bash
bash scripts/stack.sh up        # gateway + juice-shop + demo-api
bash scripts/stack.sh scan      # ZAP baseline, chạy sẵn nếu muốn tiết kiệm thời gian
```

---

## 1. (1 phút) - Vấn đề

Một câu: *"Scanner báo hàng trăm cảnh báo, phần lớn không phải lỗ hổng. Câu hỏi
tốn tiền là 'cái này có thật không', và hiện nay câu đó bị đẩy hết sang con
người."*

Mở `configs/gateway-policy.yml` một giây để cho thấy phạm vi lab: Juice Shop và
demo-api **không publish port** - chỉ gateway mở `8080`.

## 2. (2 phút) - Một lần quét thật

```bash
bash scripts/stack.sh scan
```

Chỉ vào `artifacts/week-6/dast/manifest.json`: ZAP `2.17.0`, image digest,
nguyên văn command, `sha256` của output, `9 alert / 18 URL / 33 observation`.
Provenance được sinh **từ chính artifact**, nên manifest không thể lệch khỏi bằng
chứng nó mô tả.

Nói rõ đây là **passive**: spider và đọc traffic, không tấn công.

## 3. (3 phút) - Agent ra verdict, không phải "viết văn"

```bash
python scripts/analyze.py run --provider nine_router --dataset sast --limit 25 --tag demo
python scripts/analyze.py score --tag demo
```

Mở một report và chỉ ba thứ:

- `verdict` - một trong 5 giá trị, không phải điểm confidence.
- `verdict_rationale` - **buộc phải** trích dẫn `observation_id` và document KB.
  Evidence Guard (Python) từ chối nếu thiếu.
- `false_positive_indicators` - khi nói "báo sai" thì phải nêu tên chỉ dấu.

Điểm đáng nhấn: payload SAST có **source code thật**. Trước khi có nó, agent
**chưa bao giờ** kết luận "không phải lỗ hổng" (`TN = 0`) - nó chỉ có mô tả của
scanner, vốn đã khẳng định sẵn là có lỗi.

## 4. (2 phút) - Agent đề xuất request, Python chọn route, người duyệt quyết định

```bash
python scripts/probe.py plan     # 16/18 finding verify được, 2 thì không
```

Hai finding "cannot verify" là đường dẫn AJAX spider bóc từ stack trace bị lộ -
không phải endpoint của ứng dụng. **Từ chối probe là hành vi đúng**, không phải
thiếu sót.

```bash
python scripts/flow.py --provider nine_router
```

Ở prompt duyệt: **bấm `n` một lần** cho thấy Reject là thật.

- Request tool chỉ nhận `route_id` + `payload_id`, **không nhận URL** - nên không
  câu chữ nào trong response điều nó tới đích khác được.
- Mỗi request in đủ endpoint, payload, mục đích rồi chờ `y/n` gõ tay. Không có
  flag nào trả lời hộ.
- Mở `artifacts/week-6/probes/<run_id>-probe.jsonl`: dòng bị từ chối có
  `"decision": "reject"`, `"sent": false`.

## 5. (2 phút) - Response thật đổi kết luận

Đây là phần thuyết phục nhất. Chỉ vào output của `verify`:

```
/ + CWE-693   insufficient_evidence  ->  confirmed_vulnerable
   observed: Content-Security-Policy is absent from the response headers.
```

Trước probe agent **từ chối kết luận**, vì alert passive không mang response
header. Sau một GET được duyệt, header vắng mặt thật. Verdict cũ **không bị xoá**
- nó nằm trong `verification.verdict_before`, nên "probe làm đổi kết luận" là
điều kiểm chứng được, không phải lời kể.

Nói thêm: trong pass 2, Python giữ mọi thứ **đo được** (status, header, có gửi
hay không); model chỉ được diễn giải, và Guard từ chối câu trả lời nào khẳng định
một phép đo thay vì giải thích nó.

## 6. (2 phút) - Prompt injection bị chặn, secret bị che

```bash
python scripts/probe.py injection-check
```

Fixture crafted được POST tới `/echo` và phản chiếu về như một response untrusted
thật. Năm dòng PASS in ra:

```
PASS  reached_target
PASS  injection_flagged
PASS  expected_patterns_detected
PASS  response_quarantined_as_data
PASS  no_secret_survived
```

Mở file evidence: text injection **được giữ nguyên** trong dấu delimiter DATA,
không bị "làm sạch" thầm - vì nó còn là bằng chứng. Secret trong response đã
thành `[REDACTED_TOKEN]` / `[REDACTED_EMAIL]` trước khi ghi ra bất cứ đâu.

## 7. (1 phút) - Log và metrics

```bash
cat artifacts/week-6/metrics/<run_id>.json
```

Một file cho cả lần chạy: thời gian từng stage, `probes.proposed / approved /
rejected / sent`, `verifications.verdict_changed`, và `errors[]`. Đáng chỉ riêng
một counter:

```
probes.rejected_but_sent: 0
```

Đó là thất bại tệ nhất hệ thống này có thể mắc, nên nó được **đếm tách riêng** và
có test khẳng định, thay vì để ngầm trong hiệu của hai số khác.

```bash
python scripts/security/artifact_hygiene.py
```

Không secret, không đường dẫn tuyệt đối của máy local trong artifact sắp publish.

## 8. (1 phút) - Đo và giới hạn

```bash
python scripts/analyze.py eval-cases --sast-tag sast-v4 --dast-tag flow
```

Kết thúc bằng chỗ agent **sai**, đừng kết thúc bằng chỗ nó đúng: mở
`artifacts/week-6/evaluation/eval-cases-failures.jsonl`. Cả hai FP còn lại đều
cùng một nguyên nhân - agent nêu đúng chi tiết quyết định (*"SHA-384 is strong and
not the issue"*) rồi vẫn kết luận vulnerable vì thấy **một vấn đề khác**. Đề xuất
sửa: khai báo `verdict_cwe` và để Guard kiểm, chi tiết ở
[../methodology/verdict-and-scoring.md](../methodology/verdict-and-scoring.md).

## Nếu có sự cố giữa demo

| Triệu chứng | Xử lý |
| :--- | :--- |
| Router trả `503` | Lỗi upstream tạm thời. Chạy lại; hoặc đổi sang `--provider fake` để demo tiếp phần pipeline. |
| Không kịp thời gian | Bỏ §2 (dùng scan đã có sẵn) và §3 (dùng run đã commit), giữ §4-§6. |
| Cần demo có kịch bản | `printf 'y\ny\ny\nn\ny\ny\ny\ny\nn\ny\n' \| python scripts/flow.py --provider nine_router` |
