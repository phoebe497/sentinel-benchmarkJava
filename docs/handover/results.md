# Báo cáo kết quả

Mọi số trong tài liệu này truy được về một file JSON/JSONL đã commit; đường dẫn
ghi ngay cạnh bảng. Không số nào được nhập tay.

- SAST: `artifacts/week-3/evaluation/verdict-metrics-sast-v4.json`
- DAST coverage: `artifacts/week-6/metrics/20260822T093819Z-flow.json`
- DAST LLM-as-judge (Grok 4.5): `artifacts/week-6/evaluation/verdict-metrics-dast-kb2-judge.json`
- Eval set: `artifacts/week-6/evaluation/eval-cases-metrics.json`
- Provenance quét DAST: `artifacts/week-6/dast/manifest.json`

Model: `gpt-5.6-luna` cho cả hai pass. Prompt: `week6-agent-v4`. KB: 38 doc.

## 1. Lỗ hổng đã phát hiện

### 1.1 SAST - 25 nhóm phân tích trên BenchmarkJava

Agent kết luận **24/25 nhóm là lỗ hổng thật** (21 `confirmed_vulnerable`,
3 `likely_vulnerable`), 1 nhóm `likely_false_positive`.

| CWE | Loại | Số nhóm |
| :--- | :--- | ---: |
| CWE-78 | OS Command Injection | 4 |
| CWE-89 | SQL Injection | 4 |
| CWE-22 | Path Traversal | 3 |
| CWE-327 | Weak Cryptography | 3 |
| CWE-328 | Weak Hash | 3 |
| CWE-79 | Cross-Site Scripting | 2 |
| CWE-90 | LDAP Injection | 2 |
| CWE-330 / CWE-501 / CWE-614 | Weak Random / Trust Boundary / Cookie | 1 mỗi loại |

### 1.2 DAST - Juice Shop, ZAP baseline

Quét: ZAP `2.17.0` (image digest ghim trong manifest), passive-only, traditional
spider 3 phút + AJAX spider. Kết quả: **9 loại alert trên 18 URL**, chuẩn hóa
thành **33 observation**, gom thành **18 endpoint group**.

Sau khi agent phân tích và probe xác minh:

| Verdict | Số finding |
| :--- | ---: |
| `confirmed_vulnerable` | 5 |
| `likely_vulnerable` | 3 |
| `not_vulnerable` | 5 |
| `likely_false_positive` | 1 |
| `insufficient_evidence` | 4 |

Lỗ hổng được xác nhận, theo CWE: **CWE-693** (thiếu security header) 5,
**CWE-497** (lộ thông tin nội bộ) 2, **CWE-264** 1.

Đáng chú ý nhất: `/rest/admin/application-configuration` trả về toàn bộ
configuration của ứng dụng cho một GET **không cần xác thực** - được xác nhận
bằng response thật, không phải bằng lời scanner.

## 2. Trường hợp Agent phân tích đúng

### 2.1 Số tổng

| SAST (n=25, có ground truth) | |
| :--- | ---: |
| True positive | 21 |
| True negative | 1 |
| False positive | 3 |
| False negative | **0** |
| Abstain | 0 |
| Precision / Recall / F1 | 0.875 / **1.000** / 0.933 |
| Accuracy | 0.880 |

Recall `1.000` với FN `0` là con số quan trọng nhất về mặt an toàn: **không lỗ
hổng thật nào bị agent bỏ qua**. Sai số của nó nghiêng về phía cẩn thận quá mức,
không nghiêng về phía bỏ sót.

### 2.1b DAST — LLM-as-judge (Grok 4.5), không phải corpus

Juice Shop không có nhãn corpus. Bảng Reports lấy Precision/Recall từ
`verdict-metrics-dast-kb2-judge.json`: Grok 4.5 đọc 18 packet (alert + probe,
không có verdict agent), rồi Python áp cùng policy SAST.

| DAST (run `dast-kb2`, n=18) | |
| :--- | ---: |
| Judge `vulnerable` / `not_vulnerable` / `insufficient` | 4 / 4 / 10 |
| Scored (có nhãn proxy) | 4 |
| True positive | 3 |
| False positive | 1 |
| False negative | **0** |
| True negative | 0 |
| Agent abstain trên case đã có nhãn | 4 |
| Precision / Recall / F1 | **0.750** / **1.000** / 0.857 |

FP: alert "Modern Web Application" trên `/` — agent `confirmed_vulnerable`,
judge coi là ghi chú scanner. Mười case judge abstain vì probe chưa chạy hoặc
bị reject; không bịa ô matrix cho chúng.

Cùng run đó, **5 finding được probe** (HTTP response tới endpoint; 3 path),
**2 verdict đổi** sau response. Probed ≠ true positive. Bảng Reports không có
hàng Overall: hai thước SAST/DAST không cộng được.

### 2.2 Đúng vì có source code, không phải vì đoán may

Payload SAST mang **source code thật** của test case (line-numbered, coi như
untrusted data, redact ở sink). Trước khi có nó:

| 25 nhóm SAST, cùng model | scanner-only, KB v1 | + source code, KB v2 |
| :--- | ---: | ---: |
| TP | 20 | 21 |
| FP | 4 | 2 |
| **TN** | **0** | **2** |
| Precision / F1 | 0.833 / 0.909 | 0.913 / 0.955 |

`TN = 0` ở cột đầu là điểm chính: agent **chưa bao giờ** dám kết luận "không phải
lỗ hổng". Nguyên nhân do chính rationale của nó nói ra: *"the supplied excerpt is
descriptive rather than source code"*. Nó chỉ có mô tả của scanner - vốn đã khẳng
định sẵn là có lỗi - nên không có gì để phản biện.

Ví dụ nó phân biệt được sau khi đọc code (`BenchmarkTest00056`):

```java
 66|         String bar = "alsosafe";
 69|             valuesList.add("safe");
 73|             valuesList.remove(0);       // remove the 1st safe value
 75|             bar = valuesList.get(1);    // get the last 'safe' value
```

Giá trị tới sink là **hằng số**, không phải input.

### 2.3 Đúng nhờ response thật (DAST)

Trước probe agent từ chối kết luận, vì alert passive không mang response header.
Sau một GET được người duyệt cho đi:

```
/ + CWE-693   insufficient_evidence  ->  confirmed_vulnerable
   observed: Content-Security-Policy is absent from the response headers.
   why:      The response from route_id "js-root" lacks a Content-Security-Policy
             header, directly supporting the reported CWE-693 weakness.
```

Trong một lần chạy end-to-end: 12 verdict được response thật trả lời, **6 verdict
đổi** so với trước probe. Verdict cũ **không bị xoá** - nó nằm trong
`verification.verdict_before`.

## 3. Trường hợp Agent phân tích sai

Cả **3 false positive còn lại cùng một nguyên nhân**, và đó không phải lỗi thiếu
kiến thức:

| Case | CWE được báo | Agent **tự nói** | Verdict nó ra |
| :--- | :--- | :--- | :--- |
| `BenchmarkTest00009` | CWE-328 weak hash | *"The SHA-384 algorithm is strong and not the issue"* | `confirmed_vulnerable` - vì `FileWriter` append không có quota, có thể cạn đĩa |
| `BenchmarkTest00016` | CWE-614 cookie thiếu Secure | *"Secure and HttpOnly mitigate the primary cookie risks"* | `likely_vulnerable` - vì giá trị cookie đến từ input |
| `BenchmarkTest00022` | CWE-328 weak hash | *"SHA-2 is not a CWE-328 weak hash"* | `likely_vulnerable` - vì hash mật khẩu không salt (CWE-916) |

Cả ba đều có `reasoning_matched = true` trong eval set: agent **đã nêu đúng** chi
tiết quyết định, rồi ra verdict ngược lại với chính nó. Nó trả lời **một câu hỏi
khác**: "file này có vấn đề gì không" thay vì "lỗ hổng được báo có thật không".

Ba nhận định của nó đều **đúng về mặt kỹ thuật** - chỉ là chúng nói về weakness
khác (CWE-400, CWE-20, CWE-916), không phải weakness đang được hỏi.

### 3.1 Một false negative đã sửa được, và cách sửa

Lần chạy đầu có source làm xuất hiện 1 FN: `BenchmarkTest00011` bị kết luận
`not_vulnerable` với lý do *"in Java, an absolute child ignores the parent"* -
sai, đó là hành vi của `os.path.join` bên Python. Trong Java,
`new File(parent, "/Test.txt")` **luôn** resolve child theo parent, nên attacker
kiểm soát toàn bộ phần thư mục.

Agent đã trích `KB-003` nhưng **áp sai** chỉ dấu "tên file lấy từ allowlist cố
định". Sửa ở **KB**, không sửa ở prompt: thắt lại `fp_indicator` thành "toàn bộ
đường dẫn phải từ allowlist - tên file cố định mà thư mục vẫn từ input thì
**không** phải false positive", kèm một `confirm_indicator` mô tả đúng semantics
của `File(parent, child)`. Chạy lại đúng case đó: `not_vulnerable` →
`confirmed_vulnerable`. Vòng **đo → chẩn đoán → sửa KB → đo lại** đã đóng được.

## 4. Eval set tự viết: 10 case

Ground truth của corpus không nói gì về endpoint Juice Shop, không nói abstain
lúc nào là đúng, và không nói rationale có nêu đúng chi tiết quyết định hay
không. `datasets/evaluation/week6-eval-cases.jsonl` lấp chỗ đó: 10 case với
expected answer **viết tay bằng cách đọc source hoặc response**, mỗi case kèm
`deciding_evidence` để tự bảo vệ khi agent phản đối. LLM-as-judge (Grok 4.5)
là thước **khác**: phủ cả 18 nhóm DAST trên Reports, không thay 5 case Juice
Shop viết tay.

| | prompt v3 | prompt v4 + KB-328 |
| :--- | ---: | ---: |
| TP / TN | 4 / 2 | 4 / 2 |
| FP | 1 | 2 |
| Abstain đúng | 2 | 2 |
| **Abstain sai** (đáng lẽ phải kết luận) | **1** | **0** |
| Stance accuracy | 0.8 | 0.8 |
| Đúng nhưng sai lý do | 0 | 0 |

Harness chấm ba thứ tách rời: **stance** (confusion matrix), **verdict** (nhãn có
được case chấp nhận), **reasoning** (rationale có nêu chi tiết quyết định). Tách
ra vì đúng vì lý do sai sẽ không sống sót case tiếp theo.

## 5. Đề xuất cải tiến

### 5.1 Đã thử và kết quả thật

| Thay đổi | Kết quả đo được |
| :--- | :--- |
| Đưa **source code** vào payload SAST | `TN 0 → 2`, `FP 4 → 2`, F1 `0.909 → 0.955`. Đây là thay đổi có tác dụng lớn nhất. |
| **KB v2** (38 doc, có `fp_indicators` / `confirm_indicators` / `detection_surface`) | Đổi *lý do* abstain của DAST từ "KB lạc đề" sang "KB yêu cầu bằng chứng mà passive scan không có" - chuyển việc giải quyết sang bước probe, và probe làm được. |
| Thắt `KB-003` (path traversal) | Sửa hẳn 1 FN, có case đối chứng. |
| Thêm `KB-328-HASH` | **Có tác dụng**: agent giờ nói đúng về SHA-2/SHA-3, thấy rõ trong rationale. Nhưng không sửa được lỗi phạm vi vì đó không phải lỗ hổng kiến thức. |
| Prompt `v4` - luật phạm vi (*"decide about the weakness that was reported, and only that one"*) | **Không sửa được** phía SAST: precision `0.913 → 0.875`, lệch một case ở n=25 nên là nhiễu, không phải hồi quy có nghĩa, nhưng cũng không phải cải thiện. |
| Prompt `v4` - cho pass 2 "settle in the negative" | **Sửa hẳn phía DAST**: abstain sau probe `12 → 4`, và `not_vulnerable` lần đầu xuất hiện (5 verdict). |
| Nới allowlist + bind route có tham số | Finding không verify được: `9/18 → 2/18`. |

Bài học rút ra được: **ràng buộc nào Python kiểm được thì đừng thuyết phục bằng
prompt**; còn thứ gì là kiến thức thiếu thì sửa ở KB, đừng sửa ở prompt.

### 5.2 Đề xuất tiếp, theo thứ tự giá trị

1. **`verdict_cwe` + luật Guard.** Thêm một field vào hợp đồng: *"CWE mà verdict
   của bạn nói về; copy nguyên văn từ weakness được báo"*. Guard chặn stance
   vulnerable nếu `verdict_cwe` không nằm trong tập CWE được báo. Với
   `BenchmarkTest00022`, khai báo trung thực là `CWE-916` → bị chặn → model buộc
   phải quyết định về `CWE-328`, mà nó đã biết câu trả lời là không. Đây là cơ chế
   nhắm đúng nguyên nhân đứng sau **3/3** FP còn lại.
2. **Chỗ để ghi weakness khác phát hiện được.** Hiện agent thấy CWE-916 ở `00022`
   mà hệ thống không có chỗ nào lưu nó như một observation mới, nên nó nhét vào
   verdict. Cho nó một chỗ đúng thì áp lực đó biến mất.
3. **Chặn ở normalizer** những "endpoint" vốn là đường dẫn trong stack trace, thay
   vì để chúng thành finding rồi mới từ chối probe.
4. **Đo lại với n lớn hơn 25.** Mọi so sánh ở §5.1 lệch nhau 1-2 case; ở cỡ mẫu
   đó chỉ kết luận được nguyên nhân, không kết luận được thứ hạng.
5. **Đóng vòng KB bán tự động**: mỗi FP/FN sinh một đề xuất sửa
   `fp_indicators`/`confirm_indicators` để người review chấp nhận. Vòng này hiện
   làm bằng tay và đã cho kết quả hai lần (`KB-003`, `KB-328`).
