# Verdict và cách đo

## Vấn đề

Scanner nói *"có thể có SQL injection ở dòng 40"*. Đó là một **quan sát**, chưa
phải sự thật. Đến hết Week 5, agent nhận mọi alert rồi viết giải thích + cách
sửa cho tất cả, **không bao giờ nói "cái này scanner báo nhầm"**. Nó chưa làm
được việc chính của một người phân tích: sàng lọc.

Tệ hơn, UI tự suy ra verdict từ ngưỡng confidence (`confidence >= 0.85` →
"True Positive"). Nghĩa là màn hình báo một kết luận **không ai đưa ra**.

## Verdict

Một nhãn duy nhất trả lời "finding này có thực sự là lỗ hổng?", 5 giá trị:

| Verdict | Khi nào |
| :--- | :--- |
| `confirmed_vulnerable` | Bằng chứng cho thấy trực tiếp: input không tin cậy chảy vào sink, hoặc probe đã xác nhận |
| `likely_vulnerable` | Dấu hiệu đúng nhưng thiếu một mắt xích (thấy sink, không thấy nguồn input) |
| `likely_false_positive` | Có chỉ dấu FP theo KB (prepared statement, dữ liệu là hằng số...) - **phải nêu tên chỉ dấu đó** |
| `not_vulnerable` | Bằng chứng cho thấy rõ ràng không phải |
| `insufficient_evidence` | Excerpt trống/không đọc được → không kết luận, **phải nói thiếu gì** |

Kèm hai field bắt buộc: `verdict_rationale` (20-1200 ký tự) và
`false_positive_indicators[]`.

**Vì sao 5 mức chứ không phải có/không.** Nếu buộc LLM chọn true/false, nó sẽ
đoán bừa khi thiếu dữ liệu. `insufficient_evidence` là van an toàn, và nó chính
là tiêu chí "agent xử lý được dữ liệu đầu vào trống hoặc không hợp lệ".

## Evidence Guard: verdict phải có chỗ dựa

Guard (`analysis/guard.py`) là Python, không hỏi lại model. Ngoài kiểm schema,
nó ép bốn luật *hỗ trợ* - mỗi luật biến verdict thành thứ có thể bác bỏ:

| Luật | Vì sao |
| :--- | :--- |
| `verdict_rationale` phải chứa nguyên văn một `observation_id` | Không trích dẫn thì không phân biệt được phân tích với phát biểu suông |
| ...và một `kb_document_id`, khi retrieval có trả về tài liệu | Chỉ đòi khi thực sự có tài liệu; không bắt trích thứ không tồn tại |
| `confirmed_vulnerable` đòi ít nhất một excerpt khác rỗng | Không đọc được gì thì mức trung thực nhất là "likely", không phải "confirmed" |
| `likely_false_positive` đòi chỉ dấu; `insufficient_evidence` đòi limitation | Đối xứng: mọi kết luận đều phải nói dựa vào đâu |

`ground_truth`, `outcome`, `review_status` **vĩnh viễn** nằm trong danh sách
cấm: corpus biết đáp án, model thì không.

## Chấm điểm

Policy cố định, áp y nguyên cho cả hai nguồn, nên số thay đổi là do agent thay
đổi chứ không phải do cây thước:

- `confirmed_vulnerable` + `likely_vulnerable` → agent nói **CÓ**
- `likely_false_positive` + `not_vulnerable` → agent nói **KHÔNG**
- `insufficient_evidence` → **abstain**, đếm riêng, **không** nhét vào TP/FP/FN

Cột abstain riêng là điều bắt buộc: nếu gộp nó vào FP hay FN thì agent chỉ cần
từ chối trả lời là precision đẹp lên - đúng cái động cơ ngược cần tránh.

SAST có ground truth từ BenchmarkJava nên so trực tiếp. Ground truth **chỉ được
join sau khi report đã ghi ra file** (`scripts/analyze.py score`), không bao giờ
vào prompt. DAST **không có corpus ground truth**. Precision/Recall của nhánh
này là **LLM-as-judge** (Grok 4.5, `docs/prompts/dast-llm-judge.md`): một model
khác đọc packet đã redact (alert + probe, **không** có verdict của agent) rồi
Python áp cùng policy TP/FP/FN/abstain (`scripts/analyze.py judge-dast`). Nhãn
judge là proxy, không phải nhãn Juice Shop. Case judge cũng abstain thì đếm
`no_ground_truth`, không bịa ô confusion matrix. Song song vẫn đo **bao nhiêu
verdict đã được một response thật kiểm chứng**.

Trên bảng Reports:

- **Probed** = finding DAST đã nhận được HTTP response qua Gateway. Không phải
  true positive. Một GET có thể phủ nhiều finding trên cùng path.
- **Verdict changed** = agent đổi verdict sau khi đọc response đó.
- Không có hàng Overall: Precision/Recall SAST và DAST dùng hai thước khác nhau,
  cộng chúng là số bịa.

## Probe cập nhật verdict

Đây là phần thuyết phục nhất khi demo, và nó chạy thật:

```
/ + CWE-693   insufficient_evidence  ->  confirmed_vulnerable
   observed: No Content-Security-Policy header is present in the response.
   why: The response from route_id "js-root" lacks a Content-Security-Policy
        header, directly supporting the reported CWE-693 weakness.
```

Agent từ chối kết luận khi chỉ có lời scanner. Người duyệt một request GET.
Gateway chở nó đi. Response thật cho thấy header vắng mặt thật. Agent nâng
verdict, có trích dẫn. Verdict cũ **không bị xoá** - nó nằm trong
`verification.verdict_before`, nên "probe làm đổi kết luận" là điều kiểm chứng
được, không phải lời kể.

Trong pass thứ hai, Python giữ mọi thứ **đo được** (status, header, có gửi hay
không, có tới đích hay không); model chỉ được diễn giải. Guard từ chối câu trả
lời nào khẳng định một phép đo thay vì giải thích nó.

Probe bị từ chối hoặc không có route thì verdict **giữ nguyên** kèm
`unverified_reason` - "chưa xác minh" không bao giờ được đọc thành "đã kiểm tra
và sạch".

Một response phục vụ được nhiều finding: 3 alert trên cùng `/` được trả lời bởi
một GET, nên người duyệt bị hỏi một lần, không phải ba.

## Kết quả đo được

Cùng 25 analysis group, cùng model `gpt-5.6-luna`, chỉ khác payload và KB:

| | scanner-only, KB v1 | + source code, KB v2 |
| :--- | ---: | ---: |
| TP | 20 | 21 |
| FP | 4 | **2** |
| FN | 0 | 0 |
| **TN** | **0** | **2** |
| abstain | 1 | 0 |
| precision | 0.833 | **0.913** |
| recall | 1.000 | 1.000 |
| F1 | 0.909 | **0.955** |

`TN = 0` ở cột đầu là con số đáng nói nhất: agent **chưa bao giờ** dám kết luận
"không phải lỗ hổng". Nguyên nhân do chính agent nói ra trong rationale:

> "the supplied excerpt is descriptive rather than source code"

Payload lúc đó chỉ có **mô tả của scanner** - vốn đã khẳng định có lỗi - nên
agent không có gì để phản biện. Ba case FP kinh điển của BenchmarkJava
(`00056`, `00093`, `00099`) chỉ phân biệt được khi đọc code:

```java
 66|         String bar = "alsosafe";
 69|             valuesList.add("safe");
 73|             valuesList.remove(0);       // remove the 1st safe value
 75|             bar = valuesList.get(1);    // get the last 'safe' value
```

Giá trị tới sink là **hằng số**, không phải input. Đó là bằng chứng để nói
`likely_false_positive`, và trước đây agent không được thấy dòng nào trong số đó.

### Cái giá và cách xử lý

Lần chạy đầu có source làm xuất hiện **1 FN**: `BenchmarkTest00011` bị kết luận
`not_vulnerable` với lý do *"in Java, an absolute child ignores the parent"*.
Đó là hành vi của `os.path.join` bên Python, **không phải** của Java: trong
`new File(param, "/Test.txt")`, child luôn được resolve theo parent, nên
attacker điều khiển toàn bộ phần thư mục. Agent đã trích `KB-003` nhưng **áp
sai** chỉ dấu "tên file lấy từ allowlist cố định" - tên file đúng là cố định,
nhưng thư mục thì bị nhiễm.

Sửa ở KB, không sửa ở prompt: `KB-003` được thắt lại thành "toàn bộ đường dẫn
lấy từ allowlist - tên file cố định mà thư mục vẫn từ input thì **không** phải
false positive", kèm một `confirm_indicator` mô tả đúng semantics của
`File(parent, child)`. Chạy lại đúng case đó: `not_vulnerable` →
`confirmed_vulnerable`, rationale trích chỉ dấu mới. Đây là vòng lặp mà hệ
thống này cần có: **đo → chẩn đoán → sửa KB → đo lại**.

### DAST: KB v2 không giảm abstain, và đó là điều đúng

Dự đoán ban đầu là 5 doc header sẽ cắt được 15 abstain. **Không.** Abstain đi từ
15 lên 16 - nhưng lý do thì đổi hẳn:

| | trước | sau |
| :--- | :--- | :--- |
| KB lấy về | `KB-006` (access control, lạc đề) | `KB-693-CSP`, `KB-693-XCTO`, `KB-1021-XFO` |
| Lý do abstain | "KB không xác nhận được finding này" | "KB-693-CSP **yêu cầu** xác nhận response header, mà observation chỉ có URL" |

Trước là abstain vì KB lạc đề. Giờ là abstain vì KB đã **nói rõ cần bằng chứng
gì**, và một passive scan thì về nguyên tắc không có bằng chứng đó. Alert của
ZAP baseline không mang response header - chỉ một request thật mới có.

Nên đây không còn là lỗ hổng của KB; nó chuyển việc giải quyết sang bước probe,
và probe làm được: `verify` nâng **2 verdict** từ `insufficient_evidence` lên
`confirmed_vulnerable` dựa trên header thật vắng mặt.

Điểm nghẽn còn lại của DAST không phải model mà là **độ phủ của allowlist
gateway**: 9/18 finding không có route nào chở được nên buộc phải báo "cannot
verify", và trong demo có 2 request bị người duyệt từ chối.

## Eval set tự viết: 10 case, và cái nó tìm ra

Ground truth của BenchmarkJava chỉ trả lời cho 100 case của chính nó. Nó không
nói gì về một endpoint Juice Shop, không nói abstain lúc nào là đúng, và không
nói rationale có nêu đúng chi tiết quyết định hay không.
`datasets/evaluation/week6-eval-cases.jsonl` lấp chỗ đó: 10 case với expected
answer **viết tay bằng cách đọc source hoặc response**, mỗi case kèm
`deciding_evidence` - lập luận để chính case đó tự bảo vệ khi agent phản đối.

Harness (`analysis/evalset.py`, `scripts/analyze.py eval-cases`) chấm ba thứ
tách rời nhau, cố ý:

| Chấm gì | Vì sao tách |
| :--- | :--- |
| **Stance** (vulnerable / not / abstain) | đây là confusion matrix; abstain vẫn ở cột riêng |
| **Verdict** (nhãn chính xác có được case chấp nhận) | đúng stance mà nhãn thô hơn mức cần thì vẫn là thiếu |
| **Reasoning** (rationale có nêu chi tiết quyết định) | đúng vì lý do sai sẽ không sống sót case tiếp theo |

Cột `right_for_the_wrong_reason` tồn tại chính vì lý do thứ ba.

### Kết quả và điều nó chỉ ra

| | prompt v3 | prompt v4 + KB-328 |
| :--- | ---: | ---: |
| TP / TN | 4 / 2 | 4 / 2 |
| FP | 1 | 2 |
| abstain đúng | 2 | 2 |
| abstain sai (đáng lẽ phải kết luận) | **1** | **0** |
| stance accuracy | 0.8 | 0.8 |

`v4` sửa được `EV-08`. Case đó hỏi về alert trên `/robots.txt`: response đã trả
lời xong - file public theo thiết kế, không chứa gì nhạy cảm - nhưng `v3` vẫn giữ
abstain, vì pass 2 đọc câu *"if the response cannot settle the question, keep the
previous verdict"* thành một mặc định thiên về abstain. Thêm một câu cho phép
"settle in the negative" là đủ, và hiệu ứng lan ra cả DAST: abstain sau probe đi
từ **12 xuống 4**, và `not_vulnerable` lần đầu xuất hiện (5 verdict).

### Một nguyên nhân, ba false positive

Điều đáng giá nhất eval set tìm ra là **cả 3 FP còn lại của SAST đều cùng một
lỗi**, và nó không phải lỗi thiếu kiến thức:

| Case | CWE được báo | Agent nói gì | Verdict |
| :--- | :--- | :--- | :--- |
| `00009` (EV-02) | CWE-328 weak hash | *"The SHA-384 algorithm is strong and not the issue"* | `confirmed_vulnerable` - vì `FileWriter` append không có quota, có thể cạn đĩa |
| `00016` (EV-04) | CWE-614 cookie thiếu Secure | *"Secure and HttpOnly mitigate the primary cookie risks"* | `likely_vulnerable` - vì giá trị cookie đến từ input |
| `00022` | CWE-328 weak hash | *"SHA-2 is not a CWE-328 weak hash"* | `likely_vulnerable` - vì hash mật khẩu không salt (CWE-916) |

Cả ba đều có `reasoning_matched=True`: agent **đã nêu đúng** chi tiết quyết định,
rồi ra verdict ngược lại với chính nó. Nó không hiểu sai kỹ thuật; nó **trả lời
một câu hỏi khác** - "trong file này có vấn đề gì không" thay vì "lỗ hổng được báo
có thật không".

KB-328-HASH có tác dụng: agent giờ nói đúng về SHA-2/SHA-3, và điều đó nhìn thấy
trong rationale. Nhưng nó không sửa được lỗi phạm vi, vì đây không phải lỗ hổng
kiến thức.

Một câu thêm vào prompt v4 (*"Decide about the weakness that was reported, and
only that one"*) cũng **không** sửa được. Trên 25 group, precision đi từ 0.913
xuống 0.875 - lệch một case ở n=25, tức là nhiễu, không phải hồi quy có nghĩa,
nhưng cũng không phải cải thiện. Kết luận: thuyết phục bằng prompt không đủ cho
một ràng buộc mà Python kiểm tra được.

### Đề xuất sửa: khai báo phạm vi, để Guard kiểm

Thêm một field vào hợp đồng: `verdict_cwe` - *"CWE mà verdict của bạn nói về;
copy nguyên văn từ weakness được báo"*. Rồi một luật Guard:

> Nếu stance là vulnerable và group có CWE được báo, thì `verdict_cwe` phải nằm
> trong tập CWE đó. Không thì fail, retry.

Với `00022`, `verdict_cwe` trung thực là `CWE-916` - Guard chặn, model buộc phải
quyết định về `CWE-328`, và nó đã biết câu trả lời là không. Vấn đề khác nó phát
hiện được vẫn giữ, nhưng ở `limitations`, không phải ở verdict.

Guard không kiểm được ngữ nghĩa: model vẫn có thể ghi `CWE-328` rồi lập luận về
chuyện khác. Nhưng khi đó rationale tự mâu thuẫn ngay trên mặt giấy, và người
review bắt được - thay vì như hiện nay, verdict và lý do lệch nhau mà vẫn qua.

Ba đề xuất còn lại, theo thứ tự giá trị:

1. **Mở rộng độ phủ allowlist theo pattern** thay vì từng path: `/ftp/{file}` đã
   cho thấy một route template phục vụ được nhiều finding. 2 finding còn lại không
   probe được là đường dẫn AJAX spider bóc từ stack trace - nên chặn ở
   normalizer, đừng để nó thành "endpoint" ngay từ đầu.
2. **Tách "vấn đề khác phát hiện được" thành finding riêng** thay vì nhốt trong
   `limitations`: hiện agent thấy CWE-916 ở `00022` mà hệ thống không có chỗ nào
   để ghi lại nó như một quan sát mới.
3. **Đo lại với n lớn hơn 25.** Mọi so sánh trong tài liệu này lệch nhau 1-2
   case; ở cỡ mẫu đó không kết luận được prompt nào tốt hơn, chỉ kết luận được
   nguyên nhân nào còn tồn tại.

## LLM-as-judge cho DAST (Grok 4.5)

Artifact: `artifacts/week-6/evaluation/verdict-metrics-dast-kb2-judge.json`.
Nhãn: `dast-llm-judge-labels.json`. Prompt: `docs/prompts/dast-llm-judge.md`.
Run: `20260822T085445Z-dast-kb2`.

| | Grok 4.5 judge |
| :--- | ---: |
| Judge `vulnerable` / `not_vulnerable` / `insufficient` | 4 / 4 / 10 |
| Scored (có nhãn proxy) | 4 |
| TP / FP / FN / TN | 3 / 1 / 0 / 0 |
| Agent abstain trên case đã có nhãn | 4 |
| Precision / Recall / F1 | **0.750** / **1.000** / 0.857 |

FP duy nhất: DJ-01 — agent `confirmed_vulnerable` cho alert "Modern Web
Application"; judge coi đó là ghi chú scanner, không phải lỗ hổng được báo.
Mười case `insufficient` của judge phần lớn là probe bị reject hoặc chưa gửi —
đúng policy "không kết luận khi chưa thấy header/body".
