# Giới hạn hệ thống và rủi ro bảo mật còn tồn tại

Tài liệu này nói những gì hệ thống **không** làm được. Các quyết định thiết kế
chính và lý do của chúng nằm ở [architecture.md §6](architecture.md#6-những-quyết-định-đáng-giải-thích).

## 1. Giới hạn về phạm vi đo

| Giới hạn | Hệ quả |
| :--- | :--- |
| Corpus là **100 case đầu** của BenchmarkJava | Mọi so sánh trong tài liệu lệch nhau 1-3 case trên n=25 nhóm. Ở cỡ mẫu đó không kết luận được prompt nào tốt hơn, chỉ kết luận được nguyên nhân nào còn tồn tại. |
| BenchmarkJava là corpus **tổng hợp** | Mỗi file là một sink duy nhất, ngắn, không có business logic. Precision ở đây không suy ra được precision trên codebase thật. |
| DAST **không có corpus ground truth** | Không corpus nào nói đúng/sai cho một endpoint Juice Shop. Precision/Recall trên UI là **LLM-as-judge (Grok 4.5)** — proxy, n=4 case có nhãn — cộng với coverage (verified/revised) và eval set tự viết. Judge abstain thì đếm `no_ground_truth`, không bịa ô matrix. |
| Eval set chỉ **10 case** | Nó được thiết kế để **chẩn đoán**, không để xếp hạng. Một case đổi kết quả là 10% - đừng đọc con số của nó như một benchmark. |

## 2. Giới hạn về năng lực phát hiện

**DAST là passive.** ZAP baseline spider và đọc traffic, không tấn công. Nó không
tìm được SQLi/XSS thực thi được; những gì nó báo phần lớn là thiếu security
header và lộ thông tin. Đây là chọn lựa có ý thức: active scan trên một app cố
tình có lỗ hổng thì dễ, nhưng nó biến pipeline thành công cụ tấn công.

**Không có state.** Mỗi request độc lập; không login, không session, không CSRF
token. Toàn bộ lớp lỗ hổng chỉ xuất hiện sau khi xác thực nằm ngoài tầm.

**Source code chỉ có cho corpus.** Endpoint sống không có file nào để đọc, nên
pass 1 của DAST luôn nghèo bằng chứng hơn SAST - đó là lý do abstain cao ở nhánh
DAST, và là lý do bước probe tồn tại.

**Passive alert không mang response header.** Nhiều finding DAST *về nguyên tắc*
không kết luận được nếu không probe. Đó không phải khuyết điểm của model.

**Allowlist hẹp hơn bề mặt quét.** 16/18 finding có route để xác minh. 2 finding
còn lại là đường dẫn AJAX spider bóc từ stack trace bị lộ
(`/juice-shop/node_modules/express/lib/router/index.js:365:14`) - không phải
endpoint của ứng dụng. Probe một trang 404 không chứng minh được gì, nên chúng
buộc phải báo "cannot verify".

## 3. Giới hạn của agent

**Agent vẫn sai, và sai theo một kiểu.** Cả 3 false positive còn lại của SAST
cùng một nguyên nhân: agent nêu đúng chi tiết quyết định (*"SHA-384 is strong and
not the issue"*) rồi vẫn kết luận vulnerable vì thấy **một vấn đề khác** trong
cùng file. Nó trả lời "file này có vấn đề gì không" thay vì "lỗ hổng được báo có
thật không". Chi tiết và đề xuất sửa:
[../methodology/verdict-and-scoring.md](../methodology/verdict-and-scoring.md).

**Guard kiểm cấu trúc, không kiểm ngữ nghĩa.** Nó ép verdict phải trích dẫn
`observation_id`, ép `confirmed_vulnerable` phải có excerpt, ép
`likely_false_positive` phải nêu chỉ dấu. Nó **không** kiểm được rationale có
thật sự nói về đúng lỗ hổng đó hay không.

**Không tự sửa lỗi.** Hệ thống ra verdict và gợi ý cách khắc phục; nó không sinh
patch và không tự sửa code.

**LLM là dịch vụ ngoài.** Router có thể trả `503` giữa lúc chạy (đã xảy ra trong
quá trình làm). Lỗi được ghi vào `errors[]` của metrics thay vì bị coi là "không
có finding" - nhưng lần chạy đó vẫn phải làm lại.

**Nondeterminism.** Cùng payload, cùng model, hai lần chạy có thể khác 1-2
verdict. Mọi so sánh A/B trong tài liệu đều nên đọc kèm cảnh báo này.

## 4. Rủi ro bảo mật còn tồn tại

### 4.1 Ứng dụng trong lab cố tình có lỗ hổng

BenchmarkJava và Juice Shop **không được** deploy ra môi trường công khai.
`docker-compose.yml` không mở port cho hai app đó - mọi đường vào đi qua gateway.
Thêm `ports:` cho `juice-shop` hoặc `demo-api` là phá bỏ bảo đảm này, và đó là
rủi ro *cấu hình* dễ mắc nhất của repo này.

UI công khai (Railway) chỉ đọc artifact đã commit, ở chế độ
`SENTINEL_UI_READONLY=1`, và nút Approve/Reject trên UI **chỉ ghi lại quyết
định** - nó không phải đường gửi request.

### 4.2 Prompt injection: phòng thủ nhiều lớp, không phải tuyệt đối

Filter (`guardrails/injection.py`) khớp theo **pattern đã biết**. Một injection
diễn đạt khác đi có thể lọt qua bước flag. Ba lớp sau đó là thứ thật sự chặn hậu
quả:

- Nội dung untrusted luôn được gắn nhãn DATA và đặt trong delimiter, không bao
  giờ ở chỗ dành cho chỉ thị.
- Request tool **không nhận URL**, chỉ nhận `route_id` trong allowlist - nên kể
  cả khi model bị điều khiển, nó không có cách nào gửi request tới đích khác.
- Evidence Guard từ chối mọi field ngoài hợp đồng, nên output bị bẻ hướng không
  thành report được.

Rủi ro còn lại: một injection *thuyết phục* có thể làm agent viết một rationale
sai lệch (dù vẫn phải trích dẫn `observation_id` thật). Đó là rủi ro **chất lượng
phân tích**, không phải rủi ro thực thi.

### 4.3 Redaction: anchored, nên có thể bỏ sót

Redaction bắt theo **hình dạng đã biết** (prefix key, JWT/Bearer, context
keyword) chứ không theo entropy - cố ý, để không băm nát `observation_id`,
`sha256`, `checksum`. Cái giá: một secret có định dạng lạ có thể lọt.

Đã có một lỗ thật thuộc đúng loại này và đã sửa: `sk_live_…` không bị mask khi
đứng trần, vì `[A-Za-z0-9]` dừng ở dấu `_`. Bài học: mỗi định dạng key mới là một
pattern phải thêm, và `tests/test_week5_guardrails.py` là chỗ khoá nó lại.

`DEFAULT_SKIP_KEYS` là danh sách **liệt kê tường minh**, không dùng pattern kiểu
`*_id`, vì response của ứng dụng có thể chứa `user_id` cần che. Cái giá: thêm một
field identifier mới mà quên khai báo thì giá trị của nó bị redact làm hỏng join
giữa probe record và report. Có test hồi quy cho đúng lỗi này.

### 4.4 Approval gate phụ thuộc con người

Không có auto-approve và không có đường bypass - nhưng cũng có nghĩa chất lượng
quyết định phụ thuộc người duyệt có đọc payload hay không. Hệ thống chỉ bảo đảm
được phần cơ học: payload hiện đầy đủ trước khi hỏi, Reject là không gửi,
`probes.rejected_but_sent` được đếm riêng và có test khẳng định bằng 0.

Nếu bước hỏi bị lỗi (không có stdin, EOF), mặc định là **reject**, không phải
approve.

### 4.5 Gateway là service ngoài, ghim commit

Allowlist là quyết định của Sentinel (`configs/gateway-policy.yml`), nhưng việc
thực thi nằm ở code của gateway trong submodule. Nâng submodule mà không đọc diff
là rủi ro: một thay đổi trong xử lý path hoặc header ở đó có thể mở rộng bề mặt
mà phía Sentinel không thấy.

### 4.6 Secret trong lab

`GATEWAY_API_KEY` được `scripts/stack.sh up` sinh vào `.env` (không commit).
`.env.example` không chứa giá trị thật. `scripts/security/artifact_hygiene.py`
chặn secret và đường dẫn tuyệt đối trong artifact sắp publish, và nó chạy trong
CI - nhưng nó cũng chỉ bắt theo pattern, cùng giới hạn như §4.3.

## 5. Những gì cần làm để bớt các giới hạn trên

Theo thứ tự giá trị:

1. **`verdict_cwe` + luật Guard** - sửa nguyên nhân đứng sau 3/3 false positive
   còn lại, bằng cơ chế Python kiểm được thay vì thuyết phục bằng prompt.
2. **Mở rộng corpus** lên toàn bộ BenchmarkJava và thêm một codebase thật, để
   con số có ý nghĩa thống kê.
3. **Luồng có xác thực** cho DAST, để với tới lớp lỗ hổng sau đăng nhập.
4. **Chặn ở normalizer** những "endpoint" vốn là đường dẫn trong stack trace,
   thay vì để chúng thành finding rồi mới từ chối probe.
