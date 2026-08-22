# Project Sentinel - Product brief

## Vấn đề

Một lần quét bảo mật trả về hàng trăm cảnh báo, và phần lớn trong đó **không phải
lỗ hổng**. Trên 100 case đầu của OWASP BenchmarkJava, ba scanner sinh 372 quan
sát cho 99 nhóm phân tích - và bản thân corpus xác nhận một phần đáng kể là báo
sai. Chi phí thật không nằm ở việc quét; nó nằm ở người phải đọc từng cảnh báo để
trả lời một câu hỏi duy nhất: *cái này có thật không?*

Công cụ hiện có đẩy nguyên câu hỏi đó sang con người. Chúng báo "có thể có SQL
injection ở dòng 40" rồi dừng lại. Ai đó vẫn phải mở file, đọc luồng dữ liệu, và
với lỗ hổng web thì còn phải tự gửi request để xem thực tế có đúng vậy không.

## Sản phẩm

Sentinel là lớp phân tích nằm giữa scanner và con người. Nó nhận cảnh báo thô,
đọc source code hoặc response thật, rồi trả về **một verdict có trích dẫn**:
finding này là thật, là báo sai, hay chưa đủ dữ liệu để nói. Khi thiếu bằng
chứng, nó **đề xuất một request đọc-thuần** để lấy bằng chứng đó - và không tự
gửi: con người duyệt hay từ chối, request chỉ đi qua một API Gateway có allowlist.

Khác biệt so với việc gắn một LLM vào output của scanner:

- **Verdict phải chống đỡ được.** Rationale bắt buộc trích dẫn `observation_id`
  và document KB; `confirmed_vulnerable` bắt buộc có excerpt thật. Evidence Guard
  là code Python, không hỏi lại model.
- **Abstention là câu trả lời hợp lệ.** `insufficient_evidence` được đếm ở cột
  riêng, nên hệ thống không có động cơ đoán bừa để làm đẹp precision.
- **Bằng chứng sống thay đổi kết luận.** Trong lần chạy thật gần nhất, 5 verdict
  đã đổi sau khi một response được người duyệt cho đi qua gateway. Verdict cũ
  không bị xoá, nên "probe làm đổi kết luận" là điều kiểm chứng được.

## Người dùng

| Ai | Dùng để làm gì |
| :--- | :--- |
| Kỹ sư bảo mật / AppSec | sàng lọc cảnh báo trước khi mở ticket; đọc lý do agent nói "báo sai" và bác lại nếu thấy sai |
| Developer nhận ticket | thấy ngay dòng code quyết định và cách xác minh, thay vì một CWE trừu tượng |
| Người review pipeline | mọi số trong báo cáo truy được về JSON/JSONL đã commit; mọi request có log ai duyệt lúc nào |

## Giá trị đo được

Cùng 25 nhóm SAST, cùng model, chỉ khác payload và KB:

| | scanner-only, KB v1 | + source code, KB v2 |
| :--- | ---: | ---: |
| True positive | 20 | 21 |
| False positive | 4 | **2** |
| **True negative** | **0** | **2** |
| Precision | 0.833 | **0.913** |
| F1 | 0.909 | **0.955** |

Con số đáng nói nhất là `TN = 0` ở cột đầu: khi chỉ có mô tả của scanner, agent
**chưa bao giờ** dám kết luận "không phải lỗ hổng" - nó đồng ý với scanner theo
mặc định, đúng như lý do rationale của nó tự khai: *"the supplied excerpt is
descriptive rather than source code"*. Đưa code thật vào là điều kiện để có một ý
kiến độc lập.

Về phía DAST, 16/18 finding có route để xác minh; một lần chạy thật gửi 8 request
(2 bị từ chối), và 12 verdict được một response thật trả lời.

## Phạm vi hiện tại

**Có:** SAST trên 100 case BenchmarkJava; DAST passive (ZAP baseline + AJAX
spider) trên Juice Shop; KB 38 doc có `confirm_indicators`/`fp_indicators`;
agent hai pass; guardrails (injection, redaction, approval); request tool qua
gateway; scoring theo ground truth + 10 case eval tự viết; log/metrics mỗi lần
chạy; Docker Compose; dashboard đọc artifact.

**Chưa có:** DAST chủ động (không tấn công, nên không tìm được SQLi/XSS thực thi
được); luồng có xác thực (không login, không session); sửa lỗi tự động; corpus
ngoài 100 case đầu; ground truth cho DAST.

## Giới hạn cần nói thẳng

- **Agent vẫn sai.** Eval set giữ lại đúng những case nó sai, kèm lập luận đối
  chứng: xem `artifacts/week-6/evaluation/eval-cases-failures.jsonl`.
- **Không có ground truth cho DAST**, nên chất lượng phía đó dựa vào eval set tự
  viết và tỉ lệ verdict được response thật trả lời.
- **Passive scan không mang response header**, nên nhiều finding DAST *về nguyên
  tắc* không kết luận được nếu không probe. Đó là lý do bước probe tồn tại, không
  phải khuyết điểm của model.
- **Ứng dụng trong lab cố tình có lỗ hổng** và không được deploy công khai.

## Bước tiếp theo

1. **Mở rộng corpus** từ 100 lên toàn bộ BenchmarkJava để đo precision trên mẫu
   lớn hơn, và bổ sung một codebase thật ngoài corpus tổng hợp.
2. **Luồng có xác thực** cho DAST: một route login được duyệt, giữ session, để
   với tới lớp lỗ hổng chỉ xuất hiện sau khi đăng nhập.
3. **Đóng vòng KB tự động**: mỗi false positive/negative sinh ra một đề xuất sửa
   `fp_indicators`/`confirm_indicators` để người review chấp nhận - hiện vòng
   *đo → chẩn đoán → sửa KB → đo lại* đang làm bằng tay và đã cho kết quả.
4. **Tích hợp CI của người dùng thật**: comment verdict lên pull request thay vì
   chỉ upload SARIF, để phần sàng lọc đến đúng lúc lập trình viên còn nhớ code.
