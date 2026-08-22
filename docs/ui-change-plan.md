# UI change plan - bàn giao cho session sửa UI

Tài liệu này là brief để một session khác sửa UI. Backend đã đổi nhiều trong
Week 6; phần dưới nói **dữ liệu mới nào đã có sẵn**, **chỗ nào UI đang nói sai**,
và **thứ tự nên làm**. Không có yêu cầu nào cần sửa backend: mọi field liệt kê ở
đây đã được `/api/*` trả về.

Chủ đề chung: người dùng mới mở dashboard không biết hệ thống này *làm gì*. Nó
trông như một cái đầu ra scanner nữa. Thứ khiến nó khác - agent ra verdict, người
duyệt request, response thật đổi kết luận - hiện đang bị chôn.

## 0. Bối cảnh nhanh

| | |
| :--- | :--- |
| Entry point | `app/web/main.py` (FastAPI), `app/web/catalog.py` (đọc artifact), `app/web/static/js/app.js` (render) |
| Chạy local | `PYTHONPATH=src uvicorn app.web.main:app --port 8080` |
| Live | https://sentinel-ui.up.railway.app (`SENTINEL_UI_READONLY=1`) |
| Nguồn dữ liệu | **chỉ** artifact đã commit dưới `artifacts/`. Không có DB, không gọi LLM, không gửi request. |

Ràng buộc phải giữ: nút Approve/Reject trên UI **chỉ ghi lại quyết định**, không
gửi request thật. Việc gửi nằm ở `scripts/probe.py` / `scripts/flow.py` với prompt
gõ tay (AGENTS.md 6.2). Đừng biến nút này thành đường gửi.

## 1. Ưu tiên 1 - Trang đầu phải trả lời "hệ thống này làm gì"

**Vấn đề.** Overview mở ra là KPI và biểu đồ. Không có chỗ nào nói chuỗi
xử lý là gì, nên người mới không có mô hình tinh thần để đọc phần còn lại.

**Đề xuất.** Một dải "flow" ngang trên đầu Overview, 7 bước, mỗi bước có số thật
từ lần chạy gần nhất, và **bấm được** để nhảy tới trang tương ứng:

```
Quét → Chuẩn hoá → Agent verdict → Đề xuất request → Người duyệt → Gửi qua Gateway → Verdict cập nhật
405 obs   99+18 nhóm    18 verdict      10 request      8 duyệt / 2 từ chối   8 gửi        5 verdict đổi
```

Dữ liệu có sẵn ở `artifacts/week-6/metrics/<run_id>.json` → `counters`:
`alerts.normalized`, `reports.total`, `probes.proposed`, `probes.approved`,
`probes.rejected`, `probes.sent`, `verifications.verdict_changed`. Cần thêm một
endpoint mỏng đọc file metrics mới nhất (hoặc nhồi vào `/api/overview`) - đây là
việc backend duy nhất trong plan, và nó nhỏ.

Kèm một dòng một câu, không thuật ngữ: *"Sentinel đọc cảnh báo của scanner, tự
kết luận cái nào là lỗ hổng thật, và khi cần bằng chứng thì xin bạn duyệt một
request đọc-thuần để kiểm tra."*

## 2. Ưu tiên 2 - Verdict phải là nhân vật chính, không phải severity

**Vấn đề.** Bảng finding vẫn tổ chức quanh severity như mọi công cụ scanner khác.
Verdict - thứ duy nhất mà hệ thống này *thêm vào* - chỉ là một badge nhỏ.

**Đề xuất.**

- Cột verdict lên đầu, có màu theo stance (vulnerable / not vulnerable / abstain),
  và **filter theo verdict** đặt ngang hàng với filter severity.
- Với `likely_false_positive`: hiện luôn `false_positive_indicators[]` ngay trong
  hàng (đang có trong payload), vì đó là câu trả lời "vì sao bảo là báo sai".
- Với `insufficient_evidence`: hiện `limitations[]`. Abstain kèm lý do đọc rất
  khác abstain trống trơn, và hiện UI không phân biệt.
- Thêm một dải phân bố verdict cố định trên đầu bảng (đã có
  `verdict_distribution` trong artifact scoring).

## 3. Ưu tiên 3 - Kể cho được câu chuyện "probe đổi kết luận"

Đây là thứ thuyết phục nhất của cả hệ thống và hiện gần như vô hình.

**Đề xuất.** Trong drawer chi tiết của finding DAST, một khối "Trước và sau khi
probe":

```
Trước probe   insufficient_evidence
              "Alert không mang response header, nên chưa kết luận được."
Request       GET js-root /          - bạn đã duyệt lúc 09:23:41
Đo được       HTTP 200 · thiếu Content-Security-Policy        (Python đo, không phải model nói)
Sau probe     confirmed_vulnerable
              "Response từ route_id js-root thiếu CSP header, khớp CWE-693."
```

Field có sẵn trong `report.verification`: `verdict_before`, `verdict_after`,
`changed`, `observed[]`, `rationale`, `route_id`, `status`, `checked_at`,
`unverified_reason`. Phân biệt rõ **đo được** (Python) với **diễn giải** (model)
- đó là ranh giới thiết kế của hệ thống, và UI nên thể hiện nó.

Khi `unverified_reason` có giá trị (bị từ chối, hoặc không có route), hiện đúng
câu đó. **Đừng** để trạng thái "chưa xác minh" trông giống "đã kiểm tra và sạch".

## 4. Ưu tiên 4 - Trang approval phải trông như một quyết định

**Vấn đề.** Hàng đợi hiện là một bảng. Người duyệt cần thấy đủ ba thứ trước khi
bấm: endpoint, payload chính xác, và mục đích bằng lời thường (AGENTS.md 6.2).

**Đề xuất.** Layout dạng card, mỗi card một request: method + route_id +
endpoint, payload đầy đủ (JSON), câu mục đích, và **request này phục vụ finding
nào** (`analysis_group_ids` - một request thường trả lời nhiều finding, hiện UI
không nói ra). Trạng thái đã quyết định thì hiện dấu thời gian và người quyết
định từ `approvals.jsonl`.

Giữ nguyên tắc: UI ghi quyết định, không gửi. Nói rõ điều đó ngay trên trang bằng
một dòng, thay vì để người dùng đoán.

## 5. Ưu tiên 5 - Trang Reports: số phải nói rõ đo cái gì

`/api/reports` giờ trả về số thật từ `verdict-metrics-*.json`. Việc còn lại là
trình bày cho đúng nghĩa:

- SAST có ground truth → hiện confusion matrix (TP/FP/FN/TN) + precision/recall/F1.
- DAST **không** có ground truth → **không** hiện confusion matrix. Thay bằng
  "bao nhiêu verdict đã được một response thật trả lời" và "bao nhiêu verdict đổi
  sau probe".
- Abstain là cột riêng, có nhãn giải thích: *"agent từ chối kết luận; đếm riêng
  để việc từ chối không làm precision đẹp lên."*
- Thêm khối eval set: `artifacts/week-6/evaluation/eval-cases-metrics.json` +
  `eval-cases-failures.jsonl`. Phần "case agent làm sai, kèm lập luận đối chứng"
  là thứ mentor sẽ hỏi tới.

## 6. Việc nhỏ nhưng nên làm

- **Chọn run**: hiện UI luôn lấy run mới nhất. Thêm dropdown chọn run và hiện
  `run_id`, `model`, `prompt_version` đang xem - hiện không nhìn thấy được.
- **Empty state**: khi một trang không có dữ liệu, nói *thiếu artifact nào* và
  *lệnh nào sinh ra nó*, thay vì hiện bảng rỗng.
- **Nhãn "Not Analysed"**: đang đúng nhưng chưa giải thích. Thêm tooltip: nhóm
  này thuộc run cũ hơn, chạy trước khi có verdict.
- **Trang Knowledge**: KB v2 có `confirm_indicators`, `fp_indicators`,
  `detection_questions`, `detection_surface` - chưa hiển thị cái nào. Chính chúng
  là thứ agent trích dẫn, nên nên xem được.

## 7. Không nên làm

- Đừng thêm đường gửi request từ UI.
- Đừng bịa số. Nếu một số không có trong artifact thì không hiện nó - chỗ này đã
  từng sai (verdict suy ra từ ngưỡng confidence, "vulnerability trend" tự tạo) và
  đã sửa; đừng lặp lại.
- Đừng đưa WebGoat trở lại index hay UI (AGENTS.md 4).
- Đừng hiện đường dẫn tuyệt đối của máy local trong bất kỳ payload nào.

## 8. Kiểm tra sau khi sửa

```bash
PYTHONPATH=src uvicorn app.web.main:app --port 8080   # UI load được
python -m pytest -q tests/test_web_ui.py              # test backend UI
python -m pytest -q                                   # toàn bộ
```

Rồi kiểm tay: health endpoint trả về; tìm `CWE-89` ra finding BenchmarkJava; số
hiển thị khớp `artifacts/week-*/evaluation/verdict-metrics-*.json`; một finding
DAST đã probe hiện đúng verdict trước/sau.
