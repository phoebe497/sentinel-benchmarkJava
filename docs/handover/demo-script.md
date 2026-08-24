# Kịch bản demo (10-15 phút) — UI local

Demo chính trên **http://localhost:8090**. UI đọc artifact đã commit (readonly):
số trên màn hình khớp file trong `artifacts/`. Gửi probe sống chỉ xảy ra ở CLI
khi stack lab đang lên; đừng hứa UI sẽ bắn request.

Bảy điểm mentor phải thấy, và click nào thể hiện:

| # | Phải thể hiện | Click |
| :--- | :--- | :--- |
| 1 | Một lần chạy công cụ quét | [§2 SAST Runs](#2-2-phút--quét-thật-và-agent-ra-verdict) + [§4 DAST](#4-2-phút--dast-probe-đổi-verdict) |
| 2 | Agent tạo báo cáo | [§2 Agent / drawer finding](#2-2-phút--quét-thật-và-agent-ra-verdict) |
| 3 | Agent đề xuất request kiểm tra | [§5 Approval](#5-2-phút--duyệt-gateway-injection-redaction) |
| 4 | Người dùng Approve hoặc Reject | [§5](#5-2-phút--duyệt-gateway-injection-redaction) |
| 5 | Request đi qua API Gateway | [§5](#5-2-phút--duyệt-gateway-injection-redaction) |
| 6 | Prompt Injection bị chặn | [§5](#5-2-phút--duyệt-gateway-injection-redaction) |
| 7 | Dữ liệu nhạy cảm bị che | [§5](#5-2-phút--duyệt-gateway-injection-redaction) |

Điểm nhấn riêng của bài (không nằm trong 7 mục trên, nhưng mentor đánh giá cao):
**KB v2 là thước kiểm chứng, sửa kiến thức ở KB chứ không vá prompt.** Xem [§3](#3-3-phút--kb-là-thước-không-phải-wiki).

---

## Chuẩn bị (trước khi mentor vào, không tính giờ)

```bash
PYTHONPATH=src uvicorn app.web.main:app --host 127.0.0.1 --port 8090
```

Mở sẵn hai tab:

1. http://localhost:8090/overview
2. http://localhost:8090/knowledge  (sẽ bấm `KB-003` ngay)

Stack gateway (`bash scripts/stack.sh up`) **không bắt buộc** cho kịch bản UI.
Chỉ bật nếu mentor hỏi “gửi thật thì thế nào” — lúc đó dùng CLI ở [phụ lục](#phụ-lục-b--cli-nếu-mentor-đòi-gửi-thật).

---

## 1. (1 phút) — Vấn đề

Một câu: *"Scanner báo hàng trăm cảnh báo. Câu hỏi tốn công là 'cái này có thật
không', và hiện nay câu đó bị đẩy hết sang người."*

Mở **Overview**. Chỉ bốn số đã commit, đừng đọc KPI cho đủ:

- 99 nhóm SAST (BenchmarkJava, 100 case đầu) + 18 nhóm DAST (Juice Shop)
- **24 true vulns** = 21 SAST TP + 3 DAST confirmed — hai thước **không cộng**
  thành một hàng Overall
- Agent là `gpt-5.6-luna` trên OpenCode: **một model, hai pass** (phân tích /
  verify). Semgrep và ZAP là scanner, không phải model

Câu chuyển: *"Phần còn lại của demo: agent quyết định bằng evidence + KB, rồi
mới đề xuất một GET qua gateway."*

---

## 2. (2 phút) — Quét thật và agent ra verdict

**SAST → tab Runs.** Cột Tool trên run đã chấm là `gpt-5.6-luna` — đó là **model
phân tích**, không phải Semgrep. Semgrep nằm ở artifact Week 1; agent đọc
observation đã chuẩn hoá.

**SAST → tab Findings.** Bấm một hàng CWE-89 (hoặc tìm `BenchmarkTest00008`):

- Verdict là một trong 5 nhãn hợp đồng, **không** suy từ confidence
- Rationale phải trích `observation_id` và `KB-…` — Evidence Guard (Python) từ
  chối nếu thiếu
- Source Java hiện trong drawer: payload SAST có **code thật**, không chỉ mô tả
  scanner

**Agent Analysis** (nút Open Agent trên drawer): khung Finding Summary +
Matched KB. Nói một câu: *"LLM chỉ điền JSON; Python chọn KB, ghép source, và
chặn field ngoài hợp đồng."*

Đừng chạy lại `analyze.py` trong giờ demo trừ khi mentor đòi — run `sast-v4`
đã commit.

---

## 3. (3 phút) — KB là thước, không phải wiki

Đây là đoạn làm bài khác với “có RAG”.

Mở http://localhost:8090/knowledge. Bảng đã sắp: doc có vòng **đo → sửa KB → đo
lại** nằm trên cùng. KPI **Cited in verdicts** (14/38) = doc được gọi tên trong
rationale, không phải đếm bài OWASP.

### 3.1 Bấm `KB-003` (Path Traversal) — vòng đã đóng

Trong drawer, chỉ theo thứ tự:

1. **False-positive indicators** — câu thắt: tên file cố định mà **thư mục vẫn
   từ input thì không phải FP**. Đó là chỗ agent từng áp sai.
2. **Confirm indicators** — `File(parent, child)` trong Java: child có `/` đầu
   **không** bỏ parent (khác `os.path.join` Python).
3. **Measured change** trên `BenchmarkTest00011`:
   - Before `sast-source`: `not_vulnerable` — rationale nói nhầm semantics Java
   - After `sast-kb-fix`: `confirmed_vulnerable` — rationale trích `KB-003`
4. Bảng finding: 3 rationale còn citation. Bấm một hàng → Agent Analysis.

**Câu chốt:** *"Sửa ở KB, không sửa prompt. Cùng model, cùng case, chỉ đổi chỉ
dấu — FN biến thành TP. Vòng đo → chẩn đoán → sửa thước → đo lại đã chạy thật."*

Evidence nếu drawer lỗi: xem [phụ lục A](#phụ-lục-a--evidence-kb-khi-ui-không-mở-drawer).

### 3.2 Bấm `KB-328-HASH` — KB đúng, lỗi còn lại không phải kiến thức

Measured change: verdict `BenchmarkTest00009` **không đổi**
(`confirmed_vulnerable`). Cái đổi là rationale: *"SHA-384 is strong and not the
issue, consistent with KB-328-HASH."*

**Câu chốt:** *"KB dạy đúng thuật toán. Agent vẫn FP vì nó kết luận về
FileWriter/CWE-400 — câu hỏi khác với CWE-328 được báo. Đó là lỗi phạm vi, Guard
chưa chặn được, không phải thiếu playbook."*

### 3.3 Bấm `KB-693-CSP` (một câu) — KB đẩy việc sang probe

Surface = **DAST response header**. Confirm indicator đòi thấy header, không
đòi đoán từ URL. Passive ZAP chỉ có URL → agent abstain **đúng**. Việc còn lại
là GET qua gateway — sang §4.

Câu học: *"Thiếu kiến thức thì sửa KB. Luật Python kiểm được thì đừng nhồi vào
prompt."*

---

## 4. (2 phút) — DAST, probe đổi verdict

**DAST → Findings.** Tìm CSP / CWE-693 trên `/`. Drawer:

- Verdict sau probe, và dòng *revised from … after the probe* nếu có
- Request `GET …` đi qua gateway (route_id, không dán URL cho model)
- Một GET có thể trả lời **nhiều** finding cùng path — Probed ≠ TP

**Reports.** Bảng hai hàng, không có Overall:

| | Findings | P / R / F1 | TP FP FN | Probed | Verdict changed |
| :--- | ---: | :--- | :--- | ---: | ---: |
| SAST | 99 | 0.875 / 1.000 / 0.933 | 21 / 3 / 0 | — | — |
| DAST | 18 | 0.75 / 1.0 / 0.857 | 3 / 1 / 0 | 5 | 2 |

Nói rõ thước: SAST vs BenchmarkJava GT trên 25 nhóm đã chấm; DAST vs **Grok 4.5
judge** (không phải luna). Glossary dưới bảng. Trend: mốc `… SAST` / `… DAST`,
không phải chỉ DAST.

Donut: 21 SAST TP + 3 DAST confirmed.

---

## 5. (2 phút) — Duyệt, gateway, injection, redaction

**Approval Center.**

- Một hàng **Approved**: endpoint, payload, mục đích — đã gửi qua gateway.
- Một hàng **Rejected**: `"sent": false` trên artifact. Reject là thật, không có
  bypass. Bấm hàng → Injection Flag / Redaction trên drawer.
- Hàng **Blocked** / Security Filters: payload đặc biệt hoặc pattern injection
  không đi tiếp.

Câu một hơi cho đủ điểm 3–7: *"Agent chỉ đề xuất `route_id` + `payload_id`.
Người bấm Approve/Reject. Gateway mới forward. Response là DATA: injection bị
gắn nhãn, secret thành `[REDACTED_…]` trước khi vào log hay prompt."*

Nếu mentor muốn thấy 5/5 PASS trên HTTP thật: [phụ lục B](#phụ-lục-b--cli-nếu-mentor-đòi-gửi-thật) — đừng tự chạy giữa §3.

---

## 6. (1 phút) — Đóng bằng chỗ còn sai

Quay **Reports** hoặc **Agent** trên `BenchmarkTest00009` / `00022`:

- Agent **nêu đúng** SHA-2/SHA-3 nhờ `KB-328-HASH`
- Vẫn vulnerable vì thấy weakness khác
- Đề xuất tiếp: field `verdict_cwe` + Guard — chi tiết
  [verdict-and-scoring.md](../methodology/verdict-and-scoring.md)

Một câu kết: *"Hệ thống này không giấu FP. Nó chỉ ra KB đã cứu được gì, và chỗ
nào KB không đủ vì đó không phải lỗ kiến thức."*

---

## Nếu có sự cố giữa demo

| Triệu chứng | Xử lý |
| :--- | :--- |
| UI không lên `:8090` | `PYTHONPATH=src uvicorn app.web.main:app --host 127.0.0.1 --port 8090` — **không** dùng 8080 (trùng gateway) |
| Trang Knowledge trống / Loading | Hard-refresh. Drawer: bấm **cả hàng**, đừng bấm link CWE |
| Không thấy Measured change | Mở phụ lục A, đọc hai rationale đã commit |
| Mentor hỏi Semgrep ở đâu | Week 1 artifact + CI Code scanning — cột Tool trên Runs là model agent |
| Không kịp giờ | Bỏ §2 chi tiết source; giữ §3 (`KB-003`) + §5 (Reject + redaction) |
| Mentor đòi gửi request sống | Phụ lục B. UI không gửi |

---

## Phụ lục A — Evidence KB khi UI không mở drawer

Không đọc prompt. Chỉ đọc artifact / JSONL đã commit.

### A.1 `KB-003` — sửa FN trên `BenchmarkTest00011`

Chỉ dấu hiện tại (đã thắt) trong
[`datasets/knowledge/security-topics.jsonl`](../../datasets/knowledge/security-topics.jsonl)
id `KB-003`:

- `fp_indicators`: toàn bộ đường dẫn từ allowlist — tên file cố định mà thư mục
  vẫn từ input thì **không** phải FP
- `confirm_indicators`: `new File(parent, child)` — child có `/` đầu không vô
  hiệu hoá parent bị nhiễm

| Lần chạy | File | Verdict | Rationale (rút) |
| :--- | :--- | :--- | :--- |
| Trước | `artifacts/week-3/runs/20260822T084310Z-sast-source/reports.jsonl` | `not_vulnerable` | child `"/Test.txt"` tuyệt đối → “absolute child ignores the parent” (nhầm Python) |
| Sau | `artifacts/week-3/runs/20260822T084821Z-sast-kb-fix/reports.jsonl` | `confirmed_vulnerable` | header là parent của `File`, `exists()` lộ FS, khớp `KB-003` confirm_indicators |
| Run đang chấm | `artifacts/week-3/runs/20260822T093256Z-sast-v4/reports.jsonl` | `confirmed_vulnerable` | “KB-003 confirms that an untrusted parent directory remains traversal-sensitive even with a constant child.” |

`sast-kb-fix` chỉ chạy lại **đúng một** group. Metrics 1 case:
`artifacts/week-3/evaluation/verdict-metrics-sast-kb-fix.json` — TP 1, FN 0.

### A.2 `KB-328-HASH` — kiến thức đúng, FP phạm vi còn

Citation trên `BenchmarkTest00009` (sast-v4 và eval):

> The SHA-384 algorithm is strong and not the issue, consistent with KB-328-HASH.

File: `artifacts/week-3/evaluation/false-cases-sast-v4.jsonl`,
`artifacts/week-6/evaluation/eval-cases-failures.jsonl` (EV-02). Verdict vẫn
`confirmed_vulnerable` vì FileWriter không quota — không phải vì model nghĩ
SHA-384 yếu.

### A.3 KB v2 đổi lý do abstain DAST (không hiện đủ trên một card)

| | Trước | Sau |
| :--- | :--- | :--- |
| Retrieve | `KB-006` (access control, lạc đề) | `KB-693-CSP`, `KB-693-XCTO`, `KB-1021-XFO` |
| Abstain vì | “KB không xác nhận finding” | “KB-693-CSP **đòi** response header, observation chỉ có URL” |

Sau probe (run `dast-kb2`): 5 probed, 2 verdict đổi, 3 confirmed. Judge Grok 4.5:
`artifacts/week-6/evaluation/verdict-metrics-dast-kb2-judge.json`.

Ablation cùng 25 nhóm SAST, cùng luna: scanner-only + KB v1 vs source + KB v2 —
TN `0 → 2`, FP `4 → 2`. Bảng đầy đủ:
[verdict-and-scoring.md](../methodology/verdict-and-scoring.md).

---

## Phụ lục B — CLI nếu mentor đòi gửi thật

Chỉ khi `bash scripts/stack.sh up` đã healthy. Gateway `localhost:8080`; Juice
Shop không publish port.

```bash
python scripts/flow.py --provider nine_router    # mỗi request hỏi y/n; bấm n một lần
python scripts/probe.py injection-check          # 5/5 PASS trên /echo
```

Reject: `artifacts/week-6/probes/<run_id>-probe.jsonl` có `"decision": "reject"`,
`"sent": false`. Counter cần chỉ: `probes.rejected_but_sent: 0` trong
`artifacts/week-6/metrics/<run_id>.json`.
