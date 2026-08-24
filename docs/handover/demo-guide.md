# Hướng dẫn chạy demo

Tài liệu này giúp **chạy được** toàn bộ chuỗi trên máy local. Cài đặt: [install.md](install.md).

Hai nguồn, một agent: Semgrep đọc BenchmarkJava (SAST, có ground truth, không
deploy); ZAP đọc Juice Shop (DAST, có endpoint sống, Precision/Recall là
LLM-as-judge Grok 4.5). Bước duyệt → Gateway → lọc response → cập nhật report
**chỉ chạy trên DAST**.

## 0. Cổng và mạng

| Service | Cổng | Ai gọi được |
| :--- | :--- | :--- |
| API Gateway | **public `localhost:8080`** | Máy host, agent, `probe.py` |
| Juice Shop | **internal `:3000`** | Chỉ trong mạng compose (`http://juice-shop:3000`). Không map ra host. |
| demo-api | internal (fixture injection) | Chỉ gateway |

Thêm `ports:` cho juice-shop hoặc demo-api là phá bảo đảm đó.

## 1. Chuẩn bị (một lần)

```bash
cp .env.example .env          # điền NINE_ROUTER_API_KEY (bỏ qua nếu --provider fake)
python -m pip install -r requirements.txt
python -m pip install -e .
python -m sentinel_benchmark.indexer
python -m pytest -q           # phải xanh trước khi demo
```

Submodule (BenchmarkJava + API Gateway) phải đã `git submodule update --init --recursive`.

## 2. Bật stack

```bash
bash scripts/stack.sh up       # sinh GATEWAY_API_KEY lần đầu, chờ juice-shop healthy
bash scripts/stack.sh routes   # allowlist gateway đang chở
```

Chỉ gateway publish `8080`. Juice Shop lắng nghe `:3000` trong mạng nội bộ.

## 3. Chạy demo - hai cách

### Cách A - một lệnh (khuyến nghị khi demo cho người khác)

`scripts/flow.py` chạy **cả chuỗi DAST** trong một process: normalize → agent
verdict → đề xuất request → duyệt tay → gửi qua gateway → lọc injection/redact
→ agent cập nhật verdict → ghi log + metrics.

```bash
bash scripts/stack.sh scan                          # ZAP (bỏ qua nếu artifact dast đã có)
python scripts/flow.py --provider nine_router       # mỗi request hỏi y/n
```

Ở mỗi prompt: in endpoint, payload, mục đích. `y` = gửi qua gateway; `n` = không
gửi, verdict giữ nguyên. **Bấm `n` ít nhất một lần** để chứng minh Reject là
thật. Không có flag auto-approve.

Kịch bản duyệt sẵn (10 request, từ chối cái 4 và cái 9):

```bash
printf 'y\ny\ny\nn\ny\ny\ny\ny\nn\ny\n' | python scripts/flow.py --provider nine_router
```

Không có 9Router: `--provider fake` vẫn đi hết pipeline (verdict xác định, không
gọi LLM).

### Cách B - từng bước (khi muốn chỉ từng mắt)

```bash
# 1-2  Quét + chuẩn hóa
bash scripts/stack.sh scan                            # DAST → artifacts/week-6/dast/
python scripts/analyze.py run --provider nine_router --dataset sast --limit 25 --tag demo
python scripts/analyze.py score --tag demo            # join ground truth SAU khi report nằm đĩa

# 3-4  Agent phân tích DAST + đề xuất (chưa gửi)
python scripts/analyze.py run --provider nine_router --dataset dast --tag demo
python scripts/probe.py plan                          # route_id + payload_id, không URL

# 5-8  Duyệt → Gateway :8080 → Juice Shop :3000 → lọc → cập nhật report
python scripts/probe.py run
python scripts/analyze.py verify --dast-tag demo

# 9    Log / chấm eval / vệ sinh artifact
cat artifacts/week-6/metrics/<run_id>.json
python scripts/analyze.py eval-cases
python scripts/security/artifact_hygiene.py
```

Kiểm injection + redact trên HTTP thật (fixture POST `/echo`):

```bash
python scripts/probe.py injection-check
```

Phải 5/5 PASS: tới đích, bị flag, đúng pattern, response bị quarantine thành
DATA, không secret nào sống sót.

## 4. Xem gì sau khi chạy

| Thứ | Ở đâu |
| :--- | :--- |
| Provenance lần quét DAST | `artifacts/week-6/dast/manifest.json` |
| Report + verdict | `artifacts/week-3/runs/<run_id>/reports.jsonl` (SAST) và run DAST tương ứng |
| Quyết định duyệt / đã gửi? | `artifacts/week-6/probes/<run_id>-probe.jsonl` - Reject thì `"sent": false` |
| Verdict trước/sau probe | field `verification.verdict_before` / `verdict_after` trên report |
| Metrics cả lần chạy | `artifacts/week-6/metrics/<run_id>.json` - thời gian, proposed/approved/rejected/sent, `probes.rejected_but_sent` |
| UI xem artifact (readonly) | `PYTHONPATH=src uvicorn app.web.main:app --port 8090` - **không** dùng 8080 (trùng gateway) |

UI công khai (`SENTINEL_UI_READONLY=1`) chỉ đọc artifact đã commit: nút
Approve/Reject **ghi quyết định, không gửi**. Gửi thật chỉ xảy ra ở
`scripts/flow.py` / `scripts/probe.py run` khi stack local đang lên.

## 5. Tắt

```bash
bash scripts/stack.sh down
python scripts/security/artifact_hygiene.py
```

## 6. Sự cố nhanh

| Triệu chứng | Xử lý |
| :--- | :--- |
| Thiếu `GATEWAY_API_KEY` | Chạy `bash scripts/stack.sh up` trước - key do script sinh vào `.env`. |
| juice-shop `unhealthy` | Image distroless; healthcheck dùng `/nodejs/bin/node`. Đợi thêm, đừng thêm `ports:`. |
| Router `503` | Lỗi upstream tạm. Chạy lại, hoặc `--provider fake` để đi tiếp pipeline. |
| `probe.py plan` → `cannot verify` | Endpoint không có trong `configs/gateway-policy.yml`. Đúng thiết kế, không phải bug. |
| UI và gateway cùng cổng | Gateway giữ `8080`. UI local dùng cổng khác (ví dụ `8090`). |
