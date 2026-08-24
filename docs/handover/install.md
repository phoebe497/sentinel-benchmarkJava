# Cài đặt và chạy demo

Tài liệu này đi từ đầu đến một lần chạy end-to-end có bằng chứng. Kịch bản
demo nằm ở [demo-script.md](demo-script.md), kiến trúc và lý do các quyết định ở
[architecture.md](architecture.md), deploy UI công khai ở
[../deployment.md](../deployment.md).

## 1. Yêu cầu

| Thứ | Vì sao cần |
| :--- | :--- |
| Python 3.11+ | toàn bộ pipeline |
| Git (có submodule) | BenchmarkJava và API Gateway đều là submodule ghim commit |
| Docker + Docker Compose | Juice Shop, gateway, demo-api, ZAP |
| 1 API key của 9Router | agent thật; bỏ qua nếu chỉ chạy `--provider fake` |

Không cần key nào để chạy test, index, hay UI: mọi thứ đọc artifact đã commit.

## 2. Cài

```bash
git clone --recurse-submodules <repo-url> sentinel
cd sentinel
python -m pip install -r requirements.txt
python -m pip install -e .
python -m sentinel_benchmark.indexer     # dựng SQLite index từ artifact + KB
python -m pytest -q                      # phải xanh trước khi làm gì tiếp
```

Nếu đã clone mà quên submodule: `git submodule update --init --recursive`.

Agent thật cần một file `.env` (không commit, xem `.env.example`):

```bash
cp .env.example .env
# điền NINE_ROUTER_API_KEY; SENTINEL_GATEWAY_API_KEY sẽ được sinh ở bước sau
```

## 3. Chạy từng mắt (không cần Docker)

```bash
python scripts/analyze.py baseline                                    # invariant của grouping
python scripts/analyze.py run --provider fake --limit 5 --tag smoke   # pipeline, không tốn LLM
python scripts/analyze.py run --provider nine_router --limit 25 --tag sast-run
python scripts/analyze.py score --tag sast-run                        # join ground truth SAU khi chạy
python scripts/analyze.py judge-dast --tag dast-kb2                   # join nhãn Grok 4.5 SAU khi chạy
```

`score` là bước duy nhất được đọc ground truth BenchmarkJava; `judge-dast` là
bước duy nhất được đọc nhãn LLM-as-judge. Cả hai chỉ đọc report đã nằm trên
đĩa. Không có đường nào để đáp án đi vào prompt của agent.

## 4. Dựng stack (Docker)

```bash
bash scripts/stack.sh up       # sinh GATEWAY_API_KEY lần đầu, chờ juice-shop healthy
bash scripts/stack.sh routes   # allowlist mà gateway thực sự đang chở
```

Juice Shop và demo-api **không publish port**. Chỉ gateway mở `8080`. Thêm
`ports:` cho hai service kia là phá bỏ bảo đảm đó.

```bash
bash scripts/stack.sh scan     # ZAP baseline + AJAX spider -> artifacts/week-6/dast/
```

Scan mất vài phút. `scripts/security/zap_dast.py` chạy ngay sau đó để sinh
manifest provenance từ chính artifact, nên manifest không thể lệch khỏi bằng
chứng nó mô tả.

## 5. Demo

Kịch bản demo 10-15 phút, có mốc thời gian và bảy điểm phải thể hiện, nằm ở
[demo-script.md](demo-script.md).

## 6. Dọn

```bash
bash scripts/stack.sh down
python scripts/security/artifact_hygiene.py   # không secret, không absolute path
```

## 7. Sự cố thường gặp

| Triệu chứng | Nguyên nhân và cách xử lý |
| :--- | :--- |
| `docker compose config` báo thiếu `GATEWAY_API_KEY` | Đúng như thiết kế: key do `scripts/stack.sh up` sinh. Chạy `up` trước. |
| `stack.sh routes` in lỗi JSON | `.env` bị CRLF. Script đã đọc thẳng biến bằng `grep` thay vì `source`; nếu vẫn lỗi thì đổi `.env` về LF. |
| juice-shop `unhealthy` | Image là distroless, `node` không nằm trên PATH. Healthcheck dùng đường dẫn tuyệt đối `/nodejs/bin/node`. |
| ZAP chỉ báo 4 alert trên asset tĩnh | Thiếu AJAX spider. Juice Shop là SPA Angular; cờ `-j` đã có trong compose. |
| Router trả `503` giữa lúc chạy | Lỗi upstream tạm thời. Chạy lại; `runlog` ghi lỗi LLM vào `errors[]` thay vì coi là không có finding. |
| `probe.py plan` nói `cannot verify` | Endpoint không có route trong allowlist. Đó là hành vi đúng, không phải bug - xem `configs/gateway-policy.yml`. |
