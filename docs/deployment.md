# Deployment handoff

## GitHub CI/SAST

Workflow `CI and SAST` checkout BenchmarkJava submodule, chạy tests, quét 100 file đầu bằng Semgrep, xuất SARIF và upload vào GitHub Code scanning. Run đầu đã thành công; API GitHub xác nhận 89 alerts gồm 23 `error` và 66 `warning`.

- Actions: <https://github.com/phoebe497/sentinel-benchmarkJava/actions/runs/31082995915>
- Code scanning: <https://github.com/phoebe497/sentinel-benchmarkJava/security/code-scanning>

## Streamlit Community Cloud

Deploy bằng các giá trị:

| Field | Value |
|---|---|
| Repository | `phoebe497/sentinel-benchmarkJava` |
| Branch | `main` |
| Main file path | `app/streamlit_app.py` |
| Secrets | Không cần |

URL hiện tại `https://sentinel-benchmarkjava.streamlit.app/` redirect người dùng ẩn danh tới `/login`. Owner cần mở app settings và bật public sharing. Sau đó kiểm tra ở cửa sổ ẩn danh: trang phải mở trực tiếp, tìm `CWE-89` phải có finding của ba scanner, và export JSONL phải hoạt động.

BenchmarkJava chứa code cố ý có lỗ hổng. Chỉ deploy UI đọc artifacts; không deploy webapp BenchmarkJava ra Internet.

## Railway (design-system UI)

The 7-screen Sentinel shell lives in `app/web/` and is the Railway entrypoint.

```bash
uv sync
uv run uvicorn app.web.main:app --host 0.0.0.0 --port 8080
```

Deploy:

```bash
railway init --name sentinel-ui --json
railway up -y
railway domain
```

Live: https://sentinel-ui.up.railway.app

The container serves committed artifacts only (`SENTINEL_UI_READONLY=1`). Approve/Reject is recorded; it does not send a live probe. Streamlit at `app/streamlit_app.py` remains the Community Cloud entrypoint.
