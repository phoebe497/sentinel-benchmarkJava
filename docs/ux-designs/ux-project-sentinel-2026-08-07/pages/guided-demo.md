---
name: Guided Demo
overrides: MASTER DESIGN.md + EXPERIENCE.md
updated: 2026-08-19
---

# Page override: Guided Demo

Guided Demo is a mode, not a page. It reuses existing surfaces and adds a spotlight.

## Visual

- Journey strip: current step teal, completed muted, future muted.
- Spotlight: 2px `{colors.primary}` ring, radius `{rounded.md}`, plus a coach line above the control:
  `Bước 4 - bấm Từ chối để chứng minh request không được gửi.`
- No pulse if `prefers-reduced-motion`. No dimmed overlay (Streamlit cannot reliably dim siblings). The ring + coach line are the cue.
- Strip right side: **Thoát demo**.

## Click script (authoritative)

1. Spotlight `Dùng ví dụ CWE-89` → store finding → step 2.
2. Spotlight first evidence expander, then the matching KB card → step 3.
3. Spotlight suggested question → show answer → switch to Kiểm chứng → step 4.
4. Spotlight **Từ chối** → “Request không được gửi.” → spotlight **Duyệt và gửi** (still step 4).
5. **Duyệt và gửi** → Gateway or Public replay → step 5, scroll to filtered response.
6. Spotlight **Xem đánh giá** → evaluation matrix + metrics → spotlight **Tải báo cáo JSONL**.

Skipping 4 (Reject) is not a completed mentor demo.

## Public vs Local

| Mode | Step 4b-5 |
|---|---|
| Public | Replay committed redacted artifact. Caption: “Đang xem bản ghi đã lưu. Không gọi Gateway.” |
| Local | Real `safe_probe` call after Approve. Caption: “Đã gửi qua Gateway.” |
