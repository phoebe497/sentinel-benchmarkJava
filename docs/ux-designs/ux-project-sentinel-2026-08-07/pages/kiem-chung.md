---
name: Kiểm chứng an toàn
overrides: MASTER DESIGN.md + EXPERIENCE.md
updated: 2026-08-19
---

# Page: Kiểm chứng an toàn

One column, three panels, `{spacing.7}` between panels. No tabs.

## Panel 1 — Đề xuất

- Eyebrow: `Phép thử đề xuất`
- Title: one sentence purpose, e.g. “Kiểm tra endpoint đăng nhập có chấp nhận dữ liệu sai kiểu không.”
- Body: `POST /login` in inline code; `route_id` / `payload_id` as meta.
- Help: “Agent chỉ chọn từ danh sách Gateway cho phép. Payload phá hoại không nằm trong danh sách.”
- Empty: “Chọn một lỗ hổng ở bước phân tích trước khi đề xuất phép thử.”

## Panel 2 — Approval card

| State | Copy | Actions |
|---|---|---|
| pending | “Gửi request này qua Gateway?” Endpoint + redacted payload visible | **Từ chối** (default focus) · **Duyệt và gửi** |
| rejected | “Request không được gửi.” | Buttons idle; Guided Demo then spotlights **Duyệt và gửi** |
| approved | “Đang gửi qua Gateway…” | Both disabled |
| timeout | “Gateway không trả lời kịp. Không thử lại âm thầm.” | New Approve required to retry |
| error | “Không kết nối được Gateway.” | Same |

Do not add “Gửi lại”, “Bỏ qua duyệt”, or a third button.

## Panel 3 — Phản hồi đã lọc

- Show only after a successful send or a Public-mode replay artifact.
- Body is already redacted.
- Badges (text + color): `Đã che dữ liệu nhạy cảm` · `Phát hiện chỉ dẫn lạ — đã cách ly`.
- Expander “Chi tiết kỹ thuật”: status, `X-Gateway-Route`, injection pattern names, latency. No raw secret, no API key.
- Rejected path: this panel stays empty with caption “Chưa có phản hồi vì request không được gửi.”
