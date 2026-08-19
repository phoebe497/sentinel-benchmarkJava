---
name: Sentinel Analysis Workspace
status: final
sources:
  - app/streamlit_app.py
  - docs/security-analysis-workspace.md
  - README.md
  - src/sentinel_benchmark/guardrails/
updated: 2026-08-19
---

# Sentinel Analysis Workspace — Experience Spine

## Foundation

Responsive Streamlit web application, desktop-first and usable on tablet or phone. `DESIGN.md` owns visual identity; this document owns information architecture and behavior. The public deployment is read-only and uses generated artifacts. Local mode may call OpenCode only after an explicit user action. Probe requests always go through the external Week 4 API Gateway; this app never talks to a target directly.

Assumptions used for this iteration:

- A first-time visitor understands “lỗ hổng” but may not know the Week 1–6 implementation history. The UI never leads with week numbers.
- The primary demo task is one finding, then one human-approved probe, then a filtered response.
- Mentor review needs a Reject that is visibly not sent.
- Existing datasets, Agent contracts and report artifacts remain unchanged.

## Information Architecture

Three navigation groups. Labels describe the job, not the week.

| Group | Surface | Reached from | Purpose |
|---|---|---|---|
| PHÂN TÍCH | Tổng quan | App open | Dashboard + start Guided Demo |
| PHÂN TÍCH | Lỗ hổng & bằng chứng | Nav / Guided step 1–2 | Choose a CWE/test and read scanner evidence |
| PHÂN TÍCH | Tra cứu tri thức | Nav / Guided step 2 | Read curated guidance for that weakness |
| PHÂN TÍCH | Phân tích của Agent | Nav / Guided step 3 | Read the Agent report and ask Sentinel |
| KIỂM CHỨNG | Kiểm chứng an toàn | Nav / Guided step 4–5 | Proposed request → approve/reject → filtered response |
| KẾT QUẢ | Đánh giá độ chính xác | Nav / Guided step 6 | Compare Agent output to expected answers |
| KẾT QUẢ | Chạy & số liệu | Nav / Guided step 6 | End-to-end run counts |
| KẾT QUẢ | Báo cáo | Nav | Review and export JSONL |
| KẾT QUẢ | Dữ liệu & kiểm định | Nav (secondary) | Raw tables; not on the Guided Demo path |

### Sidebar order

1. Brand: `Project Sentinel` and one-line scope copy.
2. Primary button: **Chạy demo có hướng dẫn**.
3. `st.navigation` with the three groups above.
4. Footer badge: `● Public · dùng artifact có sẵn` or `● Local · có thể gọi OpenCode`.
5. Material icons only. No emoji icons.

### Journey strip (six steps)

The strip is a progress indicator, not a clickable nav. It appears on Tổng quan, the analysis pages, Kiểm chứng, and during Guided Demo.

| # | Label | Coach copy |
|---|---|---|
| 1 | Chọn lỗ hổng | Chọn CWE và test cần xem. |
| 2 | Xem bằng chứng | Đọc cảnh báo scanner và tri thức. |
| 3 | Hỏi Agent | Nhận giải thích theo đúng ngữ cảnh. |
| 4 | Duyệt phép thử | Xem request, rồi Từ chối hoặc Duyệt. |
| 5 | Phản hồi đã lọc | Xem kết quả đã che và đã cách ly. |
| 6 | Xuất / đánh giá | Xem đúng–sai và tải báo cáo. |

Current step: teal number + label. Completed steps: muted check treatment. Future steps: muted, not clickable.

## Guided Demo — spotlight, not autoplay

Yes: on the live web UI the stepper highlights the **current** step, and exactly **one** on-page control is ringed with a coach label. The user clicks that control. Then the step advances (the page may change). The last step shows results. The demo does **not** auto-play and does **not** highlight the whole page.

Session keys: `guided_active`, `guided_step` (1–6), `guided_finding` (CWE + test). Leaving Guided Demo via **Thoát demo** clears the spotlight but keeps the selected finding.

| Step | Page | Spotlight target | After the click |
|---|---|---|---|
| 1 | Lỗ hổng & bằng chứng | Suggested finding button `Dùng ví dụ CWE-89` (fallback: the CWE select, already filled) | Store finding; go to evidence on the same page; step → 2 |
| 2 | Lỗ hổng & bằng chứng, then Tra cứu tri thức | First evidence expander, then KB result for that CWE | Open expander / show KB excerpt; step → 3 |
| 3 | Phân tích của Agent | Suggested question `Lỗ hổng này nguy hiểm như thế nào?` | Show grounded answer; step → 4; switch to Kiểm chứng |
| 4a | Kiểm chứng an toàn | **Từ chối** on the approval card | Record reject; show “Request không được gửi.”; stay on step 4; move spotlight to **Duyệt và gửi** |
| 4b | Kiểm chứng an toàn | **Duyệt và gửi** | Call Gateway via `safe_probe`; step → 5 |
| 5 | Kiểm chứng an toàn | Filtered-response panel (scroll into view; no extra click required) | Coach: “Đây là kết quả đã lọc.” Primary **Xem đánh giá** → step 6 |
| 6 | Đánh giá độ chính xác + Chạy & số liệu | Evaluation matrix, then **Tải báo cáo JSONL** | Demo complete; strip all six steps completed |

Mentor climax is 4a. A Reject that is skipped would fail the demo script.

Public/read-only: steps 4b–5 replay a committed, already-redacted artifact and still show the Reject path. The UI must not claim a live Gateway call in Public mode.

## Voice and Tone

| Do | Don't |
|---|---|
| “Chọn một lỗ hổng để bắt đầu.” | “Vulnerability analysis group” |
| “Bằng chứng từ 2 scanner.” | “2 source tools / 3 observations” without explanation |
| “Hỏi Sentinel cách xác minh lỗ hổng này.” | “Grounded chat” as the main label |
| “Duyệt phép thử này trước khi gửi.” | “HITL approval gate (W5)” |
| “Request không được gửi.” | “ApprovalRejected raised” |
| “Đã che dữ liệu nhạy cảm.” | Show the raw secret “for comparison” |
| “Chi tiết kỹ thuật” | Put week numbers, prompt hash or run ID in the main path |

Use Vietnamese for navigation, actions and explanations. Preserve CWE, scanner names, JSONL, KB, Gateway, OpenCode and evidence IDs where precision matters.

## Component Patterns

| Component | Use | Behavioral rules |
|---|---|---|
| Journey strip | Dashboard, analysis, verify, guided | Six steps; highlight current; do not navigate on click |
| Guided spotlight | Guided Demo only | One teal ring + one coach line on the required control |
| Dashboard metric | Tổng quan / Chạy & số liệu | At most five; each has scope help |
| Finding selector | Lỗ hổng & bằng chứng | CWE then test; persists for the session |
| Knowledge search mode | Tra cứu tri thức | Semantic default; Hybrid; Keyword for exact CWE |
| Knowledge result | Tra cứu tri thức | Title, document ID and rank first; body in expander |
| Suggested question | Agent chat | Includes selected CWE, name and test ID; click submits |
| Evidence list | Lỗ hổng & bằng chứng | Scanner/location visible; excerpt and IDs on demand |
| Proposed-request card | Kiểm chứng panel 1 | Purpose, method+path, Gateway `route_id`/`payload_id` |
| Approval card | Kiểm chứng panel 2 | Default focus Từ chối; Approve sends only through Gateway |
| Filtered-response panel | Kiểm chứng panel 3 | Redacted body only; injection badge when flagged |
| Report action | Báo cáo / analysis | Export selected JSONL; local generation needs confirmation |
| Evaluation matrix | Đánh giá | 2×2 + Precision/Recall/Accuracy; FP/FN table below |
| Run selector | Báo cáo / advanced | Hidden in “Nguồn dữ liệu” until needed |
| Advanced tabs | Dữ liệu & kiểm định | Raw tables only; off the Guided path |

## State Patterns

| State | Surface | Treatment |
|---|---|---|
| Initial load | Global | “Đang chuẩn bị dữ liệu phân tích…” |
| Guided idle | Sidebar | Button **Chạy demo có hướng dẫn** |
| Guided active | Strip + page | Spotlight on one control; **Thoát demo** in the strip |
| Approval pending | Kiểm chứng | Two buttons enabled; focus on Từ chối |
| Approval rejected | Kiểm chứng | “Request không được gửi.” Payload stays visible. No HTTP |
| Approval approved | Kiểm chứng | Buttons disabled; “Đang gửi qua Gateway…” |
| Gateway timeout | Kiểm chứng | Neutral: “Gateway không trả lời kịp. Request đã được ghi, không thử lại âm thầm.” |
| Gateway connection error | Kiểm chứng | “Không kết nối được Gateway.” Offer retry only after a new Approve |
| Injection flagged | Filtered response | Warning-soft badge + original text still inside quarantine wrapper |
| Redacted | Prompt, log, UI | Placeholders only; identifiers kept |
| Public read-only | Global | Uses artifacts; never claims live OpenCode or live Gateway |
| Local inference | Agent | Name OpenCode before submit; never call on rerun |
| No run artifact | Analysis / reports | Evidence still usable; say no generated report yet |
| Corrupt artifact | Analysis / reports | Stop report display; name checksum failure |
| Empty search | Data | “Không có kết quả phù hợp với bộ lọc này.” + reset |
| Missing scanner excerpt | Evidence | “Scanner không cung cấp đoạn mã trong artifact này.” |

## Interaction Primitives

- Click or tap to act. Native Streamlit keyboard and focus behavior is preserved.
- One primary action per section. Guided Demo adds a spotlight to that action, it does not add a second primary.
- Expanders hold provenance, raw excerpts, model information and checksums.
- Tabs only on Dữ liệu & kiểm định.
- Banned in the primary flow: nested tabs, raw JSON, warning banners for normal states, more than five metrics in a row, week-number navigation, auto-playing Guided Demo, “view original secret”.

## Accessibility Floor

- WCAG 2.2 AA contrast for text, controls, focus and semantic states.
- Heading order follows the reading sequence.
- Every button names the action and target. Icon-only actions are avoided.
- Severity, approval and guard states include text; color is supplemental.
- Guided spotlight ring is not the only cue: the coach label states the step and the button name.
- Page remains operable at 200% zoom. Columns stack; tables scroll.
- Focus order matches reading order. Default focus on the approval card is **Từ chối**.
- `prefers-reduced-motion`: no decorative pulse on the spotlight; a static ring is enough.

## Responsive & Platform

| Width | Behavior |
|---|---|
| ≥ 1024px | Evidence and chat may sit in two columns; content capped at 1180px. Kiểm chứng stays one column (proposal → approval → response) |
| 768–1023px | Single-column analysis; metrics in two rows |
| < 768px | Streamlit collapses nav; controls full width; journey strip wraps; tables scroll |

## Product-specific Trust Rules

- Ground truth is never shown beside the Agent answer.
- `benchmark_assisted` grouping is explained once in technical detail.
- Public mode never claims live inference or a live probe.
- Scanner absence is missing observation, never proof of clean code.
- The request tool knows only the Gateway address.
- Reject is final for that attempt. A later Approve is a new decision, logged separately.
- Gateway payloads come from the Week 4 allowlist / safe catalogue. Offensive SQLi strings are not a UI option.

## Key Flows

### Flow 1 — First finding review (Minh)

1. Opens Tổng quan. Reads one sentence about the 100-test corpus.
2. Sees the six-step strip, not week numbers.
3. Uses `Dùng ví dụ CWE-89` or browses without Guided Demo.
4. Reads evidence, asks Sentinel, exports JSONL.

### Flow 2 — Mentor Guided Demo (Phương)

1. Clicks **Chạy demo có hướng dẫn**.
2. Follows the six-step spotlight script above, including **Từ chối** before **Duyệt và gửi**.
3. Confirms the reject log line and `requests_sent = 0` under Chi tiết kỹ thuật.
4. Confirms the filtered response shows placeholders, not secrets.
5. Ends on the evaluation matrix and JSONL export.

### Flow 3 — Local analyst (Lan)

1. Selects a finding. Baked evidence loads without calling OpenCode.
2. Optionally creates a new report after a quota confirmation.
3. On Kiểm chứng, reviews the proposed Gateway route and decides Approve or Reject.
4. Secrets and Gateway keys never appear in the UI, prompt, or log.
