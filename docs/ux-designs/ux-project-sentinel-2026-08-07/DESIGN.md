---
name: Sentinel Analysis Workspace
description: A calm, evidence-first interface for understanding scanner findings and producing traceable security reports.
status: final
updated: 2026-08-19
colors:
  surface-base: '#F6F8FA'
  surface-raised: '#FFFFFF'
  surface-subtle: '#EEF4F3'
  ink-primary: '#172321'
  ink-secondary: '#536763'
  border: '#D9E3E0'
  primary: '#0F766E'
  primary-hover: '#115E59'
  primary-soft: '#DDF3EF'
  info: '#2563EB'
  info-soft: '#EAF1FF'
  warning: '#B45309'
  warning-soft: '#FFF5E6'
  danger: '#B42318'
  danger-soft: '#FDECEA'
  success: '#157347'
  success-soft: '#E8F5EE'
typography:
  display:
    fontFamily: 'Inter, system-ui, sans-serif'
    fontSize: 36px
    fontWeight: '720'
    lineHeight: '1.15'
  heading:
    fontFamily: 'Inter, system-ui, sans-serif'
    fontSize: 22px
    fontWeight: '680'
    lineHeight: '1.3'
  body:
    fontFamily: 'Inter, system-ui, sans-serif'
    fontSize: 16px
    fontWeight: '400'
    lineHeight: '1.6'
  meta:
    fontFamily: 'Inter, system-ui, sans-serif'
    fontSize: 13px
    fontWeight: '500'
    lineHeight: '1.4'
rounded:
  sm: 6px
  md: 10px
  lg: 14px
  full: 9999px
spacing:
  '1': 4px
  '2': 8px
  '3': 12px
  '4': 16px
  '5': 24px
  '6': 32px
  '7': 48px
components:
  primary-button:
    background: '{colors.primary}'
    foreground: '#FFFFFF'
    radius: '{rounded.md}'
  context-card:
    background: '{colors.surface-raised}'
    border: '{colors.border}'
    radius: '{rounded.lg}'
  evidence-chip:
    background: '{colors.primary-soft}'
    foreground: '{colors.primary-hover}'
    radius: '{rounded.full}'
---

## Brand & Style

Sentinel should feel like a review desk, not a scanner console. The interface is calm, structured and evidence-first: one clear task per section, plain-language labels, and technical detail available on demand. The product earns trust through traceability rather than visual drama.

Streamlit remains the UI system. Native controls, tables, dialogs, status messages and focus behavior are inherited unless this document names a visual delta.

## Colors

- **Sentinel teal** `{colors.primary}` marks the primary action, active navigation and verified evidence relationships. It is not used as decoration.
- **Neutral surfaces** `{colors.surface-base}` and `{colors.surface-raised}` separate the page from working cards without heavy shadows.
- **Semantic colors** are reserved for actual states: success for a passed guard, warning for limitations or incomplete input, danger for failure, and blue for explanatory information.
- Severity uses text together with color. Color never carries the meaning alone.

## Typography

The interface uses the platform sans-serif stack so Vietnamese text remains clear and deployment needs no external font request. One display size introduces a page; headings mark major tasks; body copy explains meaning; meta text holds IDs and provenance.

Technical identifiers such as `CWE-327`, observation IDs and hashes use inline code styling. Uppercase is avoided except for established acronyms.

## Layout & Spacing

The main reading width is 1180px. Pages follow one vertical story. Two-column layouts appear only when the relationship is useful, such as evidence beside grounded chat; they stack on narrow screens.

Spacing follows 4 / 8 / 12 / 16 / 24 / 32 / 48px. Major tasks use `{spacing.7}` separation. Related label-control-help groups use `{spacing.2}` or `{spacing.3}`.

## Elevation & Depth

Hierarchy comes from spacing, border and surface tone. Cards use a 1px `{colors.border}` border and at most a very soft shadow. No floating dashboard tiles, gradients or glass effects.

## Shapes

Controls and compact surfaces use `{rounded.md}`. Main context cards use `{rounded.lg}`. Pills are limited to short state and source labels; content containers are never pill-shaped.

## Components

- **Page introduction** — one eyebrow, one clear title and a two-line explanation. No duplicate title in the sidebar.
- **Journey strip** — six numbered steps: Chọn → Xem bằng chứng → Hỏi Agent → Duyệt phép thử → Phản hồi đã lọc → Xuất / đánh giá. The current step is teal; completed steps stay readable; future steps stay muted. The strip is a progress indicator, not navigation.
- **Guided spotlight** — in Guided Demo only. A teal 2px ring (`{colors.primary}`) plus a one-line coach label sits on the single control the user must click. No other control is ringed. After that click, the step advances (and the page may change).
- **Finding selector** — CWE filter followed by a concrete Benchmark test selection. Help text explains why the test is relevant.
- **Context card** — vulnerability name, test ID, scanner count and observation count. It replaces scattered badges and comments.
- **Evidence row** — scanner and location first; excerpt is disclosed in an expander. Missing excerpts use neutral copy, not a warning block.
- **Suggested question** — action-labelled button with a specific vulnerability target. Buttons wrap or stack instead of truncating.
- **Knowledge result** — ranked title, document ID and match signal in the expander label; content, tags and source appear after disclosure.
- **Report card** — vulnerability and severity first, plain-language explanation next, technical provenance last.
- **Proposed-request card** — one plain-language purpose, then `method` + path, then `route_id` / `payload_id` from the Gateway menu. Help text: the agent only picks from allowed routes.
- **Approval card** — purpose first; endpoint and payload in code; two actions: **Từ chối** (danger outline, default focus) and **Duyệt và gửi** (`{colors.primary}`). No third button. Rejected state uses `{colors.danger-soft}` with the sentence “Request không được gửi.”
- **Filtered-response panel** — redacted body only. Text badges: “Đã che dữ liệu nhạy cảm” (`{colors.success-soft}`) and/or “Phát hiện chỉ dẫn lạ — đã cách ly” (`{colors.warning-soft}`). No “view original” control.
- **Metric** — at most five decision-relevant counts. Technical integrity metrics stay on the evaluation / data surface.
- **Evaluation matrix** — 2×2 TP/TN/FP/FN with text labels plus three KPI tiles (Precision, Recall, Accuracy). Color is supplemental.

## Do's and Don'ts

| Do | Don't |
|---|---|
| Lead with “what can I do here?” | Lead with week numbers, provider names or pipeline internals |
| Keep evidence close to the Agent answer | Separate context across unrelated pages |
| Put IDs and hashes behind progressive disclosure | Show implementation metadata before the finding explanation |
| Use one primary action in each section | Present several equal-weight buttons without an obvious next step |
| Explain limitations in neutral language | Use alarming callouts for ordinary benchmark coverage states |
| Keep Vietnamese labels consistent | Mix Vietnamese and English for ordinary UI concepts |
| Spotlight exactly one Guided Demo control | Auto-play steps or highlight the whole page |
| Show redacted placeholders in the UI | Offer a “view original secret” toggle |
