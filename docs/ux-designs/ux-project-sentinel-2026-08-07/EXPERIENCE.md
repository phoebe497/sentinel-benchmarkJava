---
name: Sentinel Analysis Workspace
status: final
sources:
  - app/streamlit_app.py
  - docs/security-analysis-workspace.md
  - README.md
updated: 2026-08-07
---

# Sentinel Analysis Workspace — Experience Spine

## Foundation

Responsive Streamlit web application, desktop-first and usable on tablet or phone. `DESIGN.md` owns visual identity; this document owns information architecture and behavior. The public deployment is read-only and uses generated artifacts. Local mode may call 9Router only after an explicit user action.

Assumptions used for this iteration:

- A first-time visitor understands “lỗ hổng”, but may not know the Week 1–3 implementation history.
- The primary task is understanding one finding and exporting its report.
- Mentor review and technical audit are important secondary tasks, not the first screen.
- Existing datasets, Agent contracts and report artifacts remain unchanged.

## Information Architecture

| Surface | Reached from | Purpose |
|---|---|---|
| Tổng quan | App open | Dashboard the current data and Agent state, then route into one concrete analysis |
| Phân tích lỗ hổng | Primary navigation / CTA | Choose one finding, inspect evidence, ask Sentinel and export a report |
| Knowledge Base | Primary navigation | Search the curated security guidance by meaning, hybrid relevance or exact terms |
| Báo cáo | Primary navigation / analysis CTA | Review generated reports and export JSONL |
| Dữ liệu & kiểm định | Secondary navigation | Inspect observations, grouping and evaluation evidence |

The main navigation follows the normal task order. The dashboard keeps only decision-relevant scanner and Agent metrics; raw metrics and implementation details do not define the navigation.

## Voice and Tone

| Do | Don't |
|---|---|
| “Chọn một lỗ hổng để bắt đầu.” | “Vulnerability analysis group” |
| “Bằng chứng từ 2 scanner.” | “2 source tools / 3 observations” without explanation |
| “Hỏi Sentinel cách xác minh lỗ hổng này.” | “Grounded chat” as the main label |
| “Chưa có báo cáo cho lỗ hổng này.” | “Empty artifact state” |
| “Chi tiết kỹ thuật” | Put prompt hash and run ID in the main reading path |

Use Vietnamese for navigation, actions and explanations. Preserve CWE, scanner names, JSONL, KB, provider/model names and evidence IDs where precision matters.

## Component Patterns

| Component | Use | Behavioral rules |
|---|---|---|
| Journey strip | Dashboard and analysis | Shows the four-step mental model; does not act as navigation |
| Dashboard metric | Dashboard | Shows corpus size, observation count, analysis groups and real smoke-run status; every metric has scope help where misreading is likely |
| Finding selector | Analysis | Filter by CWE, then choose a concrete test. Selection persists for the session |
| Knowledge search mode | Knowledge Base | Semantic is the default; Hybrid combines semantic and BM25; Keyword remains available for exact CWE/term lookup |
| Knowledge result | Knowledge Base | Shows title, document ID and ranking signal first; content, tags and source remain inside a native expander |
| Suggested question | Analysis chat | Every question contains selected CWE, name and test ID; button click submits immediately |
| Evidence list | Analysis | Scanner/location visible; excerpt and raw IDs disclosed on demand |
| Report action | Analysis/report | Selected report exports directly; generation in local mode requires provider/cost confirmation |
| Run selector | Reports/advanced | Hidden in “Nguồn dữ liệu” disclosure until needed |
| Advanced tabs | Data & evaluation | Keep raw tables and machine metrics outside the primary user journey |

## State Patterns

| State | Surface | Treatment |
|---|---|---|
| Initial load | Global | Short spinner message: “Đang chuẩn bị dữ liệu phân tích…” |
| No run artifact | Analysis / reports | Evidence remains usable; explain that no generated report is available |
| Corrupt artifact | Analysis / reports | Stop report display, name checksum failure, retain navigation to evidence |
| Public read-only | Global / analysis | Neutral status text: uses existing evidence, does not call a model |
| Local inference | Analysis | State provider before submission; never trigger inference on page rerun |
| Chat provider failure | Analysis | Fall back to artifact answer when supported; state source in technical details |
| Empty search | Advanced data | “Không có kết quả phù hợp với bộ lọc này.” and a reset path |
| Missing scanner excerpt | Evidence | “Scanner không cung cấp đoạn mã trong artifact này.” No warning color |

## Interaction Primitives

- Click or tap to act. Native Streamlit keyboard and focus behavior is preserved.
- A primary button moves the task forward; secondary buttons ask a suggested question or reveal detail.
- Expanders hold provenance, raw excerpts, model information and checksums.
- Tabs are allowed only within the advanced data surface, where the user has intentionally requested comparison.
- Banned in the primary flow: nested tabs, raw JSON blocks, warning banners for normal states, more than five metrics in a row, and navigation based on internal week names.

## Accessibility Floor

- WCAG 2.2 AA contrast for text, controls, focus and semantic states.
- Heading order follows the reading sequence; no visual-only heading hierarchy.
- Every button names the action and target. Icon-only actions are avoided.
- Severity and guard states include text; color is supplemental.
- Page remains operable at 200% zoom. Columns stack, question buttons wrap and tables scroll horizontally.
- Focus order matches visual reading order. Hidden technical content remains reachable by keyboard through native expanders.
- Motion is limited to native Streamlit status transitions; no decorative animation.

## Responsive & Platform

| Width | Behavior |
|---|---|
| ≥ 1024px | Evidence and chat may sit in two columns; content capped at 1180px |
| 768–1023px | Single-column analysis; metrics use two rows |
| < 768px | Navigation collapses through Streamlit; all controls become full width; tables scroll |

## Product-specific Trust Rules

- Ground truth is never shown beside the Agent answer and is never implied to be Agent input.
- `benchmark_assisted` grouping is explained once in technical detail, not repeated as a warning.
- Answer source, citations, provider/model and fallback status remain inspectable.
- Public mode never suggests that it is performing live inference.
- Scanner absence is described as missing observation, never as proof that code is clean.

## Key Flows

### Flow 1 — First finding review (Minh, first visit, wants to understand the demo)

1. Minh opens the dashboard and reads one sentence describing the outcome.
2. He sees current data readiness and four steps: choose, inspect, ask, export.
3. He chooses the suggested `CWE-327` example.
4. Analysis opens with the vulnerability name, Benchmark test and scanner coverage together.
5. He expands one scanner observation, then asks “Lỗ hổng này nguy hiểm như thế nào?”
6. Sentinel answers from the selected evidence and shows source IDs under technical details.
7. **Climax:** Minh downloads one JSONL report and can connect its explanation back to the scanner observation without changing pages.

### Flow 2 — Mentor checks traceability (Phương, reviewing Week 3 deliverables)

1. Phương opens “Báo cáo” and sees successful report count, provider and evidence-guard status.
2. She filters to a CWE and opens one report.
3. Plain-language explanation appears before verification and remediation.
4. She expands “Nguồn và chi tiết kỹ thuật” to inspect observation IDs, KB documents, model and prompt hash.
5. She opens “Dữ liệu & kiểm định” only when she wants aggregate scanner or grouping metrics.
6. **Climax:** She verifies that the report cites committed evidence and exports the complete JSONL run.

### Flow 3 — Local analyst creates a report (Lan, has configured 9Router)

1. Lan selects a finding in “Phân tích lỗ hổng”.
2. Existing evidence and any baked report load without calling the model.
3. She opens “Tạo báo cáo mới”, selects 9Router and reads the quota note.
4. She confirms the selected finding and provider, then starts generation.
5. The canonical CLI creates and validates one report artifact.
6. **Climax:** The page reloads to the new run and offers the validated JSONL file; secrets and headers are never displayed.
