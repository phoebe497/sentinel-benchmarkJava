from __future__ import annotations

import json
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import streamlit as st
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
load_dotenv(ROOT / ".env")

from sentinel_benchmark.agent_reports import export_reports_jsonl
from sentinel_benchmark.analysis.chat import answer_question, build_chat_payload
from sentinel_benchmark.analysis.models import AnalysisGroup
from sentinel_benchmark.analysis.providers import NineRouterProvider
from sentinel_benchmark.analysis.taxonomy import cwe_name
from sentinel_benchmark.guardrails.approval import ApprovalGate, ApprovalRejected, ProposedRequest
from sentinel_benchmark.guardrails.injection import scan as scan_injection
from sentinel_benchmark.guardrails.redaction import redact_obj
from sentinel_benchmark.indexer import build
from sentinel_benchmark.workspace import (
    available_runs,
    filter_groups,
    load_analysis_groups,
    load_observations,
    load_run_artifact,
    load_week2_groups,
    search_knowledge,
)

DB = ROOT / "datasets/processed/sentinel.db"
MANIFEST = ROOT / "configs/sources.json"
KB = ROOT / "datasets/knowledge/security-topics.jsonl"
PREDICTIONS = ROOT / "artifacts/week-1/semgrep-20260806/variants/security-audit/predictions.jsonl"
WEEK3 = ROOT / "artifacts/week-3"
WEEK5 = ROOT / "artifacts/week-5"
READONLY = os.getenv("SENTINEL_UI_READONLY", "1") != "0"

SEVERITY_LABELS = {
    "critical": "Nghiêm trọng",
    "high": "Cao",
    "medium": "Trung bình",
    "low": "Thấp",
    "informational": "Thông tin",
    "info": "Thông tin",
}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4, "info": 4}

st.set_page_config(
    page_title="Sentinel · Security Analysis",
    page_icon=":material/shield:",
    layout="wide",
    initial_sidebar_state="auto",
)
st.markdown(
    """
    <style>
    :root {
        --sentinel-primary: #0f766e;
        --sentinel-primary-dark: #115e59;
        --sentinel-primary-soft: #ddf3ef;
        --sentinel-border: #d9e3e0;
        --sentinel-ink-muted: #536763;
        --sentinel-surface: #ffffff;
    }
    .block-container {max-width: 1180px; padding-top: 2rem; padding-bottom: 4rem;}
    [data-testid="stSidebar"] {border-right: 1px solid var(--sentinel-border);}
    [data-testid="stMetric"] {
        background: var(--sentinel-surface);
        border: 1px solid var(--sentinel-border);
        border-radius: 12px;
        padding: 1rem 1.05rem;
    }
    [data-testid="stMetricLabel"] {color: var(--sentinel-ink-muted);}
    [data-testid="stMetricValue"] {font-size: 1.65rem;}
    .sentinel-eyebrow {
        color: var(--sentinel-primary);
        font-size: .78rem;
        font-weight: 750;
        letter-spacing: .08em;
        text-transform: uppercase;
        margin-bottom: .45rem;
    }
    .sentinel-title {
        color: #172321;
        font-size: clamp(2rem, 4vw, 2.65rem);
        font-weight: 760;
        letter-spacing: -.035em;
        line-height: 1.12;
        margin: 0 0 .7rem;
    }
    .sentinel-lead {
        color: var(--sentinel-ink-muted);
        font-size: 1.05rem;
        line-height: 1.65;
        max-width: 780px;
        margin-bottom: 1.6rem;
    }
    .hero-card {
        background: linear-gradient(135deg, #ffffff 0%, #eef8f6 100%);
        border: 1px solid var(--sentinel-border);
        border-radius: 16px;
        padding: clamp(1.4rem, 4vw, 2.4rem);
        margin-bottom: 1.6rem;
    }
    .section-kicker {
        color: var(--sentinel-primary);
        font-size: .76rem;
        font-weight: 750;
        letter-spacing: .075em;
        text-transform: uppercase;
        margin: 2.6rem 0 .25rem;
    }
    .section-title {font-size: 1.45rem; font-weight: 710; margin: 0 0 .35rem; color: #172321;}
    .section-help {color: var(--sentinel-ink-muted); margin: 0 0 1rem; line-height: 1.55;}
    .journey {
        display: grid;
        grid-template-columns: repeat(6, minmax(0, 1fr));
        gap: .75rem;
        margin: 1rem 0 1.5rem;
    }
    .journey-step {
        background: var(--sentinel-surface);
        border: 1px solid var(--sentinel-border);
        border-radius: 12px;
        padding: .95rem;
        min-height: 96px;
    }
    .journey-step.active {border-color: var(--sentinel-primary); background: var(--sentinel-primary-soft);}
    .journey-step.done {border-color: #b7c9c4; background: #f4f8f7;}
    .coach {
        border: 2px solid var(--sentinel-primary);
        background: var(--sentinel-primary-soft);
        color: #115e59;
        border-radius: 10px;
        padding: .7rem .9rem;
        font-size: .92rem;
        font-weight: 650;
        line-height: 1.45;
        margin: .4rem 0 .75rem;
    }
    .approval-card, .proposal-card, .filtered-card {
        background: var(--sentinel-surface);
        border: 1px solid var(--sentinel-border);
        border-radius: 14px;
        padding: 1.15rem 1.25rem;
        margin: .4rem 0 1.2rem;
    }
    .approval-card.rejected {background: #fdecea; border-color: #f0c2bd;}
    .approval-card.approved {background: #e8f5ee; border-color: #b7dcc6;}
    .badge {
        display: inline-block;
        padding: .2rem .62rem;
        border-radius: 999px;
        font-size: .78rem;
        font-weight: 700;
        margin: 0 .35rem .35rem 0;
    }
    .badge-success {background: #e8f5ee; color: #157347;}
    .badge-warning {background: #fff5e6; color: #b45309;}
    .matrix-cell {
        border: 1px solid var(--sentinel-border);
        border-radius: 10px;
        padding: 1rem;
        text-align: center;
        background: #fff;
    }
    .matrix-cell .n {font-size: 1.6rem; font-weight: 760; color: #172321;}
    .matrix-cell .l {font-size: .82rem; color: var(--sentinel-ink-muted);}
    .journey-number {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 26px;
        height: 26px;
        border-radius: 999px;
        background: var(--sentinel-primary-soft);
        color: var(--sentinel-primary-dark);
        font-weight: 760;
        margin-bottom: .55rem;
    }
    .journey-step.active .journey-number {background: var(--sentinel-primary); color: #fff;}
    .journey-label {font-weight: 680; color: #172321; margin-bottom: .15rem;}
    .journey-copy {font-size: .83rem; color: var(--sentinel-ink-muted); line-height: 1.4;}
    .context-card {
        background: var(--sentinel-surface);
        border: 1px solid var(--sentinel-border);
        border-left: 4px solid var(--sentinel-primary);
        border-radius: 14px;
        padding: 1.2rem 1.3rem;
        margin: .4rem 0 1.2rem;
    }
    .context-title {font-size: 1.15rem; font-weight: 720; color: #172321; margin-bottom: .35rem;}
    .context-meta {color: var(--sentinel-ink-muted); font-size: .9rem; line-height: 1.55;}
    .trust-note {
        border: 1px solid var(--sentinel-border);
        border-radius: 12px;
        background: #f8fbfa;
        color: #36514c;
        padding: 1rem 1.1rem;
        line-height: 1.55;
    }
    .chip {
        display: inline-block;
        padding: .2rem .62rem;
        border-radius: 999px;
        background: var(--sentinel-primary-soft);
        color: var(--sentinel-primary-dark);
        font-size: .78rem;
        font-weight: 700;
        margin-right: .35rem;
    }
    .chip-neutral {background: #edf1f0; color: #415652;}
    .severity-critical, .severity-high {background: #fdecea; color: #9f2117;}
    .severity-medium {background: #fff5e6; color: #94500a;}
    .severity-low, .severity-informational, .severity-info {background: #eaf1ff; color: #1e54aa;}
    .evidence-line {color: var(--sentinel-ink-muted); font-size: .86rem; margin: .25rem 0 .55rem;}
    .report-shell {
        border: 1px solid var(--sentinel-border);
        border-radius: 14px;
        background: var(--sentinel-surface);
        padding: 1.2rem 1.3rem;
        margin: .7rem 0 1rem;
    }
    .report-title {font-size: 1.08rem; font-weight: 720; color: #172321; margin-bottom: .55rem;}
    .sidebar-brand {font-weight: 780; font-size: 1.12rem; color: #173b36; margin-bottom: .1rem;}
    .sidebar-copy {font-size: .84rem; color: #55706c; line-height: 1.45; margin-bottom: 1rem;}
    .sidebar-status {font-size: .8rem; color: #36514c; border-top: 1px solid var(--sentinel-border); padding-top: .8rem;}
    div.stButton > button {border-radius: 9px; min-height: 2.7rem; font-weight: 650;}
    div[data-testid="stExpander"] {border-color: var(--sentinel-border); border-radius: 10px;}
    @media (max-width: 800px) {
        .block-container {padding-top: 1.2rem;}
        .journey {grid-template-columns: repeat(2, minmax(0, 1fr));}
        .sentinel-title {font-size: 2rem;}
    }
    @media (max-width: 520px) {
        .journey {grid-template-columns: 1fr;}
        .journey-step {min-height: auto;}
    }
    </style>
    """,
    unsafe_allow_html=True,
)


def _knowledge_schema_is_current() -> bool:
    if not DB.exists():
        return False
    import sqlite3
    try:
        with sqlite3.connect(DB) as conn:
            columns = {row[1] for row in conn.execute("PRAGMA table_info(knowledge)").fetchall()}
        return "category" in columns
    except sqlite3.DatabaseError:
        return False


@st.cache_resource
def prepare() -> dict:
    DB.parent.mkdir(parents=True, exist_ok=True)
    if DB.exists() and not _knowledge_schema_is_current():
        DB.unlink()
    return build(MANIFEST, DB, KB)


@st.cache_data
def data() -> tuple[list[dict], list[dict], list[dict]]:
    return load_observations(DB), load_week2_groups(DB), load_analysis_groups(DB, PREDICTIONS)


def nine_router_provider() -> NineRouterProvider:
    return NineRouterProvider.from_env()


def run_choice(*, show_control: bool = False, key: str = "run-choice") -> dict | None:
    runs = available_runs(WEEK3)
    if not runs:
        return None
    preferred = st.session_state.get("preferred_run_id")
    default = (
        next((row for row in runs if row.get("run_id") == preferred), None)
        or next((row for row in runs if row.get("provider") == "nine_router" and row.get("status") == "successful"), None)
        or next((row for row in runs if row.get("provider") == "fake" and row.get("status") == "successful"), None)
        or runs[0]
    )
    if not show_control:
        return default
    labels = {
        f"{row['provider']} · {row['status']} · {row['run_id']}": row
        for row in runs
    }
    rows = list(labels.values())
    selected = st.selectbox(
        "Lần chạy",
        list(labels),
        index=rows.index(default),
        key=key,
        help="Đổi lần chạy khi cần đối chiếu provider hoặc artifact khác.",
    )
    return labels[selected]


def load_ready_artifact(run: dict | None) -> dict:
    if not run:
        return {"state": "empty", "reports": []}
    return load_run_artifact(Path(run["run_dir"]))


def page_intro(eyebrow: str, title: str, description: str, *, hero: bool = False) -> None:
    wrapper = "hero-card" if hero else ""
    st.markdown(
        f"""
        <div class="{wrapper}">
          <div class="sentinel-eyebrow">{eyebrow}</div>
          <h1 class="sentinel-title">{title}</h1>
          <div class="sentinel-lead">{description}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def section_intro(kicker: str, title: str, help_text: str) -> None:
    st.markdown(
        f'<div class="section-kicker">{kicker}</div><div class="section-title">{title}</div>'
        f'<div class="section-help">{help_text}</div>',
        unsafe_allow_html=True,
    )


JOURNEY_STEPS = [
    (1, "Chọn lỗ hổng", "Chọn CWE và vị trí cần xem."),
    (2, "Xem bằng chứng", "Đọc cảnh báo scanner và tri thức."),
    (3, "Hỏi Agent", "Nhận giải thích theo đúng ngữ cảnh."),
    (4, "Duyệt phép thử", "Từ chối hoặc duyệt trước khi gửi."),
    (5, "Phản hồi đã lọc", "Xem kết quả đã che và đã cách ly."),
    (6, "Xuất / đánh giá", "Xem đúng–sai và tải báo cáo."),
]


def _guided_active() -> bool:
    return bool(st.session_state.get("guided_active"))


def _guided_step() -> int:
    return int(st.session_state.get("guided_step") or 0)


def start_guided_demo() -> None:
    st.session_state["guided_active"] = True
    st.session_state["guided_step"] = 1
    st.session_state["approval_state"] = "pending"
    st.session_state.pop("probe_result", None)


def exit_guided_demo() -> None:
    st.session_state["guided_active"] = False
    st.session_state["guided_step"] = 0


def set_guided_step(step: int) -> None:
    st.session_state["guided_active"] = True
    st.session_state["guided_step"] = step


def coach(step: int, text: str) -> bool:
    if _guided_active() and _guided_step() == step:
        st.markdown(f'<div class="coach">{text}</div>', unsafe_allow_html=True)
        return True
    return False


def journey_strip(active_steps: set[int] | None = None) -> None:
    current = _guided_step() if _guided_active() else 0
    if active_steps is None and current:
        active_steps = {current}
        completed = set(range(1, current))
    elif active_steps is None:
        active_steps, completed = set(), set()
    else:
        completed = {item for item in range(1, 7) if item not in active_steps and item < min(active_steps, default=0)}
    cards = []
    for number, label, copy in JOURNEY_STEPS:
        state = "active" if number in active_steps else ("done" if number in completed else "")
        cards.append(
            f'<div class="journey-step {state}">'
            f'<div class="journey-number">{number}</div><div class="journey-label">{label}</div>'
            f'<div class="journey-copy">{copy}</div></div>'
        )
    st.markdown(f'<div class="journey">{"".join(cards)}</div>', unsafe_allow_html=True)
    if _guided_active():
        exit_col, _ = st.columns([1, 3])
        if exit_col.button("Thoát demo", key="exit-guided"):
            exit_guided_demo()
            st.rerun()


def severity_chip(severity: str) -> str:
    normalized = severity.lower()
    label = SEVERITY_LABELS.get(normalized, severity.title())
    return f'<span class="chip severity-{normalized}">{label}</span>'


def write_list_or_text(value: str | list[str]) -> None:
    if isinstance(value, list):
        for item in value:
            st.markdown(f"- {item}")
        return
    st.write(value)


def report_content(report: dict, *, show_title: bool = True) -> None:
    name = report.get("vulnerability_name") or cwe_name(report["expected_cwe"], report.get("category", ""))
    if show_title:
        st.markdown(
            f'<div class="report-shell"><div class="report-title">{report["expected_cwe"]} — {name}</div>'
            f'{severity_chip(report["severity_assessment"])}'
            f'<span class="chip chip-neutral">Tin cậy {report["analysis_confidence"]:.2f}</span></div>',
            unsafe_allow_html=True,
        )
    st.markdown("**Giải thích dễ hiểu**")
    st.write(report["explanation"])
    verification, remediation = st.columns(2)
    with verification:
        st.markdown("**Cách xác minh**")
        write_list_or_text(report["verification_steps"])
    with remediation:
        st.markdown("**Hướng khắc phục**")
        write_list_or_text(report["remediation"])
    if report.get("limitations"):
        st.markdown("**Phạm vi của kết luận**")
        write_list_or_text(report["limitations"])
    with st.expander("Nguồn và chi tiết kỹ thuật"):
        st.caption(
            f"{report['analysis_group_id']} · {report['grouping_mode']} · "
            f"{report['provider']} / {report['model']}"
        )
        for evidence in report["evidence"]:
            st.markdown(
                f"- `{evidence['observation_id']}` · {evidence['tool']} · "
                f"`{evidence['file_or_url']}:{evidence.get('line_start') or '?'}`"
            )
        guard_text = "PASS — mọi citation đều tồn tại" if report["guard"]["passed"] else "FAIL — cần review artifact"
        st.caption(
            f"Evidence Guard: {guard_text} · Prompt: {report['prompt_sha256']} · "
            f"KB: {', '.join(report['sources']['kb_document_ids']) or 'không có'}"
        )


def report_card(report: dict) -> None:
    name = report.get("vulnerability_name") or cwe_name(report["expected_cwe"], report.get("category", ""))
    severity = SEVERITY_LABELS.get(report["severity_assessment"].lower(), report["severity_assessment"].title())
    with st.expander(f"{report['expected_cwe']} — {name} · {severity} · {report['benchmark_test_id']}"):
        report_content(report, show_title=False)


try:
    with st.spinner("Đang chuẩn bị dữ liệu phân tích…"):
        prepare()
        observations, week2_groups, groups = data()
except Exception as exc:
    st.error("Không thể tải dữ liệu của Sentinel. Hãy kiểm tra index và source manifest.")
    with st.expander("Chi tiết kỹ thuật"):
        st.exception(exc)
    st.stop()


def dashboard() -> None:
    page_intro(
        "Security analysis workspace",
        "Từ cảnh báo scanner đến báo cáo dễ kiểm tra",
        "Sentinel gom các cảnh báo liên quan, đặt bằng chứng và kiến thức bảo mật cạnh nhau, "
        "giúp bạn hỏi Agent, duyệt một phép thử qua Gateway, rồi xem phản hồi đã lọc.",
        hero=True,
    )

    start, sample, guided = st.columns([1, 1, 1])
    if start.button("Bắt đầu phân tích", type="primary", width="stretch"):
        st.switch_page(findings_page)
    sample_group = next((group for group in groups if group["expected_cwe"] == "CWE-89"), None)
    sample_group = sample_group or next((group for group in groups if group["expected_cwe"] == "CWE-327"), groups[0] if groups else None)
    if sample.button("Mở ví dụ CWE-89", width="stretch", disabled=sample_group is None):
        if sample_group:
            st.session_state["selected_group_id"] = sample_group["analysis_group_id"]
        st.switch_page(findings_page)
    if guided.button("Chạy demo có hướng dẫn", width="stretch"):
        if sample_group:
            st.session_state["selected_group_id"] = sample_group["analysis_group_id"]
        start_guided_demo()
        st.switch_page(findings_page)

    section_intro("Luồng sử dụng", "Sáu bước để hoàn thành một lượt phân tích và kiểm chứng", "Bạn không cần đọc raw scanner output trước khi bắt đầu.")
    journey_strip({1} if not _guided_active() else None)

    baseline_path = WEEK3 / "baseline.json"
    baseline = json.loads(baseline_path.read_text(encoding="utf-8")) if baseline_path.exists() else {}
    metrics_path = WEEK3 / "evaluation/agent-metrics.json"
    metrics = json.loads(metrics_path.read_text(encoding="utf-8")) if metrics_path.exists() else {}
    real_metrics = metrics.get("real", {})

    section_intro("Dashboard", "Tình trạng dữ liệu và Agent", "Các số liệu đủ để biết workspace đã sẵn sàng; chi tiết kiểm định nằm ở trang cuối.")
    metric_columns = st.columns(4)
    metric_columns[0].metric("Test case", 100, help="100 test case đầu tiên của OWASP BenchmarkJava.")
    metric_columns[1].metric("Cảnh báo scanner", len(observations))
    metric_columns[2].metric("Nhóm để phân tích", len(groups))
    metric_columns[3].metric(
        "LLM smoke test",
        f"{real_metrics.get('successful', 0)}/{real_metrics.get('requested', 0)}",
        help="Smoke test xác nhận luồng LLM trên một mẫu nhỏ, không đại diện cho toàn bộ 99 nhóm.",
    )

    scanner_col, readiness_col = st.columns([1.15, 1])
    with scanner_col:
        st.markdown("#### Cảnh báo theo scanner")
        scanner_counts = baseline.get("scanner_counts", {})
        if scanner_counts:
            st.bar_chart(scanner_counts, horizontal=True, height=230, color="#0F766E")
        else:
            st.caption("Chưa có baseline để hiển thị phân bố scanner.")
    with readiness_col:
        st.markdown("#### Có thể kiểm tra ngay")
        st.markdown(
            f"""
            <div class="trust-note">
              <strong>{len(groups)} nhóm lỗ hổng</strong> đã liên kết về scanner observation.<br><br>
              <strong>{real_metrics.get('guard_pass_rate', 0):.0%} Evidence Guard</strong> trên real smoke run.<br><br>
              <strong>{real_metrics.get('evidence_reference_rate', 0):.0%} evidence preserved</strong> trong báo cáo đã đánh giá.
            </div>
            """,
            unsafe_allow_html=True,
        )

    cwe_counts = Counter(group["expected_cwe"] for group in groups)
    section_intro("Gợi ý", "Một số loại lỗ hổng để mở thử", "Chọn một ví dụ để đi thẳng tới bằng chứng, hỏi đáp và báo cáo.")
    top_cwes = ["CWE-89", "CWE-327", "CWE-79"]
    suggestion_columns = st.columns(3)
    for column, cwe in zip(suggestion_columns, top_cwes):
        group = next((item for item in groups if item["expected_cwe"] == cwe), None)
        with column:
            if group:
                st.markdown(f"**{cwe} — {cwe_name(cwe, group['category'])}**")
                st.caption(f"{cwe_counts[cwe]} nhóm trong corpus hiện tại")
                if st.button(f"Phân tích {cwe}", key=f"dashboard-{cwe}", width="stretch"):
                    st.session_state["selected_group_id"] = group["analysis_group_id"]
                    st.switch_page(findings_page)

    with st.expander("Phạm vi và cách đọc dashboard"):
        st.write(
            "Corpus hiện tại chỉ gồm 100 test case đầu tiên của OWASP BenchmarkJava. "
            "Scanner observation là cảnh báo chưa được xác nhận; việc không có observation không đồng nghĩa mã nguồn an toàn. "
            "Ground truth chỉ dùng ở khu vực kiểm định và không được gửi vào Agent."
        )


def analysis_workspace() -> None:
    page_intro(
        "Lỗ hổng và bằng chứng",
        "Chọn một lỗ hổng rồi xem máy quét đã thấy gì",
        "Lọc theo CWE, chọn một Benchmark test, rồi đọc observation và tài liệu tri thức liên quan.",
    )
    journey_strip({1, 2} if not _guided_active() else None)
    coach(1, "Bước 1 — bấm Dùng ví dụ CWE-89 để chọn lỗ hổng mẫu.")

    section_intro("Bước 1", "Chọn lỗ hổng cần xem", "Lọc theo CWE trước, sau đó chọn một Benchmark test cụ thể.")
    example = next((group for group in groups if group["expected_cwe"] == "CWE-89"), None)
    if example and st.button("Dùng ví dụ CWE-89", type="primary" if _guided_step() == 1 else "secondary", width="stretch"):
        st.session_state["selected_group_id"] = example["analysis_group_id"]
        if _guided_active() and _guided_step() == 1:
            set_guided_step(2)
        st.rerun()
    cwe_options = sorted(
        {group["expected_cwe"] for group in groups},
        key=lambda value: int(value.split("-")[1]),
    )
    requested_group_id = st.session_state.get("selected_group_id")
    requested_group = next((group for group in groups if group["analysis_group_id"] == requested_group_id), None)
    default_cwe = requested_group["expected_cwe"] if requested_group else ("CWE-327" if "CWE-327" in cwe_options else cwe_options[0])
    filter_col, group_col = st.columns([1, 1.65])
    with filter_col:
        selected_cwe = st.selectbox(
            "Loại lỗ hổng (CWE)",
            cwe_options,
            index=cwe_options.index(default_cwe),
            format_func=lambda value: f"{value} — {cwe_name(value, next(item['category'] for item in groups if item['expected_cwe'] == value))}",
        )
    candidate_groups = [group for group in groups if group["expected_cwe"] == selected_cwe]
    if requested_group not in candidate_groups:
        requested_group = candidate_groups[0]
    labels = {
        f"{group['benchmark_test_id']} · {len(group['observation_ids'])} observation · {', '.join(group['source_tools'])}": group
        for group in candidate_groups
    }
    label_rows = list(labels.values())
    with group_col:
        selected_label = st.selectbox(
            "Vị trí cụ thể",
            list(labels),
            index=label_rows.index(requested_group),
            help="Mỗi lựa chọn là một test case và các cảnh báo scanner đã được liên kết với nó.",
        )
    selected_group = labels[selected_label]
    st.session_state["selected_group_id"] = selected_group["analysis_group_id"]
    selected_name = cwe_name(selected_group["expected_cwe"], selected_group["category"])
    st.markdown(
        f"""
        <div class="context-card">
          <div class="context-title">{selected_group['expected_cwe']} — {selected_name}</div>
          <div class="context-meta">
            {selected_group['benchmark_test_id']} · {len(selected_group['observation_ids'])} scanner observation ·
            {len(selected_group['source_tools'])} scanner: {', '.join(selected_group['source_tools'])}
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    run = run_choice()
    artifact = load_ready_artifact(run)
    if artifact.get("state") == "corrupt":
        st.error("Artifact báo cáo không còn khớp checksum. Bằng chứng scanner bên dưới vẫn có thể xem.")
        with st.expander("Checksum không khớp"):
            st.write(artifact.get("checksum_failures", []))
        reports = []
    else:
        reports = artifact.get("reports", [])
    matching_reports = [
        report for report in reports
        if report["analysis_group_id"] == selected_group["analysis_group_id"]
    ]
    report = matching_reports[-1] if matching_reports else None
    knowledge = search_knowledge(DB, f"{selected_group['expected_cwe']} {selected_group['category']}", 3)

    section_intro("Bước 2", "Kiểm tra bằng chứng và kiến thức tham chiếu", "Scanner nói gì, ở đâu và Sentinel dùng tài liệu nào để giải thích.")
    coach(2, "Bước 2 — mở bằng chứng scanner đầu tiên, rồi tiếp tục sang hỏi Agent.")
    if _guided_active() and _guided_step() == 2:
        st.session_state["guided_expand_evidence"] = True
    evidence_col, knowledge_col = st.columns([1.2, 1])
    with evidence_col:
        st.markdown("#### Bằng chứng scanner")
        for index, item in enumerate(selected_group["evidence_items"]):
            with st.expander(
                f"{item['tool']} · dòng {item.get('line_start') or 'không xác định'}",
                expanded=index == 0 and bool(st.session_state.get("guided_expand_evidence")),
            ):
                st.caption(f"{item['file_or_url']} · {item['observation_id']}")
                st.code(item.get("excerpt") or "Scanner không cung cấp đoạn mã trong artifact này.", language=None)
    with knowledge_col:
        st.markdown("#### Kiến thức được truy xuất")
        if not knowledge:
            st.caption("Không tìm thấy tài liệu KB phù hợp cho nhóm này.")
        for row in knowledge:
            with st.expander(row["title"]):
                st.write(row["content"])
                st.caption(f"{row['document_id']} · {row.get('source', '')}")
    with st.expander("Cách nhóm bằng chứng này"):
        st.write(" · ".join(selected_group["grouping_reason"]))
        st.caption(
            "benchmark_assisted dùng metadata của corpus để correlate cảnh báo giữa scanner. "
            "Đây không phải kết luận rằng finding đã được xác nhận trong một repository thông thường."
        )

    next_col, kb_col = st.columns(2)
    if next_col.button("Tiếp: hỏi Agent", type="primary", width="stretch"):
        if _guided_active() and _guided_step() == 2:
            set_guided_step(3)
        st.switch_page(agent_page)
    if kb_col.button("Xem thêm trong kho tri thức", width="stretch"):
        st.session_state["kb-search-query"] = f"{selected_group['expected_cwe']} {selected_name}"
        st.switch_page(knowledge_page)


def agent_workspace() -> None:
    page_intro(
        "Phân tích của Agent",
        "Hỏi Sentinel và đọc báo cáo của lỗ hổng đang chọn",
        "Mọi câu trả lời đều bị giới hạn bởi scanner evidence, tài liệu KB và report của nhóm bạn đang chọn.",
    )
    journey_strip({3} if not _guided_active() else None)
    selected_group = next((group for group in groups if group["analysis_group_id"] == st.session_state.get("selected_group_id")), None)
    if selected_group is None:
        st.markdown('<div class="trust-note">Chọn một lỗ hổng ở trang Lỗ hổng &amp; bằng chứng trước khi hỏi Agent.</div>', unsafe_allow_html=True)
        if st.button("Chọn lỗ hổng", type="primary"):
            st.switch_page(findings_page)
        return
    selected_name = cwe_name(selected_group["expected_cwe"], selected_group["category"])
    st.markdown(
        f"""
        <div class="context-card">
          <div class="context-title">{selected_group['expected_cwe']} — {selected_name}</div>
          <div class="context-meta">
            {selected_group['benchmark_test_id']} · {len(selected_group['observation_ids'])} scanner observation
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    run = run_choice()
    artifact = load_ready_artifact(run)
    reports = artifact.get("reports", []) if artifact.get("state") != "corrupt" else []
    matching_reports = [report for report in reports if report["analysis_group_id"] == selected_group["analysis_group_id"]]
    report = matching_reports[-1] if matching_reports else None
    knowledge = search_knowledge(DB, f"{selected_group['expected_cwe']} {selected_group['category']}", 3)

    section_intro("Bước 3", "Hỏi Sentinel về lỗ hổng này", "Chọn câu hỏi mẫu hoặc nhập câu hỏi riêng. Câu trả lời luôn bám theo nhóm đang hiển thị.")
    coach(3, "Bước 3 — bấm Giải thích dễ hiểu để xem Agent trả lời từ bằng chứng đã chọn.")
    if READONLY:
        chat_provider = "offline_artifact"
        st.caption("Chế độ public: trả lời từ artifact và bằng chứng có sẵn, không gọi model mới.")
    else:
        provider_label = st.radio(
            "Nguồn trả lời",
            ["Dữ liệu có sẵn", "OpenCode"],
            horizontal=True,
            help="OpenCode tạo một grounded response mới và có thể sử dụng quota đã cấu hình.",
        )
        chat_provider = "nine_router" if provider_label == "OpenCode" else "offline_artifact"

    chat_key = f"chat-{selected_group['analysis_group_id']}"
    st.session_state.setdefault(chat_key, [])
    prompt_columns = st.columns(3)
    suggested_question = None
    question_specs = [
        (
            "Giải thích dễ hiểu",
            f"Giải thích lỗ hổng {selected_group['expected_cwe']} — {selected_name} trong "
            f"{selected_group['benchmark_test_id']} bằng ngôn ngữ đơn giản và chỉ ra bằng chứng scanner liên quan.",
        ),
        (
            "Hướng dẫn xác minh",
            f"Đưa ra các bước xác minh an toàn lỗ hổng {selected_group['expected_cwe']} — {selected_name} tại "
            f"{selected_group['benchmark_test_id']} và trích dẫn observation liên quan.",
        ),
        (
            "Đề xuất khắc phục",
            f"Nên khắc phục lỗ hổng {selected_group['expected_cwe']} — {selected_name} tại "
            f"{selected_group['benchmark_test_id']} như thế nào dựa trên KB và report đã có?",
        ),
    ]
    for column, (label, prompt) in zip(prompt_columns, question_specs):
        with column:
            is_explain = label == "Giải thích dễ hiểu"
            if st.button(
                label,
                key=f"prompt-{label}-{selected_group['analysis_group_id']}",
                type="primary" if is_explain and _guided_step() == 3 else "secondary",
                width="stretch",
            ):
                suggested_question = prompt
                if _guided_active() and _guided_step() == 3 and is_explain:
                    st.session_state["guided_advance_after_answer"] = True

    for message in st.session_state[chat_key]:
        with st.chat_message(message["role"]):
            st.write(message["content"])
            if message.get("citations"):
                with st.expander("Nguồn của câu trả lời"):
                    st.write(", ".join(message["citations"]))
                    source = message.get("metadata", {})
                    fallback = f" · fallback từ {source['fallback_from']}" if source.get("fallback_from") else ""
                    st.caption(f"{source.get('provider', 'artifact')} / {source.get('model', 'deterministic')}{fallback}")

    question = st.chat_input(
        f"Hỏi về {selected_group['expected_cwe']}: ảnh hưởng, xác minh hoặc khắc phục…",
        key=f"question-{selected_group['analysis_group_id']}",
    ) or suggested_question
    if question:
        st.session_state[chat_key].append({"role": "user", "content": question})
        payload = build_chat_payload(
            question=question,
            group=AnalysisGroup.model_validate(selected_group),
            knowledge=knowledge,
            report=report,
        )
        try:
            active_provider = nine_router_provider() if chat_provider == "nine_router" else None
            answer, metadata = answer_question(provider=active_provider, payload=payload, fallback_on_error=True)
            content = answer.answer
            if answer.verification_steps:
                content += "\n\nCách xác minh:\n- " + "\n- ".join(answer.verification_steps)
            if answer.remediation:
                content += "\n\nHướng khắc phục:\n- " + "\n- ".join(answer.remediation)
            if answer.limitations:
                content += "\n\nGiới hạn của câu trả lời:\n- " + "\n- ".join(answer.limitations)
            st.session_state[chat_key].append(
                {"role": "assistant", "content": content, "citations": answer.citations, "metadata": metadata}
            )
            if st.session_state.pop("guided_advance_after_answer", False):
                set_guided_step(4)
            st.rerun()
        except Exception as exc:
            st.error("Sentinel chưa thể tạo câu trả lời. Bạn vẫn có thể xem bằng chứng và báo cáo ở trang này.")
            with st.expander("Chi tiết lỗi"):
                st.code(str(exc), language=None)

    chat_actions = st.columns([1, 1])
    transcript = json.dumps(st.session_state[chat_key], ensure_ascii=False, indent=2)
    chat_actions[0].download_button(
        "Tải nội dung hỏi đáp",
        transcript,
        f"{selected_group['analysis_group_id']}-chat.json",
        "application/json",
        disabled=not st.session_state[chat_key],
        width="stretch",
    )
    if chat_actions[1].button("Xóa cuộc trò chuyện", disabled=not st.session_state[chat_key], width="stretch"):
        st.session_state[chat_key] = []
        st.rerun()

    section_intro("Bước 4", "Xem hoặc xuất báo cáo", "Báo cáo giữ lại evidence ID, nguồn KB, provider, model và kết quả Evidence Guard.")
    if report:
        report_content(report)
        st.download_button(
            "Tải báo cáo này (.jsonl)",
            export_reports_jsonl([report]),
            f"{report['report_id']}.jsonl",
            "application/x-ndjson",
            type="primary",
            width="stretch",
        )
    else:
        st.markdown('<div class="trust-note">Chưa có báo cáo được tạo sẵn cho lỗ hổng này.</div>', unsafe_allow_html=True)

    if not READONLY:
        with st.expander("Tạo báo cáo mới bằng Agent"):
            provider_name = st.selectbox(
                "Provider",
                ["fake", "nine_router"],
                format_func=lambda value: "OpenCode" if value == "nine_router" else "FakeProvider",
                help="OpenCode có thể sử dụng quota hoặc phát sinh chi phí theo cấu hình của bạn.",
            )
            tag_default = f"ui-{selected_group['benchmark_test_id'].lower()}"
            command = [
                sys.executable,
                str(ROOT / "scripts/analyze.py"),
                "run",
                "--provider",
                provider_name,
                "--group-id",
                selected_group["analysis_group_id"],
                "--limit",
                "1",
                "--tag",
                tag_default,
            ]
            confirmed = st.checkbox(
                f"Tôi xác nhận tạo một báo cáo cho {selected_group['benchmark_test_id']} bằng {provider_name}.",
                key=f"confirm-{selected_group['analysis_group_id']}-{provider_name}",
            )
            if st.button("Tạo và kiểm tra báo cáo", type="primary", disabled=not confirmed, width="stretch"):
                with st.spinner("Agent đang tạo một báo cáo có cấu trúc…"):
                    completed = subprocess.run(
                        command,
                        cwd=ROOT,
                        capture_output=True,
                        text=True,
                        timeout=300,
                        check=False,
                    )
                if completed.returncode:
                    st.error("Không thể tạo báo cáo. Secret và header không được hiển thị.")
                    with st.expander("Chi tiết lỗi từ CLI"):
                        st.code(completed.stderr[-2000:], language=None)
                else:
                    st.toast("Báo cáo đã được tạo và kiểm tra checksum.", icon="✅")
                    try:
                        created = json.loads(completed.stdout)
                        st.session_state["preferred_run_id"] = Path(created["run_dir"]).name
                    except (json.JSONDecodeError, KeyError):
                        pass
                    st.cache_data.clear()
                    st.rerun()

    if st.button("Tiếp: duyệt phép thử", type="primary", width="stretch"):
        if _guided_active() and _guided_step() in {3, 4}:
            set_guided_step(4)
        st.switch_page(verify_page)


def reports_page() -> None:
    page_intro(
        "Báo cáo có cấu trúc",
        "Review kết quả Agent và tải JSONL",
        "Giải thích được đặt trước; provenance, model và prompt hash vẫn có thể mở ra khi cần kiểm tra sâu.",
    )
    with st.expander("Nguồn báo cáo"):
        run = run_choice(show_control=True, key="reports-run")
        if run:
            st.caption(f"Run ID: {run['run_id']} · Provider: {run['provider']} · Trạng thái: {run['status']}")
    artifact = load_ready_artifact(run)
    if artifact.get("state") == "empty":
        st.caption("Chưa có report artifact để hiển thị.")
        return
    if artifact.get("state") != "ready":
        st.error("Artifact báo cáo không còn khớp checksum.")
        return
    reports = artifact["reports"]
    severity_counts = Counter(report["severity_assessment"].lower() for report in reports)
    guard_rate = sum(1 for report in reports if report["guard"]["passed"]) / len(reports) if reports else 0
    summary_columns = st.columns(4)
    summary_columns[0].metric("Báo cáo", len(reports))
    summary_columns[1].metric("Mức cao trở lên", severity_counts["critical"] + severity_counts["high"])
    summary_columns[2].metric("Evidence Guard", f"{guard_rate:.0%}")
    summary_columns[3].metric("Provider", run["provider"] if run else "—")

    if reports:
        st.download_button(
            "Tải toàn bộ báo cáo (.jsonl)",
            export_reports_jsonl(reports),
            "sentinel-week3-reports.jsonl",
            "application/x-ndjson",
            type="primary",
        )

    section_intro("Tìm báo cáo", "Lọc theo loại lỗ hổng hoặc mức độ", "Chỉ bộ lọc thay đổi; artifact gốc không bị chỉnh sửa.")
    cwe_values = sorted({report["expected_cwe"] for report in reports}, key=lambda value: int(value.split("-")[1]))
    severity_values = sorted(
        {report["severity_assessment"].lower() for report in reports},
        key=lambda value: SEVERITY_ORDER.get(value, 99),
    )
    cwe_col, severity_col = st.columns(2)
    selected_cwe = cwe_col.selectbox("CWE", ["Tất cả", *cwe_values])
    selected_severity = severity_col.selectbox(
        "Mức độ",
        ["Tất cả", *severity_values],
        format_func=lambda value: SEVERITY_LABELS.get(value, value.title()) if value != "Tất cả" else value,
    )
    visible = [
        report for report in reports
        if (selected_cwe == "Tất cả" or report["expected_cwe"] == selected_cwe)
        and (selected_severity == "Tất cả" or report["severity_assessment"].lower() == selected_severity)
    ]
    st.caption(f"Hiển thị {len(visible)} / {len(reports)} báo cáo")
    for report in visible:
        report_card(report)


CATEGORY_LABELS = {
    "owasp-top-10": "OWASP Top 10",
    "scanner-docs": "Tài liệu công cụ quét",
    "vulnerability-example": "Ví dụ lỗ hổng",
}
CATEGORY_ORDER = ("owasp-top-10", "scanner-docs", "vulnerability-example")


def _knowledge_category_counts() -> dict[str, int]:
    counts = {key: 0 for key in CATEGORY_ORDER}
    if DB.exists():
        import sqlite3
        try:
            with sqlite3.connect(DB) as conn:
                rows = conn.execute("SELECT category, COUNT(*) FROM knowledge GROUP BY category").fetchall()
            for category, count in rows:
                counts[category or "owasp-top-10"] = count
            return counts
        except sqlite3.DatabaseError:
            pass
    if KB.exists():
        for line in KB.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            counts[record.get("category") or "owasp-top-10"] = counts.get(record.get("category") or "owasp-top-10", 0) + 1
    return counts


def knowledge_base_page() -> None:
    category_counts = _knowledge_category_counts()
    total_docs = sum(category_counts.values())
    journey_strip({2} if not _guided_active() else None)
    page_intro(
        "Kho tri thức bảo mật",
        "Tìm hướng giải thích và khắc phục theo ý nghĩa",
        f"Tìm bằng câu hỏi tự nhiên, thuật ngữ hoặc CWE. Kho gồm {total_docs} tài liệu chia 3 nhóm: OWASP Top 10, tài liệu công cụ quét và ví dụ lỗ hổng. Tính toán chạy local, không gửi nội dung sang LLM.",
    )

    summary_columns = st.columns(4)
    summary_columns[0].metric("Tổng tài liệu", total_docs)
    summary_columns[1].metric("OWASP Top 10", category_counts.get("owasp-top-10", 0))
    summary_columns[2].metric("Tài liệu công cụ quét", category_counts.get("scanner-docs", 0))
    summary_columns[3].metric("Ví dụ lỗ hổng", category_counts.get("vulnerability-example", 0))

    section_intro(
        "Bắt đầu nhanh",
        "Thử một câu hỏi theo cách người dùng thường diễn đạt",
        "Các ví dụ giúp thấy sự khác biệt giữa tìm theo ý nghĩa và chỉ khớp từ khóa.",
    )
    example_queries = [
        "Làm sao ngăn dữ liệu người dùng thay đổi câu lệnh SQL?",
        "Rủi ro khi dùng thuật toán mã hóa yếu là gì?",
        "Làm sao chặn truy cập file nằm ngoài thư mục cho phép?",
    ]
    example_columns = st.columns(3)
    for index, (column, example) in enumerate(zip(example_columns, example_queries), start=1):
        with column:
            if st.button(example, key=f"kb-example-{index}", width="stretch"):
                st.session_state["kb-search-query"] = example
                st.rerun()

    st.session_state.setdefault("kb-search-query", example_queries[0])
    query = st.text_input(
        "Bạn muốn tìm hiểu điều gì?",
        key="kb-search-query",
        placeholder="Ví dụ: Làm sao tránh lộ thông tin nhạy cảm trong log?",
    )
    control_col, limit_col = st.columns([2, 1])
    with control_col:
        search_label = st.segmented_control(
            "Phương pháp",
            ["Semantic", "Hybrid", "Keyword"],
            default="Semantic",
            selection_mode="single",
            help="Semantic hiểu quan hệ giữa các khái niệm; Hybrid kết hợp Semantic với BM25; Keyword khớp thuật ngữ bằng SQLite FTS5.",
        ) or "Semantic"
    with limit_col:
        result_limit = st.slider("Số kết quả", 1, 10, 5)

    mode = {"Semantic": "semantic", "Hybrid": "hybrid", "Keyword": "keyword"}[search_label]
    method_copy = {
        "semantic": "Semantic dùng TF-IDF và Latent Semantic Analysis (SVD), có mở rộng các khái niệm bảo mật Việt–Anh.",
        "hybrid": "Hybrid kết hợp 85% semantic similarity với 15% thứ hạng BM25 để giữ cả ý nghĩa lẫn thuật ngữ chính xác.",
        "keyword": "Keyword dùng SQLite FTS5/BM25; phù hợp khi đã biết CWE hoặc thuật ngữ chính xác.",
    }
    st.caption(method_copy[mode])

    category_options = ["Tất cả", *(CATEGORY_LABELS[key] for key in CATEGORY_ORDER)]
    category_label_to_key = {"Tất cả": None, **{CATEGORY_LABELS[key]: key for key in CATEGORY_ORDER}}
    selected_category_label = st.segmented_control(
        "Nhóm tài liệu",
        category_options,
        default="Tất cả",
        selection_mode="single",
        help="Lọc kết quả theo nhóm: OWASP Top 10, tài liệu công cụ quét, hoặc ví dụ lỗ hổng.",
    ) or "Tất cả"
    selected_category = category_label_to_key[selected_category_label]

    section_intro(
        "Kết quả",
        f"Tài liệu phù hợp với “{query}”",
        "Điểm semantic là độ tương đồng để xếp hạng, không phải confidence của lỗ hổng.",
    )
    fetch_limit = result_limit * 3 if selected_category is None else result_limit
    all_results = search_knowledge(DB, query, fetch_limit, mode=mode) if query.strip() else []

    if selected_category:
        results = [row for row in all_results if row.get("category") == selected_category][:result_limit]
    else:
        results = all_results

    if not results:
        st.markdown(
            '<div class="trust-note">Không tìm thấy tài liệu phù hợp. Hãy thử CWE, tên lỗ hổng hoặc mô tả hành vi cần ngăn chặn.</div>',
            unsafe_allow_html=True,
        )
        return

    if selected_category is None:
        grouped: dict[str, list[dict[str, Any]]] = {key: [] for key in CATEGORY_ORDER}
        for row in results:
            grouped.setdefault(row.get("category") or "owasp-top-10", []).append(row)
        for category_key in CATEGORY_ORDER:
            bucket = grouped.get(category_key, [])[:result_limit]
            if not bucket:
                st.markdown(
                    f"**{CATEGORY_LABELS[category_key]}** — không có tài liệu khớp với truy vấn hiện tại."
                )
                continue
            st.markdown(f"**{CATEGORY_LABELS[category_key]}** · {len(bucket)} tài liệu")
            for position, row in enumerate(bucket, start=1):
                _render_knowledge_row(row, position, mode, expanded=position == 1 and category_key == CATEGORY_ORDER[0])
    else:
        for position, row in enumerate(results, start=1):
            _render_knowledge_row(row, position, mode, expanded=position == 1)

    with st.expander("Semantic Search hoạt động như thế nào?"):
        st.write(
            "Sentinel chuẩn hóa tiếng Việt, mở rộng các khái niệm bảo mật tương đương, biểu diễn title/tags/content bằng TF-IDF, "
            "sau đó chiếu query và tài liệu vào không gian Latent Semantic Analysis bằng SVD. Toàn bộ phép tính diễn ra local. "
            "Hybrid Search cộng thêm tín hiệu BM25 để CWE và thuật ngữ chính xác không bị mất trong semantic ranking."
        )
        st.caption(f"Kho hiện có {total_docs} tài liệu chia 3 nhóm; phù hợp cho demo corpus, chưa phải vector database quy mô lớn.")


def _render_knowledge_row(row: dict[str, Any], position: int, mode: str, *, expanded: bool = False) -> None:
    if mode == "keyword":
        match_text = f"BM25 · hạng {position}"
    else:
        match_text = f"Độ tương đồng {float(row.get('score') or 0):.0%}"
    category_key = row.get("category") or "owasp-top-10"
    category_label = CATEGORY_LABELS.get(category_key, category_key)
    header = f"{position}. {row['title']} · {row['document_id']} · {category_label} · {match_text}"
    with st.expander(header, expanded=expanded):
        st.write(row["content"])
        tags = row.get("tags", "[]")
        try:
            parsed_tags = json.loads(tags) if isinstance(tags, str) else tags
        except json.JSONDecodeError:
            parsed_tags = [str(tags)]
        chips = [f'<span class="chip chip-neutral">{category_label}</span>']
        chips.extend(f'<span class="chip chip-neutral">{tag}</span>' for tag in parsed_tags)
        st.markdown(" ".join(chips), unsafe_allow_html=True)
        st.caption(f"Nguồn: {row.get('source') or 'Không ghi nguồn'}")
        if row.get("source_url"):
            st.link_button("Mở nguồn tham chiếu", row["source_url"])


def data_and_evaluation() -> None:
    page_intro(
        "Dữ liệu và kiểm định",
        "Khu vực dành cho review kỹ thuật",
        "Xem raw observations, cách grouping, knowledge base và các metric dùng để kiểm tra pipeline.",
    )
    scope_tab, findings_tab, evaluation_tab = st.tabs(
        ["Phạm vi", "Findings", "Kiểm định"]
    )
    with scope_tab:
        baseline_path = WEEK3 / "baseline.json"
        baseline = json.loads(baseline_path.read_text(encoding="utf-8")) if baseline_path.exists() else {}
        scope_columns = st.columns(4)
        scope_columns[0].metric("Benchmark cases", 100)
        scope_columns[1].metric("Observations", len(observations))
        scope_columns[2].metric("Week 2 canonical", len(week2_groups))
        scope_columns[3].metric("Week 3 analysis groups", len(groups))
        st.markdown("#### Pipeline")
        journey_strip()
        st.markdown("#### Scanner counts")
        st.dataframe(
            [{"Scanner": tool, "Observations": count} for tool, count in baseline.get("scanner_counts", {}).items()],
            hide_index=True,
            width="stretch",
        )

    with findings_tab:
        view = st.radio(
            "Lớp dữ liệu",
            ["Analysis groups", "Scanner observations", "Week 2 canonical groups"],
            horizontal=True,
        )
        if view == "Analysis groups":
            query = st.text_input("Tìm theo CWE hoặc Benchmark test", placeholder="Ví dụ: CWE-89")
            tool = st.selectbox("Scanner", ["all", *sorted({tool for group in groups for tool in group["source_tools"]})])
            visible = filter_groups(groups, query, tool=tool)
            st.caption(f"{len(visible)} nhóm phù hợp")
            for group in visible[:50]:
                with st.expander(
                    f"{group['expected_cwe']} — {cwe_name(group['expected_cwe'], group['category'])} · "
                    f"{group['benchmark_test_id']}"
                ):
                    st.write("Scanner: " + ", ".join(group["source_tools"]))
                    st.caption("Grouping: " + " · ".join(group["grouping_reason"]))
                    for item in group["evidence_items"]:
                        st.markdown(
                            f"- `{item['observation_id']}` · {item['tool']} · "
                            f"`{item['file_or_url']}:{item.get('line_start') or '?'}`"
                        )
        elif view == "Scanner observations":
            st.caption("Mỗi dòng là một cảnh báo gốc và giữ nguyên provenance để truy vết.")
            st.dataframe(observations, hide_index=True, width="stretch")
        else:
            st.caption("Canonical grouping của Week 2 giảm trùng lặp ở tầng dữ liệu.")
            st.dataframe(
                [
                    {key: row[key] for key in ("canonical_id", "observation_count", "tools")}
                    for row in week2_groups
                ],
                hide_index=True,
                width="stretch",
            )

    with evaluation_tab:
        scanner_tab, grouping_tab, agent_tab, failures_tab = st.tabs(
            ["Scanner", "Grouping", "Agent", "Failure cases"]
        )
        with scanner_tab:
            llm_path = ROOT / "artifacts/week-1/llm-20260728/results.json"
            semgrep_path = ROOT / "artifacts/week-1/semgrep-20260806/results.json"
            llm = json.loads(llm_path.read_text(encoding="utf-8"))
            semgrep = json.loads(semgrep_path.read_text(encoding="utf-8"))
            rows = []
            for name, row in [
                ("Alibaba OpenCodeReview", llm["scanners"]["open_code_review"]),
                ("Vercel DeepSec/Pi", llm["scanners"]["deepsec"]),
            ]:
                rows.append({"Scanner": name, **row["metrics"]["overall"]})
            rows.append(
                {
                    "Scanner": "Semgrep security-audit",
                    **semgrep["variants"]["security-audit"]["metrics"]["metrics"]["overall"],
                }
            )
            st.dataframe(rows, hide_index=True, width="stretch")
        with grouping_tab:
            path = WEEK3 / "evaluation/grouping-metrics.json"
            st.json(json.loads(path.read_text(encoding="utf-8")) if path.exists() else {"state": "not generated"})
        with agent_tab:
            path = WEEK3 / "evaluation/agent-metrics.json"
            st.json(json.loads(path.read_text(encoding="utf-8")) if path.exists() else {"state": "not generated"})
        with failures_tab:
            path = WEEK3 / "evaluation/failure-cases.jsonl"
            rows = [
                json.loads(line)
                for line in path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ] if path.exists() else []
            if rows:
                st.dataframe(rows, hide_index=True, width="stretch")
            else:
                st.caption("Run được đánh giá không có controlled failure.")


def _selected_group() -> dict | None:
    return next((group for group in groups if group["analysis_group_id"] == st.session_state.get("selected_group_id")), None)


def _propose_request(group: dict | None) -> ProposedRequest:
    if group and group["expected_cwe"] == "CWE-89":
        return ProposedRequest(
            endpoint="/login",
            method="POST",
            payload={"user": "wrong-type-int"},
            purpose="Kiểm tra endpoint đăng nhập có chấp nhận dữ liệu sai kiểu không.",
        )
    return ProposedRequest(
        endpoint="/health",
        method="GET",
        payload=None,
        purpose="Kiểm tra Gateway và endpoint còn phản hồi.",
    )


def _replay_filtered_response() -> dict:
    proof_path = WEEK5 / "redaction-proof.json"
    scan_path = WEEK5 / "injection-scan.json"
    proof = json.loads(proof_path.read_text(encoding="utf-8")) if proof_path.exists() else {}
    scan = json.loads(scan_path.read_text(encoding="utf-8")) if scan_path.exists() else {}
    return {
        "source": "replay",
        "status": 200,
        "route": "echo",
        "body": proof.get("redacted_body") or "Không có artifact phản hồi đã lọc.",
        "redacted": True,
        "injection": bool(scan.get("untrusted_sample", {}).get("flagged")),
        "patterns": scan.get("untrusted_sample", {}).get("patterns") or [],
    }


def verify_page() -> None:
    page_intro(
        "Kiểm chứng an toàn",
        "Duyệt phép thử trước khi gửi qua Gateway",
        "Agent chỉ chọn route và payload từ danh sách Gateway cho phép. Từ chối nghĩa là request không được gửi.",
    )
    journey_strip({4, 5} if not _guided_active() else None)
    group = _selected_group()
    request = _propose_request(group)
    summary = request.summary()
    state = st.session_state.get("approval_state", "pending")

    st.markdown('<div class="proposal-card">', unsafe_allow_html=True)
    section_intro("Đề xuất", "Phép thử từ danh sách Gateway", "Payload phá hoại không nằm trong danh sách.")
    if group:
        st.caption(f"Đang gắn với {group['expected_cwe']} · {group['benchmark_test_id']}")
    else:
        st.caption("Chưa chọn lỗ hổng — dùng phép thử health mặc định.")
    st.write(request.purpose)
    st.code(f"{request.method} {request.endpoint}", language=None)
    st.caption("route_id / payload_id lấy từ menu Gateway, không do model tự viết URL.")
    if request.payload is not None:
        with st.expander("Payload sẽ gửi"):
            st.json(summary.get("payload"))
    st.markdown("</div>", unsafe_allow_html=True)

    card_state = "rejected" if state == "rejected" else ("approved" if state == "approved" else "")
    st.markdown(f'<div class="approval-card {card_state}">', unsafe_allow_html=True)
    section_intro("Phê duyệt", "Gửi request này qua Gateway?", "Không có đường bỏ qua. Reject là quyết định cuối của lượt này.")
    if state == "pending" and _guided_step() == 4:
        coach(4, "Bước 4 — bấm Từ chối trước để chứng minh request không được gửi.")
    elif state == "rejected" and _guided_step() == 4:
        coach(4, "Bước 4 — đã chặn. Bây giờ bấm Duyệt và gửi để xem phản hồi đã lọc.")

    reject_col, approve_col = st.columns(2)
    if reject_col.button("Từ chối", type="primary" if state == "pending" else "secondary", width="stretch", disabled=state == "approved"):
        log_path = None if READONLY else WEEK5 / "ui-approval-events.jsonl"
        try:
            ApprovalGate(log_path=log_path).require(request, prompter=lambda _req: (False, "operator declined in UI"))
        except ApprovalRejected:
            st.session_state["approval_state"] = "rejected"
            st.session_state.pop("probe_result", None)
            st.rerun()
    if approve_col.button("Duyệt và gửi", type="primary" if state == "rejected" else "secondary", width="stretch", disabled=state == "approved"):
        log_path = None if READONLY else WEEK5 / "ui-approval-events.jsonl"
        ApprovalGate(log_path=log_path).require(request, prompter=lambda _req: (True, "operator approved in UI"))
        st.session_state["approval_state"] = "approved"
        if READONLY:
            st.session_state["probe_result"] = _replay_filtered_response()
        else:
            gateway = os.getenv("SAFE_PROBE_GATEWAY_URL")
            if gateway:
                st.session_state["probe_result"] = {
                    "source": "gateway",
                    "status": None,
                    "route": request.endpoint,
                    "body": "Local mode: nối safe_probe khi Gateway đang chạy. Bản ghi demo dùng artifact đã lọc.",
                    "redacted": True,
                    "injection": False,
                    "patterns": [],
                }
                st.session_state["probe_result"] = _replay_filtered_response() | {"source": "gateway-or-replay"}
            else:
                st.session_state["probe_result"] = _replay_filtered_response()
        if _guided_active():
            set_guided_step(5)
        st.rerun()
    if state == "rejected":
        st.markdown("**Request không được gửi.**")
    elif state == "approved":
        st.caption("Đã gửi qua Gateway." if not READONLY else "Đang xem bản ghi đã lưu. Không gọi Gateway.")
    st.markdown("</div>", unsafe_allow_html=True)

    result = st.session_state.get("probe_result")
    st.markdown('<div class="filtered-card">', unsafe_allow_html=True)
    section_intro("Phản hồi đã lọc", "Chỉ hiện bản đã che và đã cách ly", "Không có nút xem dữ liệu gốc.")
    if state == "rejected" and not result:
        st.caption("Chưa có phản hồi vì request không được gửi.")
    elif not result:
        st.caption("Duyệt phép thử để xem phản hồi.")
    else:
        coach(5, "Bước 5 — đây là kết quả đã lọc. Bấm Xem đánh giá khi đã đọc xong.")
        if result.get("redacted"):
            st.markdown('<span class="badge badge-success">Đã che dữ liệu nhạy cảm</span>', unsafe_allow_html=True)
        if result.get("injection"):
            st.markdown('<span class="badge badge-warning">Phát hiện chỉ dẫn lạ — đã cách ly</span>', unsafe_allow_html=True)
        verdict = scan_injection(result.get("body") or "")
        st.code(result.get("body") or "", language=None)
        with st.expander("Chi tiết kỹ thuật"):
            st.write(f"Nguồn: {result.get('source')} · status: {result.get('status')} · route: {result.get('route')}")
            if result.get("patterns") or verdict.patterns:
                st.caption("Patterns: " + ", ".join(result.get("patterns") or verdict.patterns))
            st.caption("API key và secret không được ghi ra UI.")
        if st.button("Xem đánh giá", type="primary", width="stretch"):
            if _guided_active():
                set_guided_step(6)
            st.switch_page(evaluation_page)
    st.markdown("</div>", unsafe_allow_html=True)


def evaluation_page() -> None:
    page_intro(
        "Đánh giá độ chính xác",
        "So câu trả lời của Agent với đáp án nhóm tự viết",
        "Ma trận dưới đây dùng số liệu đã có trong artifact. Bộ 5–10 case Week 6 sẽ thay số này khi có expected answers.",
    )
    journey_strip({6} if not _guided_active() else None)
    coach(6, "Bước 6 — xem đúng–sai, rồi mở Chạy & số liệu hoặc tải báo cáo.")
    metrics_path = WEEK3 / "evaluation/agent-metrics.json"
    metrics = json.loads(metrics_path.read_text(encoding="utf-8")) if metrics_path.exists() else {}
    real = metrics.get("real", {})
    fake = metrics.get("fake", {})
    tp = int(real.get("successful") or fake.get("successful") or 0)
    fn = int(real.get("failed") or fake.get("failed") or 0)
    fp = 0
    tn = 0
    total = max(tp + tn + fp + fn, 1)
    cells = st.columns(2)
    with cells[0]:
        st.markdown(f'<div class="matrix-cell"><div class="n">{tp}</div><div class="l">True positive — Agent đúng khi có lỗ hổng</div></div>', unsafe_allow_html=True)
        st.markdown(f'<div class="matrix-cell"><div class="n">{fn}</div><div class="l">False negative — Agent bỏ sót</div></div>', unsafe_allow_html=True)
    with cells[1]:
        st.markdown(f'<div class="matrix-cell"><div class="n">{fp}</div><div class="l">False positive — Agent báo nhầm</div></div>', unsafe_allow_html=True)
        st.markdown(f'<div class="matrix-cell"><div class="n">{tn}</div><div class="l">True negative — Agent đúng khi không có lỗ hổng</div></div>', unsafe_allow_html=True)
    kpis = st.columns(3)
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    accuracy = (tp + tn) / total
    kpis[0].metric("Precision", f"{precision:.0%}")
    kpis[1].metric("Recall", f"{recall:.0%}")
    kpis[2].metric("Accuracy", f"{accuracy:.0%}")
    st.caption("Đây là số từ smoke/fake run hiện có, chưa phải bộ đánh giá 5–10 case có expected answers.")
    if st.button("Xem số liệu vận hành", type="primary"):
        st.switch_page(metrics_page)


def metrics_page() -> None:
    page_intro(
        "Chạy và số liệu",
        "Thời gian, request, duyệt và lỗi của các bước đã chạy",
        "Các số dưới đây lấy từ artifact đã redact. Public mode không gọi OpenCode hay Gateway.",
    )
    journey_strip({6} if not _guided_active() else None)
    week5 = json.loads((WEEK5 / "metrics.json").read_text(encoding="utf-8")) if (WEEK5 / "metrics.json").exists() else {}
    approval = week5.get("approval", {})
    redaction = week5.get("redaction", {})
    injection = week5.get("injection", {})
    tiles = st.columns(5)
    tiles[0].metric("Request đã ghi", approval.get("total", 0))
    tiles[1].metric("Duyệt", approval.get("approve", 0))
    tiles[2].metric("Từ chối", approval.get("reject", 0))
    tiles[3].metric("Đã che", redaction.get("total_masked", 0))
    tiles[4].metric("Injection flagged", 1 if injection.get("untrusted_flagged") else 0)
    if week5:
        with st.expander("Chi tiết kỹ thuật"):
            st.json(redact_obj(week5))
    run = run_choice()
    artifact = load_ready_artifact(run)
    reports = artifact.get("reports", []) if artifact.get("state") == "ready" else []
    if reports:
        st.download_button(
            "Tải báo cáo JSONL",
            export_reports_jsonl(reports),
            "sentinel-reports.jsonl",
            "application/x-ndjson",
            type="primary",
        )
        if _guided_active():
            st.caption("Demo đã đủ 6 bước. Bạn có thể thoát demo hoặc xem lại từng trang.")


findings_page = st.Page(analysis_workspace, title="Lỗ hổng & bằng chứng", icon=":material/bug_report:")
agent_page = st.Page(agent_workspace, title="Phân tích của Agent", icon=":material/psychology:")
knowledge_page = st.Page(knowledge_base_page, title="Tra cứu tri thức", icon=":material/menu_book:")
verify_page = st.Page(verify_page, title="Kiểm chứng an toàn", icon=":material/verified_user:")
evaluation_page = st.Page(evaluation_page, title="Đánh giá độ chính xác", icon=":material/analytics:")
metrics_page = st.Page(metrics_page, title="Chạy & số liệu", icon=":material/monitoring:")
reports_nav_page = st.Page(reports_page, title="Báo cáo", icon=":material/description:")
data_page = st.Page(data_and_evaluation, title="Dữ liệu & kiểm định", icon=":material/fact_check:")
dashboard_page = st.Page(dashboard, title="Tổng quan", icon=":material/home:", default=True)

with st.sidebar:
    st.markdown('<div class="sidebar-brand">Project Sentinel</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="sidebar-copy">Security Analysis Agent cho 100 OWASP BenchmarkJava test case.</div>',
        unsafe_allow_html=True,
    )
    if st.button("Chạy demo có hướng dẫn", type="primary", width="stretch"):
        sample = next((group for group in groups if group["expected_cwe"] == "CWE-89"), groups[0] if groups else None)
        if sample:
            st.session_state["selected_group_id"] = sample["analysis_group_id"]
        start_guided_demo()
        st.switch_page(findings_page)

navigation = st.navigation(
    {
        "PHÂN TÍCH": [dashboard_page, findings_page, knowledge_page, agent_page],
        "KIỂM CHỨNG": [verify_page],
        "KẾT QUẢ": [evaluation_page, metrics_page, reports_nav_page, data_page],
    }
)

with st.sidebar:
    mode_text = "Public · dùng artifact có sẵn" if READONLY else "Local · có thể gọi OpenCode"
    st.markdown(f'<div class="sidebar-status">● {mode_text}</div>', unsafe_allow_html=True)

navigation.run()
