from __future__ import annotations

import json
import sqlite3
import sys
from datetime import UTC, datetime
from pathlib import Path

import streamlit as st

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from sentinel_benchmark.agent_reports import (  # noqa: E402
    REPORT_STATUSES,
    generate_report,
    reports_to_jsonl,
    validate_report,
)
from sentinel_benchmark.indexer import build  # noqa: E402
from sentinel_benchmark.workspace import (  # noqa: E402
    filter_groups,
    load_analysis_groups,
    retrieval_evaluation,
    retrieve_knowledge,
)

DB = REPO_ROOT / "datasets" / "processed" / "sentinel.db"
MANIFEST = REPO_ROOT / "configs" / "sources.json"
KNOWLEDGE = REPO_ROOT / "datasets" / "knowledge" / "security-topics.jsonl"
METRICS = REPO_ROOT / "artifacts" / "week-1" / "llm-20260728" / "results.json"
SEMGREP_METRICS = REPO_ROOT / "artifacts" / "week-1" / "semgrep-20260806" / "results.json"
PREDICTIONS = REPO_ROOT / "artifacts" / "week-1" / "semgrep-20260806" / "variants" / "security-audit" / "predictions.jsonl"
PAGES = ["Overview", "Findings Explorer", "Agent Analysis", "Reports", "Evaluation"]

st.set_page_config(page_title="Sentinel Security Analysis Workspace", page_icon="🛡️", layout="wide")
st.markdown(
    """
    <style>
    .block-container {padding-top: 1.4rem; padding-bottom: 3rem; max-width: 1500px;}
    [data-testid="stMetric"] {background: #f8fafc; border: 1px solid #e2e8f0; padding: .8rem; border-radius: .75rem;}
    .pipeline-step {border: 1px solid #cbd5e1; background: #f8fafc; border-radius: .75rem; padding: .9rem .65rem; text-align: center; min-height: 76px;}
    .eyebrow {font-size: .78rem; font-weight: 700; color: #2563eb; letter-spacing: .08em; text-transform: uppercase;}
    .muted {color: #64748b; font-size: .9rem;}
    .severity-critical {color:#991b1b;font-weight:700}.severity-high {color:#b91c1c;font-weight:700}
    .severity-medium {color:#b45309;font-weight:700}.severity-low {color:#1d4ed8;font-weight:700}.severity-info {color:#475569;font-weight:700}
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_resource
def ensure_index() -> dict[str, int]:
    DB.parent.mkdir(parents=True, exist_ok=True)
    return build(MANIFEST, DB, KNOWLEDGE)


@st.cache_data
def index_stats() -> dict:
    with sqlite3.connect(DB) as conn:
        return {
            "observations": conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0],
            "knowledge": conn.execute("SELECT COUNT(*) FROM knowledge").fetchone()[0],
            "tools": conn.execute("SELECT tool, COUNT(*) FROM findings GROUP BY tool ORDER BY COUNT(*) DESC").fetchall(),
            "severities": conn.execute("SELECT severity, COUNT(*) FROM findings GROUP BY severity ORDER BY COUNT(*) DESC").fetchall(),
        }


@st.cache_data
def analysis_groups() -> list[dict]:
    return load_analysis_groups(DB, PREDICTIONS)


@st.cache_data
def scanner_metrics() -> list[dict]:
    llm = json.loads(METRICS.read_text(encoding="utf-8"))
    semgrep = json.loads(SEMGREP_METRICS.read_text(encoding="utf-8"))
    rows = []
    for label, values in (
        ("OpenCodeReview", llm["scanners"]["open_code_review"]),
        ("DeepSec/Pi", llm["scanners"]["deepsec"]),
    ):
        overall = values["metrics"]["overall"]
        rows.append({"Scanner": label, **{key: overall[key] for key in ("TP", "FP", "FN", "TN", "precision", "recall", "f1")}})
    overall = semgrep["variants"]["security-audit"]["metrics"]["metrics"]["overall"]
    rows.append({"Scanner": "Semgrep security-audit", **{key: overall[key] for key in ("TP", "FP", "FN", "TN", "precision", "recall", "f1")}})
    return rows


def initialize_state() -> None:
    st.session_state.setdefault("selected_group", None)
    st.session_state.setdefault("batch", [])
    st.session_state.setdefault("agent_reports", [])
    st.session_state.setdefault("agent_run_id", f"UI-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}")


def group_by_id(group_id: str | None) -> dict | None:
    return next((group for group in analysis_groups() if group["canonical_id"] == group_id), None)


def latest_report(group_id: str) -> dict | None:
    return next((report for report in reversed(st.session_state.agent_reports) if report["canonical_id"] == group_id), None)


def analyze(group: dict, regenerate: bool = False) -> dict:
    kb = retrieve_knowledge(DB, group, 3)
    previous = latest_report(group["canonical_id"])
    report = generate_report(
        group,
        kb,
        run_id=st.session_state.agent_run_id,
        regenerate_from=previous["report_id"] if regenerate and previous else None,
    )
    st.session_state.agent_reports.append(report)
    st.session_state.selected_group = group["canonical_id"]
    return report


def update_status(report_id: str, status: str) -> None:
    for report in st.session_state.agent_reports:
        if report["report_id"] == report_id:
            report["review_status"] = status
            report["reviewed_at"] = datetime.now(UTC).isoformat().replace("+00:00", "Z")
            return


def severity_badge(severity: str) -> str:
    value = severity.lower()
    return f'<span class="severity-{value}">{value.upper()}</span>'


def group_label(group: dict) -> str:
    return f"{group['cwe']} · {group['test_id']} · {len(group['tools'])} scanner(s)"


def render_report_card(report: dict, *, controls: bool = True) -> None:
    errors = validate_report(report)
    with st.container(border=True):
        left, right = st.columns([5, 1])
        left.markdown(f"### {report['title']} · `{report['cwe']}`")
        right.markdown(severity_badge(report["severity"]), unsafe_allow_html=True)
        v1, v2, v3 = st.columns(3)
        v1.metric("Verdict", report["verdict"])
        v2.metric("Confidence", f"{report['confidence']:.2f}")
        v3.metric("Review", report["review_status"])
        if errors:
            st.error("JSON contract chưa hợp lệ: " + ", ".join(errors))
        st.markdown("**Explanation**")
        st.write(report["explanation"])
        st.markdown("**Evidence**")
        for item in report["evidence"][:6]:
            st.caption(f"{item['location']} · {item['tool']} · {item['observation_id']}")
            if item["excerpt"]:
                st.code(item["excerpt"], language=None)
        if len(report["evidence"]) > 6:
            st.caption(f"Còn {len(report['evidence']) - 6} observation(s) trong JSON report.")
        c1, c2 = st.columns(2)
        c1.markdown("**Verification**")
        c1.write(report["verification"])
        c2.markdown("**Remediation**")
        c2.write(report["remediation"])
        st.markdown("**Sources**")
        st.code(
            "KB: " + (", ".join(report["sources"]["kb_document_ids"]) or "none") + "\n"
            "Observations: " + ", ".join(report["sources"]["observation_ids"]),
            language=None,
        )
        st.caption(
            f"Model: {report['model']} · Prompt: {report['prompt_version']} · "
            f"Run: {report['run_id']} · Created: {report['created_at']}"
        )
        if controls:
            a, b, c, d = st.columns(4)
            if a.button("Approve", key=f"approve-{report['report_id']}", width="stretch"):
                update_status(report["report_id"], "Approved")
                st.rerun()
            if b.button("Needs review", key=f"review-{report['report_id']}", width="stretch"):
                update_status(report["report_id"], "Needs review")
                st.rerun()
            if c.button("Reject", key=f"reject-{report['report_id']}", width="stretch"):
                update_status(report["report_id"], "Rejected")
                st.rerun()
            d.download_button(
                "Export JSONL",
                reports_to_jsonl([report]),
                file_name=f"{report['report_id']}.jsonl",
                mime="application/x-ndjson",
                key=f"export-{report['report_id']}",
                width="stretch",
            )


try:
    with st.spinner("Preparing the analysis workspace..."):
        ensure_index()
except Exception as exc:
    st.error("Không thể build index từ artifacts. Kiểm tra deployment logs và source manifest.")
    st.exception(exc)
    st.stop()

initialize_state()
groups = analysis_groups()
stats = index_stats()

st.sidebar.markdown("## 🛡️ Sentinel")
st.sidebar.caption("Security Analysis Workspace")
page = st.sidebar.radio("Workspace", PAGES, label_visibility="collapsed")
st.sidebar.divider()
st.sidebar.metric("Selected batch", len(st.session_state.batch))
st.sidebar.metric("Agent reports", len(st.session_state.agent_reports))
st.sidebar.caption("Week 2 built the knowledge layer. Week 3 turns it into grounded, reviewable security reports.")

if page == "Overview":
    st.markdown('<div class="eyebrow">Week 1 → Week 3</div>', unsafe_allow_html=True)
    st.title("Security Analysis Workspace")
    st.write("Từ scanner output đến báo cáo bảo mật có evidence, knowledge source và bước human review rõ ràng.")

    labels = ["Scanner outputs", "Normalize", "Deduplicate", "Retrieve KB", "Agent", "JSONL report"]
    pipeline = st.columns(len(labels))
    for column, label in zip(pipeline, labels):
        column.markdown(f'<div class="pipeline-step"><strong>{label}</strong></div>', unsafe_allow_html=True)

    st.subheader("Dataset snapshot")
    m1, m2, m3 = st.columns(3)
    m1.metric("Benchmark test cases", "100")
    m2.metric("Benchmark observations", f"{stats['observations']:,}")
    m3.metric("Canonical analysis groups", f"{len(groups):,}")
    m4, m5, m6 = st.columns(3)
    m4.metric("WebGoat observations", "121", help="Historical Week 2 snapshot; not part of the active BenchmarkJava index.")
    m5.metric("KB documents", stats["knowledge"])
    m6.metric("Agent reports this session", len(st.session_state.agent_reports))

    st.info("WebGoat được hiển thị để kể lại lịch sử Week 2, nhưng không được đưa trở lại active dataset, Findings Explorer hoặc Agent analysis của repo BenchmarkJava này.")
    st.markdown("### Cách demo trong 3 phút")
    st.markdown(
        "1. Mở **Findings Explorer** và chọn một canonical group.\n"
        "2. Xem observations từ nhiều scanner và thêm group vào batch.\n"
        "3. Sang **Agent Analysis** để xem KB được retrieve và tạo report có cấu trúc.\n"
        "4. Sang **Reports** để review và tải JSONL.\n"
        "5. Dùng **Evaluation** để phân biệt scanner, retrieval và Agent evaluation."
    )

elif page == "Findings Explorer":
    st.markdown('<div class="eyebrow">Week 2 knowledge layer</div>', unsafe_allow_html=True)
    st.title("Findings Explorer")
    st.caption("Mặc định hiển thị theo canonical analysis group; observations gốc luôn được giữ để truy vết.")
    f1, f2, f3, f4 = st.columns([2.3, 1, 1.4, 1.2])
    query = f1.text_input("Search", placeholder="CWE-89, SQL Injection, BenchmarkTest00008...")
    severity = f2.selectbox("Severity", ["all", "critical", "high", "medium", "low", "info"])
    tools = sorted({tool for group in groups for tool in group["tools"]})
    tool = f3.selectbox("Detected by", ["all", *tools])
    truth = f4.selectbox("Ground truth", ["all", "vulnerable", "not vulnerable"])
    visible = filter_groups(groups, query, severity, tool, truth)
    st.write(f"**{len(visible)} group(s)** · {sum(group['observation_count'] for group in visible)} observation(s)")

    for group in visible[:50]:
        with st.container(border=True):
            header, badge = st.columns([5, 1])
            header.markdown(f"### {group['cwe']} · {group['title']}")
            badge.markdown(severity_badge(group["severity"]), unsafe_allow_html=True)
            st.code(group["locations"][0], language=None)
            st.caption(
                f"Detected by: {', '.join(group['tools'])} · "
                f"Ground truth: {'Vulnerable' if group['ground_truth'] else 'Not vulnerable'} · "
                f"Observations: {group['observation_count']}"
            )
            a, b, c = st.columns(3)
            if a.button("View evidence", key=f"evidence-{group['canonical_id']}", width="stretch"):
                st.session_state.selected_group = group["canonical_id"]
            if b.button("Analyze with Agent", key=f"analyze-{group['canonical_id']}", type="primary", width="stretch"):
                analyze(group)
                st.success("Report đã được tạo. Mở Agent Analysis hoặc Reports để review.")
            in_batch = group["canonical_id"] in st.session_state.batch
            if c.button("Remove from batch" if in_batch else "Add to batch", key=f"batch-{group['canonical_id']}", width="stretch"):
                if in_batch:
                    st.session_state.batch.remove(group["canonical_id"])
                else:
                    st.session_state.batch.append(group["canonical_id"])
                st.rerun()
            if st.session_state.selected_group == group["canonical_id"]:
                with st.expander("Evidence and grouped observations", expanded=True):
                    for row in group["observations"]:
                        st.markdown(f"**{row['tool']}** · `{row['observation_id']}`")
                        st.caption(f"{Path(str(row['file_or_url'])).name}:{row.get('line_start') or '?'}")
                        st.code(str(row.get("evidence") or row.get("description") or "No evidence")[:1600], language=None)
    if len(visible) > 50:
        st.info("Đang hiển thị 50 groups đầu tiên. Hãy dùng search/filter để thu hẹp kết quả.")

elif page == "Agent Analysis":
    st.markdown('<div class="eyebrow">Week 3 main workspace</div>', unsafe_allow_html=True)
    st.title("Agent Analysis")
    st.warning("MVP hiện dùng `grounded-template-v1` để kiểm thử contract, evidence flow, review và JSONL export. Chưa có external LLM call; khi tích hợp model, contract và UI này được giữ nguyên.")

    options = {group_label(group): group["canonical_id"] for group in groups}
    labels = list(options)
    selected_index = 0
    if st.session_state.selected_group in options.values():
        selected_index = list(options.values()).index(st.session_state.selected_group)
    selected_label = st.selectbox("Canonical group", labels, index=selected_index)
    st.session_state.selected_group = options[selected_label]
    selected = group_by_id(st.session_state.selected_group)
    kb_hits = retrieve_knowledge(DB, selected, 3) if selected else []

    a, b, c = st.columns([1.05, 1.05, 1.25])
    with a:
        st.subheader("Finding context")
        if selected:
            st.markdown(f"**{selected['cwe']} · {selected['title']}**")
            st.code("\n".join(selected["locations"][:6]), language=None)
            st.caption(f"Ground truth: {'Vulnerable' if selected['ground_truth'] else 'Not vulnerable'}")
            st.write("Detected by: " + ", ".join(selected["tools"]))
            st.write(f"Grouped observations: {selected['observation_count']}")
            for row in selected["observations"][:4]:
                with st.expander(f"{row['tool']} · {row['observation_id']}"):
                    st.code(str(row.get("evidence") or row.get("description") or "")[:1400], language=None)
    with b:
        st.subheader("Retrieved knowledge")
        if not kb_hits:
            st.info("Không tìm thấy KB document phù hợp.")
        for doc in kb_hits:
            with st.container(border=True):
                st.markdown(f"**{doc['title']}** · `{doc['document_id']}`")
                st.write(doc["content"])
                st.caption(f"{doc.get('source') or 'No source'} · retrieval score {doc.get('rank', 0):.3f}")
    with c:
        st.subheader("Agent report")
        report = latest_report(selected["canonical_id"]) if selected else None
        if report:
            render_report_card(report, controls=False)
        else:
            st.info("Chọn Analyze selected group để tạo structured report.")

    x1, x2, x3, x4 = st.columns(4)
    if x1.button("Analyze selected group", type="primary", width="stretch", disabled=selected is None):
        analyze(selected)
        st.rerun()
    if x2.button("Analyze batch", width="stretch", disabled=not st.session_state.batch):
        for group_id in list(st.session_state.batch):
            group = group_by_id(group_id)
            if group:
                analyze(group)
        st.rerun()
    if x3.button("Regenerate", width="stretch", disabled=selected is None or latest_report(selected["canonical_id"]) is None):
        analyze(selected, regenerate=True)
        st.rerun()
    current = latest_report(selected["canonical_id"]) if selected else None
    x4.download_button(
        "Export JSONL",
        reports_to_jsonl([current]) if current else "",
        file_name=f"{current['report_id']}.jsonl" if current else "agent-report.jsonl",
        mime="application/x-ndjson",
        disabled=current is None,
        width="stretch",
    )

elif page == "Reports":
    st.markdown('<div class="eyebrow">Human review queue</div>', unsafe_allow_html=True)
    st.title("Reports")
    reports = st.session_state.agent_reports
    if not reports:
        st.info("Chưa có Agent report. Tạo report từ Findings Explorer hoặc Agent Analysis.")
    else:
        r1, r2, r3, r4 = st.columns(4)
        severity = r1.selectbox("Severity", ["all", "critical", "high", "medium", "low", "info"], key="report-severity")
        cwes = sorted({report["cwe"] for report in reports})
        cwe = r2.selectbox("CWE", ["all", *cwes])
        status = r3.selectbox("Approval status", ["all", *REPORT_STATUSES])
        minimum = r4.slider("Min confidence", 0.0, 1.0, 0.0, 0.05)
        visible_reports = [
            report for report in reports
            if (severity == "all" or report["severity"] == severity)
            and (cwe == "all" or report["cwe"] == cwe)
            and (status == "all" or report["review_status"] == status)
            and report["confidence"] >= minimum
        ]
        valid = sum(not validate_report(report) for report in visible_reports)
        h1, h2, h3 = st.columns(3)
        h1.metric("Visible reports", len(visible_reports))
        h2.metric("JSON valid", f"{valid}/{len(visible_reports)}")
        h3.download_button(
            "Download all JSONL",
            reports_to_jsonl(visible_reports) if visible_reports else "",
            file_name="sentinel-agent-reports.jsonl",
            mime="application/x-ndjson",
            disabled=not visible_reports,
            width="stretch",
        )
        for report in reversed(visible_reports):
            render_report_card(report)
        with st.expander("Validated JSON preview"):
            st.json(visible_reports)

elif page == "Evaluation":
    st.markdown('<div class="eyebrow">Three evaluation layers</div>', unsafe_allow_html=True)
    st.title("Evaluation")
    scanner_tab, retrieval_tab, agent_tab = st.tabs(["Scanner", "Retrieval", "Agent"])
    with scanner_tab:
        st.subheader("Scanner evaluation against OWASP ground truth")
        st.dataframe(
            scanner_metrics(),
            hide_index=True,
            width="stretch",
            column_config={
                "precision": st.column_config.NumberColumn("Precision", format="%.2f"),
                "recall": st.column_config.NumberColumn("Recall", format="%.2f"),
                "f1": st.column_config.NumberColumn("F1", format="%.2f"),
            },
        )
        st.info("Ground truth được join sau scan và chỉ dùng để tính TP/FP/FN/TN, precision, recall và F1.")
    with retrieval_tab:
        result = retrieval_evaluation(DB, groups, 3)
        e1, e2, e3 = st.columns(3)
        e1.metric("Evaluated groups", result["evaluated_groups"])
        e2.metric("Top-K", result["top_k"])
        e3.metric("CWE hit rate", f"{(result['hit_rate'] or 0):.1%}")
        st.caption("Một retrieval hit được tính khi Top-K có KB document mang tag CWE mong đợi. Đây là phép đo retrieval, không phải đánh giá chất lượng câu trả lời Agent.")
    with agent_tab:
        reports = st.session_state.agent_reports
        valid = sum(not validate_report(report) for report in reports)
        reviewed = sum(report["review_status"] != "Needs review" for report in reports)
        a1, a2, a3 = st.columns(3)
        a1.metric("Reports", len(reports))
        a2.metric("JSON contract valid", f"{valid}/{len(reports)}" if reports else "0/0")
        a3.metric("Human-reviewed", f"{reviewed}/{len(reports)}" if reports else "0/0")
        st.warning("OWASP ground truth có thể đánh giá CWE/verdict trên Benchmark, nhưng không tự đánh giá được chất lượng explanation hoặc remediation. Hai phần này cần rubric riêng hoặc human review.")
