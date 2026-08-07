from __future__ import annotations

import json
import os
import re
import subprocess
import sqlite3
import sys
from datetime import UTC, datetime
from pathlib import Path

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
from sentinel_benchmark.indexer import build
from sentinel_benchmark.workspace import (
    available_runs, filter_groups, load_analysis_groups, load_observations,
    load_run_artifact, load_week2_groups, search_knowledge,
)

DB = ROOT / "datasets/processed/sentinel.db"
MANIFEST = ROOT / "configs/sources.json"
KB = ROOT / "datasets/knowledge/security-topics.jsonl"
PREDICTIONS = ROOT / "artifacts/week-1/semgrep-20260806/variants/security-audit/predictions.jsonl"
WEEK3 = ROOT / "artifacts/week-3"
READONLY = os.getenv("SENTINEL_UI_READONLY", "1") != "0"

st.set_page_config(page_title="Sentinel Security Analysis Workspace", page_icon="🛡️", layout="wide")
st.markdown("""<style>.block-container{max-width:1500px;padding-top:1.25rem}.badge{display:inline-block;padding:.15rem .55rem;border-radius:1rem;background:#d8ebe7;color:#0f5d57;font-weight:700}.mode{display:inline-block;padding:.18rem .6rem;border:1px solid #9bbdb7;border-radius:1rem;color:#315f59;font-size:.82rem}.guard{color:#0f766e;font-weight:700}.muted{color:#55706c}.pipeline{padding:.8rem;border:1px solid #b8cbc7;border-radius:.65rem;text-align:center;background:#fff}.context{padding:1rem 1.1rem;border:1px solid #c8d9d5;border-left:4px solid #0f766e;border-radius:.5rem;background:#fff;margin:.4rem 0 1rem}</style>""", unsafe_allow_html=True)


@st.cache_resource
def prepare() -> dict:
    DB.parent.mkdir(parents=True, exist_ok=True)
    return build(MANIFEST, DB, KB)


@st.cache_data
def data():
    return load_observations(DB), load_week2_groups(DB), load_analysis_groups(DB, PREDICTIONS)


def selected_run() -> dict | None:
    runs = available_runs(WEEK3)
    if not runs: return None
    preferred = st.session_state.get("preferred_run_id")
    default = next((row for row in runs if row.get("run_id") == preferred), None) or next((row for row in runs if row.get("provider") == "nine_router" and row.get("status") == "successful"), None) or next((row for row in runs if row.get("provider") == "fake" and row.get("status") == "successful"), runs[0])
    labels = {f"{row['run_id']} · {row['provider']} · {row['status']}": row for row in runs}
    label_list = list(labels)
    index = list(labels.values()).index(default)
    return labels[st.selectbox("Run artifact", label_list, index=index)]


def nine_router_provider() -> NineRouterProvider:
    return NineRouterProvider(
        base_url=os.getenv("NINE_ROUTER_BASE_URL", "http://127.0.0.1:20128/v1"),
        model=os.getenv("NINE_ROUTER_MODEL", ""),
        api_key=os.getenv("NINE_ROUTER_API_KEY", ""),
        timeout=float(os.getenv("NINE_ROUTER_TIMEOUT_SECONDS", "60")),
        max_retries=int(os.getenv("NINE_ROUTER_MAX_RETRIES", "1")),
    )


def report_card(report: dict) -> None:
    name = report.get("vulnerability_name") or cwe_name(report["expected_cwe"], report.get("category", ""))
    with st.expander(f"{report['expected_cwe']} — {name} · {report['severity_assessment'].upper()} · {report['benchmark_test_id']}"):
        st.caption(f"{report['analysis_group_id']} · {report['grouping_mode']} · {report['provider']} / {report['model']}")
        st.write(report["explanation"])
        left, right = st.columns(2)
        left.markdown("**Verification**"); left.write(report["verification_steps"])
        right.markdown("**Remediation**"); right.write(report["remediation"])
        if report["limitations"]:
            with st.expander("Phạm vi và hạn chế của phân tích"):
                st.write(report["limitations"])
        st.markdown("**Evidence**")
        for evidence in report["evidence"]:
            st.caption(f"{evidence['tool']} · {evidence['observation_id']} · {evidence['file_or_url']}:{evidence.get('line_start') or '?'}")
        guard_text = "Evidence Guard: PASS" if report["guard"]["passed"] else "Evidence Guard: FAIL"
        st.markdown(f'<span class="guard">{guard_text}</span>', unsafe_allow_html=True)
        st.caption(f"Confidence {report['analysis_confidence']:.2f} · Prompt {report['prompt_sha256']} · KB {', '.join(report['sources']['kb_document_ids']) or 'none'}")


try:
    prepare(); observations, week2_groups, groups = data()
except Exception as exc:
    st.error("Không thể tải dữ liệu Security Analysis Workspace."); st.exception(exc); st.stop()


def overview() -> None:
    st.title("Week 3 · Security Analysis Agent")
    st.write("Agent đọc kết quả của ba scanner, hợp nhất cảnh báo liên quan, bổ sung tri thức bảo mật và tạo báo cáo JSONL có bằng chứng truy vết.")
    baseline = json.loads((WEEK3 / "baseline.json").read_text(encoding="utf-8")) if (WEEK3 / "baseline.json").exists() else {}
    cols = st.columns(5)
    for col, label, value in zip(cols, ["Benchmark cases", "Observations", "Week 2 canonical", "Week 3 analysis", "KB documents"], [100, len(observations), len(week2_groups), len(groups), 12]): col.metric(label, value)
    st.subheader("Luồng phân tích")
    pipeline = st.columns(6)
    for col, label in zip(pipeline, ["Scanner outputs", "Normalize", "Group alerts", "Retrieve KB", "LLM analysis", "JSONL report"]): col.markdown(f'<div class="pipeline">{label}</div>', unsafe_allow_html=True)
    st.subheader("Nguồn cảnh báo")
    scanner_columns = st.columns(3)
    for column, (tool, count) in zip(scanner_columns, baseline.get("scanner_counts", {}).items()):
        column.metric(tool, count)
    metrics_path = WEEK3 / "evaluation/agent-metrics.json"
    if metrics_path.exists():
        metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
        st.subheader("Kết quả chạy Agent")
        result_columns = st.columns(4)
        result_columns[0].metric("FakeProvider", f"{metrics['fake']['successful']}/{metrics['fake']['requested']}")
        result_columns[1].metric("9Router smoke test", f"{metrics['real']['successful']}/{metrics['real']['requested']}")
        result_columns[2].metric("Guard pass", f"{metrics['real']['guard_pass_rate']:.0%}")
        result_columns[3].metric("Evidence preserved", f"{metrics['real']['evidence_reference_rate']:.0%}")


def findings() -> None:
    st.title("Findings Explorer")
    observations_tab, canonical_tab, analysis_tab, kb_tab = st.tabs(["Observations", "Week 2 canonical groups", "Week 3 analysis groups", "Knowledge Base"])
    with observations_tab:
        st.caption("Mỗi dòng là một cảnh báo gốc từ scanner, giữ nguyên provenance để truy vết.")
        st.dataframe(observations, hide_index=True, width="stretch")
    with canonical_tab:
        st.caption("Nhóm canonical của Week 2 dùng để giảm trùng lặp ở tầng dữ liệu.")
        st.write(f"{len(week2_groups)} canonical groups"); st.dataframe([{k: row[k] for k in ("canonical_id", "observation_count", "tools")} for row in week2_groups], hide_index=True, width="stretch")
    with analysis_tab:
        q = st.text_input("Search analysis groups", placeholder="CWE-89 or BenchmarkTest00008")
        tool = st.selectbox("Scanner", ["all", *sorted({tool for group in groups for tool in group["source_tools"]})])
        visible = filter_groups(groups, q, tool=tool)
        st.write(f"{len(visible)} analysis groups")
        for group in visible[:50]:
            with st.expander(f"{group['expected_cwe']} — {cwe_name(group['expected_cwe'], group['category'])} · {group['benchmark_test_id']}"):
                st.markdown('<span class="badge">benchmark_assisted</span>', unsafe_allow_html=True)
                st.write("Scanners: " + ", ".join(group["source_tools"])); st.write("Grouping: " + ", ".join(group["grouping_reason"]))
                for item in group["evidence_items"]: st.caption(f"{item['tool']} · {item['observation_id']} · {item['file_or_url']}:{item.get('line_start') or '?'}")
    with kb_tab:
        query = st.text_input("Keyword search", value="CWE-89")
        top_k = st.slider("Top K", 1, 20, 5)
        st.caption("Tìm kiếm keyword trên 12 tài liệu hướng dẫn bảo mật của Week 2.")
        for row in search_knowledge(DB, query, top_k):
            with st.expander(f"{row['title']} · {row['document_id']} · {row.get('rank', 0):.3f}"):
                st.write(row["content"]); st.caption(row.get("source", ""))


def agent_analysis() -> None:
    st.title("Agent Analysis")
    st.write("Chọn một nhóm lỗ hổng để xem bằng chứng, tạo báo cáo và hỏi đáp với Sentinel.")
    mode_text = "Public · baked artifacts" if READONLY else "Local · 9Router enabled"
    st.markdown(f'<span class="mode">{mode_text}</span>', unsafe_allow_html=True)
    run = selected_run()
    artifact = load_run_artifact(Path(run["run_dir"])) if run else {"state": "empty", "reports": []}
    if artifact.get("state") == "corrupt": st.error("Corrupt artifact: " + ", ".join(artifact["checksum_failures"])); return
    group_labels = {f"{group['expected_cwe']} — {cwe_name(group['expected_cwe'], group['category'])} · {group['benchmark_test_id']}": group for group in groups}
    selected_label = st.selectbox("Vulnerability analysis group", list(group_labels))
    selected_group = group_labels[selected_label]
    selected_name = cwe_name(selected_group["expected_cwe"], selected_group["category"])
    st.markdown(f'<div class="context"><strong>{selected_group["expected_cwe"]} — {selected_name}</strong><br>{selected_group["benchmark_test_id"]} · {len(selected_group["observation_ids"])} scanner observations · {len(selected_group["source_tools"])} scanner(s)</div>', unsafe_allow_html=True)
    matching_reports = [report for report in artifact.get("reports", []) if report["analysis_group_id"] == selected_group["analysis_group_id"]]
    report = matching_reports[-1] if matching_reports else None

    evidence_tab, report_tab, chat_tab = st.tabs(["Scanner evidence & KB", "Create / view report", "Ask Sentinel"])
    with evidence_tab:
        st.markdown(f"<span class='badge'>{selected_group['grouping_mode']}</span>", unsafe_allow_html=True)
        st.write("Detected by: " + ", ".join(selected_group["source_tools"]))
        for item in selected_group["evidence_items"]:
            with st.expander(f"{item['tool']} · {item['observation_id']}"):
                st.caption(f"{item['file_or_url']}:{item.get('line_start') or '?'}")
                st.code(item.get("excerpt") or "No scanner excerpt", language=None)
        st.markdown("#### Retrieved knowledge")
        for row in search_knowledge(DB, f"{selected_group['expected_cwe']} {selected_group['category']}", 3):
            st.markdown(f"**{row['title']}** · `{row['document_id']}`")
            st.write(row["content"])

    with report_tab:
        if report:
            report_card(report)
            st.download_button("Export selected report JSONL", export_reports_jsonl([report]), f"{report['report_id']}.jsonl", "application/x-ndjson", width="stretch")
        else:
            st.caption("Chưa có report trong run đang chọn cho analysis group này.")
        if not READONLY:
            provider_name = st.selectbox("Report provider", ["fake", "nine_router"], help="nine_router có thể dùng quota/cost của model đã cấu hình.")
            tag_default = f"ui-{selected_group['benchmark_test_id'].lower()}"
            command = [sys.executable, str(ROOT / "scripts/analyze.py"), "run", "--provider", provider_name, "--group-id", selected_group["analysis_group_id"], "--limit", "1", "--tag", tag_default]
            st.code(" ".join(command), language="powershell")
            confirmed = st.checkbox("Tôi xác nhận group, provider và khả năng phát sinh quota/cost.", key=f"confirm-{selected_group['analysis_group_id']}-{provider_name}")
            if st.button("Generate structured report", type="primary", disabled=not confirmed, width="stretch"):
                with st.spinner("Running one-shot analysis through the canonical CLI..."):
                    completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=300, check=False)
                if completed.returncode:
                    st.error("Analysis failed. Secret/header values are never shown.")
                    st.code(completed.stderr[-2000:], language=None)
                else:
                    st.toast("Report artifact đã được tạo và kiểm tra checksum.", icon="✅")
                    try:
                        created = json.loads(completed.stdout)
                        st.session_state["preferred_run_id"] = Path(created["run_dir"]).name
                    except (json.JSONDecodeError, KeyError):
                        pass
                    st.cache_data.clear(); st.rerun()

    with chat_tab:
        chat_key = f"chat-{selected_group['analysis_group_id']}"
        st.session_state.setdefault(chat_key, [])
        chat_provider = st.selectbox("Answer mode", ["offline_artifact"] if READONLY else ["offline_artifact", "nine_router"], help="Offline mode summarizes only baked evidence/report; nine_router performs a new grounded response.")
        st.caption("Câu trả lời chỉ được trích dẫn observation, tài liệu KB và report đang có của nhóm lỗ hổng.")
        for message in st.session_state[chat_key]:
            with st.chat_message(message["role"]):
                st.write(message["content"])
                if message.get("citations"): st.caption("Sources: " + ", ".join(message["citations"]))
                if message.get("metadata"):
                    source = message["metadata"]
                    fallback = f" · fallback from {source['fallback_from']}" if source.get("fallback_from") else ""
                    st.caption(f"Answer source: {source.get('provider')} / {source.get('model')}{fallback}")
        st.markdown(f"**Câu hỏi gợi ý · {selected_group['expected_cwe']} — {selected_name}**")
        suggest_1, suggest_2, suggest_3 = st.columns(3)
        suggested_question = None
        if suggest_1.button(f"{selected_group['expected_cwe']} là gì?", key=f"summary-{selected_group['analysis_group_id']}", width="stretch"):
            suggested_question = f"Giải thích lỗ hổng {selected_group['expected_cwe']} — {selected_name} trong {selected_group['benchmark_test_id']} bằng ngôn ngữ đơn giản và chỉ ra bằng chứng scanner liên quan."
        if suggest_2.button(f"Kiểm tra {selected_group['expected_cwe']}", key=f"verify-{selected_group['analysis_group_id']}", width="stretch"):
            suggested_question = f"Đưa ra các bước xác minh an toàn lỗ hổng {selected_group['expected_cwe']} — {selected_name} tại {selected_group['benchmark_test_id']} và trích dẫn observation liên quan."
        if suggest_3.button(f"Khắc phục {selected_group['expected_cwe']}", key=f"remediate-{selected_group['analysis_group_id']}", width="stretch"):
            suggested_question = f"Nên khắc phục lỗ hổng {selected_group['expected_cwe']} — {selected_name} tại {selected_group['benchmark_test_id']} như thế nào dựa trên KB và report đã có?"
        question = st.chat_input("Hỏi về cách xác minh, impact, evidence hoặc remediation...", key=f"question-{selected_group['analysis_group_id']}") or suggested_question
        if question:
            st.session_state[chat_key].append({"role": "user", "content": question})
            chat_group = selected_group
            requested = re.search(r"CWE-\d+", question, re.IGNORECASE)
            if requested and requested.group(0).upper() != selected_group["expected_cwe"]:
                requested_cwe = requested.group(0).upper()
                chat_group = next((candidate for candidate in groups if candidate["expected_cwe"] == requested_cwe), selected_group)
            chat_report = next((candidate for candidate in reversed(artifact.get("reports", [])) if candidate["analysis_group_id"] == chat_group["analysis_group_id"]), None)
            knowledge = search_knowledge(DB, f"{chat_group['expected_cwe']} {chat_group['category']}", 3)
            payload = build_chat_payload(question=question, group=AnalysisGroup.model_validate(chat_group), knowledge=knowledge, report=chat_report)
            try:
                active_provider = nine_router_provider() if chat_provider == "nine_router" else None
                answer, metadata = answer_question(provider=active_provider, payload=payload, fallback_on_error=True)
                content = answer.answer
                if answer.verification_steps: content += "\n\nVerification:\n- " + "\n- ".join(answer.verification_steps)
                if answer.remediation: content += "\n\nRemediation:\n- " + "\n- ".join(answer.remediation)
                if answer.limitations: content += "\n\nLimitations:\n- " + "\n- ".join(answer.limitations)
                st.session_state[chat_key].append({"role": "assistant", "content": content, "citations": answer.citations, "metadata": metadata})
                st.rerun()
            except Exception as exc:
                st.error(f"Grounded chat failed: {exc}")
        transcript = json.dumps(st.session_state[chat_key], ensure_ascii=False, indent=2)
        st.download_button("Export chat transcript", transcript, f"{selected_group['analysis_group_id']}-chat.json", "application/json", disabled=not st.session_state[chat_key])


def reports_page() -> None:
    st.title("Reports")
    run = selected_run()
    if not run: st.caption("Chưa có report artifact để hiển thị."); return
    artifact = load_run_artifact(Path(run["run_dir"]))
    if artifact["state"] != "ready": st.error("Checksum mismatch"); return
    reports = artifact["reports"]
    st.download_button("Download JSONL", export_reports_jsonl(reports) if reports else "", "sentinel-week3-reports.jsonl", "application/x-ndjson", disabled=not reports)
    for report in reports: report_card(report)


def evaluation() -> None:
    st.title("Evaluation")
    scanner, grouping, agent, failures = st.tabs(["Scanner metrics", "Grouping integrity", "Agent integrity", "Failure cases"])
    with scanner:
        llm = json.loads((ROOT / "artifacts/week-1/llm-20260728/results.json").read_text(encoding="utf-8")); semgrep = json.loads((ROOT / "artifacts/week-1/semgrep-20260806/results.json").read_text(encoding="utf-8"))
        rows = []
        for name, data_row in [("Alibaba OpenCodeReview", llm["scanners"]["open_code_review"]), ("Vercel DeepSec/Pi", llm["scanners"]["deepsec"])]: rows.append({"Scanner": name, **data_row["metrics"]["overall"]})
        rows.append({"Scanner": "Semgrep security-audit", **semgrep["variants"]["security-audit"]["metrics"]["metrics"]["overall"]})
        st.dataframe(rows, hide_index=True, width="stretch")
    with grouping:
        path = WEEK3 / "evaluation/grouping-metrics.json"; st.json(json.loads(path.read_text(encoding="utf-8")) if path.exists() else {"state": "not generated"})
    with agent:
        path = WEEK3 / "evaluation/agent-metrics.json"; st.json(json.loads(path.read_text(encoding="utf-8")) if path.exists() else {"state": "not generated"})
    with failures:
        path = WEEK3 / "evaluation/failure-cases.jsonl"; rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()] if path.exists() else []
        st.dataframe(rows, hide_index=True, width="stretch") if rows else st.caption("Run được chọn không có controlled failure.")


pages = {
    "Workspace": [
        st.Page(overview, title="Overview", icon="🏠"),
        st.Page(findings, title="Findings Explorer", icon="🔎"),
        st.Page(agent_analysis, title="Agent Analysis", icon="🛡️"),
        st.Page(reports_page, title="Reports", icon="📄"),
        st.Page(evaluation, title="Evaluation", icon="📊"),
    ]
}
st.navigation(pages).run()
