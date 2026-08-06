from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

import streamlit as st

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from sentinel_benchmark.indexer import build  # noqa: E402
from sentinel_benchmark.search import search_index  # noqa: E402

DB = REPO_ROOT / "datasets" / "processed" / "sentinel.db"
MANIFEST = REPO_ROOT / "configs" / "sources.json"
KNOWLEDGE = REPO_ROOT / "datasets" / "knowledge" / "security-topics.jsonl"
METRICS = REPO_ROOT / "artifacts" / "week-1" / "llm-20260728" / "results.json"
SEMGREP_METRICS = REPO_ROOT / "artifacts" / "week-1" / "semgrep-20260806" / "results.json"

st.set_page_config(page_title="Sentinel BenchmarkJava", page_icon="🛡️", layout="wide")


@st.cache_resource
def ensure_index() -> dict[str, int]:
    DB.parent.mkdir(parents=True, exist_ok=True)
    return build(MANIFEST, DB, KNOWLEDGE)


@st.cache_data
def stats() -> dict:
    with sqlite3.connect(DB) as conn:
        return {
            "observations": conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0],
            "canonical": conn.execute("SELECT COUNT(DISTINCT canonical_id) FROM findings").fetchone()[0],
            "knowledge": conn.execute("SELECT COUNT(*) FROM knowledge").fetchone()[0],
            "tools": conn.execute("SELECT tool, COUNT(*) FROM findings GROUP BY tool ORDER BY COUNT(*) DESC").fetchall(),
            "severities": conn.execute("SELECT severity, COUNT(*) FROM findings GROUP BY severity ORDER BY COUNT(*) DESC").fetchall(),
        }


def load_metrics() -> list[dict]:
    llm = json.loads(METRICS.read_text(encoding="utf-8"))
    semgrep = json.loads(SEMGREP_METRICS.read_text(encoding="utf-8"))
    rows = []
    for label, values in (
        ("OpenCodeReview", llm["scanners"]["open_code_review"]),
        ("DeepSec/Pi", llm["scanners"]["deepsec"]),
    ):
        overall = values["metrics"]["overall"]
        rows.append({"Scanner": label, "TP": overall["TP"], "FP": overall["FP"], "FN": overall["FN"], "TN": overall["TN"], "Precision": overall["precision"], "Recall": overall["recall"], "F1": overall["f1"]})
    overall = semgrep["variants"]["security-audit"]["metrics"]["metrics"]["overall"]
    rows.append({"Scanner": "Semgrep security-audit", "TP": overall["TP"], "FP": overall["FP"], "FN": overall["FN"], "TN": overall["TN"], "Precision": overall["precision"], "Recall": overall["recall"], "F1": overall["f1"]})
    return rows


def decode(value) -> list[str]:
    if isinstance(value, list):
        return value
    try:
        result = json.loads(value or "[]")
        return result if isinstance(result, list) else [str(result)]
    except (TypeError, json.JSONDecodeError):
        return [str(value)] if value else []


st.title("🛡️ Sentinel BenchmarkJava")
st.caption("100 OWASP BenchmarkJava cases · 3 scanner views · ground-truth scoring · no WebGoat")

try:
    with st.spinner("Building reproducible local search index..."):
        ensure_index()
except Exception as exc:
    st.error("Không thể build index từ artifacts. Kiểm tra deployment logs và source manifest.")
    st.exception(exc)
    st.stop()

s = stats()
m1, m2, m3, m4 = st.columns(4)
m1.metric("Benchmark cases", "100")
m2.metric("Scanner observations", f"{s['observations']:,}")
m3.metric("Canonical groups", f"{s['canonical']:,}")
m4.metric("Knowledge docs", s["knowledge"])

search_tab, metrics_tab, provenance_tab = st.tabs(["🔎 Findings", "📊 Scanner metrics", "🧾 Provenance"])

with search_tab:
    st.write("Tìm theo `CWE-89`, `SQL Injection`, `CWE-79`, `XSS`, `Path Traversal` hoặc tên file benchmark.")
    with st.form("search"):
        query = st.text_input("CWE hoặc từ khóa", placeholder="CWE-89")
        c1, c2 = st.columns([2, 1])
        severity = c1.selectbox("Severity", ["all", "critical", "high", "medium", "low", "info"])
        limit = c2.selectbox("Top K", [5, 10, 20], index=1)
        submitted = st.form_submit_button("Tìm kiếm", type="primary", width="stretch")
    if submitted and not query.strip():
        st.warning("Nhập ít nhất một CWE hoặc từ khóa.")
    elif query.strip():
        kb_hits = search_index(DB, query, "knowledge", limit)
        findings = search_index(DB, query, "findings", limit, "owasp-benchmark-java", None if severity == "all" else severity)
        left, right = st.columns([1, 1.4])
        with left:
            st.subheader(f"Knowledge ({len(kb_hits)})")
            for hit in kb_hits:
                with st.expander(hit["title"]):
                    st.write(hit["content"])
                    st.caption(hit.get("source") or "No source")
        with right:
            st.subheader(f"Scanner observations ({len(findings)})")
            for hit in findings:
                with st.expander(f"[{hit['severity'].upper()}] {hit['title']}"):
                    st.caption(f"{hit['tool']} · {', '.join(decode(hit['cwe'])) or 'CWE n/a'} · canonical {hit['canonical_id']}")
                    st.code(f"{hit['file_or_url']}:{hit.get('line_start') or '?'}", language=None)
                    st.write(hit.get("description") or "Không có mô tả.")
                    if hit.get("evidence"):
                        st.markdown("**Evidence**")
                        st.code(str(hit["evidence"])[:2500])
                    st.caption(f"Run {hit['run_id']} · artifact {hit['source_artifact']}")
            if findings:
                st.download_button("Tải JSON", json.dumps(findings, ensure_ascii=False, indent=2), "benchmark-findings.json", "application/json")

with metrics_tab:
    st.dataframe(load_metrics(), hide_index=True, width="stretch", column_config={"Precision": st.column_config.NumberColumn(format="%.2f"), "Recall": st.column_config.NumberColumn(format="%.2f"), "F1": st.column_config.NumberColumn(format="%.2f")})
    st.info("Một test chỉ được tính TP khi scanner báo đúng nhóm CWE trong ground truth. Ground truth không được gửi vào scanner.")
    a, b = st.columns(2)
    a.markdown("**Observations theo scanner**")
    a.dataframe([{"Scanner": k, "Observations": v} for k, v in s["tools"]], hide_index=True, width="stretch")
    b.markdown("**Observations theo severity**")
    b.dataframe([{"Severity": k, "Observations": v} for k, v in s["severities"]], hide_index=True, width="stretch")

with provenance_tab:
    st.markdown("""
1. Upstream OWASP BenchmarkJava được pin tại commit `79b9bd6`.
2. Phạm vi là `BenchmarkTest00001.java` đến `BenchmarkTest00100.java` (75 positive, 25 negative).
3. Scanner chỉ nhận source Java; `expectedresults-1.2.csv` được join sau khi scan.
4. JSON/JSONL gốc nằm trong `artifacts/week-1/`; manifest nguồn nằm ở `configs/sources.json`.
5. Observation là output của scanner, không mặc định là lỗ hổng đã human-validate. Canonical group chỉ là phép gom deterministic.
""")
