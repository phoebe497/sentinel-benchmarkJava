const PAGES = [
  ["overview", "Overview", icon("home")],
  ["sast", "SAST Analysis", icon("fileSearch")],
  ["dast", "DAST Analysis", icon("shield")],
  ["agent", "Agent Analysis", icon("userSquare")],
  ["approval", "Approval Center", icon("squareCheck")],
  ["reports", "Reports", icon("file")],
  ["knowledge", "Knowledge Base & Audit", icon("list")],
];

const state = {
  page: "overview",
  tab: {},
  selected: null,
  selectedRun: null,
  sastRun: "",
  cache: {},
  pageIndex: {},
  charts: [],
  chat: {},
};

function icon(name, size = 16) {
  const paths = {
    home: '<path d="m3 9 9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/>',
    search: '<circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>',
    code: '<path d="m16 18 6-6-6-6"/><path d="m8 6-6 6 6 6"/>',
    codeSlash: '<path d="m18 16 4-4-4-4"/><path d="m6 8-4 4 4 4"/><path d="m14.5 4-5 16"/>',
    radar: '<circle cx="12" cy="12" r="3"/><path d="M5 12a7 7 0 0 1 7-7M12 5a7 7 0 0 1 7 7"/>',
    bot: '<path d="M12 8V4H8"/><rect x="4" y="8" width="16" height="12" rx="2"/><path d="M2 14h2M20 14h2M9 13v2M15 13v2"/>',
    shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10"/>',
    shieldCheck: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10"/><path d="m9 12 2 2 4-4"/>',
    chart: '<path d="M4 19h16M7 16V9M12 16V5M17 16v-6"/>',
    book: '<path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/>',
    userSquare: '<rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="12" cy="10" r="3"/><path d="M7 20.7V19a2 2 0 0 1 2-2h6a2 2 0 0 1 2 2v1.7"/>',
    squareCheck: '<rect x="3" y="3" width="18" height="18" rx="2"/><path d="m9 12 2 2 4-4"/>',
    file: '<path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z"/><path d="M14 2v4a2 2 0 0 0 2 2h4"/>',
    list: '<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>',
    tag: '<path d="M12.6 2.6A2 2 0 0 0 11.2 2H4a2 2 0 0 0-2 2v7.2a2 2 0 0 0 .6 1.4l8.8 8.8a2 2 0 0 0 2.8 0l7.2-7.2a2 2 0 0 0 0-2.8Z"/><circle cx="7.5" cy="7.5" r="1" fill="currentColor"/>',
    eye: '<path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/>',
    globe: '<circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/><path d="M2 12h20"/>',
    alertCircle: '<circle cx="12" cy="12" r="10"/><path d="M12 8v4M12 16h.01"/>',
    hash: '<path d="M4 9h16M4 15h16M10 3 8 21M16 3l-2 18"/>',
    check: '<path d="M20 6 9 17l-5-5"/>',
    userLock: '<circle cx="9" cy="8" r="3.2"/><path d="M3.4 20v-1.1A5.6 5.6 0 0 1 9 13.3"/><rect x="13" y="14.4" width="8" height="6.1" rx="1.2"/><path d="M15 14.4v-1.6a2 2 0 1 1 4 0v1.6"/>',
    plus: '<path d="M12 5v14M5 12h14"/>',
    clipboard: '<rect x="8" y="3" width="8" height="4" rx="1"/><path d="M8 5H6a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7a2 2 0 0 0-2-2h-2"/><path d="M9 12h6M9 16h6"/>',
    refresh: '<path d="M21 12a9 9 0 1 1-2.6-6.3"/><path d="M21 3v6h-6"/>',
    users: '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/>',
    target: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1"/>',
    more: '<circle cx="12" cy="5" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="12" cy="19" r="1"/>',
    download: '<path d="M12 3v12M7 11l5 5 5-5M5 21h14"/>',
    upload: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m17 8-5-5-5 5"/><path d="M12 3v12"/>',
    fileSearch: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z"/><path d="M14 2v6h6"/><circle cx="11.5" cy="14.5" r="2.5"/><path d="m13.4 16.4 2.1 2.1"/>',
    branch: '<circle cx="6" cy="5" r="2"/><circle cx="6" cy="19" r="2"/><circle cx="18" cy="12" r="2"/><path d="M6 7v10M6 12h10"/>',
    alertTriangle: '<path d="m12 3 10 18H2L12 3Z"/><path d="M12 10v4M12 18h.01"/>',
    checkCircle: '<circle cx="12" cy="12" r="9"/><path d="m8.5 12 2.4 2.4 4.6-4.8"/>',
    clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    calendar: '<rect x="3" y="5" width="18" height="16" rx="2"/><path d="M3 10h18M8 3v4M16 3v4"/>',
    link: '<path d="M10 13a5 5 0 0 0 7.5.5l2-2a5 5 0 0 0-7.1-7.1l-1.2 1.2"/><path d="M14 11a5 5 0 0 0-7.5-.5l-2 2a5 5 0 1 0 7.1 7.1l1.1-1.1"/>',
    external: '<path d="M14 5h5v5M19 5l-8 8"/><path d="M11 5H6a1 1 0 0 0-1 1v12a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-5"/>',
  };
  return `<svg class="sentinel-icon" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name] || ""}</svg>`;
}

function semgrepLogo() {
  return `<svg class="tool-logo" width="16" height="16" viewBox="0 0 24 24" aria-hidden="true"><path fill="#7c3aed" d="M8.8 4.8a5.6 5.6 0 0 1 7.2 1.8 1 1 0 1 1-1.7 1.1 3.6 3.6 0 1 0-1.1 5.1 1 1 0 0 1 1.1 1.7A5.6 5.6 0 1 1 8.8 4.8Zm6.4 14.4a5.6 5.6 0 0 1-7.2-1.8 1 1 0 1 1 1.7-1.1 3.6 3.6 0 1 0 1.1-5.1 1 1 0 0 1-1.1-1.7 5.6 5.6 0 1 1 5.5 9.7Z"/></svg>`;
}

function toolMark(name) {
  const label = String(name || "—");
  if (/semgrep/i.test(label)) return `${semgrepLogo()} ${esc(label)}`;
  return `${icon(/agent|gpt-|luna|router/i.test(label) ? "bot" : "search")} ${esc(label)}`;
}

function esc(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function badge(label, kind) {
  const map = {
    "True Positive": "success",
    "True Negative": "success",
    "False Positive": "critical",
    "Needs Review": "warning",
    Approved: "success",
    Pending: "warning",
    Rejected: "critical",
    Blocked: "critical",
    Allowed: "success",
    Completed: "success",
    Running: "info",
    Failed: "critical",
    "Confirmed Vulnerable": "success",
    "Likely Vulnerable": "warning",
    "Likely False Positive": "muted",
    "Not Vulnerable": "muted",
    "Insufficient Evidence": "warning",
    Critical: "critical",
    High: "high",
    Medium: "warning",
    Low: "info",
    Info: "muted",
    SAST: "info",
    DAST: "success",
    GET: "info",
    POST: "warning",
  };
  return `<span class="sentinel-badge sentinel-badge--${map[label] || kind || "muted"}">${esc(label)}</span>`;
}

async function api(path) {
  if (state.cache[path]) return state.cache[path];
  const res = await fetch(path);
  if (!res.ok) throw new Error(`Failed ${path}`);
  const data = await res.json();
  state.cache[path] = data;
  return data;
}

function toast(text) {
  const el = document.getElementById("toast");
  el.hidden = false;
  el.textContent = text;
  setTimeout(() => { el.hidden = true; }, 2800);
}

function setPage(page, extra = {}) {
  state.page = page;
  if (extra.finding) state.selected = extra.finding;
  history.replaceState({}, "", `/${page}`);
  document.querySelectorAll(".sentinel-sidebar__item[data-page]").forEach((item) => {
    item.setAttribute("aria-current", item.dataset.page === page ? "page" : "false");
  });
  render();
}

function renderNav() {
  document.getElementById("nav").innerHTML = PAGES.map(([id, label, svg]) => `
    <a class="sentinel-sidebar__item" href="/${id}" data-page="${id}" ${state.page === id ? 'aria-current="page"' : ""}>
      ${svg}<span class="sentinel-sidebar__label">${label}</span>
    </a>
  `).join("");
}

function metric(label, value, delta, iconClass, svg) {
  return `
    <article class="sentinel-card sentinel-metric">
      <div>
        <div class="sentinel-metric__label">${label}</div>
        <div class="sentinel-metric__value">${esc(value)}</div>
        ${delta ? `<div class="sentinel-metric__delta">${delta}</div>` : ""}
      </div>
      <div class="sentinel-metric__icon ${iconClass}">${svg}</div>
    </article>`;
}

function pager(id, total, size = 8) {
  const page = state.pageIndex[id] || 1;
  const pages = Math.max(1, Math.ceil(total / size));
  const start = (page - 1) * size;
  return {
    start,
    end: Math.min(total, start + size),
    html: `<div class="pager"><span>${total ? start + 1 : 0}-${Math.min(total, start + size)} of ${total}</span>
      <div class="pager__btns">${Array.from({ length: Math.min(pages, 5) }, (_, i) => {
        const n = i + 1;
        return `<button type="button" class="${n === page ? "is-on" : ""}" data-pager="${id}" data-n="${n}">${n}</button>`;
      }).join("")}</div></div>`,
  };
}

function destroyCharts() {
  state.charts.forEach((chart) => chart.destroy());
  state.charts = [];
}

function donut(canvasId, labels, values, colors, center) {
  const ctx = document.getElementById(canvasId);
  if (!ctx || !window.Chart) return;
  const chart = new Chart(ctx, {
    type: "doughnut",
    data: { labels, datasets: [{ data: values, backgroundColor: colors, borderWidth: 0 }] },
    options: { cutout: "72%", plugins: { legend: { display: false } }, maintainAspectRatio: false },
  });
  state.charts.push(chart);
  const centerEl = ctx.parentElement.querySelector(".donut-center");
  if (centerEl && center) centerEl.innerHTML = center;
}

async function renderOverview() {
  const data = await api("/api/overview");
  const total = data.severity.reduce((sum, row) => sum + row.count, 0) || 1;
  const colors = ["#dc2626", "#ea580c", "#d97706", "#2563eb", "#94a3b8"];
  document.getElementById("page").innerHTML = `
    <div class="sentinel-page-header">
      <div>
        <h1 class="sentinel-page-title">Overview</h1>
        <p class="sentinel-page-description">Unified SAST & DAST Analysis Pipeline powered by one Security Analysis Agent.</p>
      </div>
      <button class="sentinel-button sentinel-button--outline" type="button">Customize Overview</button>
    </div>
    <div class="sentinel-grid sentinel-grid--metrics">
      ${metric("Total Findings", data.total_findings, "from committed scanner artifacts", "icon-blue", icon("code"))}
      ${metric("True Vulnerabilities", data.true_vulnerabilities, "ground truth + confirmed DAST", "icon-green", icon("shield"))}
      ${metric("Pending Approval", data.pending_approval, "human gate before Gateway", "icon-orange", icon("radar"))}
      ${metric("Active Scans", data.active_scans, "ZAP baseline recorded", "icon-purple", icon("chart"))}
    </div>
    <article class="sentinel-card" style="margin-top:1rem">
      <div class="sentinel-card__header"><h2 class="sentinel-card__title">Analysis Pipeline Status</h2></div>
      <div class="pipeline">${data.pipeline.map((step) => `
        <div class="pipeline__step">
          <strong class="pipeline__name">${esc(step.label)}</strong>
          <span class="pipeline__state is-${step.state}">${esc(step.detail)}</span>
        </div>`).join("")}</div>
    </article>
    <div class="sentinel-grid split-wide" style="margin-top:1rem">
      <article class="sentinel-card">
        <div class="sentinel-card__header"><h2 class="sentinel-card__title">Findings by Severity</h2></div>
        <div class="chart-box">
          <div class="donut-wrap"><canvas id="sev-donut"></canvas><div class="donut-center"></div></div>
          <div class="legend">${data.severity.map((row, i) => `
            <div class="legend__row"><span><i class="swatch" style="background:${colors[i]}"></i> ${row.label}</span>
            <strong>${row.count} (${Math.round((row.count / total) * 100)}%)</strong></div>`).join("")}</div>
        </div>
      </article>
      <article class="sentinel-card">
        <div class="sentinel-card__header"><h2 class="sentinel-card__title">Recent Scan Runs</h2>
          <a class="linkish" href="/sast">View all runs →</a></div>
        <div class="sentinel-table-wrap">
          <table class="sentinel-table"><thead><tr>
            <th>Run ID</th><th>Type</th><th>Target / Project</th><th>Status</th><th>Findings</th><th>Started At</th>
          </tr></thead><tbody>
            ${data.runs.map((run) => `<tr>
              <td class="mono">${esc(run.id)}</td><td>${badge(run.type)}</td><td>${esc(run.target)}</td>
              <td>${badge(run.status)}</td><td>${run.findings}</td><td>${esc(run.started)}</td>
            </tr>`).join("")}
          </tbody></table>
        </div>
      </article>
    </div>`;
  donut("sev-donut", data.severity.map((r) => r.label), data.severity.map((r) => r.count), colors, `<strong>${data.total_findings}</strong><small>Total</small>`);
}

function searchField(tableId, placeholder) {
  return `<label class="search-field">${icon("search")}<input class="sentinel-control" data-filter-table="${tableId}" placeholder="${placeholder}" /></label>`;
}

function selectField(label, iconName) {
  return `<label class="select-field">${iconName ? icon(iconName) : ""}<select class="sentinel-control" disabled><option>${esc(label)}</option></select></label>`;
}

function shortPath(path) {
  const parts = String(path || "").split(/[\\/]/).filter(Boolean);
  if (parts.length <= 2) return path || "—";
  return `.../${parts.slice(-2).join("/")}`;
}

function sastHeader(data, tab) {
  return `
    <div class="sentinel-page-header">
      <div>
        <h1 class="sentinel-page-title">SAST Analysis</h1>
        <p class="sentinel-page-description">Project: ${esc(data.project)}</p>
        <div class="sentinel-tabs">
          <button class="sentinel-tab" data-tab="sast" data-value="runs" aria-selected="${tab === "runs"}">Runs</button>
          <button class="sentinel-tab" data-tab="sast" data-value="findings" aria-selected="${tab === "findings"}">Findings</button>
        </div>
      </div>
      ${tab === "runs" ? `<button class="sentinel-button sentinel-button--compact" type="button" data-toast="The public UI does not start a new scan.">${icon("plus")} Start New Scan</button>` : ""}
    </div>`;
}

function sastRuns(data) {
  const stats = data.run_stats || { total: 0, completed: 0, running: 0, failed: 0 };
  const page = pager("sast-runs", data.runs.length, 6);
  const rows = data.runs.slice(page.start, page.end);
  const active = data.runs.find((row) => row.status === "Running");
  return `
    <div class="sentinel-grid sentinel-grid--metrics">
      ${metric("Total Runs", stats.total, "committed scanner and agent runs", "icon-blue", icon("clipboard"))}
      ${metric("Completed", stats.completed, "", "icon-green", icon("checkCircle"))}
      ${metric("Running", stats.running, "", "icon-orange", icon("refresh"))}
      ${metric("Failed", stats.failed, "", "icon-red", icon("alertTriangle"))}
    </div>
    ${active ? `
    <article class="sentinel-card run-progress">
      <div class="donut-wrap run-progress__ring"><canvas id="sast-run-donut"></canvas><div class="donut-center"><strong>${active.progress}%</strong></div></div>
      <div>
        <p><strong class="mono">${esc(active.id)}</strong> ${badge(active.status)}</p>
        <div class="run-meta">
          <span>${icon("branch")} ${esc(active.branch)}</span>
          <span>${icon("hash")} ${esc(active.commit)}</span>
          <span>${toolMark(active.tool)}</span>
          <span>${icon("bot")} ${esc(active.stage)}</span>
          <span>${icon("clock")} ${esc(active.duration)}</span>
        </div>
      </div>
    </article>` : ""}
    <div class="toolbar">
      ${searchField("sast-run-rows", "Search run...")}
      ${selectField("Status")}
      ${selectField("Branch", "branch")}
      ${selectField("Date Range", "calendar")}
    </div>
    <div class="sentinel-table-wrap">
      <table class="sentinel-table"><thead><tr>
        <th>Run ID</th><th>Branch / Commit</th><th>Tool</th><th>Ruleset</th><th>Status</th><th>Duration</th><th>Findings</th><th>Agent Results</th><th>Started At</th><th></th>
      </tr></thead>
      <tbody id="sast-run-rows">
        ${rows.map((row) => `<tr class="is-clickable${state.selectedRun?.id === row.id ? " is-selected" : ""}" data-open-run="${row.id}">
          <td class="mono">${esc(row.id)}</td>
          <td class="stack-cell">
            <span>${icon("branch")} ${esc(row.branch)}</span>
            <small>${icon("link")} ${esc(row.commit)}</small>
          </td>
          <td><span class="tool-cell">${toolMark(row.tool)}</span></td>
          <td class="mono">${esc(row.ruleset)}</td>
          <td>${badge(row.status)}</td>
          <td>${esc(row.duration)}</td>
          <td>${row.findings ?? "—"}</td>
          <td>${esc(row.agent_results)}</td>
          <td>${esc(row.started)}</td>
          <td class="row-action row-action--pair">${icon("eye")}${icon("more")}</td>
        </tr>`).join("")}
      </tbody></table>
      ${page.html}
    </div>`;
}

function sastFindings(data) {
  const runFilter = state.sastRun || "";
  const findings = runFilter ? data.findings.filter((row) => row.run_id === runFilter) : data.findings;
  const page = pager("sast-find", findings.length, 10);
  const rows = findings.slice(page.start, page.end);
  return `
    <div class="sentinel-grid sentinel-grid--metrics">
      ${metric("Total Findings", data.total, "analysis groups with a report", "icon-blue", icon("fileSearch"))}
      ${metric("True Vulnerabilities", data.true_vulnerabilities, "BenchmarkJava ground truth", "icon-green", icon("shieldCheck"))}
      ${metric("Needs Review", data.needs_review, "", "icon-orange", icon("users"))}
      ${metric("False Positives", data.false_positives, "", "icon-purple", icon("target"))}
    </div>
    <div class="toolbar">
      ${searchField("sast-find-rows", "Search finding...")}
      ${selectField(runFilter || "Run")}
      ${selectField("Severity")}
      ${selectField("CWE")}
      ${selectField("Agent Verdict")}
      ${selectField("Confidence")}
      <button class="sentinel-button sentinel-button--outline sentinel-button--compact toolbar__action" type="button" data-toast="Export stays on this machine.">${icon("download")} Export Findings</button>
    </div>
    <div class="sentinel-table-wrap">
      <table class="sentinel-table"><thead><tr>
        <th>ID</th><th>CWE</th><th>Rule</th><th>Severity</th><th>File / Location</th><th>Agent Verdict</th><th>Confidence</th><th>Evidence</th>
      </tr></thead>
      <tbody id="sast-find-rows">
        ${rows.map((row) => `<tr class="is-clickable${state.selected?.id === row.id ? " is-selected" : ""}" data-open="sast" data-id="${row.id}">
          <td class="mono">${row.id}</td>
          <td>${esc(row.cwe)}</td>
          <td class="mono wrap-cell">${esc(row.rule || row.title || "—")}</td>
          <td>${badge(row.severity)}</td>
          <td class="file-cell"><a class="linkish mono" href="#source-${row.id}" data-open="sast" data-id="${row.id}" data-source="1" title="${esc(row.file)}">${esc(shortPath(row.file))}</a></td>
          <td>${badge(row.verdict)}</td>
          <td>${row.confidence}%</td>
          <td class="row-action">${icon("eye")}</td>
        </tr>`).join("")}
      </tbody></table>
      ${page.html}
    </div>`;
}

async function renderSast() {
  const data = await api("/api/sast");
  const tab = state.tab.sast || "runs";
  document.getElementById("page").innerHTML = sastHeader(data, tab) + (tab === "findings" ? sastFindings(data) : sastRuns(data));
  bindTableSearch();
  const active = data.runs.find((row) => row.status === "Running");
  if (tab === "runs" && active) {
    donut("sast-run-donut", ["done", "rest"], [active.progress, Math.max(0, 100 - active.progress)], ["#2563eb", "#e2e8f0"], `<strong>${active.progress}%</strong>`);
  }
  if (state.selectedRun && tab === "runs") openRunDrawer(state.selectedRun);
  if (state.selected && String(state.selected.id).startsWith("SAST") && tab === "findings") {
    openDrawer(state.selected, "sast");
  }
}

function dastHeader(data, tab) {
  const labels = { overview: "Overview", endpoints: "Endpoints", findings: "Findings", probes: "Proposed Safe Probes" };
  return `
    <div class="sentinel-page-header">
      <div>
        <h1 class="sentinel-page-title">DAST Analysis</h1>
        <p class="sentinel-page-description">Target: ${esc(data.target)}</p>
        <div class="sentinel-tabs">
          ${["overview", "endpoints", "findings", "probes"].map((id) => `
            <button class="sentinel-tab" data-tab="dast" data-value="${id}" aria-selected="${tab === id}">${labels[id]}</button>`).join("")}
        </div>
      </div>
    </div>`;
}

function dastOverview(data) {
  return `
    <div class="sentinel-grid split-dast">
      <article class="sentinel-card">
        <div class="sentinel-card__header"><h2 class="sentinel-card__title">Scan Progress</h2></div>
        <div class="chart-box">
          <div class="donut-wrap"><canvas id="dast-donut"></canvas><div class="donut-center"></div></div>
          <div>
            <div class="probe-stat"><span>Spider</span><strong>${esc(data.elapsed)}</strong></div>
            <div class="probe-stat"><span>Probes sent</span><strong>${data.requests}</strong></div>
            <div class="probe-stat"><span>Endpoints with alerts</span><strong>${data.endpoints}</strong></div>
            <div class="probe-stat"><span>Findings</span><strong>${data.findings_count}</strong></div>
            <div class="probe-stat"><span>Verdicts verified live</span><strong>${data.verified_count} <small>(${data.revised_count} revised)</small></strong></div>
            <p class="sentinel-page-description">Scanned: ${esc(data.started)}</p>
          </div>
        </div>
      </article>
      <article class="sentinel-card">
        <div class="sentinel-card__header"><h2 class="sentinel-card__title">Proposed Safe Probes</h2>
          <button class="linkish" type="button" data-tab="dast" data-value="probes">View All</button></div>
        ${[
          ["Total", data.probes.total, "info"],
          ["Approved", data.probes.approved, "success"],
          ["Pending", data.probes.pending, "warning"],
          ["Blocked", (data.probes.blocked || 0) + (data.probes.rejected || 0), "critical"],
        ].map(([label, value, kind]) => `<div class="probe-stat"><span>${label}</span>${badge(String(value), kind)}</div>`).join("")}
      </article>
    </div>
    <article class="sentinel-card" style="margin-top:1rem">
      <div class="sentinel-card__header"><h2 class="sentinel-card__title">Recent Findings</h2></div>
      ${dastFindingsTable(data.findings, pager("dast", data.findings.length, 5))}
    </article>`;
}

function dastFindingsTable(findings, page) {
  const rows = findings.slice(page.start, page.end);
  return `
    <div class="sentinel-table-wrap">
      <table class="sentinel-table"><thead><tr>
        <th>ID</th><th>Endpoint</th><th>Method</th><th>Category</th><th>Severity</th><th>Agent Verdict</th><th>Confidence</th><th>Evidence</th>
      </tr></thead><tbody>
        ${rows.map((row) => `<tr class="is-clickable" data-open="dast" data-id="${row.id}">
          <td class="mono">${row.id}</td><td class="mono">${esc(row.endpoint)}</td><td>${badge(row.method)}</td>
          <td>${esc(row.category || row.cwe_name || "—")}</td>
          <td>${badge(row.severity)}</td><td>${badge(row.verdict)}</td><td>${row.confidence}%</td><td class="row-action">${icon("eye")}</td>
        </tr>`).join("")}
      </tbody></table>
      ${page.html}
    </div>`;
}

function dastEndpoints(data) {
  const stats = data.endpoint_stats;
  const page = pager("dast-ep", data.endpoint_rows.length, 8);
  const rows = data.endpoint_rows.slice(page.start, page.end);
  return `
    <div class="sentinel-grid sentinel-grid--metrics">
      ${metric("Total Endpoints", stats.total, "from ZAP spider + probes", "icon-blue", icon("globe"))}
      ${metric("Tested", stats.tested, "live response through Gateway", "icon-green", icon("shieldCheck"))}
      ${metric("With Findings", stats.with_findings, "paths with at least one alert", "icon-orange", icon("alertCircle"))}
      ${metric("Not Reached", stats.not_reached, "seen by spider, not probed", "icon-purple", icon("radar"))}
    </div>
    <div class="toolbar">
      <input class="sentinel-control" data-filter-table="dast-ep-rows" placeholder="Search endpoint..." />
      <select class="sentinel-control" disabled><option>Method</option></select>
      <select class="sentinel-control" disabled><option>Authentication</option></select>
      <select class="sentinel-control" disabled><option>Scan Status</option></select>
    </div>
    <div class="sentinel-table-wrap">
      <table class="sentinel-table"><thead><tr>
        <th>Endpoint</th><th>Method</th><th>Authentication</th><th>Status</th><th>Findings</th><th>Requests</th><th>Last Seen</th><th></th>
      </tr></thead>
      <tbody id="dast-ep-rows">
        ${rows.map((row) => `<tr class="is-clickable" data-open-endpoint="${row.id}">
          <td class="mono">${esc(row.endpoint)}</td>
          <td>${badge(row.method)}</td>
          <td>${esc(row.auth)}</td>
          <td>${badge(row.status, row.status === "Tested" ? "success" : row.status === "Partial" ? "warning" : "muted")}</td>
          <td class="${row.findings ? "tone-critical" : ""}">${row.findings}</td>
          <td>${row.requests}</td>
          <td>${esc(row.last_seen)}</td>
          <td class="row-action">${icon("eye")}</td>
        </tr>`).join("")}
      </tbody></table>
      ${page.html}
    </div>`;
}

function dastFindings(data) {
  const stats = data.finding_stats;
  return `
    <div class="sentinel-grid grid-6">
      ${metric("Total Findings", stats.total, "agent-analysed DAST groups", "icon-blue", icon("file"))}
      ${metric("High", stats.high, "", "icon-red", icon("alertCircle"))}
      ${metric("Medium", stats.medium, "", "icon-orange", icon("alertCircle"))}
      ${metric("Low", stats.low, "", "icon-blue", icon("alertCircle"))}
      ${metric("Agent Verified", stats.verified, "live response reached the target", "icon-green", icon("shieldCheck"))}
      ${metric("Needs Review", stats.needs_review, "insufficient evidence or review", "icon-purple", icon("userSquare"))}
    </div>
    <div class="toolbar">
      <input class="sentinel-control" data-filter-table="dast-find-rows" placeholder="Search findings..." />
      <select class="sentinel-control" disabled><option>Severity</option></select>
      <select class="sentinel-control" disabled><option>Agent Verdict</option></select>
      <select class="sentinel-control" disabled><option>Endpoint</option></select>
    </div>
    ${dastFindingsTable(data.findings, pager("dast-find", data.findings.length, 8)).replace("<tbody>", '<tbody id="dast-find-rows">')}`;
}

function dastProbes(data) {
  const status = state.tab.dastProbe || "All";
  const all = data.probe_rows || [];
  const filtered = status === "All" ? all : all.filter((row) => row.status === status || (status === "Blocked" && row.gateway === "Blocked"));
  const page = pager("dast-probe", filtered.length, 8);
  const rows = filtered.slice(page.start, page.end);
  return `
    <div class="sentinel-grid grid-5">
      ${metric("Total", data.probes.total, "recorded Gateway probes", "icon-blue", icon("list"))}
      ${metric("Approved", data.probes.approved, "", "icon-green", icon("shieldCheck"))}
      ${metric("Pending Approval", data.probes.pending, "", "icon-orange", icon("radar"))}
      ${metric("Rejected", data.probes.rejected, "", "icon-red", icon("alertCircle"))}
      ${metric("Blocked by Policy", data.probes.blocked, "", "icon-purple", icon("shield"))}
    </div>
    <div class="toolbar">
      <div class="filter-pills">
        ${["All", "Pending", "Approved", "Rejected", "Blocked"].map((id) =>
          `<button type="button" class="filter-pill${status === id ? " is-on" : ""}" data-tab="dastProbe" data-value="${id}">${id}</button>`
        ).join("")}
      </div>
      <input class="sentinel-control" data-filter-table="dast-probe-rows" placeholder="Search probes..." />
    </div>
    <div class="sentinel-table-wrap">
      <table class="sentinel-table"><thead><tr>
        <th>Request ID</th><th>Finding ID</th><th>Method</th><th>Endpoint</th><th>Probe Type</th><th>Risk</th><th>Policy Checks</th><th>Approval</th><th>Gateway</th>
      </tr></thead>
      <tbody id="dast-probe-rows">
        ${rows.map((row) => `<tr class="is-clickable" data-open-probe="${row.id}">
          <td class="mono">${esc(row.id)}</td>
          <td class="mono">${esc(row.finding_id)}</td>
          <td>${badge(row.method)}</td>
          <td class="mono">${esc(row.path || row.endpoint)}</td>
          <td>${esc(row.probe_type)}</td>
          <td>${badge(row.risk, row.risk === "High" ? "critical" : row.risk === "Medium" ? "warning" : "info")}</td>
          <td class="${String(row.policy).includes("Pass") ? "tone-success" : "tone-critical"}">${esc(row.policy)}</td>
          <td>${badge(row.status)}</td>
          <td>${badge(row.gateway, row.gateway === "Executed" ? "success" : row.gateway === "Blocked" ? "critical" : "muted")}</td>
        </tr>`).join("")}
      </tbody></table>
      ${page.html}
    </div>`;
}

async function renderDast() {
  const data = await api("/api/dast");
  const tab = state.tab.dast || "overview";
  const views = { overview: dastOverview, endpoints: dastEndpoints, findings: dastFindings, probes: dastProbes };
  document.getElementById("page").innerHTML = dastHeader(data, tab) + (views[tab] || dastOverview)(data);
  if (tab === "overview") {
    donut("dast-donut", ["Done", "Rest"], [data.progress, Math.max(0, 100 - data.progress)], ["#2563eb", "#e2e8f0"], `<strong>${data.progress}%</strong>`);
  }
  bindTableSearch();
  if (state.selectedEndpoint) openEndpointDrawer(state.selectedEndpoint);
  if (state.selectedProbe) openProbeDrawer(state.selectedProbe);
  if (state.selected && String(state.selected.id).startsWith("DAST") && tab === "findings") {
    openDrawer(state.selected, "dast");
  }
}

async function renderAgent() {
  const id = state.selected?.id || new URLSearchParams(location.search).get("finding");
  const data = await api(`/api/agent${id ? `?finding_id=${encodeURIComponent(id)}` : ""}`);
  const finding = data.finding;
  state.selected = finding;
  document.getElementById("page").innerHTML = `
    <div class="sentinel-page-header">
      <div>
        <h1 class="sentinel-page-title">Agent Analysis</h1>
        <p class="sentinel-page-description">Finding ${esc(finding.id)}</p>
      </div>
    </div>
    <div class="sentinel-grid split-agent">
      <article class="sentinel-card">
        <div class="sentinel-card__header"><h2 class="sentinel-card__title">Finding Summary</h2></div>
        <ul class="meta-list">
          <li><span class="meta-icon icon-blue">${icon("tag")}</span><div><small>Type</small>${badge(finding.kind)}</div></li>
          <li><span class="meta-icon icon-blue">${icon(finding.kind === "DAST" ? "globe" : "file")}</span><div><small>${finding.kind === "DAST" ? "Endpoint" : "File"}</small><span class="mono">${esc(finding.endpoint || finding.file)}</span></div></li>
          <li><span class="meta-icon icon-blue">${icon(finding.method ? "code" : "hash")}</span><div><small>${finding.method ? "Method" : "CWE"}</small><span class="mono">${esc(finding.method || finding.cwe)}</span></div></li>
          <li><span class="meta-icon icon-orange">${icon("alertCircle")}</span><div><small>Severity</small>${badge(finding.severity)}</div></li>
          <li><span class="meta-icon icon-purple">${icon("hash")}</span><div><small>Run ID</small><span class="mono">${esc(finding.run_id)}</span></div></li>
        </ul>
      </article>
      <article class="sentinel-card">
        <div class="sentinel-card__header"><h2 class="sentinel-card__title">Matched Knowledge Base Entries</h2>
          <a class="linkish" href="/knowledge">View All Matches →</a></div>
        <table class="sentinel-table"><thead><tr><th>ID</th><th>CWE / OWASP</th><th>Title</th><th>Match Score</th></tr></thead>
        <tbody>${data.knowledge.map((row) => `<tr><td class="mono">${esc(row.id)}</td><td>${esc(row.cwe)}</td><td>${esc(row.title)}</td><td>${row.score}%</td></tr>`).join("")}</tbody></table>
      </article>
      <article class="sentinel-card">
        <div class="sentinel-card__header"><h2 class="sentinel-card__title">Collected Evidence</h2></div>
        <ul class="evidence-list">${data.evidence.map((item) => `<li><span class="check-dot">${icon("check")}</span><span>${esc(item)}</span></li>`).join("")}</ul>
      </article>
    </div>
    <div class="sentinel-grid split-agent-bottom" style="margin-top:1rem">
      <article class="sentinel-card">
        <div class="sentinel-card__header"><h2 class="sentinel-card__title">Agent Justification</h2></div>
        <div class="justification">${esc(data.justification).split(". ").slice(0, 3).map((p) => `<p>${p}${p.endsWith(".") ? "" : "."}</p>`).join("")}</div>
        ${finding.kind === "SAST" ? `<button class="accordion" type="button" data-acc="agent-source" aria-expanded="true">Code Snippet <span>▾</span></button>
        <div class="accordion-body is-open" data-acc-body="agent-source"><div id="agent-source"></div></div>` : ""}
      </article>
      <article class="sentinel-card verdict-card">
        ${badge(data.verdict)}
        <div class="donut-wrap" style="width:8.5rem;height:8.5rem"><canvas id="conf-donut"></canvas><div class="donut-center"></div></div>
        <strong class="tone-success">High Confidence</strong>
      </article>
      <article class="sentinel-card">
        <div class="sentinel-card__header"><h2 class="sentinel-card__title">Recommended Remediation</h2></div>
        <ul class="remediation">${data.remediation.map((item, index) => {
          const remIcon = ["codeSlash", "shieldCheck", "userLock"][index % 3];
          return `<li><span class="sentinel-metric__icon icon-green">${icon(remIcon)}</span><span>${esc(item)}</span></li>`;
        }).join("")}</ul>
      </article>
    </div>
    <article class="sentinel-card agent-chat" id="agent-chat">
      <div class="sentinel-card__header">
        <div>
          <h2 class="sentinel-card__title">Ask Sentinel</h2>
          <p class="sentinel-page-description">Answers stay on this finding's evidence, knowledge documents, and baked report.</p>
        </div>
      </div>
      <div class="agent-chat__prompts">${(data.suggested_questions || []).map((item) =>
        `<button type="button" class="sentinel-button sentinel-button--outline" data-ask="${esc(item.question)}">${esc(item.label)}</button>`
      ).join("")}</div>
      <div class="agent-chat__thread" id="agent-chat-thread"></div>
      <form class="agent-chat__form" id="agent-chat-form">
        <input class="sentinel-control" id="agent-chat-input" maxlength="500" placeholder="Ask about impact, verification, or remediation…" autocomplete="off" />
        <button class="sentinel-button" type="submit">Ask</button>
      </form>
    </article>`;
  donut("conf-donut", ["c", "r"], [data.confidence, Math.max(0, 100 - data.confidence)], ["#16a34a", "#e2e8f0"], `<strong>${data.confidence}%</strong>`);
  if (finding.kind === "SAST") fillSource(finding.id, "agent-source");
  paintChat(finding.id);
  bindAgentChat(finding.id);
}

function chatThread(findingId) {
  if (!state.chat[findingId]) state.chat[findingId] = [];
  return state.chat[findingId];
}

function paintChat(findingId) {
  const thread = document.getElementById("agent-chat-thread");
  if (!thread) return;
  const messages = chatThread(findingId);
  if (!messages.length) {
    thread.innerHTML = `<p class="agent-chat__empty">Ask about this finding. Suggested questions already include the CWE and location.</p>`;
    return;
  }
  thread.innerHTML = messages.map((message) => {
    if (message.role === "user") {
      return `<div class="agent-chat__msg agent-chat__msg--user"><p>${esc(message.content)}</p></div>`;
    }
    const lists = [
      ["How to verify", message.verification_steps],
      ["Remediation", message.remediation],
      ["Limits", message.limitations],
    ].filter(([, items]) => items?.length).map(([label, items]) =>
      `<div class="agent-chat__list"><strong>${label}</strong><ul>${items.map((item) => `<li>${esc(item)}</li>`).join("")}</ul></div>`
    ).join("");
    const cites = message.citations?.length ? `<p class="agent-chat__cites">Citations: ${message.citations.map((id) => `<code>${esc(id)}</code>`).join(" ")}</p>` : "";
    return `<div class="agent-chat__msg agent-chat__msg--agent"><p>${esc(message.content)}</p>${lists}${cites}</div>`;
  }).join("");
  thread.scrollTop = thread.scrollHeight;
}

function bindAgentChat(findingId) {
  const form = document.getElementById("agent-chat-form");
  const input = document.getElementById("agent-chat-input");
  const panel = document.getElementById("agent-chat");
  if (!form || !input || !panel) return;
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    askFinding(findingId, input.value);
  });
  panel.addEventListener("click", (event) => {
    const prompt = event.target.closest("[data-ask]");
    if (prompt) askFinding(findingId, prompt.dataset.ask);
  });
}

async function askFinding(findingId, question) {
  const text = String(question || "").trim();
  if (!text) return;
  const thread = chatThread(findingId);
  thread.push({ role: "user", content: text });
  paintChat(findingId);
  const input = document.getElementById("agent-chat-input");
  if (input) input.value = "";
  try {
    const res = await fetch("/api/agent/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ finding_id: findingId, question: text }),
    });
    const body = await res.json();
    if (!res.ok) throw new Error(body.detail || "chat failed");
    thread.push({
      role: "assistant",
      content: body.answer,
      citations: body.citations,
      verification_steps: body.verification_steps,
      remediation: body.remediation,
      limitations: body.limitations,
    });
  } catch (error) {
    thread.push({
      role: "assistant",
      content: "Sentinel could not answer from the baked evidence for this finding.",
      limitations: [String(error.message || error)],
    });
  }
  paintChat(findingId);
}

async function renderApproval() {
  delete state.cache["/api/approval"];
  const data = await api("/api/approval");
  const tab = state.tab.approval || "Pending";
  const filtered = data.items.filter((item) => tab === "History" || item.status === tab);
  const current = filtered[0] || data.items[0];
  document.getElementById("page").innerHTML = `
    <div class="sentinel-page-header">
      <div>
        <h1 class="sentinel-page-title">Approval Center</h1>
        <div class="sentinel-tabs">
          ${["Pending", "Approved", "Rejected", "History"].map((id) => `
            <button class="sentinel-tab" data-tab="approval" data-value="${id}" aria-selected="${tab === id}">
              ${id}${id === "Pending" ? `<span class="count">${data.counts.Pending}</span>` : ""}
            </button>`).join("")}
        </div>
      </div>
    </div>
    ${current ? `
    <article class="sentinel-card">
      <div class="sentinel-card__header">
        <div><div class="sentinel-page-description">Request ID</div>
        <h2 class="sentinel-page-title" style="font-size:1.25rem">${current.id}</h2></div>
        ${badge(current.status)}
      </div>
      <div class="approval-grid">
        <section>
          <h3 class="sentinel-card__title">Request Details</h3>
          <p><small>HTTP Method</small><br><strong>${esc(current.method)}</strong></p>
          <p><small>Allowlisted Endpoint</small><br><span class="mono">${esc(current.endpoint)}</span></p>
          <p><small>Sanitized Payload Preview</small></p>
          <pre class="sentinel-code">${esc(JSON.stringify(current.payload ?? {}, null, 2))}</pre>
          <p><small>Purpose</small><br>${esc(current.purpose)}</p>
        </section>
        <section>
          <h3 class="sentinel-card__title">Risk & Impact</h3>
          <p>${badge(`${current.risk} Risk`, current.risk === "High" ? "critical" : "warning")} ${badge(current.impact, "info")}</p>
          <p class="sentinel-page-description">This request stays on the Gateway allowlist. Reject means the probe is not sent.</p>
        </section>
        <section>
          <h3 class="sentinel-card__title">Policy Checks</h3>
          <ul class="check-list">
            ${["Endpoint Allowlist", "Method Allowlist", "Payload Size", "Redaction", "Injection Filter"].map((name) =>
              `<li><span>${name}</span>${badge("Pass", "success")}</li>`).join("")}
          </ul>
        </section>
        <section>
          <h3 class="sentinel-card__title">Gateway Route Status</h3>
          <ul class="meta-list">
            <li><div><small>Status</small><strong class="tone-success">Ready</strong></div></li>
            <li><div><small>Route</small><span class="mono">api-gateway-prod</span></div></li>
            <li><div><small>Rate Limit</small>30 req/min</div></li>
            <li><div><small>Timeout</small>5s</div></li>
            <li><div><small>Authentication</small>Service Token</div></li>
          </ul>
        </section>
      </div>
      <div class="approval-actions">
        <button class="sentinel-button sentinel-button--approve" data-decide="approve" data-id="${current.id}" ${current.status !== "Pending" ? "disabled" : ""}>Approve</button>
        <button class="sentinel-button sentinel-button--reject" data-decide="reject" data-id="${current.id}" ${current.status !== "Pending" ? "disabled" : ""}>Reject</button>
      </div>
      <p class="sentinel-page-description" style="margin-top:0.8rem">Approving records the decision. The public UI does not forward a live probe.</p>
    </article>` : `<article class="sentinel-card">No requests in this tab.</article>`}`;
}

async function renderReports() {
  const data = await api("/api/reports");
  const kpis = data.kpis || {};
  const compared = data.sast_vs_dast || { sast: 0, dast: 0 };
  const total = (compared.sast || 0) + (compared.dast || 0) || 1;
  const severity = data.severity_open || [];
  const peak = Math.max(...severity.map((row) => row.open), 1);
  const summary = data.summary || [];
  document.getElementById("page").innerHTML = `
    <div class="sentinel-page-header">
      <div><h1 class="sentinel-page-title">Reports</h1></div>
      <div class="toolbar" style="margin:0">
        <select class="sentinel-control"><option>Last 30 Days</option></select>
        <button class="sentinel-button" type="button">Export Report</button>
      </div>
    </div>
    <div class="sentinel-grid grid-5">
      ${metric("Precision", `${kpis.precision ?? 0}%`, `agent verdicts, ${kpis.scored ?? 0} scored`, "icon-green", icon("radar"))}
      ${metric("Recall", `${kpis.recall ?? 0}%`, "agent verdicts vs ground truth", "icon-blue", icon("chart"))}
      ${metric("True Positives", kpis.true_positives ?? 0, "", "icon-green", icon("shield"))}
      ${metric("False Positives", kpis.false_positives ?? 0, "", "icon-orange", icon("code"))}
      ${metric("Abstained", kpis.abstained ?? 0, "scored separately, never as an error", "icon-blue", icon("bot"))}
    </div>
    <div class="sentinel-grid split-reports">
      <article class="sentinel-card">
        <div class="sentinel-card__header"><h2 class="sentinel-card__title">Verdict Distribution</h2></div>
        <div class="chart-frame"><canvas id="verdicts"></canvas></div>
      </article>
      <article class="sentinel-card">
        <div class="sentinel-card__header"><h2 class="sentinel-card__title">Confirmed by ground truth vs by a live probe</h2></div>
        <div class="donut-wrap"><canvas id="sd-donut"></canvas><div class="donut-center"></div></div>
      </article>
    </div>
    <div class="sentinel-grid split-reports">
      <article class="sentinel-card">
        <div class="sentinel-card__header"><h2 class="sentinel-card__title">Open Findings by Severity</h2></div>
        ${severity.map((row) => `<div class="severity-bar"><strong>${esc(row.severity)}</strong> <span class="mono">${row.open}</span>
          <div class="severity-bar__track"><i style="width:${Math.round((row.open / peak) * 100)}%"></i></div>
        </div>`).join("")}
      </article>
      <article class="sentinel-card">
        <div class="banner">Precision and recall measure the <strong>agent's verdicts</strong> against BenchmarkJava ground truth, which is joined only after the reports are written. A running app has no ground truth, so the DAST row reports how many verdicts a live response checked instead of a confusion matrix.</div>
        <div class="sentinel-table-wrap" style="border:0;margin-top:.8rem">
          <table class="sentinel-table sentinel-table--wrap"><thead><tr>
            <th>Category</th><th>Precision</th><th>Recall</th><th>F1</th><th>TP</th><th>FP</th><th>FN</th><th>Abstain</th>
          </tr></thead><tbody>
            ${summary.map((row) => `<tr>
              <td class="wrap">${esc(row.category)}</td>
              <td>${row.precision ?? "—"}</td><td>${row.recall ?? "—"}</td>
              <td>${row.f1 ?? "—"}</td><td>${row.tp ?? "—"}</td><td>${row.fp ?? "—"}</td><td>${row.fn ?? "—"}</td>
              <td>${row.abstain ?? (row.verified !== undefined ? `${row.verified} verified, ${row.changed_by_probe} revised` : "—")}</td>
            </tr>`).join("")}
          </tbody></table>
        </div>
        <p class="sentinel-page-description">Source: ${(data.sources || []).map((row) => `<code>${esc(row)}</code>`).join(", ")}</p>
      </article>
    </div>`;
  const ctx = document.getElementById("verdicts");
  const distribution = Object.entries(data.verdict_distribution || {});
  if (ctx && window.Chart && distribution.length) {
    const palette = {
      confirmed_vulnerable: "#ef4444",
      likely_vulnerable: "#f97316",
      likely_false_positive: "#f59e0b",
      not_vulnerable: "#16a34a",
      insufficient_evidence: "#94a3b8",
    };
    const tick = getComputedStyle(document.documentElement).getPropertyValue("--sentinel-text-muted").trim() || "#94a3b8";
    state.charts.push(new Chart(ctx, {
      type: "bar",
      data: {
        labels: distribution.map(([key]) => key.replace(/_/g, " ")),
        datasets: [{ label: "Verdicts", data: distribution.map(([, value]) => value), backgroundColor: distribution.map(([key]) => palette[key] || "#94a3b8") }],
      },
      options: {
        plugins: { legend: { display: false } },
        maintainAspectRatio: false,
        scales: {
          x: { ticks: { color: tick }, grid: { color: "transparent" } },
          y: { beginAtZero: true, ticks: { precision: 0, color: tick }, grid: { color: "rgb(148 163 184 / 0.2)" } },
        },
      },
    }));
  } else if (ctx) {
    ctx.parentElement.innerHTML = `<p class="sentinel-page-description">No scored verdict distribution is committed yet.</p>`;
  }
  if ((compared.sast || 0) + (compared.dast || 0) > 0) {
    donut("sd-donut", ["SAST true positives", "DAST verified by probe"], [compared.sast, compared.dast], ["#2563eb", "#16a34a"], `<strong>${total}</strong><small>Confirmed</small>`);
  }
}

async function renderKnowledge() {
  const data = await api("/api/knowledge");
  const tab = state.tab.knowledge || "kb";
  const page = pager(tab === "kb" ? "kb" : "audit", tab === "kb" ? data.documents.length : data.audit.length, 8);
  const docs = data.documents.slice(page.start, page.end);
  const audit = data.audit.slice(page.start, page.end);
  document.getElementById("page").innerHTML = `
    <div class="sentinel-page-header">
      <div>
        <h1 class="sentinel-page-title">Knowledge Base & Audit</h1>
        <div class="sentinel-tabs">
          <button class="sentinel-tab" data-tab="knowledge" data-value="kb" aria-selected="${tab === "kb"}">Knowledge Base</button>
          <button class="sentinel-tab" data-tab="knowledge" data-value="audit" aria-selected="${tab === "audit"}">Audit Log</button>
        </div>
      </div>
    </div>
    <div class="sentinel-grid sentinel-grid--metrics">
      ${metric("KB Entries", data.entries, "Total knowledge base entries", "icon-blue", icon("book"))}
      ${metric("CWE Coverage", data.cwe_coverage, "Unique CWE IDs covered", "icon-green", icon("shield"))}
      ${metric("OWASP Categories", data.owasp_categories, "OWASP Top 10 categories", "icon-purple", icon("radar"))}
      ${metric("Last Updated", "Today", data.updated, "icon-orange", icon("chart"))}
    </div>
    ${tab === "kb" ? `
      <div class="toolbar">
        <input class="sentinel-control" placeholder="Search knowledge base..." />
        <select class="sentinel-control"><option>All Types</option></select>
        <select class="sentinel-control"><option>All Categories</option></select>
      </div>
      <div class="sentinel-table-wrap">
        <table class="sentinel-table"><thead><tr>
          <th>ID</th><th>CWE / OWASP</th><th>Title</th><th>Required Evidence</th><th>False-Positive Indicators</th><th>Safe Verification</th><th>Remediation</th>
        </tr></thead><tbody>
          ${docs.map((row) => `<tr>
            <td class="mono">${esc(row.id)}</td>
            <td><a class="linkish" href="#">${esc(row.cwe)}</a><br><small>${esc(row.owasp)}</small></td>
            <td>${esc(row.title)}</td><td>${esc(row.required_evidence)}</td>
            <td>${esc(row.fp_indicators)}</td><td>${esc(row.safe_verification)}</td>
            <td>${esc(row.remediation)}</td>
          </tr>`).join("")}
        </tbody></table>
        ${page.html}
      </div>` : `
      <article class="sentinel-card" style="margin-top:1rem">
        <div class="sentinel-card__header"><h2 class="sentinel-card__title">Audit Log</h2></div>
        <div class="sentinel-table-wrap">
          <table class="sentinel-table"><thead><tr>
            <th>Timestamp</th><th>Run ID</th><th>Finding ID</th><th>Agent Decision</th><th>Approval</th><th>Gateway Status</th><th>Latency</th><th>Redaction Event</th>
          </tr></thead><tbody>
            ${audit.map((row) => `<tr>
              <td>${esc(row.timestamp)}</td><td class="mono">${esc(row.run_id)}</td><td class="mono">${esc(row.finding_id)}</td>
              <td>${badge(row.decision)}</td><td>${badge(row.approval)}</td><td>${badge(row.gateway)}</td>
              <td>${esc(row.latency)}</td><td>${badge(row.redaction)}</td>
            </tr>`).join("")}
          </tbody></table>
          ${page.html}
        </div>
      </article>`}`;
}

function renderSourceBlock(source) {
  if (!source || !source.lines?.length) {
    return `<pre class="sentinel-code">Source file is not available in this workspace.</pre>`;
  }
  return `<pre class="sentinel-code sentinel-code--source">${source.lines.map((row) =>
    `<span class="sentinel-code__line${row.highlight ? " is-hit" : ""}"><span class="sentinel-code__n">${row.n}</span><span>${esc(row.text)}</span></span>`
  ).join("")}</pre>`;
}

async function loadSource(findingId) {
  const res = await fetch(`/api/source/${encodeURIComponent(findingId)}`);
  if (!res.ok) return null;
  return res.json();
}

async function fillSource(findingId, targetId) {
  const host = document.getElementById(targetId);
  if (!host) return;
  host.innerHTML = `<p class="sentinel-page-description">Loading source…</p>`;
  const source = await loadSource(findingId);
  host.innerHTML = renderSourceBlock(source);
  const hit = host.querySelector(".is-hit");
  if (hit) hit.scrollIntoView({ block: "center" });
}

function kbList(items) {
  if (!items?.length) {
    return `<p class="sentinel-page-description">No knowledge entries were retrieved for this finding.</p>`;
  }
  return `<ul class="evidence-list">${items.map((row) =>
    `<li><span class="check-dot">${icon("check")}</span><div><strong>${esc(row.title || row.document_id)}</strong><br><small>${esc(row.source || row.document_id || "")}</small></div></li>`
  ).join("")}</ul>`;
}

function openRunDrawer(run) {
  if (!run) return;
  const drawer = document.getElementById("drawer");
  drawer.hidden = false;
  drawer.classList.add("is-open");
  drawer.classList.remove("drawer-hidden");
  document.getElementById("page").classList.add("with-drawer");
  drawer.innerHTML = `
    <div class="sentinel-card__header"><h2 class="sentinel-card__title">Run Details</h2>
      <button class="sentinel-icon-btn" data-close-drawer type="button">✕</button></div>
    <p><strong class="mono">${esc(run.id)}</strong> ${badge(run.status)}</p>
    <dl class="kv">
      <div><dt>Status</dt><dd>${badge(run.status)}</dd></div>
      <div><dt>Branch</dt><dd>${icon("branch")} ${esc(run.branch)}</dd></div>
      <div><dt>Commit</dt><dd>${icon("link")} ${esc(run.commit)}</dd></div>
      <div><dt>Triggered By</dt><dd>${esc(run.triggered_by)}</dd></div>
      <div><dt>Tool</dt><dd>${toolMark(run.tool)}</dd></div>
      <div><dt>Ruleset</dt><dd class="mono">${esc(run.ruleset)}</dd></div>
      <div><dt>Duration</dt><dd>${esc(run.duration)}</dd></div>
    </dl>
    <div class="run-counts">
      <div><strong>${run.raw_findings ?? "—"}</strong><small>Raw Findings</small></div>
      <div><strong>${run.normalized ?? "—"}</strong><small>Normalized</small></div>
      <div><strong>${run.agent_analyzed ?? "—"}</strong><small>Agent Analyzed</small></div>
    </div>
    ${run.precision != null || run.recall != null ? `
    <h3 class="sentinel-card__title">Evaluation (Agent Results)</h3>
    <dl class="kv">
      <div><dt>Precision</dt><dd>${run.precision != null ? `${run.precision}%` : "—"}</dd></div>
      <div><dt>Recall</dt><dd>${run.recall != null ? `${run.recall}%` : "—"}</dd></div>
    </dl>` : ""}
    <h3 class="sentinel-card__title">Artifacts</h3>
    <button class="artifact-link" type="button" data-toast="${esc(run.scan_output || "Artifact path is not published.")}">
      <span>${icon("file")} Scan Output</span>${icon("external")}
    </button>
    <button class="artifact-link" type="button" data-toast="${esc(run.final_report || "Artifact path is not published.")}">
      <span>${icon("file")} Final Report</span>${icon("external")}
    </button>
    <div class="approval-actions">
      <button class="sentinel-button" type="button" data-view-run-findings="${esc(run.id)}">View Findings</button>
      <button class="sentinel-button sentinel-button--outline" type="button" data-toast="Reports stay in the committed artifacts folder.">${icon("download")} Download Report</button>
    </div>`;
}

function openDrawer(finding, kind) {
  const drawer = document.getElementById("drawer");
  drawer.hidden = false;
  drawer.classList.add("is-open");
  drawer.classList.remove("drawer-hidden");
  document.getElementById("page").classList.add("with-drawer");
  if (kind === "sast") {
    const rem = (finding.remediation || []).join(" ") || finding.explanation || "No remediation was recorded for this finding.";
    drawer.innerHTML = `
      <div class="sentinel-card__header"><h2 class="sentinel-card__title">Finding Details</h2>
        <button class="sentinel-icon-btn" data-close-drawer type="button">✕</button></div>
      <p><strong>${finding.id}</strong> ${badge(finding.severity)}</p>
      <dl class="kv">
        <div><dt>CWE</dt><dd>${esc(finding.cwe)}</dd></div>
        <div><dt>Rule</dt><dd class="mono">${esc(finding.rule || finding.title || "—")}</dd></div>
        <div><dt>File / Location</dt><dd><a class="linkish" href="#source-${finding.id}" data-open-source="${finding.id}">${esc(finding.file)}</a></dd></div>
        <div><dt>Agent Verdict</dt><dd>${badge(finding.verdict)}</dd></div>
        <div><dt>Confidence</dt><dd>${finding.confidence}%</dd></div>
      </dl>
      <button class="accordion" type="button" data-acc="code" aria-expanded="true">Code Snippet <span>▾</span></button>
      <div class="accordion-body is-open" data-acc-body="code">
        <div id="drawer-source"></div>
      </div>
      <button class="accordion" type="button" data-acc="flow" aria-expanded="false">Data Flow <span>▸</span></button>
      <div class="accordion-body" data-acc-body="flow">
        <p class="sentinel-page-description">${esc((finding.tools || []).join(" · ") || "Scanner evidence")}</p>
        <p class="sentinel-page-description">${esc(finding.excerpt || "")}</p>
      </div>
      <button class="accordion" type="button" data-acc="kb" aria-expanded="false">Matched KB Entries <span>▸</span></button>
      <div class="accordion-body" data-acc-body="kb">${kbList(finding.kb)}</div>
      <button class="accordion" type="button" data-acc="logs" aria-expanded="false">Supporting Logs <span>▸</span></button>
      <div class="accordion-body" data-acc-body="logs">
        <p class="sentinel-page-description">${esc(finding.report_id || finding.group_id || "")}</p>
      </div>
      <h3 class="sentinel-card__title">Recommended Remediation</h3>
      <p class="sentinel-page-description">${esc(rem)}</p>
      <div class="approval-actions">
        <button class="sentinel-button" type="button" data-open-agent="${finding.id}">Open Agent Analysis ${icon("external")}</button>
      </div>
      <div class="banner" style="margin-top:1rem">
        <div><strong>Ground Truth (Evaluation Only)</strong><br>
        <span class="${finding.ground_truth ? "tone-success" : ""}">${esc(finding.ground_truth_label)}</span><br>
        <small>Used for evaluation. Not provided as Agent input.</small></div>
      </div>`;
    fillSource(finding.id, "drawer-source");
  } else {
    drawer.innerHTML = `
      <div class="sentinel-card__header"><h2 class="sentinel-card__title">Finding Details</h2>
        <button class="sentinel-icon-btn" data-close-drawer type="button">✕</button></div>
      <p><strong>${finding.id}</strong> ${badge(finding.severity)}</p>
      <dl class="kv">
        <div><dt>Endpoint</dt><dd class="mono">${esc(finding.endpoint)}</dd></div>
        <div><dt>Method</dt><dd>${esc(finding.method)}</dd></div>
        <div><dt>Agent Verdict</dt><dd>${badge(finding.verdict)}${finding.verdict_changed ? ` <small>revised from ${esc(finding.verdict_before)} after the probe</small>` : ""}</dd></div>
        <div><dt>Confidence</dt><dd>${finding.confidence}%</dd></div>
      </dl>
      ${finding.verdict_rationale ? `<p class="sentinel-page-description">${esc(finding.verdict_rationale)}</p>` : ""}
      <h3 class="sentinel-card__title">Live probe through the gateway</h3>
      <p>${badge(finding.response, finding.verified ? "success" : "muted")}</p>
      <pre class="sentinel-code">${esc(finding.request || "")}</pre>
      ${finding.observed?.length
        ? `<ul>${finding.observed.map((row) => `<li>${esc(row)}</li>`).join("")}</ul>`
        : `<p class="sentinel-page-description">${esc(finding.unverified_reason || "No probe was attempted for this finding.")}</p>`}
      <h3 class="sentinel-card__title">Scanner evidence</h3>
      <pre class="sentinel-code">${esc(finding.evidence || "")}</pre>
      <p class="sentinel-page-description">Analysed by ${esc(finding.provider || "—")} · ${esc(finding.model || "—")}</p>
      <div class="approval-actions" style="margin-top:1rem">
        <button class="sentinel-button" type="button" data-open-agent="${finding.id}">Open Agent Analysis</button>
        <button class="sentinel-button sentinel-button--outline" type="button" data-tab="dast" data-value="probes">Propose Safe Probe</button>
      </div>`;
  }
}

function openEndpointDrawer(endpoint) {
  if (!endpoint) return;
  const drawer = document.getElementById("drawer");
  drawer.hidden = false;
  drawer.classList.add("is-open");
  drawer.classList.remove("drawer-hidden");
  document.getElementById("page").classList.add("with-drawer");
  drawer.innerHTML = `
    <div class="sentinel-card__header"><h2 class="sentinel-card__title">Endpoint Details</h2>
      <button class="sentinel-icon-btn" data-close-drawer type="button">✕</button></div>
    <p class="mono"><strong>${esc(endpoint.endpoint)}</strong> ${badge(endpoint.method)}</p>
    <dl class="kv">
      <div><dt>Authentication</dt><dd class="tone-success">${esc(endpoint.auth)}</dd></div>
      <div><dt>Status</dt><dd>${badge(endpoint.status, endpoint.status === "Tested" ? "success" : endpoint.status === "Partial" ? "warning" : "muted")}</dd></div>
      <div><dt>Source</dt><dd>${esc(endpoint.source)}</dd></div>
      <div><dt>Requests</dt><dd>${endpoint.requests}</dd></div>
      <div><dt>Last Response</dt><dd>${esc(endpoint.response || "—")}</dd></div>
      <div><dt>Findings</dt><dd class="${endpoint.findings ? "tone-critical" : ""}">${endpoint.findings}</dd></div>
      <div><dt>Last Seen</dt><dd>${esc(endpoint.last_seen || "—")}</dd></div>
    </dl>
    <p>${(endpoint.tags || []).map((tag) => badge(tag, "muted")).join(" ")}</p>
    <div class="approval-actions">
      <button class="sentinel-button" type="button" data-tab="dast" data-value="findings">View Findings</button>
      <button class="sentinel-button sentinel-button--outline" type="button" data-tab="dast" data-value="probes">Propose Safe Probe</button>
    </div>`;
}

function openProbeDrawer(probe) {
  if (!probe) return;
  const drawer = document.getElementById("drawer");
  drawer.hidden = false;
  drawer.classList.add("is-open");
  drawer.classList.remove("drawer-hidden");
  document.getElementById("page").classList.add("with-drawer");
  const preview = JSON.stringify({ method: probe.method, endpoint: probe.path || probe.endpoint, payload: probe.payload || null }, null, 2);
  drawer.innerHTML = `
    <div class="sentinel-card__header"><h2 class="sentinel-card__title">Safe Probe Details</h2>
      <span>${badge(probe.status)}</span>
      <button class="sentinel-icon-btn" data-close-drawer type="button">✕</button></div>
    <dl class="kv">
      <div><dt>Request ID</dt><dd class="mono">${esc(probe.id)}</dd></div>
      <div><dt>Linked Finding</dt><dd class="mono">${esc(probe.finding_id)}</dd></div>
      <div><dt>Method</dt><dd>${esc(probe.method)}</dd></div>
      <div><dt>Endpoint</dt><dd class="mono">${esc(probe.path || probe.endpoint)} ${probe.allowlisted ? badge("Allowlisted", "success") : ""}</dd></div>
    </dl>
    <h3 class="sentinel-card__title">Harmless Probe (Sanitized Preview)</h3>
    <pre class="sentinel-code">${esc(preview)}</pre>
    <p class="sentinel-page-description">${esc(probe.purpose || "")}</p>
    <p>${badge(`${probe.risk} / ${probe.impact || "Read Only"}`, probe.risk === "High" ? "critical" : "info")}</p>
    <ul class="check-list">
      ${["Endpoint Allowlist", "Method Allowlist", "Payload Safety", "Rate Limit"].map((name) =>
        `<li><span>${name}</span>${badge(probe.injection_flagged ? "Fail" : "Pass", probe.injection_flagged ? "critical" : "success")}</li>`).join("")}
    </ul>
    <div class="approval-actions">
      <button class="sentinel-button" type="button" data-jump="approval">Review Approval</button>
    </div>`;
}

function bindTableSearch() {
  document.querySelectorAll("[data-filter-table]").forEach((input) => {
    input.addEventListener("input", () => {
      const query = input.value.toLowerCase();
      const body = document.getElementById(input.dataset.filterTable);
      if (!body) return;
      body.querySelectorAll("tr").forEach((row) => {
        row.hidden = Boolean(query) && !row.textContent.toLowerCase().includes(query);
      });
    });
  });
}

function closeDrawer() {
  const drawer = document.getElementById("drawer");
  drawer.hidden = true;
  drawer.classList.remove("is-open");
  drawer.classList.add("drawer-hidden");
  document.getElementById("page").classList.remove("with-drawer");
}

async function render() {
  destroyCharts();
  closeDrawer();
  const page = document.getElementById("page");
  page.innerHTML = `<p class="sentinel-page-description">Loading…</p>`;
  const views = {
    overview: renderOverview,
    sast: renderSast,
    dast: renderDast,
    agent: renderAgent,
    approval: renderApproval,
    reports: renderReports,
    knowledge: renderKnowledge,
  };
  await (views[state.page] || renderOverview)();
}

function bind() {
  renderNav();
  document.getElementById("nav").addEventListener("click", (event) => {
    const link = event.target.closest("[data-page]");
    if (!link) return;
    event.preventDefault();
    state.selected = null;
    setPage(link.dataset.page);
  });
  document.getElementById("collapse-btn").addEventListener("click", () => {
    document.getElementById("shell").classList.toggle("is-collapsed");
  });
  document.getElementById("menu-btn").addEventListener("click", () => {
    document.getElementById("shell").classList.toggle("is-collapsed");
  });
  document.getElementById("settings-btn").addEventListener("click", () => {
    toast("Settings stay local. No secrets are shown.");
  });
  document.getElementById("page").addEventListener("click", async (event) => {
    const notice = event.target.closest("[data-toast]");
    if (notice) {
      toast(notice.dataset.toast);
      return;
    }
    const tab = event.target.closest("[data-tab]");
    if (tab) {
      if (tab.dataset.tab === "dast") {
        state.selectedEndpoint = null;
        state.selectedProbe = null;
      }
      if (tab.dataset.tab === "sast") {
        state.selectedRun = null;
        if (tab.dataset.value === "runs") state.selected = null;
        if (tab.dataset.value === "findings") state.sastRun = state.sastRun || "";
      }
      state.tab[tab.dataset.tab] = tab.dataset.value;
      render();
      return;
    }
    const pagerBtn = event.target.closest("[data-pager]");
    if (pagerBtn) {
      state.pageIndex[pagerBtn.dataset.pager] = Number(pagerBtn.dataset.n);
      render();
      return;
    }
    const openEndpoint = event.target.closest("[data-open-endpoint]");
    if (openEndpoint) {
      const payload = await api("/api/dast");
      state.selectedEndpoint = payload.endpoint_rows.find((row) => row.id === openEndpoint.dataset.openEndpoint);
      state.selectedProbe = null;
      openEndpointDrawer(state.selectedEndpoint);
      return;
    }
    const openProbe = event.target.closest("[data-open-probe]");
    if (openProbe) {
      const payload = await api("/api/dast");
      state.selectedProbe = payload.probe_rows.find((row) => row.id === openProbe.dataset.openProbe);
      state.selectedEndpoint = null;
      openProbeDrawer(state.selectedProbe);
      return;
    }
    const openRun = event.target.closest("[data-open-run]");
    if (openRun) {
      const payload = await api("/api/sast");
      state.selectedRun = payload.runs.find((row) => row.id === openRun.dataset.openRun);
      document.querySelectorAll("[data-open-run]").forEach((row) => {
        row.classList.toggle("is-selected", row.dataset.openRun === openRun.dataset.openRun);
      });
      openRunDrawer(state.selectedRun);
      return;
    }
    const viewRun = event.target.closest("[data-view-run-findings]");
    if (viewRun) {
      state.tab.sast = "findings";
      state.sastRun = viewRun.dataset.viewRunFindings;
      state.selectedRun = null;
      render();
      return;
    }
    const openAgent = event.target.closest("[data-open-agent]");
    if (openAgent) {
      const [sast, dast] = await Promise.all([api("/api/sast"), api("/api/dast")]);
      state.selected = [...sast.findings, ...dast.findings].find((row) => row.id === openAgent.dataset.openAgent);
      setPage("agent", { finding: state.selected });
      return;
    }
    const jump = event.target.closest("[data-jump]");
    if (jump && !jump.dataset.id) {
      setPage(jump.dataset.jump);
      return;
    }
    const open = event.target.closest("[data-open]");
    if (open) {
      const kind = open.dataset.open;
      const payload = await api(kind === "sast" ? "/api/sast" : "/api/dast");
      state.selected = payload.findings.find((row) => row.id === open.dataset.id);
      if (event.detail === 2) {
        setPage("agent", { finding: state.selected });
        return;
      }
      document.getElementById("page").classList.add("with-drawer");
      openDrawer(state.selected, kind);
      return;
    }
    const acc = event.target.closest("[data-acc]");
    if (acc) {
      const open = acc.getAttribute("aria-expanded") !== "true";
      acc.setAttribute("aria-expanded", String(open));
      acc.querySelector("span").textContent = open ? "▾" : "▸";
      const body = document.querySelector(`[data-acc-body="${acc.dataset.acc}"]`);
      if (body) body.classList.toggle("is-open", open);
      return;
    }
    const sourceLink = event.target.closest("[data-open-source]");
    if (sourceLink) {
      event.preventDefault();
      const code = document.querySelector('[data-acc="code"]');
      if (code && code.getAttribute("aria-expanded") !== "true") code.click();
      document.getElementById("drawer-source")?.scrollIntoView({ block: "nearest" });
      return;
    }
    const decide = event.target.closest("[data-decide]");
    if (decide) {
      const approved = decide.dataset.decide === "approve";
      const res = await fetch(`/api/approval/${decide.dataset.id}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ approved }),
      });
      const body = await res.json();
      delete state.cache["/api/approval"];
      delete state.cache["/api/dast"];
      toast(body.note || body.status);
      render();
    }
  });
  document.getElementById("drawer").addEventListener("click", async (event) => {
    const panel = event.currentTarget;
    if (event.target.closest("[data-close-drawer]")) closeDrawer();
    const notice = event.target.closest("[data-toast]");
    if (notice) {
      toast(notice.dataset.toast);
      return;
    }
    const viewRun = event.target.closest("[data-view-run-findings]");
    if (viewRun) {
      state.tab.sast = "findings";
      state.sastRun = viewRun.dataset.viewRunFindings;
      state.selectedRun = null;
      render();
      return;
    }
    const openAgent = event.target.closest("[data-open-agent]");
    if (openAgent) {
      const [sast, dast] = await Promise.all([api("/api/sast"), api("/api/dast")]);
      state.selected = [...sast.findings, ...dast.findings].find((row) => row.id === openAgent.dataset.openAgent);
      setPage("agent", { finding: state.selected });
      return;
    }
    const acc = event.target.closest("[data-acc]");
    if (acc) {
      const open = acc.getAttribute("aria-expanded") !== "true";
      acc.setAttribute("aria-expanded", String(open));
      const mark = acc.querySelector("span");
      if (mark) mark.textContent = open ? "▾" : "▸";
      const body = panel.querySelector(`[data-acc-body="${acc.dataset.acc}"]`);
      if (body) body.classList.toggle("is-open", open);
    }
    if (event.target.closest("[data-open-source]")) {
      event.preventDefault();
      const code = panel.querySelector('[data-acc="code"]');
      if (code && code.getAttribute("aria-expanded") !== "true") code.click();
      document.getElementById("drawer-source")?.scrollIntoView({ block: "nearest" });
    }
  });
  const search = document.getElementById("search");
  const results = document.getElementById("search-results");
  const closeSearch = () => { results.hidden = true; };
  const runSearch = async (query) => {
    if (!query.trim()) {
      results.hidden = true;
      results.innerHTML = "";
      return;
    }
    const data = await fetch(`/api/search?q=${encodeURIComponent(query)}`).then((r) => r.json());
    results.innerHTML = data.results.length
      ? data.results.map((row) =>
          `<button type="button" data-jump="${row.page}" data-id="${row.id}">${esc(row.kind)} · ${esc(row.title)}</button>`
        ).join("")
      : "<p class='sentinel-page-description'>No matches</p>";
    results.hidden = false;
  };
  search.addEventListener("input", (event) => { runSearch(event.target.value); });
  search.addEventListener("focus", () => {
    if (search.value.trim()) runSearch(search.value);
  });
  document.addEventListener("keydown", (event) => {
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
      event.preventDefault();
      search.focus();
    }
    if (event.key === "Escape") {
      closeSearch();
      search.blur();
      closeDrawer();
    }
  });
  document.addEventListener("pointerdown", (event) => {
    if (!event.target.closest(".sentinel-search-wrap")) closeSearch();
  });
  results.addEventListener("click", (event) => {
    const btn = event.target.closest("[data-jump]");
    if (!btn) return;
    closeSearch();
    search.value = "";
    state.selected = { id: btn.dataset.id };
    setPage(btn.dataset.jump);
  });
  document.getElementById("theme-btn").addEventListener("click", () => {
    applyTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark");
  });
}

function applyTheme(theme) {
  const next = theme === "dark" ? "dark" : "light";
  document.documentElement.dataset.theme = next;
  localStorage.setItem("sentinel-theme", next);
  const button = document.getElementById("theme-btn");
  if (button) button.setAttribute("aria-pressed", String(next === "dark"));
}

document.addEventListener("DOMContentLoaded", () => {
  applyTheme(localStorage.getItem("sentinel-theme") || "light");
  const first = location.pathname.replace(/^\//, "") || "overview";
  state.page = PAGES.some(([id]) => id === first) ? first : "overview";
  bind();
  render();
});
