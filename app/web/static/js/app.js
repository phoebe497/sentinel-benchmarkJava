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
  selectedKb: null,
  sastRun: "",
  cache: {},
  pageIndex: {},
  charts: [],
  chat: {},
  gateway: {
    routeId: "health",
    purpose: "Verify gateway health response and filtering.",
    invalidKey: false,
    approved: false,
    scenario: "",
    result: null,
    analysis: null,
    busy: false,
  },
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
    hourglass: '<path d="M6 3h12M6 21h12M8 3v4l4 4 4-4V3M8 21v-4l4-4 4 4v4"/>',
    xCircle: '<circle cx="12" cy="12" r="9"/><path d="m9 9 6 6M15 9l-6 6"/>',
    play: '<polygon points="8 5 19 12 8 19"/>',
    x: '<path d="M18 6 6 18M6 6l12 12"/>',
    gauge: '<path d="M5 19a8.5 8.5 0 1 1 14 0"/><path d="m12 16 4-5"/>',
    ban: '<circle cx="12" cy="12" r="9"/><path d="m7 7 10 10"/>',
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
    Executed: "success",
    Queued: "warning",
    Active: "success",
    Clean: "success",
    Flagged: "critical",
    Pass: "success",
    Fail: "critical",
    Deny: "critical",
    "Not Executed": "muted",
    "Probe Executed": "info",
    "Response Redacted": "info",
    "Prompt Injection": "critical",
    User: "info",
    Policy: "muted",
    "Read Only": "info",
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

function metric(label, value, delta, iconClass, svg, jump, deltaUp) {
  const tone = deltaUp === true ? "is-up" : deltaUp === false ? "is-down" : "";
  const dest = jump ? ` data-jump="${jump.page}"${jump.tab ? ` data-tab-target="${jump.tab}"` : ""}` : "";
  return `
    <article class="sentinel-card sentinel-metric${jump ? " is-clickable" : ""}"${dest}>
      <div>
        <div class="sentinel-metric__label">${label}</div>
        <div class="sentinel-metric__value">${esc(value)}</div>
        ${delta ? `<div class="sentinel-metric__delta ${tone}">${esc(delta)}</div>` : ""}
      </div>
      <div class="sentinel-metric__icon ${iconClass}">${svg}</div>
    </article>`;
}

async function downloadExport(kind, format) {
  const res = await fetch(`/api/export/${kind}?format=${format}`);
  if (!res.ok) {
    toast("Export is not available for this view.");
    return;
  }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `sentinel-${kind}.${format}`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
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
      <button class="sentinel-button sentinel-button--outline sentinel-button--compact" type="button" data-toast="Layout stays as the committed pipeline view.">${icon("list")} Customize Overview</button>
    </div>
    <div class="sentinel-grid sentinel-grid--metrics">
      ${metric("Total Findings", data.total_findings, "from committed scanner artifacts", "icon-blue", icon("fileSearch"), { page: "sast", tab: "findings" })}
      ${metric("True Vulnerabilities", data.true_vulnerabilities, data.true_vulnerability_note || "SAST TP + DAST confirmed", "icon-green", icon("shieldCheck"), { page: "reports" })}
      ${metric("Pending Approval", data.pending_approval, "human gate before Gateway", "icon-orange", icon("hourglass"), { page: "approval" })}
      ${metric("Active Scans", data.active_scans, "no scan is running in this build", "icon-purple", icon("target"), { page: "dast" })}
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
          <button class="linkish" type="button" data-jump="sast" data-tab-target="runs">View all runs →</button></div>
        <div class="sentinel-table-wrap">
          <table class="sentinel-table"><thead><tr>
            <th>Run ID</th><th>Type</th><th>Target / Project</th><th>Status</th><th>Findings</th><th>Started At</th>
          </tr></thead><tbody>
            ${data.runs.map((run) => `<tr class="is-clickable" data-jump="${run.page || "sast"}" data-tab-target="${run.type === "DAST" ? "findings" : "runs"}">
              <td class="mono">${esc(run.id)}</td><td>${badge(run.type)}</td><td>${esc(run.target)}</td>
              <td>${badge(run.status)}</td><td>${run.findings ?? "—"}</td><td>${esc(run.started)}</td>
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

function filterSelect(tableId, label, values, key, iconName) {
  const options = [...new Set((values || []).map((item) => String(item || "")).filter(Boolean))];
  return `<label class="select-field">${iconName ? icon(iconName) : ""}<select class="sentinel-control" data-col-filter="${key}" data-filter-table="${tableId}">
    <option value="">${esc(label)}</option>
    ${options.map((opt) => `<option value="${esc(opt)}">${esc(opt)}</option>`).join("")}
  </select></label>`;
}

function dash(value) {
  return value == null || value === "" ? "—" : value;
}

function firstItem(items) {
  return items && items.length ? items[0] : "—";
}

function bulletList(items, empty) {
  if (!items?.length) {
    return `<p class="sentinel-page-description">${esc(empty || "None recorded.")}</p>`;
  }
  return `<ul class="evidence-list">${items.map((item) => `<li><span class="check-dot">${icon("check")}</span><span>${esc(item)}</span></li>`).join("")}</ul>`;
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
      ${selectField("Corpus", "branch")}
      ${selectField("Date Range", "calendar")}
    </div>
    <div class="sentinel-table-wrap">
      <table class="sentinel-table"><thead><tr>
        <th>Run ID</th><th>Corpus / Commit</th><th>Tool</th><th>Ruleset</th><th>Status</th><th>Duration</th><th>Findings</th><th>Agent Results</th><th>Started At</th><th></th>
      </tr></thead>
      <tbody id="sast-run-rows">
        ${rows.map((row) => `<tr class="is-clickable${state.selectedRun?.id === row.id ? " is-selected" : ""}" data-open-run="${row.id}">
          <td class="mono">${esc(row.id)}</td>
          <td class="stack-cell">
            <span>${icon("branch")} ${esc(row.branch)}</span>
            <small title="${esc(row.commit_full || row.commit)}">${icon("link")} ${esc(row.commit)}</small>
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
      ${metric("Total Findings", data.total, `${data.total} BenchmarkJava analysis groups`, "icon-blue", icon("fileSearch"))}
      ${metric("Corpus true", data.true_vulnerabilities, `BenchmarkJava ground truth on those ${data.total} tests`, "icon-green", icon("shieldCheck"))}
      ${metric("Analysed", data.analysed ?? 0, `${data.not_analysed ?? 0} groups still have no verdict`, "icon-orange", icon("users"))}
      ${metric("Scored FP", data.false_positives, `vs ground truth on the newest scored run (n=${data.scored ?? 0})`, "icon-purple", icon("target"))}
    </div>
    <div class="toolbar">
      ${searchField("sast-find-rows", "Search finding...")}
      ${selectField(runFilter || "Run")}
      ${selectField("Severity")}
      ${selectField("CWE")}
      ${selectField("Agent Verdict")}
      ${selectField("Confidence")}
      <button class="sentinel-button sentinel-button--outline sentinel-button--compact toolbar__action" type="button" data-export="sast" data-format="csv">${icon("download")} Export Findings</button>
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
            <div class="probe-stat"><span>Findings probed</span><strong>${data.verified_count} <small>on ${data.probed_endpoints ?? "—"} endpoints</small></strong></div>
            <div class="probe-stat"><span>Verdicts changed after probe</span><strong>${data.revised_count}</strong></div>
            <p class="sentinel-page-description">ZAP scan: ${esc(data.started)}${data.run_id ? ` · agent run <code>${esc(data.run_id)}</code>` : ""}</p>
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
      ${metric("Probed", stats.verified, "live response reached the endpoint — not a true positive", "icon-green", icon("shieldCheck"))}
      ${metric("Needs Review", stats.needs_review, "insufficient evidence", "icon-purple", icon("userSquare"))}
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
          <li><span class="meta-icon icon-blue">${icon(finding.kind === "DAST" ? "globe" : "file")}</span><div><small>${finding.kind === "DAST" ? "Endpoint" : "File"}</small><span class="mono path-break" title="${esc(finding.endpoint || finding.file)}">${esc(finding.endpoint || finding.file)}</span></div></li>
          <li><span class="meta-icon icon-blue">${icon(finding.method ? "code" : "hash")}</span><div><small>${finding.method ? "Method" : "CWE"}</small><span class="mono">${esc(finding.method || finding.cwe)}</span></div></li>
          <li><span class="meta-icon icon-orange">${icon("alertCircle")}</span><div><small>Severity</small>${badge(finding.severity)}</div></li>
          <li><span class="meta-icon icon-purple">${icon("hash")}</span><div><small>Run ID</small><span class="mono path-break">${esc(finding.run_id)}</span></div></li>
        </ul>
      </article>
      <article class="sentinel-card">
        <div class="sentinel-card__header"><h2 class="sentinel-card__title">Matched Knowledge Base Entries</h2>
          <a class="linkish" href="/knowledge">View All Matches →</a></div>
        <div class="sentinel-table-wrap" style="border:0">
          <table class="sentinel-table sentinel-table--wrap"><thead><tr><th>ID</th><th>CWE</th><th>Title</th><th>Score</th></tr></thead>
          <tbody>${data.knowledge.map((row) => `<tr>
            <td class="mono">${esc(row.id)}</td>
            <td class="mono">${esc(row.cwe)}</td>
            <td class="wrap-cell">${esc(row.title)}</td>
            <td>${row.score}%</td>
          </tr>`).join("")}</tbody></table>
        </div>
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
          <p class="sentinel-page-description">${data.chat_mode === "live"
            ? `Grounded LLM (${esc(data.chat_model)}): answers this finding only, with citations from evidence, KB, and the baked report.`
            : "Follow-up on this finding only: explain, verify, or fix from the baked report. This does not run a new analysis."}</p>
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
    thread.innerHTML = `<p class="agent-chat__empty">Ask about this finding only. The three prompts cover explain, verify, and fix; a question about another weakness is answered as not in this record.</p>`;
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
    const source = message.provider ? `<p class="agent-chat__cites">${esc(message.provider)}${message.model ? ` · ${esc(message.model)}` : ""}</p>` : "";
    return `<div class="agent-chat__msg agent-chat__msg--agent"><p>${esc(message.content)}</p>${lists}${cites}${source}</div>`;
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
      provider: body.provider,
      model: body.model,
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

function approvalTabs(data, tab) {
  const counts = data.counts || {};
  return ["Pending", "Approved", "Rejected", "History", "Gateway"].map((id) => `
    <button class="sentinel-tab${id === "Rejected" ? " is-reject" : ""}" data-tab="approval" data-value="${id}" aria-selected="${tab === id}">
      ${id}${id !== "Gateway" && counts[id] != null ? `<span class="count">${counts[id]}</span>` : ""}
    </button>`).join("");
}

function policyList(item) {
  const rejected = item.status === "Rejected" || item.status === "Blocked";
  const rows = [
    ["Endpoint Allowlist", "Pass"],
    ["Method Allowlist", "Pass"],
    ["Payload Safety", item.injection_flagged ? "Fail" : "Pass"],
    ["Rate Limit", "Pass"],
    ["Authentication", "Pass"],
  ];
  if (rejected) rows.push(["Approval", "Reject"]);
  if (item.sent) rows.push(["Gateway", "Pass"]);
  else if (rejected) rows.push(["Gateway", "Not Executed"]);
  return `<ul class="check-list">${rows.map(([name, result]) =>
    `<li><span class="check-dot">${icon(result === "Pass" ? "check" : "x")}</span><span>${name}</span>${badge(result, result === "Pass" ? "success" : result === "Reject" ? "critical" : "muted")}</li>`).join("")}</ul>`;
}

function pendingCard(current) {
  if (!current) {
    return `<article class="sentinel-card"><p class="sentinel-page-description">No pending requests. New probes are proposed from DAST analysis.</p></article>`;
  }
  return `
    <article class="sentinel-card">
      <div class="sentinel-card__header">
        <div><div class="sentinel-page-description">Request ID</div>
        <h2 class="sentinel-page-title" style="font-size:1.25rem">${esc(current.id)}</h2></div>
        ${badge(current.status)}
      </div>
      <div class="approval-grid">
        <section>
          <h3 class="sentinel-card__title">Request Details</h3>
          <p><small>HTTP Method</small><br><strong>${icon("tag")} ${esc(current.method)}</strong></p>
          <p><small>Allowlisted Endpoint</small><br>${icon("globe")} <span class="mono">${esc(current.endpoint)}</span></p>
          <p><small>Sanitized Payload Preview</small></p>
          <pre class="sentinel-code">${esc(typeof current.payload === "string" ? current.payload : JSON.stringify(current.payload ?? {}, null, 2))}</pre>
          <p><small>Purpose</small><br>${esc(current.purpose)}</p>
        </section>
        <section>
          <h3 class="sentinel-card__title">Risk & Impact</h3>
          <p>${badge(`${current.risk} Risk`, current.risk === "High" ? "critical" : current.risk === "Medium" ? "warning" : "success")} ${badge(current.impact || "Read Only")}</p>
          <p class="sentinel-page-description">${current.impact === "Read Only" ? "This request is read-only and does not modify data. The potential impact is limited to information disclosure." : "This request carries a special payload. Reject means the probe is not sent."}</p>
        </section>
        <section>
          <h3 class="sentinel-card__title">Policy Checks</h3>
          ${policyList(current)}
        </section>
        <section>
          <h3 class="sentinel-card__title">Gateway Route Status</h3>
          <ul class="meta-list">
            <li><span class="meta-icon icon-green">${icon("checkCircle")}</span><div><small>Status</small><strong class="tone-success">${esc(current.gateway || "Ready")}</strong></div></li>
            <li><span class="meta-icon icon-blue">${icon("branch")}</span><div><small>Route</small><span class="mono">${esc(current.route_id || "api-gateway-lab")}</span></div></li>
            <li><span class="meta-icon icon-orange">${icon("gauge")}</span><div><small>Rate Limit</small>30 req/min</div></li>
            <li><span class="meta-icon icon-blue">${icon("clock")}</span><div><small>Timeout</small>5s</div></li>
            <li><span class="meta-icon icon-green">${icon("shieldCheck")}</span><div><small>Authentication</small>Service Token</div></li>
          </ul>
        </section>
      </div>
      <div class="approval-actions">
        <button class="sentinel-button sentinel-button--approve" data-decide="approve" data-id="${esc(current.id)}" ${current.status !== "Pending" ? "disabled" : ""}>${icon("check")} Approve</button>
        <button class="sentinel-button sentinel-button--reject" data-decide="reject" data-id="${esc(current.id)}" ${current.status !== "Pending" ? "disabled" : ""}>${icon("x")} Reject</button>
      </div>
      <p class="sentinel-page-description" style="margin-top:0.8rem">Approving records the decision. The public UI does not forward a live probe. Use the Gateway tab to exercise the live lab.</p>
    </article>`;
}

function approvalTableToolbar(tableId, placeholder, filters) {
  return `<div class="toolbar">
    ${searchField(tableId, placeholder)}
    ${filters}
  </div>`;
}

function approvalApproved(data) {
  const stats = data.stats || {};
  const rows = (data.items || []).filter((row) => row.status === "Approved");
  const page = pager("appr-ok", rows.length, 8);
  const slice = rows.slice(page.start, page.end);
  return `
    <div class="sentinel-grid sentinel-grid--metrics">
      ${metric("Approved", stats.approved ?? rows.length, "human-approved probe requests", "icon-green", icon("checkCircle"))}
      ${metric("Executed", stats.executed ?? 0, "sent through the gateway", "icon-blue", icon("play"))}
      ${metric("Awaiting Execution", stats.queued ?? 0, "approved and not yet sent", "icon-orange", icon("clock"))}
      ${metric("Success Rate", `${stats.success_rate ?? 0}%`, "HTTP 200 among executed probes", "icon-purple", icon("chart"))}
    </div>
    ${approvalTableToolbar("appr-ok-rows", "Search approved request...", `${filterSelect("appr-ok-rows", "Gateway Status", rows.map((r) => r.gateway), "gateway")}${filterSelect("appr-ok-rows", "Approved By", rows.map((r) => r.approved_by), "actor")}${selectField("Date Range", "calendar")}`)}
    <div class="sentinel-table-wrap">
      <table class="sentinel-table"><thead><tr>
        <th>Request ID</th><th>Finding ID</th><th>Method</th><th>Route ID</th><th>Purpose</th><th>Approved By</th><th>Approved At</th><th>Gateway</th><th>Result</th>
      </tr></thead>
      <tbody id="appr-ok-rows">
        ${slice.map((row) => `<tr class="is-clickable" data-open-approval="${esc(row.id)}" data-gateway="${esc(row.gateway || "")}" data-actor="${esc(row.approved_by || "")}">
          <td class="mono">${esc(row.id)}</td>
          <td><a class="linkish" data-jump="dast" data-tab-target="findings">${esc(row.finding_id || "—")}</a></td>
          <td>${badge(row.method)}</td>
          <td class="mono">${esc(row.route_id)}</td>
          <td class="wrap-cell">${esc(row.purpose)}</td>
          <td>${esc(row.approved_by || "Operator")}</td>
          <td>${esc(row.decided_at || "—")}</td>
          <td>${badge(row.gateway || "Queued")}</td>
          <td class="${row.http_status === 200 ? "tone-success" : "tone-info"}">${esc(row.result || "—")}</td>
        </tr>`).join("")}
      </tbody></table>
      ${page.html}
    </div>`;
}

function approvalRejected(data) {
  const stats = data.stats || {};
  const rows = (data.items || []).filter((row) => row.status === "Rejected");
  const page = pager("appr-no", rows.length, 8);
  const slice = rows.slice(page.start, page.end);
  return `
    <div class="sentinel-grid sentinel-grid--metrics">
      ${metric("Total Rejected", stats.rejected ?? rows.length, "blocked before send", "icon-red", icon("xCircle"))}
      ${metric("Rejected by User", stats.rejected_user ?? 0, "operator chose not to send", "icon-blue", icon("users"))}
      ${metric("Blocked by Policy", stats.rejected_policy ?? 0, "gate or allowlist refused", "icon-purple", icon("shield"))}
      ${metric("Never Executed", stats.never_executed ?? rows.length, "reject means not sent", "icon-blue", icon("clock"))}
    </div>
    ${approvalTableToolbar("appr-no-rows", "Search rejected request...", `${filterSelect("appr-no-rows", "Rejection Source", rows.map((r) => r.rejected_source), "source")}${filterSelect("appr-no-rows", "Risk", rows.map((r) => r.risk), "risk")}${selectField("Date Range", "calendar")}`)}
    <div class="sentinel-table-wrap">
      <table class="sentinel-table"><thead><tr>
        <th>Request ID</th><th>Finding ID</th><th>Method</th><th>Route ID</th><th>Risk</th><th>Rejected By</th><th>Reason</th><th>Rejected At</th><th>Execution</th>
      </tr></thead>
      <tbody id="appr-no-rows">
        ${slice.map((row) => `<tr class="is-clickable" data-open-approval="${esc(row.id)}" data-source="${esc(row.rejected_source || "")}" data-risk="${esc(row.risk || "")}">
          <td class="mono tone-critical">${esc(row.id)}</td>
          <td><a class="linkish" data-jump="dast" data-tab-target="findings">${esc(row.finding_id || "—")}</a></td>
          <td>${badge(row.method)}</td>
          <td class="mono">${esc(row.route_id)} ${badge("Active", "success")}</td>
          <td>${badge(row.risk)}</td>
          <td>${esc(row.rejected_by || "User")}</td>
          <td class="wrap-cell">${esc(row.reason || "Operator rejected the probe.")}</td>
          <td>${esc(row.decided_at || "—")}</td>
          <td>${badge("Not Executed")}</td>
        </tr>`).join("")}
      </tbody></table>
      ${page.html}
    </div>`;
}

function approvalHistory(data) {
  const stats = data.stats || {};
  const rows = data.history || [];
  const page = pager("appr-hist", rows.length, 8);
  const slice = rows.slice(page.start, page.end);
  return `
    <div class="sentinel-grid sentinel-grid--metrics">
      ${metric("Audit Events", stats.audit_events ?? rows.length, "approval and gateway events", "icon-blue", icon("clipboard"))}
      ${metric("Approval Actions", stats.approval_actions ?? 0, "approve or reject decisions", "icon-green", icon("squareCheck"))}
      ${metric("Gateway Executions", stats.gateway_executions ?? 0, "safe probes that were sent", "icon-blue", icon("play"))}
      ${metric("Security Filters", stats.security_filters ?? 0, "injection or redaction events", "icon-orange", icon("shield"))}
    </div>
    ${approvalTableToolbar("appr-hist-rows", "Search audit event...", `${filterSelect("appr-hist-rows", "Event", rows.map((r) => r.event), "event")}${filterSelect("appr-hist-rows", "Approval", rows.map((r) => r.approval), "approval")}`)}
    <div class="sentinel-table-wrap">
      <table class="sentinel-table"><thead><tr>
        <th>Timestamp</th><th>Request ID</th><th>Finding ID</th><th>Event</th><th>Actor</th><th>Approval</th><th>Gateway</th><th>HTTP & Latency</th><th>Security Filter</th>
      </tr></thead>
      <tbody id="appr-hist-rows">
        ${slice.map((row) => `<tr class="is-clickable" data-open-event="${esc(row.id)}" data-event="${esc(row.event || "")}" data-approval="${esc(row.approval || "")}">
          <td>${esc(row.when || row.timestamp || "—")}</td>
          <td class="mono">${esc(row.request_id)}</td>
          <td class="mono">${esc(row.finding_id)}</td>
          <td>${badge(row.event)}</td>
          <td>${esc(row.actor)}</td>
          <td>${badge(row.approval)}</td>
          <td class="mono">${esc(row.gateway)}</td>
          <td>${esc(row.http_status != null ? row.http_status : "—")} · ${esc(row.latency)}</td>
          <td>${esc(row.filter || "—")}</td>
        </tr>`).join("")}
      </tbody></table>
      ${page.html}
    </div>`;
}

function gatewayStep(form, result) {
  if (result) return 5;
  if (form.approved) return 4;
  if (form.purpose) return 3;
  if (form.routeId) return 2;
  return 1;
}

function approvalGateway(gw) {
  const form = state.gateway;
  const routes = gw.routes || [];
  const selected = routes.find((row) => row.id === form.routeId) || routes[0] || {};
  const step = gatewayStep(form, form.result);
  const steps = ["Select Route", "Purpose", "Approve", "Run Probe", "Result"];
  const checks = (form.result && form.result.checks) || [
    { name: "Endpoint Allowlist", result: "Pass" },
    { name: "Method Allowlist", result: "Pass" },
    { name: "Payload Safety", result: form.scenario === "sqli" ? "Fail" : "Pass" },
    { name: "Rate Limit", result: "Pass" },
    { name: "Authentication", result: form.invalidKey ? "401" : "Pass" },
  ];
  const result = form.result;
  return `
    <div class="sentinel-grid split-gateway">
      <div>
        <div class="sentinel-grid grid-2 gateway-limits">
          ${metric("Allowed Routes", gw.limits?.allowed_routes ?? 0, "published allowlist", "icon-blue", icon("globe"))}
          ${metric("Rate Limit", gw.limits?.rate_limit || "—", "requests per minute", "icon-orange", icon("gauge"))}
          ${metric("Timeout", gw.limits?.timeout || "—", "upstream wait", "icon-blue", icon("clock"))}
          ${metric("Max Body", gw.limits?.max_body || "—", "response cap", "icon-purple", icon("shield"))}
        </div>
        <article class="sentinel-card" style="margin-top:1rem">
          <div class="sentinel-card__header"><h2 class="sentinel-card__title">Route Allowlist</h2></div>
          <div class="sentinel-table-wrap" style="border:0">
            <table class="sentinel-table"><thead><tr>
              <th>Route ID</th><th>Method</th><th>Path</th><th>Preset</th><th>Status</th>
            </tr></thead><tbody>
              ${routes.map((row) => `<tr class="is-clickable${row.id === selected.id ? " is-selected" : ""}" data-pick-route="${esc(row.id)}">
                <td class="mono">${esc(row.id)}</td>
                <td>${badge(row.method)}</td>
                <td class="mono">${esc(row.path)}</td>
                <td>${esc(row.preset)}</td>
                <td><span class="dot-ok"></span> ${esc(row.status)}</td>
              </tr>`).join("")}
            </tbody></table>
          </div>
        </article>
        <article class="sentinel-card" style="margin-top:1rem">
          <div class="sentinel-card__header"><h2 class="sentinel-card__title">Deny-list</h2></div>
          <div class="sentinel-table-wrap" style="border:0">
            <table class="sentinel-table"><thead><tr><th>Method</th><th>Path</th><th>Reason</th><th>Status</th></tr></thead>
            <tbody>${(gw.deny_list || []).map((row) => `<tr>
              <td>${badge(row.method)}</td><td class="mono">${esc(row.path)}</td>
              <td class="wrap-cell">${esc(row.reason)}</td><td>${badge("Blocked")}</td>
            </tr>`).join("")}</tbody></table>
          </div>
        </article>
      </div>
      <div>
        <article class="sentinel-card probe-runner">
          <div class="sentinel-card__header"><h2 class="sentinel-card__title">Probe Runner</h2></div>
          <ol class="gateway-steps">
            ${steps.map((label, index) => `<li class="${index + 1 < step ? "is-done" : index + 1 === step ? "is-on" : ""}"><i>${index + 1}</i>${label}</li>`).join("")}
          </ol>
          <div class="scenario-row">
            ${(gw.scenarios || []).map((row) => `<button type="button" class="sentinel-button sentinel-button--outline sentinel-button--compact${form.scenario === row.id ? " is-on" : ""}" data-scenario="${esc(row.id)}">${esc(row.label)}</button>`).join("")}
          </div>
          <label class="field-label">Route ID
            <select class="sentinel-control" id="gw-route">${routes.map((row) => `<option value="${esc(row.id)}" ${row.id === selected.id ? "selected" : ""}>${esc(row.id)}</option>`).join("")}</select>
          </label>
          <div class="gateway-meta-grid">
            <label class="field-label">Method<input class="sentinel-control" id="gw-method" value="${esc(selected.method || "")}" readonly /></label>
            <label class="field-label">Path<input class="sentinel-control" id="gw-path" value="${esc(selected.path || "")}" title="${esc(selected.path || "")}" readonly /></label>
            <label class="field-label">Preset<input class="sentinel-control" id="gw-preset" value="${esc(selected.preset || "")}" title="${esc(selected.preset || "")}" readonly /></label>
          </div>
          <label class="field-label">Purpose
            <textarea class="sentinel-control" id="gw-purpose" rows="3">${esc(form.purpose)}</textarea>
          </label>
          <label class="check-inline"><input type="checkbox" id="gw-bad-key" ${form.invalidKey ? "checked" : ""} /> Use invalid API key → expect 401</label>
          <div class="policy-grid">${checks.map((row) => `<div><span>${esc(row.name)}</span>${badge(row.result, row.result === "Pass" ? "success" : "critical")}</div>`).join("")}</div>
          <div class="approval-actions">
            <button class="sentinel-button sentinel-button--outline" type="button" data-gw-approve ${form.approved ? "disabled" : ""}>${icon("check")} Approve Request</button>
            <button class="sentinel-button" type="button" data-gw-run ${form.busy ? "disabled" : ""}>${icon("play")} ${form.busy ? "Running…" : "Run Probe"}</button>
          </div>
        </article>
        <article class="sentinel-card" style="margin-top:1rem">
          <div class="sentinel-card__header">
            <h2 class="sentinel-card__title">Probe Result</h2>
            <button class="linkish" type="button" data-gw-reset>${icon("refresh")} Reset</button>
          </div>
          ${result ? `
            <div class="gateway-result-metrics">
              <div><small>Status</small><strong class="${result.status === 200 ? "tone-success" : result.sent ? "tone-critical" : ""}">${esc(result.status_label || "Not sent")}</strong></div>
              <div><small>Expected</small><strong>${esc(result.expected || (result.sent ? result.status_label : "live lab only"))}</strong></div>
              <div><small>Latency</small><strong>${result.latency_ms != null ? `${result.latency_ms} ms` : "—"}</strong></div>
              <div><small>Mode</small><strong>${esc({ live: "Live gateway", policy: "Blocked before send", readonly: "Public · not sent", needs_approval: "Needs Approve", offline: "Gateway offline", error: "Error" }[result.mode] || result.mode || "—")}</strong></div>
            </div>
            <p class="sentinel-page-description">${esc(result.note || "")}</p>
            <button class="accordion" type="button" data-acc="gw-headers" aria-expanded="false">Response Headers <span>▸</span></button>
            <pre class="sentinel-code accordion-body" data-acc-body="gw-headers">${esc(JSON.stringify(result.headers || {}, null, 2))}</pre>
            <p class="field-label">Response Body (Redacted)</p>
            <pre class="sentinel-code">${esc(result.body || "(empty)")}</pre>
            <div class="approval-actions">
              <button class="sentinel-button sentinel-button--outline" type="button" data-gw-analyze>${icon("bot")} Analyze with Agent</button>
            </div>
            ${form.analysis ? `<div class="banner" style="margin-top:0.8rem"><div><strong>${esc(form.analysis.summary)}</strong><p>${esc(form.analysis.gateway_decision || "")}</p>${(form.analysis.what_to_try_next || []).map((item) => `<p>· ${esc(item)}</p>`).join("")}</div></div>` : ""}
          ` : `<p class="sentinel-page-description">Pick an allowlisted route or a sample scenario, then Run Probe. Attack-shaped payloads are refused before send.</p>`}
        </article>
      </div>
    </div>`;
}

async function renderApproval() {
  delete state.cache["/api/approval"];
  delete state.cache["/api/gateway"];
  const tab = state.tab.approval || "Pending";
  const data = await api("/api/approval");
  const gw = tab === "Gateway" ? await api("/api/gateway") : null;
  const pending = (data.items || []).filter((row) => row.status === "Pending");
  document.getElementById("page").innerHTML = `
    <div class="sentinel-page-header">
      <div>
        <h1 class="sentinel-page-title">Approval Center</h1>
        <div class="sentinel-tabs">${approvalTabs(data, tab)}</div>
      </div>
      ${tab === "Gateway" && gw ? `<span class="gateway-pill ${gw.reachable ? "is-ok" : "is-off"}">${esc(gw.status_label || "Gateway Offline")}</span>` : ""}
    </div>
    ${tab === "Pending" ? pendingCard(pending[0] || null)
      : tab === "Approved" ? approvalApproved(data)
      : tab === "Rejected" ? approvalRejected(data)
      : tab === "History" ? approvalHistory(data)
      : approvalGateway(gw || {})}`;
  bindTableSearch();
  if (tab === "Gateway") bindGatewayForm(gw || {});
  if (state.selectedApproval && (tab === "Approved" || tab === "Rejected")) {
    const item = (data.items || []).find((row) => row.id === state.selectedApproval);
    if (item) openApprovalDrawer(item);
  }
  if (state.selectedEvent && tab === "History") {
    const event = (data.history || []).find((row) => row.id === state.selectedEvent);
    if (event) openHistoryDrawer(event, data.items || []);
  }
}

function bindGatewayForm(gw) {
  const route = document.getElementById("gw-route");
  const purpose = document.getElementById("gw-purpose");
  const bad = document.getElementById("gw-bad-key");
  if (route) route.addEventListener("change", () => {
    state.gateway.routeId = route.value;
    state.gateway.approved = false;
    state.gateway.scenario = "";
    state.gateway.query = {};
    state.gateway.body = null;
    render();
  });
  if (purpose) purpose.addEventListener("input", () => { state.gateway.purpose = purpose.value; });
  if (bad) bad.addEventListener("change", () => { state.gateway.invalidKey = bad.checked; });
  document.querySelectorAll("[data-pick-route]").forEach((row) => {
    row.addEventListener("click", () => {
      state.gateway.routeId = row.dataset.pickRoute;
      state.gateway.approved = false;
      state.gateway.scenario = "";
      state.gateway.query = {};
      state.gateway.body = null;
      render();
    });
  });
  document.querySelectorAll("[data-scenario]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const scenario = (gw.scenarios || []).find((row) => row.id === btn.dataset.scenario);
      if (!scenario) return;
      state.gateway.scenario = scenario.id;
      state.gateway.routeId = scenario.route_id;
      state.gateway.purpose = scenario.purpose;
      state.gateway.invalidKey = Boolean(scenario.invalid_api_key);
      state.gateway.query = scenario.query || {};
      state.gateway.body = scenario.body || null;
      state.gateway.approved = false;
      state.gateway.result = null;
      state.gateway.analysis = null;
      render();
    });
  });
}

function collectGatewayForm(gw) {
  const selected = (gw.routes || []).find((row) => row.id === state.gateway.routeId) || {};
  const scenario = (gw.scenarios || []).find((row) => row.id === state.gateway.scenario);
  return {
    route_id: state.gateway.routeId,
    purpose: document.getElementById("gw-purpose")?.value || state.gateway.purpose,
    invalid_api_key: document.getElementById("gw-bad-key")?.checked || state.gateway.invalidKey,
    approved: state.gateway.approved,
    query: state.gateway.query || scenario?.query || {},
    body: state.gateway.body || scenario?.body || null,
    method: selected.method,
    scenario: state.gateway.scenario || scenario?.id || "",
  };
}

async function runGatewayProbe() {
  const gw = await api("/api/gateway");
  state.gateway.busy = true;
  state.gateway.purpose = document.getElementById("gw-purpose")?.value || state.gateway.purpose;
  state.gateway.invalidKey = Boolean(document.getElementById("gw-bad-key")?.checked);
  render();
  try {
    const res = await fetch("/api/gateway/probe", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(collectGatewayForm(gw)),
    });
    state.gateway.result = await res.json();
    state.gateway.analysis = null;
  } catch (error) {
    state.gateway.result = { status_label: "Error", note: String(error.message || error), sent: false, checks: [] };
  }
  state.gateway.busy = false;
  delete state.cache["/api/approval"];
  const out = state.gateway.result || {};
  toast(out.request_id ? `Logged ${out.request_id} · ${out.status_label || "Not sent"}` : (out.sent ? `Gateway ${out.status_label}` : (out.note || out.status_label || "Not sent")));
  render();
}

function openApprovalDrawer(item) {
  if (!item) return;
  const drawer = document.getElementById("drawer");
  drawer.hidden = false;
  drawer.classList.add("is-open");
  drawer.classList.remove("drawer-hidden");
  document.getElementById("page").classList.add("with-drawer");
  const rejected = item.status === "Rejected" || item.status === "Blocked";
  drawer.innerHTML = `
    <div class="sentinel-card__header">
      <h2 class="sentinel-card__title">${rejected ? "Rejected" : "Approved"} Request Details</h2>
      <button class="sentinel-icon-btn" data-close-drawer type="button">✕</button>
    </div>
    <p><strong class="mono">${esc(item.id)}</strong> ${badge(item.status)}</p>
    <dl class="kv">
      <div><dt>Finding ID</dt><dd><a class="linkish" data-jump="dast" data-tab-target="findings">${esc(item.finding_id || "—")}</a></dd></div>
      <div><dt>Method / Route</dt><dd>${esc(item.method)} ${esc(item.route_id)}</dd></div>
      <div><dt>Resolved Path</dt><dd class="mono">${esc(item.path || item.endpoint)} ${badge(item.impact || "Read Only")}</dd></div>
      <div><dt>Purpose</dt><dd>${esc(item.purpose)}</dd></div>
      <div><dt>Risk</dt><dd>${badge(`${item.risk} Risk`, item.risk === "High" ? "critical" : "warning")}</dd></div>
      ${rejected ? `<div><dt>Rejected By</dt><dd>${esc(item.rejected_by || "User")}</dd></div><div><dt>Reason</dt><dd>${esc(item.reason || "")}</dd></div>` : `<div><dt>Approved By / At</dt><dd>${esc(item.approved_by || "Operator")} · ${esc(item.decided_at || "—")}</dd></div>`}
      <div><dt>Gateway Status</dt><dd>${badge(item.gateway || "Not Executed")}</dd></div>
      <div><dt>Response</dt><dd>${esc(item.result || "—")}</dd></div>
      <div><dt>Injection Flag</dt><dd>${badge(item.injection_flag || "Clean")}</dd></div>
      <div><dt>Redaction Applied</dt><dd>${badge(item.redaction_applied || "No", "info")}</dd></div>
    </dl>
    <h3 class="sentinel-card__title">${rejected ? "Policy Snapshot" : "Policy Checks"}</h3>
    ${policyList(item)}
    ${item.body ? `<h3 class="sentinel-card__title">Response Body (Redacted)</h3><pre class="sentinel-code">${esc(item.body)}</pre>` : ""}
    <div class="approval-actions">
      ${rejected
        ? `<button class="sentinel-button sentinel-button--outline" type="button" data-jump="dast" data-tab-target="findings">Return to Finding</button>
           <button class="sentinel-button" type="button" data-open-gateway="${esc(item.route_id || "")}">${icon("plus")} Create Revised Probe</button>`
        : `<button class="sentinel-button sentinel-button--outline" type="button" data-toast="Response is already on this panel.">${icon("eye")} View Response</button>
           <button class="sentinel-button" type="button" data-open-gateway="${esc(item.route_id || "")}">${icon("external")} Open in Gateway</button>`}
    </div>`;
}

function openHistoryDrawer(event, items) {
  if (!event) return;
  const item = items.find((row) => row.id === event.request_id) || {};
  const drawer = document.getElementById("drawer");
  drawer.hidden = false;
  drawer.classList.add("is-open");
  drawer.classList.remove("drawer-hidden");
  document.getElementById("page").classList.add("with-drawer");
  const steps = event.lifecycle || [];
  drawer.innerHTML = `
    <div class="sentinel-card__header">
      <h2 class="sentinel-card__title">Audit Event Details</h2>
      <button class="sentinel-icon-btn" data-close-drawer type="button">✕</button>
    </div>
    <p><strong class="mono">${esc(event.id)}</strong> ${badge(event.event)}</p>
    <dl class="kv">
      <div><dt>Event Type</dt><dd>${esc(event.event)}</dd></div>
      <div><dt>Request / Finding</dt><dd class="mono">${esc(event.request_id)} · ${esc(event.finding_id)}</dd></div>
      <div><dt>Actor</dt><dd>${esc(event.actor)}</dd></div>
      <div><dt>Timestamp</dt><dd>${esc(event.when)}</dd></div>
      <div><dt>HTTP / Latency</dt><dd>${esc(event.http_status ?? "—")} · ${esc(event.latency)}</dd></div>
      <div><dt>Injection Flag</dt><dd>${badge(item.injection_flag || "Clean")}</dd></div>
    </dl>
    <ol class="lifecycle">${steps.map((step) => `<li class="is-${esc(step.state)}"><strong>${esc(step.label)}</strong></li>`).join("")}</ol>
    <div class="approval-actions">
      <button class="sentinel-button" type="button" data-open-approval="${esc(event.request_id || "")}">View Full Request</button>
    </div>`;
}

function kpiDelta(delta) {
  if (!delta) return ["scored against the newest committed run", null];
  return [delta.label, delta.unchanged ? null : Boolean(delta.improved)];
}

async function renderReports() {
  const data = await api("/api/reports");
  const kpis = data.kpis || {};
  const deltas = kpis.deltas || {};
  const compared = data.sast_vs_dast || { sast: 0, dast: 0 };
  const confirmed = (compared.sast || 0) + (compared.dast || 0);
  const summary = data.summary || [];
  const severity = data.severity_open || [];
  const peak = Math.max(...severity.map((row) => row.open), 1);
  const range = state.tab.reportRange || "all";
  const trend = range === "latest" ? (data.trend || []).slice(-1) : (data.trend || []);
  const [pDelta, pUp] = kpiDelta(deltas.precision);
  const [rDelta, rUp] = kpiDelta(deltas.recall);
  const [tpDelta, tpUp] = kpiDelta(deltas.true_positives);
  const [fpDelta, fpUp] = kpiDelta(deltas.false_positives);
  const [fnDelta, fnUp] = kpiDelta(deltas.false_negatives);
  document.getElementById("page").innerHTML = `
    <div class="sentinel-page-header">
      <div><h1 class="sentinel-page-title">Reports</h1></div>
      <div class="toolbar toolbar--header">
        <label class="select-field">${icon("calendar")}<select class="sentinel-control" data-tab="reportRange">
          <option value="all" ${range === "all" ? "selected" : ""}>All committed runs</option>
          <option value="latest" ${range === "latest" ? "selected" : ""}>Latest scored run</option>
        </select></label>
        <button class="sentinel-button sentinel-button--compact" type="button" data-export="reports" data-format="json">${icon("download")} Export Report</button>
      </div>
    </div>
    <div class="sentinel-grid grid-5">
      ${metric("Precision", `${kpis.precision ?? 0}%`, pDelta, "icon-green", icon("target"), { page: "sast", tab: "findings" }, pUp)}
      ${metric("Recall", `${kpis.recall ?? 0}%`, rDelta, "icon-blue", icon("radar"), { page: "sast", tab: "findings" }, rUp)}
      ${metric("True Positives", kpis.true_positives ?? 0, tpDelta, "icon-green", icon("checkCircle"), { page: "sast", tab: "findings" }, tpUp)}
      ${metric("False Positives", kpis.false_positives ?? 0, fpDelta, "icon-orange", icon("alertTriangle"), { page: "sast", tab: "findings" }, fpUp)}
      ${metric("False Negatives", kpis.false_negatives ?? 0, fnDelta, "icon-red", icon("xCircle"), { page: "sast", tab: "findings" }, fnUp)}
    </div>
    <div class="sentinel-grid split-reports">
      <article class="sentinel-card">
        <div class="sentinel-card__header"><h2 class="sentinel-card__title">Vulnerability Trend</h2></div>
        <div class="chart-frame"><canvas id="trend-line"></canvas></div>
      </article>
      <article class="sentinel-card">
        <div class="sentinel-card__header"><h2 class="sentinel-card__title">SAST vs DAST True Vulnerabilities</h2></div>
        <div class="chart-box">
          <div class="donut-wrap"><canvas id="sd-donut"></canvas><div class="donut-center"></div></div>
          <div class="legend">
            <div class="legend__row"><span><i class="swatch" style="background:#2563eb"></i> SAST (ground truth)</span><strong>${compared.sast || 0} (${Math.round(((compared.sast || 0) / Math.max(confirmed, 1)) * 100)}%)</strong></div>
            <div class="legend__row"><span><i class="swatch" style="background:#16a34a"></i> DAST (confirmed live)</span><strong>${compared.dast || 0} (${Math.round(((compared.dast || 0) / Math.max(confirmed, 1)) * 100)}%)</strong></div>
          </div>
        </div>
      </article>
    </div>
    <div class="sentinel-grid split-reports">
      <article class="sentinel-card">
        <div class="sentinel-card__header"><h2 class="sentinel-card__title">Remediation Status</h2></div>
        ${severity.map((row) => `<div class="severity-bar">
          <strong>${esc(row.severity)}</strong> <span class="mono">${row.open}</span>
          <div class="severity-bar__track"><i class="is-${esc(String(row.severity || "").toLowerCase())}" style="width:${Math.round((row.open / peak) * 100)}%"></i></div>
        </div>`).join("")}
      </article>
      <article class="sentinel-card">
        <div class="sentinel-card__header">
          <h2 class="sentinel-card__title">Report Summary</h2>
          <div class="report-exports">
            <button class="linkish" type="button" data-export="reports" data-format="csv">${icon("download")} Export CSV</button>
            <button class="linkish" type="button" data-export="reports" data-format="json">${icon("file")} Export JSON</button>
          </div>
        </div>
        <div class="sentinel-table-wrap" style="border:0">
          <table class="sentinel-table sentinel-table--wrap"><thead><tr>
            <th>Category</th><th>Findings</th><th>Precision</th><th>Recall</th><th>F1 Score</th><th>True Positives</th><th>False Positives</th><th>False Negatives</th><th>Probed</th><th>Verdict changed</th>
          </tr></thead><tbody>
            ${summary.map((row) => `<tr class="is-clickable" data-jump="${row.category === "DAST" ? "dast" : "sast"}" data-tab-target="findings">
              <td>${esc(row.category)}</td>
              <td>${dash(row.findings)}</td>
              <td>${row.precision != null ? Number(row.precision).toFixed(3) : "—"}</td>
              <td>${row.recall != null ? Number(row.recall).toFixed(3) : "—"}</td>
              <td>${row.f1 != null ? Number(row.f1).toFixed(3) : "—"}</td>
              <td>${dash(row.tp)}</td>
              <td>${dash(row.fp)}</td>
              <td>${dash(row.fn)}</td>
              <td>${dash(row.probed ?? row.verified)}</td>
              <td>${dash(row.revised ?? row.changed_by_probe)}</td>
            </tr>`).join("")}
          </tbody></table>
        </div>
        <div class="banner" style="margin-top:.8rem">${(data.glossary || []).map((item) => `<p><strong>${esc(item.column)}.</strong> ${esc(item.meaning)}</p>`).join("")}</div>
      </article>
    </div>`;
  const tick = getComputedStyle(document.documentElement).getPropertyValue("--sentinel-text-muted").trim() || "#94a3b8";
  const trendCanvas = document.getElementById("trend-line");
  if (trendCanvas && window.Chart && trend.length) {
    state.charts.push(new Chart(trendCanvas, {
      type: "line",
      data: {
        labels: trend.map((row) => row.label),
        datasets: [
          { label: "True Vulnerabilities", data: trend.map((row) => row.true_vulnerabilities), borderColor: "#2563eb", backgroundColor: "transparent", tension: 0.3 },
          { label: "All Findings", data: trend.map((row) => row.findings), borderColor: "#93c5fd", borderDash: [6, 4], backgroundColor: "transparent", tension: 0.3 },
        ],
      },
      options: {
        plugins: {
          legend: { labels: { color: tick } },
          tooltip: {
            callbacks: {
              title: (items) => {
                const row = trend[items[0]?.dataIndex] || {};
                return `${row.kind || ""} ${row.run_id || row.label || ""}`.trim();
              },
            },
          },
        },
        maintainAspectRatio: false,
        scales: {
          x: { ticks: { color: tick, maxRotation: 45, minRotation: 0 }, grid: { color: "transparent" } },
          y: { beginAtZero: true, ticks: { precision: 0, color: tick }, grid: { color: "rgb(148 163 184 / 0.2)" } },
        },
      },
    }));
  }
  if (confirmed > 0) {
    donut("sd-donut", ["SAST true positives", "DAST confirmed live"], [compared.sast, compared.dast], ["#2563eb", "#16a34a"], `<strong>${confirmed}</strong><small>Confirmed</small>`);
  }
}

async function renderKnowledge() {
  const data = await api("/api/knowledge");
  const tab = state.tab.knowledge || "kb";
  const page = pager(tab === "kb" ? "kb" : "audit", tab === "kb" ? data.documents.length : data.audit.length, 12);
  const docs = data.documents.slice(page.start, page.end);
  const audit = data.audit.slice(page.start, page.end);
  document.getElementById("page").innerHTML = `
    <div class="sentinel-page-header">
      <div>
        <h1 class="sentinel-page-title">Knowledge Base & Audit</h1>
        <p class="sentinel-page-description">Each document is a verification ruler: confirm and false-positive indicators feed the agent verdict. Open a row to see who retrieved it and whether a later run cited it.</p>
        <div class="sentinel-tabs">
          <button class="sentinel-tab" data-tab="knowledge" data-value="kb" aria-selected="${tab === "kb"}">Knowledge Base</button>
          <button class="sentinel-tab" data-tab="knowledge" data-value="audit" aria-selected="${tab === "audit"}">Audit Log</button>
        </div>
      </div>
    </div>
    <div class="sentinel-grid sentinel-grid--metrics">
      ${metric("KB Entries", data.entries, "Committed knowledge documents", "icon-blue", icon("book"))}
      ${metric("CWE Coverage", data.cwe_coverage, "Unique CWE IDs covered", "icon-green", icon("shield"))}
      ${metric("Cited in verdicts", data.cited_docs ?? 0, "Documents named in a recorded rationale", "icon-purple", icon("fileSearch"))}
      ${metric("Last Updated", data.updated || "—", "Knowledge file timestamp", "icon-orange", icon("chart"))}
    </div>
    ${tab === "kb" ? `
      <div class="toolbar">
        ${searchField("kb-rows", "Search knowledge base...")}
        ${filterSelect("kb-rows", "All surfaces", data.documents.map((row) => row.detection_surface_label), "surface")}
        ${filterSelect("kb-rows", "All sources", data.documents.map((row) => row.source), "source")}
      </div>
      <div class="sentinel-table-wrap">
        <table class="sentinel-table sentinel-table--wrap"><thead><tr>
          <th>ID</th><th>CWE</th><th>Title</th><th>Surface</th><th>Confirm indicator</th><th>False-positive indicator</th><th>Retrieved</th><th>Cited</th>
        </tr></thead><tbody id="kb-rows">
          ${docs.map((row) => `<tr class="is-clickable${state.selectedKb === row.id ? " is-selected" : ""}" data-open-kb="${esc(row.id)}" data-source="${esc(row.source || "")}" data-surface="${esc(row.detection_surface_label || "")}">
            <td class="mono">${esc(row.id)}</td>
            <td class="mono">${esc(row.cwe)}</td>
            <td>${esc(row.title)}</td>
            <td>${esc(row.detection_surface_label)}</td>
            <td>${esc(firstItem(row.confirm_indicators))}</td>
            <td>${esc(firstItem(row.fp_indicators))}</td>
            <td>${row.retrieved_count ?? 0}</td>
            <td>${row.cited_count ?? 0}</td>
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
  bindTableSearch();
}

function openKbDrawer(doc) {
  if (!doc) return;
  state.selectedKb = doc.id;
  const drawer = document.getElementById("drawer");
  drawer.hidden = false;
  drawer.classList.add("is-open", "is-wide");
  drawer.classList.remove("drawer-hidden");
  document.getElementById("page").classList.add("with-drawer", "with-drawer-wide");
  document.querySelectorAll("[data-open-kb]").forEach((row) => {
    row.classList.toggle("is-selected", row.dataset.openKb === doc.id);
  });
  const change = doc.measured_change;
  const used = doc.used_by || [];
  const cited = used.filter((row) => row.cited);
  const provenance = doc.provenance || {};
  drawer.innerHTML = `
    <div class="sentinel-card__header">
      <h2 class="sentinel-card__title">${esc(doc.id)}</h2>
      <button class="sentinel-icon-btn" data-close-drawer type="button">✕</button>
    </div>
    <p><strong>${esc(doc.title)}</strong></p>
    <dl class="kv">
      <div><dt>CWE</dt><dd class="mono">${esc(doc.cwe)}</dd></div>
      <div><dt>Surface</dt><dd>${esc(doc.detection_surface_label || doc.detection_surface || "—")}</dd></div>
      <div><dt>Source</dt><dd>${doc.source_url ? `<a class="linkish" href="${esc(doc.source_url)}" target="_blank" rel="noopener">${esc(doc.source)}</a>` : esc(doc.source || "—")}</dd></div>
      <div><dt>Retrieved / cited</dt><dd>${doc.retrieved_count ?? 0} retrieved · ${doc.cited_count ?? 0} cited in a rationale</dd></div>
    </dl>
    <h3 class="sentinel-card__title">Confirm indicators</h3>
    ${bulletList(doc.confirm_indicators, "No confirm indicators on this document.")}
    <h3 class="sentinel-card__title">False-positive indicators</h3>
    ${bulletList(doc.fp_indicators, "No false-positive indicators on this document.")}
    <h3 class="sentinel-card__title">Detection questions</h3>
    ${bulletList(doc.detection_questions, "No review questions on this document.")}
    ${change ? `
      <h3 class="sentinel-card__title">Measured change</h3>
      <p class="sentinel-page-description">${esc(change.subject_id)} · same model, KB tightened between these committed runs.</p>
      <dl class="kv">
        <div><dt>Before</dt><dd>${badge(change.before.verdict_label)} <small class="mono">${esc(change.before.run_id)}</small>${change.before.cited ? " · cited" : ""}</dd></div>
        <div><dt>After</dt><dd>${badge(change.after.verdict_label)} <small class="mono">${esc(change.after.run_id)}</small>${change.after.cited ? " · cited" : ""}</dd></div>
      </dl>
      ${change.before.rationale ? `<p class="sentinel-page-description"><strong>Before rationale.</strong> ${esc(change.before.rationale)}</p>` : ""}
      ${change.after.rationale ? `<p class="sentinel-page-description"><strong>After rationale.</strong> ${esc(change.after.rationale)}</p>` : ""}
    ` : ""}
    <h3 class="sentinel-card__title">Findings that used this document</h3>
    ${used.length ? `<div class="sentinel-table-wrap" style="border:0"><table class="sentinel-table sentinel-table--wrap"><thead><tr>
      <th>Finding</th><th>Subject</th><th>Verdict</th><th>Retrieved</th><th>Cited</th>
    </tr></thead><tbody>
      ${used.map((row) => `<tr class="is-clickable" data-open-agent="${esc(row.finding_id)}">
        <td class="mono">${esc(row.finding_id)}</td>
        <td class="mono">${esc(row.subject)}</td>
        <td>${badge(row.verdict)}</td>
        <td>${row.retrieved ? "Yes" : "—"}</td>
        <td>${row.cited ? "Yes" : "—"}</td>
      </tr>`).join("")}
    </tbody></table></div>
    ${cited.length && cited[0].rationale ? `<p class="sentinel-page-description"><strong>Citation.</strong> ${esc(cited[0].rationale)}</p>` : ""}` : `<p class="sentinel-page-description">No current SAST or DAST finding retrieved or cited this document.</p>`}
    <h3 class="sentinel-card__title">Document text</h3>
    <p class="sentinel-page-description">${esc(doc.content || "—")}</p>
    ${provenance.trust_tier || provenance.retrieved_at ? `<dl class="kv">
      <div><dt>Trust</dt><dd>${esc(provenance.trust_tier || "—")}</dd></div>
      <div><dt>Retrieved at</dt><dd>${esc(provenance.retrieved_at || "—")}</dd></div>
    </dl>` : ""}`;
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
      <div><dt>Corpus</dt><dd>${icon("branch")} ${esc(run.branch)}</dd></div>
      <div><dt>Commit</dt><dd>${icon("link")} <span title="${esc(run.commit_full || run.commit)}">${esc(run.commit)}</span></dd></div>
      <div><dt>Triggered By</dt><dd>${esc(run.triggered_by)}</dd></div>
      <div><dt>Tool</dt><dd>${toolMark(run.tool)}</dd></div>
      ${run.model ? `<div><dt>Model</dt><dd>${toolMark(run.model)}</dd></div>` : ""}
      <div><dt>Ruleset</dt><dd class="mono">${esc(run.ruleset)}</dd></div>
      <div><dt>Duration</dt><dd>${esc(run.duration)}</dd></div>
    </dl>
    <div class="run-counts">
      <div><strong>${run.raw_findings ?? "—"}</strong><small>Raw Findings</small></div>
      <div><strong>${run.normalized ?? "—"}</strong><small>Normalized</small></div>
      <div><strong>${run.agent_analyzed ?? "—"}</strong><small>Agent Analyzed</small></div>
    </div>
    ${run.precision != null || run.recall != null ? `
    <h3 class="sentinel-card__title">Evaluation (${esc(run.eval_label || "committed metrics")})</h3>
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

function applyTableFilters(tableId) {
  const body = document.getElementById(tableId);
  if (!body) return;
  const search = document.querySelector(`input[data-filter-table="${tableId}"]`);
  const query = (search?.value || "").toLowerCase();
  const filters = [...document.querySelectorAll(`select[data-col-filter][data-filter-table="${tableId}"]`)]
    .map((select) => [select.dataset.colFilter, select.value])
    .filter(([, value]) => value);
  body.querySelectorAll("tr").forEach((row) => {
    const textHit = !query || row.textContent.toLowerCase().includes(query);
    const colHit = filters.every(([key, value]) => (row.dataset[key] || "") === value);
    row.hidden = !(textHit && colHit);
  });
}

function bindTableSearch() {
  document.querySelectorAll("[data-filter-table]").forEach((input) => {
    const tableId = input.dataset.filterTable;
    const eventName = input.tagName === "SELECT" ? "change" : "input";
    input.addEventListener(eventName, () => applyTableFilters(tableId));
  });
}

function closeDrawer() {
  const drawer = document.getElementById("drawer");
  drawer.hidden = true;
  drawer.classList.remove("is-open", "is-wide");
  drawer.classList.add("drawer-hidden");
  document.getElementById("page").classList.remove("with-drawer", "with-drawer-wide");
  state.selectedKb = null;
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
  try {
    await (views[state.page] || renderOverview)();
  } catch (err) {
    page.innerHTML = `<p class="sentinel-page-description">Could not load this page. ${esc(err.message || String(err))}</p>`;
  }
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
  document.querySelector(".sentinel-topbar").addEventListener("click", (event) => {
    const jump = event.target.closest("[data-jump]");
    if (jump) setPage(jump.dataset.jump);
  });
  document.getElementById("page").addEventListener("click", async (event) => {
    const notice = event.target.closest("[data-toast]");
    if (notice) {
      toast(notice.dataset.toast);
      return;
    }
    const exported = event.target.closest("[data-export]");
    if (exported) {
      downloadExport(exported.dataset.export, exported.dataset.format || "json");
      if (exported.dataset.format === "json" && exported.dataset.export === "reports") {
        toast("Downloaded the scored report JSON.");
      }
      return;
    }
    const tab = event.target.closest("[data-tab]");
    if (tab && tab.tagName !== "SELECT") {
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
    const openKb = event.target.closest("[data-open-kb]");
    if (openKb) {
      const payload = await api("/api/knowledge");
      openKbDrawer(payload.documents.find((row) => row.id === openKb.dataset.openKb));
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
      event.preventDefault();
      if (jump.dataset.tabTarget) {
        if (jump.dataset.jump === "sast") state.tab.sast = jump.dataset.tabTarget;
        if (jump.dataset.jump === "dast") state.tab.dast = jump.dataset.tabTarget;
      }
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
    const openApproval = event.target.closest("[data-open-approval]");
    if (openApproval) {
      const payload = await api("/api/approval");
      const item = payload.items.find((row) => row.id === openApproval.dataset.openApproval);
      state.selectedApproval = item?.id || null;
      if (item && item.status === "Rejected") state.tab.approval = "Rejected";
      if (item && item.status === "Approved") state.tab.approval = "Approved";
      if (item && state.tab.approval === "History") {
        /* keep history table; only open the request drawer */
      }
      openApprovalDrawer(item);
      return;
    }
    const openEvent = event.target.closest("[data-open-event]");
    if (openEvent) {
      const payload = await api("/api/approval");
      const row = payload.history.find((item) => item.id === openEvent.dataset.openEvent);
      state.selectedEvent = row?.id || null;
      openHistoryDrawer(row, payload.items);
      return;
    }
    const openGateway = event.target.closest("[data-open-gateway]");
    if (openGateway) {
      state.tab.approval = "Gateway";
      if (openGateway.dataset.openGateway) state.gateway.routeId = openGateway.dataset.openGateway;
      state.gateway.result = null;
      render();
      return;
    }
    const gwApprove = event.target.closest("[data-gw-approve]");
    if (gwApprove) {
      state.gateway.approved = true;
      state.gateway.purpose = document.getElementById("gw-purpose")?.value || state.gateway.purpose;
      toast("Approved. Run Probe is now allowed for this request.");
      render();
      return;
    }
    const gwRun = event.target.closest("[data-gw-run]");
    if (gwRun) {
      await runGatewayProbe();
      return;
    }
    const gwReset = event.target.closest("[data-gw-reset]");
    if (gwReset) {
      state.gateway.result = null;
      state.gateway.analysis = null;
      state.gateway.approved = false;
      state.gateway.busy = false;
      render();
      return;
    }
    const gwAnalyze = event.target.closest("[data-gw-analyze]");
    if (gwAnalyze) {
      if (!state.gateway.result) return;
      toast("Asking the Security Analysis Agent…");
      try {
        const res = await fetch("/api/gateway/analyze", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ result: state.gateway.result }),
        });
        state.gateway.analysis = await res.json();
      } catch (error) {
        state.gateway.analysis = { summary: String(error.message || error), gateway_decision: "", what_to_try_next: [] };
      }
      render();
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
  document.getElementById("page").addEventListener("change", (event) => {
    const ranged = event.target.closest("select[data-tab]");
    if (ranged) {
      state.tab[ranged.dataset.tab] = ranged.value;
      render();
    }
  });
  document.getElementById("drawer").addEventListener("click", async (event) => {
    const panel = event.currentTarget;
    if (event.target.closest("[data-close-drawer]")) {
      state.selectedApproval = null;
      state.selectedEvent = null;
      closeDrawer();
      return;
    }
    const openGateway = event.target.closest("[data-open-gateway]");
    if (openGateway) {
      state.tab.approval = "Gateway";
      if (openGateway.dataset.openGateway) state.gateway.routeId = openGateway.dataset.openGateway;
      closeDrawer();
      render();
      return;
    }
    const openApproval = event.target.closest("[data-open-approval]");
    if (openApproval) {
      const payload = await api("/api/approval");
      openApprovalDrawer(payload.items.find((row) => row.id === openApproval.dataset.openApproval));
      return;
    }
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
