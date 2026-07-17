/* ============================================================
   Orion SOC dashboard — client logic (Day 9)
   Dependency-free. Real data over WebSocket + REST; mock panels
   are clearly labeled DEMO in the markup.
   ============================================================ */
"use strict";

const SEV_WEIGHT = { critical: 100, high: 70, medium: 40, low: 20, none: 0 };
const SEV_COLOR = { critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#38bdf8", none: "#5a6b85" };
const MAX_STREAM = 60, MAX_ALERTS = 25, MAX_BUCKETS = 30;

const state = {
  totalLogs: 0, totalAlerts: 0,
  sev: { critical: 0, high: 0, medium: 0, low: 0 },
  cats: {},                 // event_type -> count (alerts)
  recentSev: [],            // rolling severity weights for threat index
  buckets: new Array(MAX_BUCKETS).fill(0),
  confSum: 0, confN: 0,
  hist: { logs: [], alerts: [], crit: [], rate: [], conf: [] },
  logTimes: [],
};

/* ---------- small helpers ---------- */
const $ = (s) => document.querySelector(s);
const el = (tag, cls, html) => { const e = document.createElement(tag); if (cls) e.className = cls; if (html != null) e.innerHTML = html; return e; };
const fmt = (n) => n >= 1000 ? (n / 1000).toFixed(n >= 10000 ? 0 : 1) + "k" : String(n);
const sevClass = (s) => "sev-" + (s || "none");
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const timeStr = (iso) => { try { return new Date(iso).toLocaleTimeString("en-GB"); } catch { return "--:--:--"; } };

function animateCount(node, to, suffix = "", decimals = null) {
  const from = parseFloat(node.dataset.v || "0"); node.dataset.v = to;
  const dp = decimals != null ? decimals : (to % 1 === 0 ? 0 : 1);
  const t0 = performance.now(), dur = 550;
  const step = (t) => {
    const k = Math.min(1, (t - t0) / dur);
    const val = from + (to - from) * (1 - Math.pow(1 - k, 3));
    node.textContent = val.toFixed(dp) + suffix;
    if (k < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

function pushHist(key, v) { const h = state.hist[key]; h.push(v); if (h.length > 40) h.shift(); }

/* ---------- KPI cards ---------- */
const KPIS = [
  { id: "logs", label: "Logs Processed", icon: '<path d="M3 12h4l3 8 4-16 3 8h4"/>' },
  { id: "alerts", label: "Detected Alerts", icon: '<path d="M12 2l9 4v6c0 5-3.8 8.5-9 10-5.2-1.5-9-5-9-10V6l9-4z"/>' },
  { id: "crit", label: "Critical", icon: '<path d="M12 2 1 21h22L12 2z"/><path d="M12 9v5M12 17h.01"/>' },
  { id: "rate", label: "Alert Rate", icon: '<path d="M5 19L19 5M8 6a2 2 0 1 1-4 0 2 2 0 0 1 4 0zM20 18a2 2 0 1 1-4 0 2 2 0 0 1 4 0z"/>' },
  { id: "conf", label: "Avg Anomaly Score", icon: '<rect x="4" y="4" width="16" height="16" rx="2"/><path d="M9 9h6v6H9z"/>' },
];
function buildKPIs() {
  const row = $("#kpiRow");
  KPIS.forEach(k => {
    const c = el("div", "card kpi");
    c.dataset.kpi = k.id;
    if (k.id === "crit" || k.id === "alerts") c.classList.add("clickable");
    c.innerHTML = `
      <div class="k-top"><div class="k-ico"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">${k.icon}</svg></div>
      <div class="k-label">${k.label}</div></div>
      <div class="k-val" id="kpi-${k.id}" data-v="0">0</div>
      <div class="k-foot" id="kpif-${k.id}"></div>
      <svg class="spark" id="spark-${k.id}" viewBox="0 0 90 34" preserveAspectRatio="none"></svg>`;
    row.appendChild(c);
  });
}
function drawSpark(id, arr, color) {
  const svg = $("#spark-" + id); if (!svg || arr.length < 2) return;
  const max = Math.max(...arr, 1), min = Math.min(...arr, 0), span = max - min || 1;
  const pts = arr.map((v, i) => `${(i / (arr.length - 1)) * 90},${34 - ((v - min) / span) * 30 - 2}`).join(" ");
  svg.innerHTML = `<polyline points="${pts}" fill="none" stroke="${color}" stroke-width="2" opacity="0.9"/>`;
}
function renderKPIs() {
  const rate = state.totalLogs ? (state.totalAlerts / state.totalLogs) * 100 : 0;
  // Mean Isolation-Forest anomaly score across ALERTS (0–1). This is a
  // raw model score, NOT a calibrated probability — so we show the value
  // itself, not a "confidence %".
  const meanScore = state.confN ? (state.confSum / state.confN) : 0;
  animateCount($("#kpi-logs"), state.totalLogs);
  animateCount($("#kpi-alerts"), state.totalAlerts);
  animateCount($("#kpi-crit"), state.sev.critical);
  animateCount($("#kpi-rate"), +rate.toFixed(1), "%");
  animateCount($("#kpi-conf"), +meanScore.toFixed(2), "", 2);
  $("#kpif-crit").innerHTML = state.sev.critical ? `<span class="trend-up">▲</span> needs review` : `<span style="color:var(--ok)">✓ clear</span>`;
  $("#kpif-alerts").innerHTML = `<span class="trend-up">▲</span> ${state.sev.high} high`;
  $("#kpif-rate").innerHTML = `<span class="sub">of all traffic</span>`;
  $("#kpif-conf").innerHTML = `<span class="sub">mean IF score · alerts</span>`;
  $("#kpif-logs").innerHTML = `<span class="sub">since start</span>`;
  drawSpark("logs", state.hist.logs, "#22d3ee");
  drawSpark("alerts", state.hist.alerts, "#f97316");
  drawSpark("crit", state.hist.crit, "#ef4444");
  drawSpark("rate", state.hist.rate, "#3b82f6");
  drawSpark("conf", state.hist.conf, "#22c55e");
}

/* ---------- Threat index gauge ---------- */
function renderGauge() {
  const arr = state.recentSev;
  const idx = arr.length ? Math.round(arr.reduce((a, b) => a + b, 0) / arr.length) : 0;
  const arc = $("#gaugeArc");
  arc.style.strokeDashoffset = String(283 - (283 * idx / 100));
  animateCount($("#threatNum"), idx);
  const lab = idx >= 75 ? "CRITICAL" : idx >= 50 ? "HIGH" : idx >= 25 ? "ELEVATED" : "LOW";
  $("#threatLab").textContent = lab;
  $("#threatNum").style.color = idx >= 75 ? "#ef4444" : idx >= 50 ? "#f97316" : idx >= 25 ? "#eab308" : "#22c55e";
}

/* ---------- Live stream ---------- */
function addStreamRow(d) {
  const body = $("#streamBody");
  const tr = el("tr", "row-enter");
  tr.dataset.sev = d.severity || "none";
  tr.dataset.evt = (d.event_type || "").toLowerCase();
  const scorePct = d.anomaly_score != null ? Math.round(d.anomaly_score * 100) : 0;
  tr.innerHTML = `
    <td class="mono">${timeStr(d.created_at)}</td>
    <td class="evt">${esc(d.event_type || "—")}</td>
    <td class="mono">${esc(d.source_ip || "—")} → ${esc(d.destination_ip || "—")}</td>
    <td>${esc(d.protocol || "—")}</td>
    <td><span class="scorebar"><i style="width:${scorePct}%"></i></span> <span class="mono">${(d.anomaly_score ?? 0).toFixed(2)}</span></td>
    <td><span class="sev ${sevClass(d.severity)}"><i></i>${d.severity || "benign"}</span></td>`;
  tr.addEventListener("click", () => openDrawer(d));
  body.prepend(tr);
  while (body.children.length > MAX_STREAM) body.lastChild.remove();
  applySearch();
}

/* ---------- Alerts ---------- */
function addAlert(d) {
  const list = $("#alertsList");
  const sk = { critical: "crit", high: "high", medium: "med", low: "low" }[d.severity] || "low";
  const a = el("div", "alert " + sk + " row-enter");
  a.innerHTML = `
    <div class="a-top"><span class="sev ${sevClass(d.severity)}"><i></i>${d.severity}</span>
      <span class="a-type">${esc(d.event_type || "Anomaly")}</span>
      <span class="a-time">${timeStr(d.created_at)}</span></div>
    <div class="a-meta"><span>Score <b>${(d.anomaly_score ?? 0).toFixed(3)}</b></span>
      <span>ID <b>#${d.id}</b></span><span>Status <b>open</b></span></div>`;
  a.addEventListener("click", () => openDrawer(d));
  list.prepend(a);
  while (list.children.length > MAX_ALERTS) list.lastChild.remove();
  $("#alertCount").textContent = state.totalAlerts + " detected";
}

/* ---------- Charts ---------- */
function renderDonut() {
  const svg = $("#donut"), legend = $("#donutLegend");
  const entries = Object.entries(state.sev);
  const sum = entries.reduce((a, [, v]) => a + v, 0);
  const total = sum || 1;   // guards the arc math below; display `sum`
  let off = 0; let paths = "";
  const R = 45, C = 2 * Math.PI * R;
  entries.forEach(([k, v]) => {
    const frac = v / total, len = frac * C;
    paths += `<circle cx="60" cy="60" r="${R}" fill="none" stroke="${SEV_COLOR[k]}" stroke-width="14"
      stroke-dasharray="${len} ${C - len}" stroke-dashoffset="${-off}" transform="rotate(-90 60 60)"/>`;
    off += len;
  });
  svg.innerHTML = paths + `<text x="60" y="58" text-anchor="middle" fill="var(--text)" font-size="20" font-weight="800">${sum}</text><text x="60" y="74" text-anchor="middle" fill="var(--text-faint)" font-size="9">ALERTS</text>`;
  legend.innerHTML = entries.map(([k, v]) => `<span class="clk" data-sev="${k}" title="Show all ${k} alerts"><i style="background:${SEV_COLOR[k]}"></i>${k}<b>${v}</b></span>`).join("");
}
function renderCats() {
  const box = $("#catBars");
  const items = Object.entries(state.cats).sort((a, b) => b[1] - a[1]).slice(0, 6);
  const max = Math.max(1, ...items.map(([, v]) => v));
  box.innerHTML = items.length ? items.map(([k, v]) =>
    `<div class="bar-item"><span title="${esc(k)}" style="overflow:hidden;text-overflow:ellipsis">${esc(k)}</span>
     <div class="bar-track"><div class="bar-fill" style="width:${(v / max) * 100}%"></div></div>
     <span class="val">${v}</span></div>`).join("")
    : `<div class="sub" style="padding:20px 0;text-align:center">No alerts yet — ingest data to populate</div>`;
}
function renderSparkChart() {
  const svg = $("#spark"), b = state.buckets, max = Math.max(1, ...b);
  const w = 300, h = 130;
  const pts = b.map((v, i) => `${(i / (b.length - 1)) * w},${h - (v / max) * (h - 12) - 6}`).join(" ");
  const area = `0,${h} ${pts} ${w},${h}`;
  svg.innerHTML = `<polygon points="${area}" fill="url(#ag)" opacity="0.35"/>
    <polyline points="${pts}" fill="none" stroke="#3b82f6" stroke-width="2"/>
    <defs><linearGradient id="ag" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#3b82f6"/><stop offset="1" stop-color="#3b82f600"/></linearGradient></defs>`;
}

/* ---------- Model status (real) ---------- */
async function loadModel() {
  try {
    const m = await (await fetch("/model/info")).json();
    const grid = $("#modelMeta"), line = $("#modelStatusLine");
    if (m.status !== "loaded") {
      $("#modelStatus").textContent = "unavailable";
      grid.innerHTML = `<div class="sub" style="grid-column:1/-1">No trained model loaded. Run fit_pipeline + train_detector, then restart.</div>`;
      line.innerHTML = `<span class="dot" style="background:var(--med)"></span><span>Detection disabled — graceful degradation</span>`;
      return;
    }
    $("#modelStatus").textContent = "healthy";
    grid.innerHTML = `
      <div class="meta"><span class="m-lab">Model</span><span class="m-val">${m.model_type}</span></div>
      <div class="meta"><span class="m-lab">Trees</span><span class="m-val mono">${m.n_estimators}</span></div>
      <div class="meta"><span class="m-lab">Features</span><span class="m-val mono">${m.n_features}</span></div>
      <div class="meta"><span class="m-lab">Contamination</span><span class="m-val mono">${m.contamination}</span></div>
      <div class="meta"><span class="m-lab">Threshold</span><span class="m-val mono">${m.decision_threshold}</span></div>
      <div class="meta"><span class="m-lab">Live clients</span><span class="m-val mono">${m.live_connections}</span></div>`;
    line.innerHTML = `<span class="dot" style="background:var(--ok);box-shadow:0 0 8px var(--ok)"></span><span>Loaded · scoring live traffic</span>`;
  } catch { /* offline */ }
}

/* ---------- Health (mock, labeled DEMO) + MITRE (mock) + Threat intel (mock) ---------- */
function renderHealth(apiUp) {
  const rows = [
    ["API Gateway", apiUp ? 100 : 0, apiUp ? "var(--ok)" : "var(--crit)", apiUp ? "OK" : "DOWN"],
    ["ML Inference", 100, "var(--ok)", "OK"],
    ["Database", 100, "var(--ok)", "OK"],
    ["CPU", 34, "var(--ok)", "34%"],
    ["Memory", 61, "var(--med)", "61%"],
    ["Disk", 47, "var(--ok)", "47%"],
  ];
  $("#healthRow").innerHTML = rows.map(([n, p, c, v]) =>
    `<div class="health-item"><span class="h-name">${n}</span><div class="h-bar"><i style="width:${p}%;background:${c}"></i></div><span class="h-val">${v}</span></div>`).join("");
}
const MITRE = [
  ["Initial Access", ["Exploit Public App", "Valid Accounts"]],
  ["Execution", ["Command &amp; Scripting"]],
  ["Persistence", ["Valid Accounts"]],
  ["Priv. Escalation", ["Exploitation"]],
  ["Defense Evasion", ["Obfuscation"]],
  ["Credential Access", ["Brute Force"]],
  ["Discovery", ["Network Service Scan"]],
  ["Lateral Movement", ["Remote Services"]],
  ["Collection", ["Data Staged"]],
  ["Exfiltration", ["Over C2"]],
];
const CAT2TECH = { "portscan": "Network Service Scan", "ftp-patator": "Brute Force", "ssh-patator": "Brute Force", "bot": "Command &amp; Scripting", "ddos": "Exploitation", "dos hulk": "Exploitation", "infiltration": "Valid Accounts" };
const mitreHits = new Set();
function renderMitre() {
  const cols = MITRE.slice(0, 5).concat(MITRE.slice(5, 10)); // keep 10 in 5-wide grid (2 rows visually)
  $("#mitre").innerHTML = MITRE.map(([tac, techs]) =>
    `<div class="mitre-col"><div class="tac">${tac}</div>${techs.map(t =>
      `<div class="tech ${mitreHits.has(t) ? "hit" : ""}">${t}</div>`).join("")}</div>`).join("");
}
function noteMitre(evt) {
  const t = CAT2TECH[(evt || "").toLowerCase()]; if (t) { mitreHits.add(t); renderMitre(); }
}
function renderThreatIntel() {
  const ips = [
    ["45.134.26.11", "malware C2", "rep-bad", "98"],
    ["193.36.119.4", "scanner", "rep-warn", "71"],
    ["185.220.101.7", "tor exit", "rep-warn", "64"],
    ["91.219.236.18", "botnet", "rep-bad", "95"],
  ];
  $("#tiList").innerHTML = ips.map(([ip, tag, cls, sc]) =>
    `<div class="ti-item"><span class="ti-ip">${ip}</span><span class="sub">${tag}</span><span class="ti-rep ${cls}">${sc}</span></div>`).join("");
}

/* ---------- AI explanation drawer (REAL top_features) ---------- */
function openDrawer(d) {
  const body = $("#drawerBody");
  const score = d.anomaly_score ?? 0, pct = Math.round(score * 100);
  const feats = d.top_features || [];
  const maxDev = Math.max(1, ...feats.map(f => Math.abs(f.deviation)));
  $("#drawerTitle").textContent = d.is_alert ? "Alert Investigation" : "Detection Analysis";
  const nl = buildNarrative(d, feats);
  body.innerHTML = `
    <div class="explain-hero">
      <div class="explain-score" style="--pct:${pct}%"><div><b style="color:${SEV_COLOR[d.severity || "none"]}">${pct}</b></div></div>
      <div class="explain-meta">
        Prediction <b>${d.is_alert ? "ANOMALY" : "normal"}</b><br>
        Severity <b style="color:${SEV_COLOR[d.severity || "none"]}">${d.severity || "benign"}</b><br>
        Event <b>${esc(d.event_type || "—")}</b> · ID <b>#${d.id}</b>
      </div>
    </div>
    <div>
      <div class="section-lab">Largest deviations from benign baseline</div>
      <div class="feat-note">Standardized distance (σ) of each feature from the model's learned benign baseline — an analyst signal, not the forest's internal attribution.</div>
      ${feats.length ? feats.map(f => {
        const dir = f.deviation >= 0 ? "#ef4444" : "#38bdf8";
        return `<div class="feat"><span class="f-name">${esc(f.feature)}</span>
          <span class="f-dev" style="color:${dir}">${f.deviation >= 0 ? "+" : ""}${f.deviation}σ</span>
          <div class="f-bar"><i style="width:${(Math.abs(f.deviation) / maxDev) * 100}%;background:${dir}"></i></div></div>`;
      }).join("") : '<div class="sub">No feature deviations (unscored log).</div>'}
    </div>
    <div>
      <div class="section-lab">Natural-language explanation</div>
      <div class="explain-text">${nl}</div>
    </div>
    <div>
      <div class="section-lab">Recommended actions</div>
      <div class="explain-text">${recommend(d)}</div>
    </div>
    <div>
      <div class="section-lab">Raw event</div>
      <div class="raw">${esc(JSON.stringify({ id: d.id, event_type: d.event_type, anomaly_score: d.anomaly_score, is_alert: d.is_alert, severity: d.severity, created_at: d.created_at }, null, 2))}</div>
    </div>`;
  $("#drawer").classList.add("open"); $("#drawerMask").classList.add("open");
}
function buildNarrative(d, feats) {
  if (!d.is_alert) return `This flow scored <b>${(d.anomaly_score ?? 0).toFixed(3)}</b>, within the learned benign baseline — no anomaly flagged.`;
  const top = feats.slice(0, 2).map(f => `<b>${esc(f.feature)}</b> (${f.deviation >= 0 ? "+" : ""}${f.deviation}σ)`).join(" and ");
  return `This traffic deviates from the benign baseline. The Isolation Forest isolated it with an anomaly score of <b>${(d.anomaly_score ?? 0).toFixed(3)}</b>. Its largest deviations from normal are ${top || "spread across several features"} — the features sitting furthest from the baseline learned on benign flows. These highlight where the traffic is unusual; they are an analyst signal, not the model's internal reason for isolating it. Classified <b>${esc(d.event_type || "anomaly")}</b> at <b>${d.severity}</b> severity.`;
}
function recommend(d) {
  const s = d.severity;
  if (s === "critical") return "Isolate affected host, capture full packet detail, and escalate to Tier-2 immediately.";
  if (s === "high") return "Review source/destination context, correlate with recent events, and prepare containment.";
  if (s === "medium") return "Monitor for repetition; add to watchlist if pattern recurs.";
  return "Low priority — log for baseline tuning and false-positive review.";
}
function closeDrawer() { $("#drawer").classList.remove("open"); $("#drawerMask").classList.remove("open"); }

/* ---------- Message handling ---------- */
let bucketTimer = null;
function handleMessage(msg) {
  if (msg.type !== "log") return;
  const d = msg.data;
  state.totalLogs++;
  state.logTimes.push(Date.now());
  const sev = d.severity || "none";
  state.recentSev.push(SEV_WEIGHT[sev] ?? 0);
  if (state.recentSev.length > 40) state.recentSev.shift();

  addStreamRow(d);
  noteGeo(d, true);

  if (d.is_alert) {
    state.totalAlerts++;
    if (state.sev[sev] != null) state.sev[sev]++;
    state.cats[d.event_type || "Unknown"] = (state.cats[d.event_type || "Unknown"] || 0) + 1;
    state.buckets[MAX_BUCKETS - 1]++;
    if (d.anomaly_score != null) { state.confSum += d.anomaly_score; state.confN++; }
    addAlert(d);
    noteMitre(d.event_type);
    renderDonut(); renderCats();
  }
  renderGauge();
  renderKPIsThrottled();
}

let kpiRAF = null;
function renderKPIsThrottled() { if (kpiRAF) return; kpiRAF = requestAnimationFrame(() => { kpiRAF = null; renderKPIs(); }); }

/* every 3s: roll the time-bucket window + push KPI history + logs/min */
setInterval(() => {
  state.buckets.push(0); if (state.buckets.length > MAX_BUCKETS) state.buckets.shift();
  renderSparkChart();
  pushHist("logs", state.totalLogs); pushHist("alerts", state.totalAlerts); pushHist("crit", state.sev.critical);
  pushHist("rate", state.totalLogs ? (state.totalAlerts / state.totalLogs) * 100 : 0);
  pushHist("conf", state.confN ? (state.confSum / state.confN) : 0);
  const now = Date.now(); state.logTimes = state.logTimes.filter(t => now - t < 60000);
  $("#streamRate").textContent = state.logTimes.length + " logs/min";
  renderKPIs();
}, 3000);

/* ---------- Initial REST load ---------- */
async function loadInitial() {
  try {
    const s = await (await fetch("/stats")).json();
    state.totalLogs = s.total_logs; state.totalAlerts = s.total_alerts;
    Object.assign(state.sev, s.alerts_by_severity || {});
    renderKPIs(); renderDonut(); renderGauge();
  } catch { /* offline */ }
  try {
    const alerts = await (await fetch("/logs/alerts?limit=12")).json();
    alerts.reverse().forEach(a => {
      addAlert(a);
      state.cats[a.event_type || "Unknown"] = (state.cats[a.event_type || "Unknown"] || 0) + 1;
      noteMitre(a.event_type); noteGeo(a);
      // Seed the running mean-score + threat gauge so they aren't stuck at
      // zero before the first live message arrives.
      if (a.anomaly_score != null) { state.confSum += a.anomaly_score; state.confN++; }
      state.recentSev.push(SEV_WEIGHT[a.severity || "none"] ?? 0);
    });
    renderCats(); renderKPIs(); renderGauge();
  } catch { /* offline */ }
  loadModel();
}

/* ---------- Connection ---------- */
function setConn(up) {
  const c = $("#conn");
  c.className = "conn " + (up ? "live" : "down");
  $("#connText").textContent = up ? "Live" : "Reconnecting…";
  renderHealth(up);
}
function connectWS() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  let ws;
  try { ws = new WebSocket(`${proto}://${location.host}/ws`); }
  catch { setConn(false); setTimeout(connectWS, 2500); return; }
  ws.onopen = () => { setConn(true); loadModel(); };
  ws.onmessage = (e) => { try { handleMessage(JSON.parse(e.data)); } catch {} };
  ws.onclose = () => { setConn(false); setTimeout(connectWS, 2500); };
  ws.onerror = () => ws.close();
}

/* ---------- Live-stream client-side filters (search + severity chips) ---------- */
const streamFilter = { text: "", sev: "", alertsOnly: false };
function applySearch() {
  streamFilter.text = ($("#search").value || "").toLowerCase().trim();
  filterStream();
}
function filterStream() {
  const { text, sev, alertsOnly } = streamFilter;
  document.querySelectorAll("#streamBody tr").forEach(tr => {
    const okText = !text || tr.textContent.toLowerCase().includes(text);
    const okSev = !sev || tr.dataset.sev === sev;
    const okAlert = !alertsOnly || (tr.dataset.sev && tr.dataset.sev !== "none");
    tr.style.display = okText && okSev && okAlert ? "" : "none";
  });
}

/* ---------- Toast ---------- */
let toastTimer = null;
function toast(msg) {
  const t = $("#toast");
  t.textContent = msg; t.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove("show"), 2600);
}

/* ---------- Sidebar navigation (scroll-to-section, honest for the rest) ---------- */
function setActiveNav(node) {
  document.querySelector(".nav-item.active")?.classList.remove("active");
  node.classList.add("active");
}
function navTo(node) {
  if (node.dataset.explorer) { openExplorer(); return; }
  if (node.dataset.target) {
    const target = document.querySelector(node.dataset.target);
    if (target) {
      setActiveNav(node);
      target.scrollIntoView({ behavior: "smooth", block: "start" });
      target.classList.remove("flash"); void target.offsetWidth; target.classList.add("flash");
    }
  } else if (node.dataset.soon) {
    toast(node.dataset.soon);
  }
  closeMobileSidebar();
}

/* ---------- Mobile sidebar ---------- */
const isMobile = () => window.matchMedia("(max-width: 720px)").matches;
function toggleSidebar() {
  if (isMobile()) $("#app").classList.toggle("mobile-open");
  else $("#app").classList.toggle("collapsed");
}
function closeMobileSidebar() { $("#app").classList.remove("mobile-open"); }

/* ---------- Log Explorer (real backend queries: /logs?…) ---------- */
function openExplorer(preset = {}) {
  if (preset.severity !== undefined) $("#fSeverity").value = preset.severity || "";
  if (preset.alertsOnly !== undefined) $("#fAlerts").checked = !!preset.alertsOnly;
  if (preset.ip !== undefined) $("#fIp").value = preset.ip || "";
  $("#explorer").classList.add("open"); $("#explorerMask").classList.add("open");
  runExplorerQuery();
}
function closeExplorer() { $("#explorer").classList.remove("open"); $("#explorerMask").classList.remove("open"); }
function resetFilters() {
  $("#fSeverity").value = ""; $("#fIp").value = ""; $("#fStart").value = "";
  $("#fEnd").value = ""; $("#fLimit").value = "200"; $("#fAlerts").checked = false;
  runExplorerQuery();
}
async function runExplorerQuery() {
  const body = $("#explorerBody");
  const params = new URLSearchParams();
  const sev = $("#fSeverity").value; if (sev) params.set("severity", sev);
  const ip = $("#fIp").value.trim(); if (ip) params.set("source_ip", ip);
  if ($("#fAlerts").checked) params.set("is_alert", "true");
  const start = $("#fStart").value; if (start) params.set("start_time", start);
  const end = $("#fEnd").value; if (end) params.set("end_time", end);
  params.set("limit", $("#fLimit").value || "200");

  body.innerHTML = `<tr><td colspan="6" class="explorer-msg">Loading…</td></tr>`;
  try {
    const rows = await (await fetch("/logs?" + params.toString())).json();
    $("#explorerCount").textContent = `${rows.length} result${rows.length === 1 ? "" : "s"}`;
    if (!rows.length) {
      body.innerHTML = `<tr><td colspan="6" class="explorer-msg">No logs match these filters.</td></tr>`;
      return;
    }
    body.innerHTML = "";
    rows.forEach(d => {
      const tr = el("tr");
      const scorePct = d.anomaly_score != null ? Math.round(d.anomaly_score * 100) : 0;
      tr.innerHTML = `
        <td class="mono">${timeStr(d.created_at)}</td>
        <td class="evt">${esc(d.event_type || "—")}</td>
        <td class="mono">${esc(d.source_ip || "—")} → ${esc(d.destination_ip || "—")}</td>
        <td>${esc(d.protocol || "—")}</td>
        <td><span class="scorebar"><i style="width:${scorePct}%"></i></span> <span class="mono">${(d.anomaly_score ?? 0).toFixed(2)}</span></td>
        <td><span class="sev ${sevClass(d.severity)}"><i></i>${d.severity || "benign"}</span></td>`;
      tr.style.cursor = "pointer";
      tr.addEventListener("click", () => openDrawer(d));
      body.appendChild(tr);
    });
  } catch {
    body.innerHTML = `<tr><td colspan="6" class="explorer-msg" style="color:var(--crit)">Query failed — is the API running?</td></tr>`;
  }
}

/* ---------- Observed source network location (SIMULATED positions) ----------
   The BASEMAP is real: Natural Earth country boundaries, projected to a
   1000x500 equirectangular SVG at build time (dashboard/worldmap.js) — no
   runtime map dependency, no third-party tiles.
   The POSITIONS are simulated: an IP is a network endpoint, not a place,
   and we have no GeoIP/ASN enrichment, so each IP maps to a DETERMINISTIC
   point via a hash. Same IP -> same spot, but NOT its real location. */
const geo = new Map(); // ip -> { count, x, y, sev, alert, lastScore, lastTime, lastEvent, demo, flash, city, country, asn, net }
function ipToXY(ip) {
  let h = 2166136261 >>> 0;
  const s = String(ip);
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619) >>> 0; }
  const a = h / 4294967295;
  let h2 = (h ^ 0x9e3779b9) >>> 0; h2 = Math.imul(h2, 2654435761) >>> 0;
  const b = h2 / 4294967295;
  const lon = a * 360 - 180, lat = 66 - b * 116; // bias toward the populated band
  return { x: (lon + 180) / 360 * 1000, y: (90 - lat) / 180 * 500 };
}

/* Fixed SAMPLE alerts so the map isn't empty in a demo (CICIDS carries no
   IPs). These are NOT live and NOT real: the IPs are RFC-5737 documentation
   ranges (203.0.113/198.51.100/192.0.2 — reserved for examples), the
   locations/ASNs are illustrative, and the whole map is badged SIMULATED
   DATA. Real ingested logs that DO carry a source_ip still plot alongside
   these via noteGeo(). Placed at real city coords so they sit on land. */
const DEMO_MARKERS = [
  { ip: "203.0.113.45", sev: "critical", score: 0.98, event: "DDoS",         city: "Amsterdam",    country: "NL", asn: "AS60781 LeaseWeb",      net: "Hosting",   lon: 4.90,   lat: 52.37, count: 41, age: 2 },
  { ip: "198.51.100.7", sev: "critical", score: 0.97, event: "Bot C2",        city: "Moscow",       country: "RU", asn: "AS49505 Selectel",      net: "Hosting",   lon: 37.62,  lat: 55.75, count: 33, age: 4 },
  { ip: "192.0.2.222",  sev: "critical", score: 0.95, event: "DoS Hulk",      city: "Singapore",    country: "SG", asn: "AS135377 UCloud",       net: "Hosting",   lon: 103.82, lat: 1.35,  count: 27, age: 1 },
  { ip: "203.0.113.88", sev: "high",     score: 0.88, event: "PortScan",      city: "Frankfurt",    country: "DE", asn: "AS200651 Tor",          net: "Tor exit",  lon: 8.68,   lat: 50.11, count: 19, age: 6 },
  { ip: "198.51.100.19",sev: "high",     score: 0.86, event: "SSH-Patator",   city: "Kyiv",         country: "UA", asn: "AS29632 Botnet",        net: "Botnet",    lon: 30.52,  lat: 50.45, count: 22, age: 3 },
  { ip: "192.0.2.140",  sev: "high",     score: 0.84, event: "PortScan",      city: "Tokyo",        country: "JP", asn: "AS2516 KDDI",           net: "ISP",       lon: 139.69, lat: 35.68, count: 14, age: 8 },
  { ip: "203.0.113.201",sev: "high",     score: 0.82, event: "DDoS",          city: "Bogotá",       country: "CO", asn: "AS19429 ETB",           net: "Hosting",   lon: -74.07, lat: 4.71,  count: 11, age: 5 },
  { ip: "198.51.100.23",sev: "medium",   score: 0.61, event: "FTP-Patator",   city: "New York",     country: "US", asn: "AS7922 Comcast",        net: "ISP",       lon: -74.01, lat: 40.71, count: 9,  age: 11 },
  { ip: "192.0.2.54",   sev: "medium",   score: 0.58, event: "Infiltration",  city: "Mumbai",       country: "IN", asn: "AS9829 BSNL",           net: "ISP",       lon: 72.88,  lat: 19.08, count: 7,  age: 14 },
  { ip: "203.0.113.108",sev: "medium",   score: 0.55, event: "SSH-Patator",   city: "Johannesburg", country: "ZA", asn: "AS37457 Telkom",        net: "Hosting",   lon: 28.04,  lat: -26.20,count: 6,  age: 9 },
  { ip: "198.51.100.90",sev: "low",      score: 0.34, event: "Web Attack",    city: "São Paulo",    country: "BR", asn: "AS28573 Claro",         net: "ISP",       lon: -46.63, lat: -23.55,count: 4,  age: 18 },
  { ip: "192.0.2.200",  sev: "low",      score: 0.31, event: "Anomaly",       city: "Sydney",       country: "AU", asn: "AS1221 Telstra",        net: "ISP",       lon: 151.21, lat: -33.87,count: 3,  age: 22 },
  { ip: "203.0.113.12", sev: "low",      score: 0.29, event: "Anomaly",       city: "London",       country: "GB", asn: "AS5089 Virgin Media",   net: "ISP",       lon: -0.13,  lat: 51.51, count: 3,  age: 27 },
];
function seedDemoMarkers() {
  DEMO_MARKERS.forEach(d => {
    geo.set(d.ip, {
      count: d.count, alert: true, sev: d.sev, demo: true, flash: true,
      x: (d.lon + 180) / 360 * 1000, y: (90 - d.lat) / 180 * 500,
      lastScore: d.score, lastEvent: d.event,
      lastTime: new Date(Date.now() - d.age * 60000).toISOString(),
      city: d.city, country: d.country, asn: d.asn, net: d.net,
    });
  });
}
function renderWorldMap() {
  const land = $("#worldLand"); const grat = $("#worldGraticule");
  if (grat) {
    let g = "";
    for (let lon = -150; lon <= 150; lon += 30) { const x = (lon + 180) / 360 * 1000; g += `<line x1="${x}" y1="0" x2="${x}" y2="500"/>`; }
    for (let lat = -60; lat <= 60; lat += 30) { const y = (90 - lat) / 180 * 500; g += `<line x1="0" y1="${y}" x2="1000" y2="${y}"/>`; }
    grat.innerHTML = g;
  }
  if (land && window.WORLD_PATHS) {
    land.innerHTML = window.WORLD_PATHS.map(d => `<path d="${d}" class="country"/>`).join("");
  }
}
const NEUTRAL_DOT = "#5a86c9";
function noteGeo(d, live = false) {
  if (!d || !d.source_ip) return;
  const cur = geo.get(d.source_ip) || { count: 0, ...ipToXY(d.source_ip) };
  cur.count++;
  cur.lastScore = d.anomaly_score; cur.lastTime = d.created_at; cur.lastEvent = d.event_type;
  if (d.is_alert) { cur.alert = true; cur.sev = d.severity || cur.sev; }
  geo.set(d.source_ip, cur);
  renderMapMarkers();
  // A ring pulses only for a NEWLY RECEIVED critical/high hit (live=true) —
  // never for the historical rows replayed on initial load, and never a
  // constant blink.
  if (live && d.is_alert && (d.severity === "critical" || d.severity === "high")) pulseAt(cur, d.severity);
}
function renderMapMarkers() {
  const layer = $("#mapMarkers"); if (!layer) return;
  const items = [...geo.entries()];
  const flashDur = { critical: 1.6, high: 2.0, medium: 2.6, low: 3.2 };
  layer.innerHTML = items.map(([ip, m]) => {
    const col = m.alert ? (SEV_COLOR[m.sev] || "#f97316") : NEUTRAL_DOT;
    const r = Math.min(8, 2.6 + Math.log2(m.count + 1));
    // Flashing halo for demo/sample markers (steady breathing pulse), a
    // plain static halo otherwise. Live NEW crit/high still get a one-shot
    // expanding ripple via pulseAt().
    const halo = m.flash
      ? `<circle cx="${m.x}" cy="${m.y}" r="${(r * 1.7).toFixed(1)}" fill="${col}">
          <animate attributeName="r" values="${(r * 1.5).toFixed(1)};${(r * 3.3).toFixed(1)};${(r * 1.5).toFixed(1)}" dur="${flashDur[m.sev] || 2.4}s" repeatCount="indefinite"/>
          <animate attributeName="opacity" values="0.34;0.04;0.34" dur="${flashDur[m.sev] || 2.4}s" repeatCount="indefinite"/>
        </circle>`
      : `<circle cx="${m.x}" cy="${m.y}" r="${(r * 2.2).toFixed(1)}" fill="${col}" opacity="0.16"/>`;
    return `<g class="mk" data-ip="${esc(ip)}">${halo}
      <circle cx="${m.x}" cy="${m.y}" r="${r.toFixed(1)}" fill="${col}" stroke="#0b1220" stroke-width="0.6" opacity="0.95"/>
    </g>`;
  }).join("");
  const top = items.sort((a, b) => b[1].count - a[1].count).slice(0, 6);
  $("#mapList").innerHTML = top.length
    ? top.map(([ip, m]) => `<div class="ti-item"><span class="ti-ip">${esc(ip)}</span><span class="sub">${m.count} event${m.count > 1 ? "s" : ""}</span><span class="ti-rep ${m.alert ? "rep-bad" : "rep-warn"}">${m.alert ? (m.sev || "alert") : "benign"}</span></div>`).join("")
    : `<div class="sub" style="padding:10px 0">No source IPs seen yet.</div>`;
}
function pulseAt(m, sev) {
  const layer = $("#mapRipples"); if (!layer) return;
  const col = SEV_COLOR[sev] || "#f97316";
  const g = document.createElementNS("http://www.w3.org/2000/svg", "circle");
  g.setAttribute("cx", m.x); g.setAttribute("cy", m.y); g.setAttribute("r", "3");
  g.setAttribute("fill", "none"); g.setAttribute("stroke", col); g.setAttribute("stroke-width", "1.6");
  g.setAttribute("class", "ripple");
  g.innerHTML = `<animate attributeName="r" from="3" to="34" dur="2.2s" fill="freeze"/>
    <animate attributeName="stroke-width" from="2" to="0" dur="2.2s" fill="freeze"/>
    <animate attributeName="opacity" from="0.9" to="0" dur="2.2s" fill="freeze"/>`;
  layer.appendChild(g);
  setTimeout(() => g.remove(), 2300);
}
function mapPopupFor(ip) {
  const m = geo.get(ip); if (!m) return "";
  const sev = m.alert ? (m.sev || "alert") : "benign";
  const loc = m.city ? `${esc(m.city)}, ${esc(m.country)}` : `Not resolved <em>(no GeoIP)</em>`;
  return `<div class="mp-ip">${esc(ip)} <span class="sev ${sevClass(m.alert ? m.sev : "none")}"><i></i>${sev}</span></div>
    <div class="mp-row"><span>Approx. location</span><b>${loc}</b></div>
    <div class="mp-row"><span>ASN / org</span><b>${m.asn ? esc(m.asn) : "—"}</b></div>
    <div class="mp-row"><span>Network type</span><b>${m.net ? esc(m.net) : "—"}</b></div>
    <div class="mp-row"><span>Event</span><b>${esc(m.lastEvent || "—")}</b></div>
    <div class="mp-row"><span>Events</span><b>${m.count}</b></div>
    <div class="mp-row"><span>Last score</span><b class="mono">${m.lastScore != null ? m.lastScore.toFixed(3) : "—"}</b></div>
    <div class="mp-row"><span>Last seen</span><b class="mono">${timeStr(m.lastTime)}</b></div>
    <div class="mp-sim">${m.demo ? "SAMPLE alert · mock enrichment" : "SIMULATED position — see note"}</div>`;
}

/* ---------- Boot ---------- */
document.addEventListener("DOMContentLoaded", () => {
  buildKPIs(); renderKPIs(); renderGauge(); renderDonut(); renderCats();
  renderSparkChart(); renderMitre(); renderThreatIntel(); renderHealth(false);
  renderWorldMap(); seedDemoMarkers(); renderMapMarkers();
  loadInitial(); connectWS();

  // Chrome
  $("#collapseBtn").addEventListener("click", toggleSidebar);
  $("#sidebarScrim").addEventListener("click", closeMobileSidebar);
  $("#drawerClose").addEventListener("click", closeDrawer);
  $("#drawerMask").addEventListener("click", closeDrawer);
  $("#search").addEventListener("input", applySearch);
  $("#themeBtn").addEventListener("click", () => {
    const root = document.documentElement;
    root.dataset.theme = root.dataset.theme === "light" ? "dark" : "light";
  });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") { closeDrawer(); closeExplorer(); } });

  // Sidebar nav
  document.querySelectorAll(".nav-item").forEach(n =>
    n.addEventListener("click", (e) => { e.preventDefault(); navTo(n); }));

  // Live-stream quick filters (client-side, on the rolling window)
  $("#streamFilters").addEventListener("click", (e) => {
    const chip = e.target.closest(".fchip"); if (!chip) return;
    if (chip.dataset.alerts !== undefined) {
      streamFilter.alertsOnly = !streamFilter.alertsOnly;
      chip.classList.toggle("active", streamFilter.alertsOnly);
    } else {
      streamFilter.sev = chip.dataset.sev || "";
      $("#streamFilters").querySelectorAll(".fchip:not(.alerts)").forEach(c => c.classList.remove("active"));
      chip.classList.add("active");
    }
    filterStream();
  });

  // Log Explorer (backed by GET /logs)
  $("#exploreBtn").addEventListener("click", () => openExplorer());
  $("#explorerClose").addEventListener("click", closeExplorer);
  $("#explorerMask").addEventListener("click", closeExplorer);
  $("#filters").addEventListener("submit", (e) => { e.preventDefault(); runExplorerQuery(); });
  $("#fReset").addEventListener("click", resetFilters);

  // Source map: hover previews a marker's details; CLICK pins them open
  // (click the flashing dot). Click elsewhere dismisses the pinned popup.
  const canvas = document.querySelector(".map-canvas");
  const popup = $("#mapPopup");
  let popupPinned = false;
  function showPopup(ip) {
    const m = geo.get(ip); if (!m || !canvas) return;
    popup.innerHTML = mapPopupFor(ip);
    popup.hidden = false;
    const left = (m.x / 1000) * canvas.clientWidth;
    const top = (m.y / 500) * canvas.clientHeight;
    popup.style.left = Math.min(left + 12, canvas.clientWidth - 220) + "px";
    popup.style.top = Math.max(top - 10, 8) + "px";
  }
  $("#mapMarkers").addEventListener("mouseover", (e) => {
    const mk = e.target.closest(".mk"); if (!mk || popupPinned) return;
    showPopup(mk.dataset.ip);
  });
  $("#mapMarkers").addEventListener("mouseout", (e) => {
    if (!popupPinned && e.target.closest(".mk")) popup.hidden = true;
  });
  $("#mapMarkers").addEventListener("click", (e) => {
    const mk = e.target.closest(".mk"); if (!mk) return;
    e.stopPropagation(); popupPinned = true; showPopup(mk.dataset.ip);
  });
  document.addEventListener("click", (e) => {
    if (popupPinned && !e.target.closest(".mk")) { popupPinned = false; popup.hidden = true; }
  });

  // Severity drill-down: donut legend + Critical/Detected KPI cards
  $("#donutLegend").addEventListener("click", (e) => {
    const s = e.target.closest("[data-sev]"); if (s) openExplorer({ severity: s.dataset.sev, alertsOnly: false });
  });
  $("#kpiRow").addEventListener("click", (e) => {
    const card = e.target.closest(".kpi.clickable"); if (!card) return;
    if (card.dataset.kpi === "crit") openExplorer({ severity: "critical" });
    else openExplorer({ alertsOnly: true, severity: "" });
  });
});
