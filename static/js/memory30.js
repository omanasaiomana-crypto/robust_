// IdentityShield 30-day memory page. All dynamic text is escaped (log data is untrusted).
const API = "/api/memory";
const $ = (id) => document.getElementById(id);

const esc = (v) => String(v ?? "").replace(/[&<>"'`]/g, (c) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;", "`": "&#96;" }[c]));
const band = (r) => (r >= 90 ? "revoke" : r >= 70 ? "restrict" : r >= 40 ? "step_up" : "monitor");
const BAND_COLOR = { monitor: "#94A3B8", step_up: "#E0A800", restrict: "#F08A4B", revoke: "#E5484D" };
const STAGE_LABEL = {
  initial_access: "Initial access", persistence: "Persistence", discovery: "Discovery",
  privilege_escalation: "Privilege escalation", collection: "Collection", impact: "Impact",
  exfiltration: "Exfiltration", defense_evasion: "Defense evasion",
};
let selected = null;

function token() {
  try { return localStorage.getItem("is_analyst_token") || ""; } catch { return ""; }
}
function saveToken(v) {
  try { localStorage.setItem("is_analyst_token", v); } catch { /* storage unavailable */ }
}

function toast(msg, isErr = false) {
  const t = $("toast");
  t.textContent = msg;
  t.className = "toast" + (isErr ? " err" : "");
  t.style.display = "block";
  clearTimeout(toast._h);
  toast._h = setTimeout(() => { t.style.display = "none"; }, 4500);
}

async function api(path, opts = {}) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), opts.timeout || 60000);
  const headers = { "Content-Type": "application/json" };
  if (opts.method === "POST" && token()) headers["X-Analyst-Token"] = token();
  try {
    const res = await fetch(API + path, { method: opts.method || "GET", headers,
      body: opts.body ? JSON.stringify(opts.body) : undefined, signal: ctrl.signal });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
    return data;
  } finally {
    clearTimeout(timer);
  }
}

function fmtBytes(n) {
  if (!n) return "0 KB";
  return n > 1048576 ? (n / 1048576).toFixed(1) + " MB" : Math.max(1, Math.round(n / 1024)) + " KB";
}
const num = (n) => Number(n || 0).toLocaleString();

function renderTiles(s) {
  const rows = s.rows || {};
  const tiles = [
    ["Database size", fmtBytes(s.db_size_bytes), "one SQLite file on this laptop"],
    ["Raw events kept", num(rows.events), s.last_prune
      ? `last ${s.retention?.raw_event_days ?? 7} days + evidence`
      : "retention not applied yet"],
    ["Evidence events", num(s.evidence_events), "kept as long as their case"],
    ["Identities", num(rows.identity_meta), `${num(rows.identity_daily)} daily summaries`],
    ["Linked findings", num(rows.findings), `${num(rows.chain_hits)} stage hits`],
    ["Memory window", s.memory_days?.first ? `${s.memory_days.first.slice(5)} → ${s.memory_days.last.slice(5)}` : "empty",
      `${s.retention?.memory_days ?? 30}-day rolling memory`],
  ];
  $("tiles").innerHTML = tiles.map(([k, v, sub]) =>
    `<div class="card tile"><div class="k">${esc(k)}</div><div class="v">${esc(v)}</div><div class="s">${esc(sub)}</div></div>`
  ).join("");
}

function renderBanner(rep) {
  if (!rep || rep.status === "no_synthetic_labels" || !rep.total) { $("banner").innerHTML = ""; return; }
  const ok = rep.passed === rep.total && rep.false_positive_count === 0;
  $("banner").innerHTML = `<div class="banner ${ok ? "" : "warn"}"><span class="tag">SYNTHETIC TEST DATA</span>
    <span>${esc(rep.passed)}/${esc(rep.total)} hidden multi-day attacks detected · ${esc(rep.false_positive_count)}
    false positives among ${esc(rep.normal_identities)} normal identities. Official KPIs use the official dataset only.</span></div>`;
}

function renderFindings(list) {
  if (!list.length) {
    $("findings").innerHTML = `<div class="empty">No multi-day attack chains yet. Ingest data or generate the 30-day test set.</div>`;
    return;
  }
  $("findings").innerHTML = list.map((f) => {
    const b = band(f.risk);
    return `<div class="finding ${f.identity === selected ? "active" : ""}" data-id="${esc(f.identity)}" tabindex="0" role="button">
      <div class="frow"><span class="who">${esc(f.identity)}</span>
        <span class="badge b-${b}">risk ${esc(Math.round(f.risk))}</span></div>
      <div class="chips">${f.stages.map((s) => `<span class="stage st-${esc(s)}">${esc(STAGE_LABEL[s] || s)}</span>`).join("")}</div>
      <div class="meta">${esc(f.days_spanned)} day(s) of evidence · ${esc(f.first_time.slice(0, 10))} → ${esc(f.last_time.slice(0, 10))}</div>
      <div class="narr">${esc(f.narrative)}</div></div>`;
  }).join("");
  document.querySelectorAll(".finding").forEach((el) => {
    const open = () => loadIdentity(el.dataset.id);
    el.addEventListener("click", open);
    el.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); open(); } });
  });
}

function stripSvg(days) {
  const W = 30 * 22 + 40, H = 170, base = 130, x0 = 30;
  const n = days.length, bw = Math.max(6, Math.floor((W - x0 - 10) / n) - 4);
  let s = `<svg viewBox="0 0 ${W} ${H}" width="100%" role="img" aria-label="Risk per day over the last ${n} days">`;
  [0, 40, 70, 90].forEach((v) => {
    const y = base - (v / 100) * 110;
    s += `<line x1="${x0}" x2="${W - 6}" y1="${y}" y2="${y}" stroke="#EFE8DC"/>`;
    s += `<text x="${x0 - 6}" y="${y + 4}" font-size="10" text-anchor="end" fill="#6B7280">${v}</text>`;
  });
  days.forEach((d, i) => {
    const x = x0 + 6 + i * (bw + 4);
    const r = d.max_risk || 0;
    const h = Math.max(r > 0 ? 3 : 0, (r / 100) * 110);
    const activity = Math.min(1, (d.events || 0) / 40);
    s += `<rect x="${x}" y="${base - 6 * activity}" width="${bw}" height="${6 * activity}" fill="#E8E1D6" rx="2"/>`;
    if (h) s += `<rect x="${x}" y="${base - h}" width="${bw}" height="${h}" rx="3" fill="${BAND_COLOR[band(r)]}">
      <title>${esc(d.day)}: risk ${Math.round(r)} · ${esc(d.events)} events${d.hits.length ? " · " + esc(d.hits.join(", ")) : ""}</title></rect>`;
    if (d.hits.length) s += `<circle cx="${x + bw / 2}" cy="${base + 12}" r="4" fill="#6D4FD8"><title>${esc(d.hits.join(", "))}</title></circle>`;
    if (i % 5 === 0 || i === n - 1) s += `<text x="${x + bw / 2}" y="${H - 8}" font-size="10" text-anchor="middle" fill="#4B5263">${esc(d.day.slice(5))}</text>`;
  });
  return s + "</svg>";
}

async function loadIdentity(identity) {
  selected = identity;
  document.querySelectorAll(".finding").forEach((el) => el.classList.toggle("active", el.dataset.id === identity));
  $("idTitle").textContent = "Identity memory: " + identity;
  $("identity").innerHTML = `<div class="skel"></div>`;
  try {
    const v = await api(`/identity/${encodeURIComponent(identity)}?days=30`);
    const hits = v.hits.map((h) => `<tr><td class="mono">${esc(h.day)}</td>
        <td><span class="stage st-${esc(h.stage)}">${esc(STAGE_LABEL[h.stage] || h.stage)}</span></td>
        <td>${esc(h.label)}${h.detail && (h.detail.action || h.detail.resource) ? `<div class="meta">${esc([h.detail.action, h.detail.resource].filter(Boolean).join(" · "))}</div>` : ""}</td>
        <td><button class="linkbtn" data-ids="${esc(h.event_ids.join(","))}" type="button">${esc(h.event_ids.length)} event(s)</button></td></tr>`).join("");
    $("identity").innerHTML = `
      <div class="frow"><span class="meta">Window ${esc(v.window.start)} → ${esc(v.window.end)} · first seen ${esc(v.first_seen.slice(0, 10))}</span>
        <span class="badge b-${band(v.risk_now)}">identity risk now ${esc(Math.round(v.risk_now))} (peak ${esc(Math.round(v.risk_peak))})</span></div>
      <div class="legend"><span><i style="background:#E5484D"></i>risk ≥ 90</span><span><i style="background:#F08A4B"></i>70–89</span>
        <span><i style="background:#E0A800"></i>40–69</span><span><i style="background:#E8E1D6"></i>daily activity</span>
        <span><i style="background:#6D4FD8;border-radius:50%"></i>attack-stage hit</span></div>
      <div class="strip-wrap">${stripSvg(v.days)}</div>
      <h2 style="margin-top:16px">Stage hits remembered</h2>
      ${v.hits.length ? `<div style="max-height:320px;overflow:auto"><table><thead><tr><th>Day</th><th>Stage</th><th>What</th><th>Evidence</th></tr></thead><tbody>${hits}</tbody></table></div>`
        : `<div class="empty">No attack-stage hits for this identity in the window.</div>`}
      <div id="evidence"></div>`;
    document.querySelectorAll("#identity .linkbtn").forEach((b) => b.addEventListener("click", () => showEvidence(b.dataset.ids)));
  } catch (e) {
    $("identity").innerHTML = `<div class="empty">Could not load: ${esc(e.message)}</div>`;
  }
}

async function showEvidence(ids) {
  const box = $("evidence");
  box.innerHTML = `<div class="skel" style="margin-top:12px"></div>`;
  try {
    const d = await api(`/evidence?ids=${encodeURIComponent(ids)}`);
    if (!d.events.length) { box.innerHTML = `<div class="empty" style="margin-top:12px">Evidence pruned or not found.</div>`; return; }
    const lines = d.events.map((e) => {
      let raw = e.raw;
      try { raw = JSON.stringify(JSON.parse(e.raw), null, 2); } catch { /* keep text */ }
      return `${e.time}  ${e.source}  ${e.action}  ${e.resource || ""}\n${raw}`;
    }).join("\n\n");
    box.innerHTML = `<pre>${esc(lines)}</pre>`;
  } catch (e) {
    box.innerHTML = `<div class="empty">Could not load evidence: ${esc(e.message)}</div>`;
  }
}

async function refresh() {
  try {
    const [s, f, rep] = await Promise.all([api("/stats"), api("/findings?limit=50"), api("/report").catch(() => null)]);
    renderTiles(s);
    renderFindings(f.findings);
    renderBanner(rep);
    const wanted = new URLSearchParams(location.search).get("identity");
    if (!selected && wanted) loadIdentity(wanted);
    else if (!selected && f.findings.length) loadIdentity(f.findings[0].identity);
  } catch (e) {
    toast("Memory API not reachable: " + e.message, true);
    $("findings").innerHTML = `<div class="empty">Memory API not reachable. Is the server running?</div>`;
  }
}

async function run(btn, fn, okMsg) {
  if (btn.disabled) return;
  btn.disabled = true;
  btn.classList.add("is-loading");
  try {
    const out = await fn();
    toast(okMsg(out));
    selected = null;
    await refresh();
  } catch (e) {
    toast(e.message, true);
  } finally {
    btn.disabled = false;
    btn.classList.remove("is-loading");
  }
}

function init() {
  $("token").value = token();
  $("token").addEventListener("change", (e) => saveToken(e.target.value.trim()));
  $("btnSynth").addEventListener("click", (e) => run(e.currentTarget,
    () => api("/synth", { method: "POST", body: { days: 30, identities: 200, seed: 42, ingest: true, reset_first: true }, timeout: 180000 }),
    (o) => `Generated ${num(o.ingest?.inserted)} events over 30 days · ${o.report?.passed}/${o.report?.total} attacks detected`));
  $("btnIngest").addEventListener("click", (e) => run(e.currentTarget,
    () => api("/ingest", { method: "POST", body: {}, timeout: 180000 }),
    (o) => `Ingested ${num(o.inserted)} new events from ${num(o.files)} file(s)`));
  $("btnPrune").addEventListener("click", (e) => run(e.currentTarget,
    () => api("/prune", { method: "POST", body: { vacuum: true } }),
    (o) => `Retention applied: ${num(o.events_deleted)} raw events removed, ${num(o.evidence_kept)} evidence events kept`));
  refresh();
}

init();
