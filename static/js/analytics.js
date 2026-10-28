// static/js/analytics.js — rules vs ML vs hybrid, detection heatmap, attack-time heatmap, identity heatmap.
import { api, toast, renderLayout, keepMock } from "./v21kit.js";
import { escHtml as esc } from "./jsonview.js";

const root = await renderLayout("analytics", "Detection analytics", "Rules vs ML performance and attack activity");
root.innerHTML = `
<section id="an-winner" class="bg-panel border border-line rounded-xl p-5"><div class="h-10 animate-pulse rounded bg-panel2"></div></section>
<section id="an-cards" class="mt-6 grid gap-6 lg:grid-cols-3"></section>
<section id="an-chart-card" class="mt-6 bg-panel border border-line rounded-xl p-5">
  <h3 class="text-sm font-semibold">Precision, recall and F1</h3><div class="mt-4 h-[260px]"><canvas id="an-chart"></canvas></div></section>
<div class="mt-6 grid gap-6 lg:grid-cols-3">
  <section class="lg:col-span-2 bg-panel border border-line rounded-xl p-5 min-w-0">
    <h3 class="text-sm font-semibold">Which detector catches which attack</h3>
    <p class="text-xs text-muted">Share of attack sessions of each type that the detector flagged</p>
    <div id="an-matrix" class="mt-4"></div></section>
  <section class="bg-panel border border-line rounded-xl p-5"><h3 class="text-sm font-semibold">Agreement: rules vs ML</h3><div id="an-agree" class="mt-4"></div></section>
</div>
<section class="mt-6 bg-panel border border-line rounded-xl p-5 min-w-0">
  <div class="flex items-start"><div><h3 class="text-sm font-semibold">When are we attacked</h3><p id="an-time-sub" class="text-xs text-muted"></p></div>
  <div class="ml-auto text-right"><div id="an-time-total" class="text-2xl font-semibold tabular-nums"></div><div class="text-[11px] text-muted">attack events</div></div></div>
  <div id="an-time" class="mt-4"></div></section>
<section class="mt-6 bg-panel border border-line rounded-xl p-5 min-w-0">
  <h3 class="text-sm font-semibold">Identities × detectors</h3><p class="text-xs text-muted">Signals per detector for the riskiest identities</p>
  <div id="an-ids" class="mt-4"></div></section>
<details class="mt-6 bg-panel border border-line rounded-xl p-5 text-xs text-muted"><summary class="cursor-pointer text-sm text-ink">How we measure</summary>
  <ul class="mt-3 list-disc pl-5 space-y-1">
    <li>Session level: a session is an attack session if any of its events has a non-benign label.</li>
    <li>Rules = sessions with a P1–P5 signal; ML = sessions with an anomaly score ≥ 0.6; Hybrid = final alerts with risk ≥ 40.</li>
    <li>Precision = flagged attack sessions ÷ flagged sessions; Recall = flagged attack sessions ÷ attack sessions; F1 = 2PR ÷ (P + R).</li>
    <li>Winner = highest F1 (ties: precision, then recall). Heatmap cells print their numbers, so color is never the only signal.</li>
  </ul></details>`;
const $ = (id) => document.getElementById(id);
const fmt = (v) => (v == null ? "—" : Number(v).toFixed(2));
const human = (s) => String(s).replace(/_/g, " ").replace(/^./, (c) => c.toUpperCase());
const errBox = (msg) => `<div class="rounded-lg border border-red-500/40 bg-red-500/10 p-3 text-sm text-red-300">${esc(msg)}</div>`;
const empty = (msg) => `<div class="py-6 text-center text-sm text-muted">${esc(msg)}</div>`;

function cellStyle(value, max, rgb) {
  if (!value || !max) return { cls: "bg-panel2", style: "", text: "#8A97AD" };
  const a = 0.15 + 0.8 * Math.min(1, value / max);
  return { cls: "", style: `background:rgba(${rgb},${a.toFixed(3)})`, text: a > 0.55 ? "#0B0F17" : "#E6EBF2" };
}

function heatGrid({ rows, cols, cell, rowLabelWidth = "170px", minCol = 34, height = 28, colEvery = 1, onRowClick = false }) {
  const head = `<div></div>` + cols.map((c, i) => `<div class="text-center text-[10px] text-muted truncate" title="${esc(c.title || c.label)}">${i % colEvery === 0 ? esc(c.label) : ""}</div>`).join("");
  const body = rows.map((r, ri) => {
    if (r.divider) return `<div style="grid-column:1/-1;height:1px;background:#1F2A3C;margin:4px 0"></div>`;
    const label = `<div class="truncate pr-2 text-xs ${onRowClick ? "cursor-pointer hover:text-cyan-300" : ""}" ${onRowClick ? `data-row="${esc(r.key)}"` : ""} title="${esc(r.title || r.label)}">${r.labelHtml || esc(r.label)}</div>`;
    return label + cols.map((c, ci) => {
      const x = cell(ri, ci);
      const s = cellStyle(x.value, x.max, x.rgb);
      return `<div class="${s.cls} flex items-center justify-center rounded-[3px] text-[11px] tabular-nums" style="${s.style};height:${height}px;color:${s.text}" title="${esc(x.title)}">${esc(x.text ?? "")}</div>`;
    }).join("");
  }).join("");
  return `<div class="overflow-x-auto"><div style="display:grid;grid-template-columns:${rowLabelWidth} repeat(${cols.length},minmax(${minCol}px,1fr));gap:2px;min-width:${parseInt(rowLabelWidth, 10) + cols.length * (minCol + 2)}px">${head}${body}</div></div>`;
}

let chart = null;
function renderDetectors(d) {
  const summary = d.rows.filter((r) => r.kind === "summary");
  if (d.winner) {
    $("an-winner").innerHTML = `<div class="flex items-center gap-4"><div class="h-12 w-1 rounded-full bg-cyan-400"></div>
      <div><div class="font-semibold">✔ ${esc(d.winner.text)}</div>
      <div class="text-xs text-muted">Session-level comparison · ${esc(d.malicious_sessions)} attack sessions · labels from the dataset</div></div></div>`;
  } else {
    $("an-winner").innerHTML = `<div class="text-sm text-muted">ⓘ ${esc(d.note || "No ground-truth labels: showing detection counts only.")}</div>`;
  }
  $("an-cards").innerHTML = summary.map((r) => {
    const best = d.winner && d.winner.id === r.id;
    const mini = (k, v) => `<div><div class="text-[10px] uppercase tracking-wide text-muted">${esc(k)}</div><div class="text-sm font-semibold tabular-nums">${esc(v)}</div></div>`;
    return `<div class="bg-panel border border-line rounded-xl p-5 ${best ? "ring-1 ring-cyan-400" : ""}">
      <div class="flex items-center text-sm text-muted">${esc(r.label)}${best ? `<span class="ml-auto rounded-full bg-cyan-400/15 px-2 py-0.5 text-[11px] text-cyan-300">Best</span>` : ""}</div>
      <div class="mt-2 text-4xl font-semibold tabular-nums">${d.labeled ? fmt(r.f1) : esc(r.flagged)}</div>
      <div class="text-[11px] text-muted">${d.labeled ? "F1 score" : "sessions flagged"}</div>
      ${d.labeled ? `<div class="mt-4 grid grid-cols-4 gap-2">${mini("Precision", fmt(r.precision))}${mini("Recall", fmt(r.recall))}${mini("Flagged", r.flagged)}${mini("False alarms", r.fp)}</div>
      <div class="mt-3 h-1.5 rounded-full bg-panel2"><div class="h-1.5 rounded-full bg-cyan-400" style="width:${Math.round((r.recall || 0) * 100)}%"></div></div>` : ""}
    </div>`;
  }).join("");
  $("an-chart-card").classList.toggle("hidden", !d.labeled);
  if (d.labeled) {
    if (typeof window.Chart === "undefined") { $("an-chart").parentElement.innerHTML = errBox("Chart library failed to load"); }
    else {
      if (chart) chart.destroy();
      chart = new window.Chart($("an-chart"), {
        type: "bar",
        data: { labels: summary.map((r) => r.label.split(" (")[0]), datasets: [
          { label: "Precision", data: summary.map((r) => r.precision), backgroundColor: "#3B82F6", borderRadius: 4, maxBarThickness: 28 },
          { label: "Recall", data: summary.map((r) => r.recall), backgroundColor: "#22D3EE", borderRadius: 4, maxBarThickness: 28 },
          { label: "F1", data: summary.map((r) => r.f1), backgroundColor: "#10B981", borderRadius: 4, maxBarThickness: 28 }] },
        options: { maintainAspectRatio: false, scales: {
          y: { min: 0, max: 1, ticks: { color: "#8A97AD", callback: (v) => Number(v).toFixed(1) }, grid: { color: "#1F2A3C" } },
          x: { ticks: { color: "#8A97AD" }, grid: { display: false } } },
          plugins: { legend: { position: "bottom", labels: { color: "#8A97AD" } } } },
      });
    }
  }
  if (!d.labeled || !d.matrix.length) {
    $("an-matrix").innerHTML = empty("Labels needed to compare detectors per attack type");
  } else {
    const rows = [];
    d.matrix.forEach((m, i) => { if (i > 0 && m.kind === "detector" && d.matrix[i - 1].kind === "summary") rows.push({ divider: true }); rows.push(m); });
    const realRows = rows.filter((r) => !r.divider);
    const maxFa = Math.max(1, ...d.matrix.map((m) => m.false_alarms));
    const cols = [...d.scenarios.map((s) => ({ label: human(s) })), { label: "False alarms" }];
    let k = -1;
    const rowIdx = rows.map((r) => (r.divider ? null : ++k));
    $("an-matrix").innerHTML = heatGrid({
      rows, cols, minCol: 70,
      cell: (ri, ci) => {
        const m = realRows[rowIdx[ri]];
        if (ci === cols.length - 1) return { value: m.false_alarms, max: maxFa, rgb: "239,68,68", text: m.false_alarms, title: `${m.label}: ${m.false_alarms} false-alarm sessions` };
        const c = m.cells[ci];
        return { value: c.recall || 0, max: 1, rgb: "34,211,238", text: `${c.caught}/${c.total}`,
          title: `${m.label} · ${human(c.scenario)}: ${c.caught} of ${c.total} sessions (${Math.round((c.recall || 0) * 100)}%)` };
      },
    }) + `<div class="mt-3 flex items-center gap-2 text-[11px] text-muted">0%<div class="h-2 w-32 rounded" style="background:linear-gradient(90deg,rgba(34,211,238,.15),rgba(34,211,238,.95))"></div>100% of attack sessions caught</div>`;
  }
  const a = d.agreement || {};
  const lab = d.labeled;
  const segs = [["Rules only", lab ? a.rules_only_true : a.rules_only, "#3B82F6"], ["Both", lab ? a.both_true : a.both, "#22D3EE"],
    ["ML only", lab ? a.ml_only_true : a.ml_only, "#A78BFA"], ["Missed by both", lab ? a.missed_by_both : 0, "rgba(239,68,68,.7)"]];
  const total = segs.reduce((s, x) => s + (x[1] || 0), 0);
  $("an-agree").innerHTML = total ? `<div class="flex h-4 w-full overflow-hidden rounded-full bg-panel2">${segs.filter((s) => s[1]).map((s) =>
      `<div style="width:${(100 * s[1]) / total}%;background:${s[2]}" title="${esc(s[0])}: ${esc(s[1])}"></div>`).join("")}</div>
    <ul class="mt-3 space-y-1 text-xs">${segs.map((s) => `<li class="flex items-center gap-2"><span class="h-2 w-2 rounded-full" style="background:${s[2]}"></span>${esc(s[0])}<span class="ml-auto tabular-nums">${esc(s[1] ?? 0)}</span></li>`).join("")}</ul>
    <p class="mt-3 text-sm">${lab ? `ML caught <b>${esc(a.ml_only_true ?? 0)}</b> attack session(s) that rules missed; rules caught <b>${esc(a.rules_only_true ?? 0)}</b> that ML missed; <b>${esc(a.missed_by_both ?? 0)}</b> missed by both.`
      : `Sessions flagged: <b>${esc(a.rules_only ?? 0)}</b> by rules only, <b>${esc(a.ml_only ?? 0)}</b> by ML only, <b>${esc(a.both ?? 0)}</b> by both.`}</p>` : empty("No detections yet");
}

function renderTime(h) {
  $("an-time-sub").textContent = `Events cited as evidence in alerts · last ${h.days.length || 0} days · ${h.tz}`;
  $("an-time-total").textContent = String(h.total || 0);
  if (!h.cells.length || !h.total) { $("an-time").innerHTML = empty("No attack activity in this period"); return; }
  const dayLabel = (s) => { const [y, m, d] = s.split("-").map(Number); return new Date(y, m - 1, d).toLocaleDateString([], { weekday: "short", day: "2-digit", month: "short" }); };
  const cols = h.hours.map((x) => ({ label: String(x).padStart(2, "0"), title: `${String(x).padStart(2, "0")}:00` }));
  $("an-time").innerHTML = heatGrid({
    rows: h.days.map((d) => ({ label: dayLabel(d) })), cols, rowLabelWidth: "110px", minCol: 22, height: 18,
    colEvery: window.innerWidth < 640 ? 3 : 1,
    cell: (ri, ci) => { const v = h.cells[ri][ci]; return { value: v, max: h.max, rgb: "34,211,238", text: v || "",
      title: `${dayLabel(h.days[ri])}, ${String(ci).padStart(2, "0")}:00–${String(ci + 1).padStart(2, "0")}:00: ${v} attack events` }; },
  }) + `<div class="mt-3 flex items-center gap-2 text-[11px] text-muted">0<div class="h-2 w-32 rounded" style="background:linear-gradient(90deg,rgba(34,211,238,.15),rgba(34,211,238,.95))"></div>${esc(h.max)}</div>`;
}

function renderIds(h) {
  if (!h.identities.length) { $("an-ids").innerHTML = empty("No alerts yet"); return; }
  $("an-ids").innerHTML = heatGrid({
    rows: h.identities.map((id, i) => ({ key: id, label: id, labelHtml: `${esc(id)} <span class="text-red-300 tabular-nums">${esc(Math.round(h.risk[i]))}</span>` })),
    cols: h.patterns.map((p, i) => ({ label: p, title: h.pattern_names[i] })), minCol: 48, onRowClick: true,
    cell: (ri, ci) => { const v = h.cells[ri][ci]; return { value: v, max: h.max, rgb: "249,115,22", text: v || "", title: `${h.identities[ri]} · ${h.pattern_names[ci]}: ${v} signal(s)` }; },
  });
}
$("an-ids").addEventListener("click", (e) => {
  const r = e.target.closest("[data-row]");
  if (r) location.href = keepMock(`explorer.html?identity=${encodeURIComponent(r.dataset.row)}`);
});

const [det, time, ids] = await Promise.allSettled([api("/analytics/detectors"), api("/analytics/heatmap/time"), api("/analytics/heatmap/identities")]);
if (det.status === "fulfilled") renderDetectors(det.value); else { $("an-winner").innerHTML = errBox(det.reason.message); toast(det.reason.message, "error"); }
if (time.status === "fulfilled") renderTime(time.value); else $("an-time").innerHTML = errBox(time.reason.message);
if (ids.status === "fulfilled") renderIds(ids.value); else $("an-ids").innerHTML = errBox(ids.reason.message);
