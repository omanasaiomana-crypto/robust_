// static/js/agents.js — the 15 agents, live, grouped by layer.
import { api, toast, renderLayout, keepMock } from "./v21kit.js";
import { highlightJson, escHtml as esc, LAYER_STYLE } from "./jsonview.js";

const LAYERS = ["data", "detection", "decision", "learning", "oversight"];
const STATE = {
  waiting: ["Waiting", "bg-panel2 text-muted", "#475569"], running: ["Running", "bg-cyan-400/15 text-cyan-300", "#22D3EE"],
  done: ["Done", "bg-emerald-500/15 text-emerald-300", "#10B981"], failed: ["Failed", "bg-red-500/15 text-red-300", "#EF4444"],
  skipped: ["Skipped", "bg-amber-500/15 text-amber-300", "#F59E0B"], idle: ["Idle", "bg-panel2 text-muted", "#475569"],
};
const RUN = { idle: "Idle", running: "Running", done: "Complete", failed: "Failed" };
let data = { agents: [], run: {} };
let selected = null;
let timer = null;

const root = await renderLayout("agents", "Agents", "15 cooperating agents · live status of every layer");
root.innerHTML = `
<section id="ag-banner" class="bg-panel border border-line rounded-xl p-5"><div class="h-16 animate-pulse rounded bg-panel2"></div></section>
<section id="ag-grid" class="mt-6 grid gap-4 lg:grid-cols-5"></section>
<section id="ag-detail" class="mt-6 hidden"></section>`;
const $ = (id) => document.getElementById(id);

function pill(state) {
  const [label, cls, dot] = STATE[state] || STATE.idle;
  return `<span class="inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[11px] font-medium ${cls}">
    <span class="h-1.5 w-1.5 rounded-full ${state === "running" ? "animate-pulse" : ""}" style="background:${dot}"></span>${esc(label)}</span>`;
}

function banner() {
  const run = data.run || {};
  const orch = data.agents.find((a) => a.id === "orchestrator") || { name: "Orchestrator & Supervisor Agent" };
  const pct = Math.round((run.progress || 0) * 100);
  const step = Math.min((run.completed || []).length + (run.state === "running" ? 1 : 0), run.total_steps || 13);
  $("ag-banner").innerHTML = `
    <div class="flex flex-col gap-4 lg:flex-row lg:items-center">
      <div class="min-w-0 flex-1">
        <div class="flex flex-wrap items-center gap-2"><span class="font-mono text-xs text-muted">15</span>
          <span class="font-semibold">${esc(orch.name)}</span>${pill(run.state === "running" ? "running" : run.state === "failed" ? "failed" : run.state === "done" ? "done" : "idle")}
          <span class="text-xs text-muted">${esc(RUN[run.state] || "Idle")}</span></div>
        <div class="mt-1 font-mono text-xs text-muted truncate">${esc(run.run_id || "No scan yet: start one from Live scan")}${run.mode ? " · mode " + esc(run.mode) : ""}</div>
        <div class="mt-3 flex items-center gap-3"><div class="h-2 flex-1 rounded-full bg-panel2 overflow-hidden">
          <div class="h-2 rounded-full bg-brand2 transition-all" style="width:${pct}%"></div></div>
          <span class="text-xs tabular-nums text-muted">Step ${step} / ${esc(run.total_steps || 13)}</span></div>
      </div>
      <div class="grid grid-cols-3 gap-3 lg:w-[340px]">
        <div class="rounded-lg border border-line bg-panel2 p-3"><div class="text-[10px] uppercase tracking-wide text-muted">Agents</div><div class="text-xl font-semibold">15</div></div>
        <div class="rounded-lg border border-line bg-panel2 p-3"><div class="text-[10px] uppercase tracking-wide text-muted">Threats</div><div class="text-xl font-semibold text-crit">${esc(run.threats ?? 0)}</div></div>
        <div class="rounded-lg border border-line bg-panel2 p-3"><div class="text-[10px] uppercase tracking-wide text-muted">Duration</div><div class="text-xl font-semibold tabular-nums">${run.duration_ms != null ? esc((run.duration_ms / 1000).toFixed(1)) + "s" : "—"}</div></div>
      </div>
      <a href="${esc(keepMock("scan.html"))}" class="bg-brand hover:bg-blue-500 text-white rounded-lg px-3.5 py-2 text-sm font-medium text-center">Open live scan</a>
    </div>`;
}

function card(a) {
  const st = a.state || "idle";
  const ring = st === "running" ? "ring-1 ring-cyan-400" : st === "failed" ? "border-red-500/60" : "";
  const sig = a.pattern ? `<span class="rounded bg-panel2 border border-line px-1.5 py-0.5 font-mono text-[10px]">${esc(a.pattern)}</span>
    <span class="text-[11px] ${a.signals ? "text-red-300" : "text-muted"}">${esc(a.signals ?? 0)} signal${a.signals === 1 ? "" : "s"}</span>` : "";
  return `<button data-agent="${esc(a.id)}" class="ag-card w-full text-left bg-panel border border-line rounded-xl p-4 hover:border-slate-500 transition ${ring} ${selected === a.id ? "outline outline-1 outline-cyan-400" : ""}">
    <div class="flex items-center gap-2"><span class="font-mono text-[11px] text-muted">${String(a.num).padStart(2, "0")}</span>
      <span class="truncate text-sm font-medium">${esc(a.name)}</span><span class="ml-auto shrink-0">${pill(st)}</span></div>
    <p class="mt-2 text-xs text-muted line-clamp-2">${esc(a.role)}</p>
    <div class="mt-3 flex flex-wrap items-center gap-2 text-[11px] text-muted">
      <span>${a.last_duration_ms != null ? esc(Math.round(a.last_duration_ms)) + " ms" : "—"}</span><span>·</span><span>${esc(a.runs || 0)} runs</span>${sig ? "<span>·</span>" + sig : ""}</div>
    <div class="mt-2 flex flex-wrap gap-1">${(a.permissions || []).map((p) => `<span class="rounded bg-panel2 px-1.5 py-0.5 font-mono text-[10px] text-muted">${esc(p)}</span>`).join("")}</div>
    ${a.last_error ? `<div class="mt-2 text-[11px] text-red-300 truncate">${esc(a.last_error)}</div>` : ""}
  </button>`;
}

function grid() {
  $("ag-grid").innerHTML = LAYERS.map((layer, i) => {
    const st = LAYER_STYLE[layer];
    const list = data.agents.filter((a) => a.layer === layer);
    return `<div class="relative"><div class="mb-3 flex items-center gap-2 text-xs uppercase tracking-wide text-muted">
        <span class="h-2 w-2 rounded-full" style="background:${st.dot}"></span>${esc(st.label)} <span class="text-muted/60">(${list.length})</span>
        ${i < LAYERS.length - 1 ? `<span class="ml-auto hidden lg:inline text-lg leading-none">›</span>` : ""}</div>
      <div class="flex flex-col gap-3">${list.map(card).join("")}</div></div>`;
  }).join("");
}

async function detail(id) {
  selected = id;
  grid();
  const a = data.agents.find((x) => x.id === id);
  if (!a) return;
  let recent = [];
  try {
    const t = await api("/scan/trace?after=0&limit=2000");
    recent = (t.events || []).filter((e) => e.agent_id === id).slice(-10);
  } catch { /* optional */ }
  const box = $("ag-detail");
  box.className = "mt-6 bg-panel border border-line rounded-xl p-5";
  box.innerHTML = `<div class="flex items-center gap-3"><span class="font-mono text-xs text-muted">${String(a.num).padStart(2, "0")}</span>
      <h3 class="font-semibold">${esc(a.name)}</h3>${pill(a.state)}
      <button id="ag-close" class="ml-auto border border-line hover:bg-panel2 rounded-md px-2 py-1 text-xs">Close</button></div>
    <p class="mt-1 text-sm text-muted">${esc(a.role)} · layer ${esc(a.layer)}</p>
    <div class="mt-4 grid gap-6 lg:grid-cols-2">
      <div><div class="text-xs uppercase tracking-wide text-muted">Last output</div>
        <div class="mt-1 text-xs text-muted">${esc(a.last_message || "")}</div>
        <pre class="mt-2 max-h-80 overflow-auto rounded-lg border border-line p-3 font-mono text-[11.5px] leading-5 whitespace-pre-wrap" style="background:#05070C">${a.last_output != null ? highlightJson(a.last_output) : '<span class="text-slate-500">No output yet. Run a scan.</span>'}</pre></div>
      <div><div class="text-xs uppercase tracking-wide text-muted">Recent events</div>
        <ul class="mt-2 flex flex-col gap-1 font-mono text-[11.5px]">${recent.map((e) => `<li class="truncate"><span class="text-slate-500">#${esc(e.seq)}</span>
          <span class="${e.state === "threat" || e.state === "failed" ? "text-red-300" : e.state === "done" ? "text-emerald-300" : "text-sky-300"}">${esc(e.state)}</span>
          ${esc(e.message)}</li>`).join("") || '<li class="text-muted">No events in the current trace.</li>'}</ul></div>
    </div>`;
  $("ag-close").onclick = () => { selected = null; box.className = "mt-6 hidden"; grid(); };
}

$("ag-grid").addEventListener("click", (e) => {
  const c = e.target.closest(".ag-card");
  if (c) detail(c.dataset.agent);
});

async function refresh() {
  clearTimeout(timer);
  try {
    data = await api("/agents");
    banner();
    grid();
  } catch (err) {
    $("ag-banner").innerHTML = `<div class="text-sm text-red-300">${esc(err.message)}</div>`;
    toast(err.message, "error");
  }
  if (!document.hidden) timer = setTimeout(refresh, data.run && data.run.state === "running" ? 1500 : 10000);
}
document.addEventListener("visibilitychange", () => { if (!document.hidden) refresh(); else clearTimeout(timer); });
refresh();
