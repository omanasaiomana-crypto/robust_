// static/js/scan.js — Live scan: watch all 15 agents check for malicious activity, step by step.
// Full-color console + full JSON of the current step + agent strip + threat list.
// Uses only: api.js (api, esc), ui.js (toast), layout.js (renderLayout), jsonview.js.
import { api, toast, renderLayout, MOCK, keepMock } from "./v21kit.js";
import { highlightJson, consoleLine, LAYER_STYLE, escHtml as esc } from "./jsonview.js";

const DELAY = { "0.5": 280, "1": 140, "2": 70, "4": 35, instant: 0 };
const SCAN_STEPS = 13;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const S = {
  agents: [], queue: [], shown: [], lastSeq: 0, runId: null, runState: "idle",
  polling: false, playing: false, done: false, speed: "1", inlineJson: false, filter: "all",
  selectedSeq: null, agentState: {}, threats: [], completed: new Set(), current: null, firstTs: null,
};

const root = await renderLayout("scan", "Live scan", "Watch all 15 agents check for malicious activity, step by step");

root.innerHTML = `
<section class="bg-panel border border-line rounded-xl p-5">
  <div class="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
    <div class="min-w-0 flex-1">
      <div class="flex items-center gap-3">
        <span id="sc-pill" class="text-xs font-medium px-2 py-0.5 rounded-full bg-panel2 text-muted">Idle</span>
        <span id="sc-run" class="font-mono text-xs text-muted truncate"></span>
      </div>
      <div id="sc-step" class="mt-3 text-lg font-semibold">Ready to scan</div>
      <div id="sc-msg" class="mt-1 text-sm text-muted truncate">Choose a data source and press Start scan.</div>
      <div class="mt-4 h-2 w-full rounded-full bg-panel2 overflow-hidden">
        <div id="sc-bar" class="h-2 rounded-full bg-brand2 transition-all duration-300" style="width:0%"></div>
      </div>
    </div>
    <div class="grid grid-cols-3 gap-3 lg:w-[360px]">
      <div class="rounded-lg border border-line bg-panel2 p-3"><div class="text-[11px] uppercase tracking-wide text-muted">Elapsed</div><div id="sc-elapsed" class="text-xl font-semibold tabular-nums">0.0s</div></div>
      <div class="rounded-lg border border-line bg-panel2 p-3"><div class="text-[11px] uppercase tracking-wide text-muted">Events</div><div id="sc-events" class="text-xl font-semibold tabular-nums">0</div></div>
      <div class="rounded-lg border border-line bg-panel2 p-3"><div class="text-[11px] uppercase tracking-wide text-muted">Threats</div><div id="sc-threats" class="text-xl font-semibold tabular-nums text-crit">0</div></div>
    </div>
  </div>
  <div class="mt-5 flex flex-wrap items-center gap-2">
    <select id="sc-mode" aria-label="Data source" class="bg-panel2 border border-line rounded-lg px-3 py-2 text-sm">
      <option value="dataset">Dataset</option><option value="only">Input data only</option><option value="merge">Dataset + input</option>
    </select>
    <button id="sc-start" class="bg-brand hover:bg-blue-500 text-white rounded-lg px-3.5 py-2 text-sm font-medium">Start scan</button>
    <button id="sc-replay" class="border border-line hover:bg-panel2 rounded-lg px-3.5 py-2 text-sm">Replay last scan</button>
    <label class="ml-auto flex items-center gap-2 text-sm text-muted">Speed
      <select id="sc-speed" class="bg-panel2 border border-line rounded-lg px-2 py-1.5 text-sm text-ink">
        <option value="0.5">0.5×</option><option value="1" selected>1×</option><option value="2">2×</option><option value="4">4×</option><option value="instant">Instant</option>
      </select></label>
    <label class="flex items-center gap-2 text-sm text-muted"><input id="sc-json" type="checkbox" class="accent-cyan-400"> Inline JSON</label>
    <select id="sc-filter" aria-label="Filter" class="bg-panel2 border border-line rounded-lg px-2 py-1.5 text-sm">
      <option value="all">All events</option><option value="threat">Threats</option><option value="errors">Errors</option>
    </select>
    <button id="sc-download" class="border border-line hover:bg-panel2 rounded-lg px-3 py-1.5 text-sm">Download JSON</button>
  </div>
  <div id="sc-strip" class="mt-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-5"></div>
</section>

<div id="sc-banner" class="hidden mt-6"></div>

<div class="mt-6 grid gap-6 lg:grid-cols-3">
  <section class="lg:col-span-2 rounded-xl border border-line overflow-hidden" style="background:#05070C">
    <div class="flex items-center gap-2 px-4 py-2.5 border-b border-line bg-panel">
      <span class="h-3 w-3 rounded-full bg-red-500/80"></span><span class="h-3 w-3 rounded-full bg-amber-400/80"></span><span class="h-3 w-3 rounded-full bg-emerald-500/80"></span>
      <span id="sc-term-title" class="ml-3 font-mono text-xs text-muted truncate">identityshield — scan</span>
      <span id="sc-follow" class="ml-auto text-[11px] text-muted">following</span>
    </div>
    <div id="sc-console" class="font-mono text-[12.5px] leading-6 h-[560px] overflow-auto py-2 whitespace-pre" role="log" aria-live="polite">
      <div class="px-3 text-slate-500">$ python -m app.scan --json   # waiting for a scan…</div>
    </div>
  </section>
  <div class="flex flex-col gap-6 min-w-0">
    <section class="bg-panel border border-line rounded-xl p-5 min-w-0">
      <div class="flex items-center justify-between"><h3 class="text-sm font-semibold">Current step · full JSON</h3>
        <button id="sc-copy" class="border border-line hover:bg-panel2 rounded-md px-2 py-1 text-xs">Copy</button></div>
      <div id="sc-sel-head" class="mt-2 text-xs text-muted">Click any console line to inspect it.</div>
      <pre id="sc-sel" class="mt-3 max-h-[300px] overflow-auto rounded-lg border border-line p-3 font-mono text-[11.5px] leading-5 whitespace-pre-wrap" style="background:#05070C"></pre>
    </section>
    <section class="bg-panel border border-line rounded-xl p-5">
      <h3 class="text-sm font-semibold">Threats detected <span class="text-muted font-normal">· each logged to the audit log</span></h3>
      <div id="sc-threat-list" class="mt-3 flex flex-col gap-2"><div class="text-sm text-muted">No threats yet.</div></div>
    </section>
  </div>
</div>`;

const $ = (id) => document.getElementById(id);
const consoleEl = $("sc-console");
let follow = true;
consoleEl.addEventListener("scroll", () => {
  follow = consoleEl.scrollTop + consoleEl.clientHeight >= consoleEl.scrollHeight - 40;
  $("sc-follow").textContent = follow ? "following" : "paused · scroll down to follow";
});
consoleEl.addEventListener("click", (e) => {
  const line = e.target.closest("[data-seq]");
  if (!line) return;
  const ev = S.shown.find((x) => String(x.seq) === line.dataset.seq);
  if (ev) select(ev);
});

function chipClass(state) {
  return {
    waiting: "border-line text-muted",
    running: "border-brand2 text-ink ring-2 ring-brand2/40 animate-pulse",
    done: "border-emerald-500/50 text-ink",
    failed: "border-red-500 text-red-300",
    skipped: "border-amber-500/60 text-amber-200",
    idle: "border-line text-muted",
  }[state] || "border-line text-muted";
}
function stateDot(state) {
  return { running: "#22D3EE", done: "#10B981", failed: "#EF4444", skipped: "#F59E0B" }[state] || "#334155";
}

function renderStrip() {
  const layers = ["data", "detection", "decision", "learning", "oversight"];
  $("sc-strip").innerHTML = layers.map((layer) => {
    const st = LAYER_STYLE[layer];
    const chips = S.agents.filter((a) => a.layer === layer).map((a) => {
      const state = S.agentState[a.id] || "idle";
      const threats = S.threats.filter((t) => t.agent_id === a.id).length;
      return `<div class="flex items-center gap-2 rounded-lg border bg-panel2 px-2.5 py-1.5 text-xs ${chipClass(state)}" title="${esc(a.role || "")}">
        <span class="h-2 w-2 shrink-0 rounded-full" style="background:${stateDot(state)}"></span>
        <span class="font-mono text-[10px] text-muted">${String(a.num).padStart(2, "0")}</span>
        <span class="truncate">${esc(a.name)}</span>
        ${threats ? `<span class="ml-auto rounded bg-red-600 px-1.5 text-[10px] font-bold text-white">${threats}</span>` : ""}</div>`;
    }).join("");
    return `<div><div class="mb-2 flex items-center gap-2 text-[11px] uppercase tracking-wide text-muted">
      <span class="h-2 w-2 rounded-full" style="background:${st.dot}"></span>${esc(st.label)}</div>
      <div class="flex flex-col gap-1.5">${chips}</div></div>`;
  }).join("");
}

function setPill(state) {
  const map = {
    idle: ["Idle", "bg-panel2 text-muted"], running: ["Scanning…", "bg-brand2/15 text-brand2"],
    replay: ["Replaying", "bg-brand/15 text-blue-300"], done: ["Complete", "bg-emerald-500/15 text-emerald-300"],
    failed: ["Failed", "bg-red-500/15 text-red-300"],
  };
  const [label, cls] = map[state] || map.idle;
  $("sc-pill").textContent = label;
  $("sc-pill").className = `text-xs font-medium px-2 py-0.5 rounded-full ${cls}`;
}

function updateHeader() {
  const done = S.completed.size;
  const cur = S.current;
  $("sc-bar").style.width = `${Math.round((done / SCAN_STEPS) * 100)}%`;
  $("sc-events").textContent = String(S.shown.length);
  $("sc-threats").textContent = String(S.threats.length);
  if (cur) {
    $("sc-step").textContent = `Step ${Math.min(done + (S.agentState[cur.agent_id] === "running" ? 1 : 0), SCAN_STEPS)} / ${SCAN_STEPS} · ${cur.agent_name}`;
    $("sc-msg").textContent = cur.message;
  }
  if (S.firstTs && S.shown.length) {
    const last = Date.parse(S.shown[S.shown.length - 1].ts);
    $("sc-elapsed").textContent = `${Math.max(0, (last - S.firstTs) / 1000).toFixed(1)}s`;
  }
}

function visible(ev) {
  if (S.filter === "threat") return ev.state === "threat";
  if (S.filter === "errors") return ev.state === "failed" || ev.level === "crit" && ev.state !== "threat";
  return true;
}

function renderConsole() {
  consoleEl.innerHTML = S.shown.filter(visible).map((ev) => consoleLine(ev, { showJson: S.inlineJson })).join("")
    || `<div class="px-3 text-slate-500">No matching events.</div>`;
  markSelected();
  if (follow) consoleEl.scrollTop = consoleEl.scrollHeight;
}

function markSelected() {
  consoleEl.querySelectorAll("[data-seq]").forEach((el) => {
    el.classList.toggle("bg-white/5", el.dataset.seq === String(S.selectedSeq));
  });
}

function select(ev) {
  S.selectedSeq = ev.seq;
  $("sc-sel-head").innerHTML = `<span class="font-mono">#${esc(ev.seq)}</span> · ${esc(ev.agent_name)} · <span class="uppercase">${esc(ev.state)}</span>`;
  $("sc-sel").innerHTML = highlightJson(ev);
  markSelected();
}

function addThreat(ev) {
  const d = ev.data || {};
  S.threats.push({ agent_id: ev.agent_id, ...d });
  const color = d.band === "revoke" ? "text-red-300 bg-red-500/15" : d.band === "restrict" ? "text-orange-300 bg-orange-500/15" : "text-amber-300 bg-amber-500/15";
  const href = keepMock(`alert.html?id=${encodeURIComponent(d.alert_id || "")}`);
  const item = `<a href="${esc(href)}" class="flex items-center gap-3 rounded-lg border border-line bg-panel2 px-3 py-2 hover:border-red-500/60">
      <span class="text-lg font-semibold tabular-nums text-red-300">${esc(Math.round(d.risk ?? 0))}</span>
      <span class="min-w-0 flex-1"><span class="block truncate text-sm">${esc(d.identity_id || "unknown")}</span>
      <span class="block truncate text-[11px] text-muted">${esc((d.patterns || []).join(" · "))} · audit entry written</span></span>
      <span class="rounded-full px-2 py-0.5 text-[11px] ${color}">${esc(d.band || "")}</span></a>`;
  const list = $("sc-threat-list");
  if (S.threats.length === 1) list.innerHTML = "";
  list.insertAdjacentHTML("beforeend", item);
}

function reveal(ev) {
  if (!S.firstTs) S.firstTs = Date.parse(ev.ts);
  S.shown.push(ev);
  if (ev.agent_num >= 1 && ev.agent_num <= SCAN_STEPS) {
    if (ev.state === "started" || ev.state === "progress") { S.agentState[ev.agent_id] = "running"; S.current = ev; }
    if (ev.state === "done" || ev.state === "skipped") { S.agentState[ev.agent_id] = ev.state; S.completed.add(ev.agent_id); }
    if (ev.state === "failed") S.agentState[ev.agent_id] = "failed";
  }
  if (ev.agent_id === "orchestrator" && ev.state !== "threat") S.agentState.orchestrator = ev.state === "started" ? "running" : ev.state;
  if (ev.state === "threat") addThreat(ev);
  if (visible(ev)) {
    consoleEl.insertAdjacentHTML("beforeend", consoleLine(ev, { showJson: S.inlineJson }));
    if (follow) consoleEl.scrollTop = consoleEl.scrollHeight;
  }
  if (S.selectedSeq == null || S.autoSelect) { S.autoSelect = true; select(ev); }
  updateHeader();
  renderStrip();
}

async function play() {
  if (S.playing) return;
  S.playing = true;
  try {
    let n = 0;
    while (S.queue.length) {
      reveal(S.queue.shift());
      const d = DELAY[S.speed] ?? 140;
      if (d > 0) await sleep(d);
      else if (++n % 50 === 0) await sleep(0);
    }
  } finally {
    S.playing = false;
  }
  if (!S.polling && S.runState !== "running" && !S.queue.length && S.shown.length && !S.done) finish();
}

function finish() {
  S.done = true;
  const end = [...S.shown].reverse().find((e) => e.agent_id === "orchestrator" && (e.state === "done" || e.state === "failed"));
  const ok = !end || end.state === "done";
  setPill(ok ? "done" : "failed");
  S.agentState.orchestrator = ok ? "done" : "failed";
  renderStrip();
  const actual = end && end.duration_ms != null ? `${(end.duration_ms / 1000).toFixed(2)} s` : "n/a";
  const speed = S.speed === "instant" ? "instant" : `${S.speed}×`;
  $("sc-banner").className = `mt-6 rounded-xl border px-5 py-4 ${ok ? "border-emerald-500/40 bg-emerald-500/10" : "border-red-500/40 bg-red-500/10"}`;
  $("sc-banner").innerHTML = `<div class="font-semibold ${ok ? "text-emerald-300" : "text-red-300"}">${ok ? "Scan complete" : "Scan failed"} · ${S.threats.length} threat(s), each written to the audit log</div>
    <div class="mt-1 text-sm text-muted">Actual scan time ${esc(actual)} · ${esc(S.shown.length)} events · visual replay speed ${esc(speed)}
    · <a class="text-brand2 hover:underline" href="${esc(keepMock("audit.html"))}">Open audit log</a>
    · <a class="text-brand2 hover:underline" href="${esc(keepMock("alerts.html"))}">Open alerts</a></div>`;
  $("sc-step").textContent = ok ? `All ${SCAN_STEPS} steps finished` : "Scan stopped with an error";
  $("sc-msg").textContent = end ? end.message : "";
  $("sc-bar").style.width = ok ? "100%" : $("sc-bar").style.width;
  toast(ok ? `Scan complete · ${S.threats.length} threat(s)` : "Scan failed", ok ? "success" : "error");
}

async function poll() {
  if (S.polling) return;
  S.polling = true;
  try {
    for (let i = 0; i < 600; i++) {
      const q = `/scan/trace?after=${S.lastSeq}&limit=500${S.runId ? `&run_id=${encodeURIComponent(S.runId)}` : ""}`;
      const res = await api(q);
      if (!res) break;
      if (!S.runId && res.run_id) S.runId = res.run_id;
      $("sc-run").textContent = S.runId || "";
      $("sc-term-title").textContent = `identityshield — ${S.runId || "scan"}`;
      for (const ev of res.events || []) {
        if (ev.seq > S.lastSeq && (!S.runId || ev.run_id === S.runId)) { S.queue.push(ev); S.lastSeq = ev.seq; }
      }
      S.runState = res.state || "done";
      play();
      if (MOCK || S.runState !== "running") break;
      await sleep(400);
    }
  } catch (err) {
    toast(err.message || "Could not load the scan trace", "error");
    S.runState = "failed";
  } finally {
    S.polling = false;
  }
  if (!S.playing && !S.queue.length && S.shown.length && !S.done) finish();
}

function resetView(state) {
  Object.assign(S, { queue: [], shown: [], lastSeq: 0, runId: null, done: false, selectedSeq: null, autoSelect: true,
    threats: [], completed: new Set(), current: null, firstTs: null, runState: "running" });
  S.agentState = Object.fromEntries(S.agents.map((a) => [a.id, a.num <= SCAN_STEPS ? "waiting" : "idle"]));
  consoleEl.innerHTML = "";
  $("sc-threat-list").innerHTML = `<div class="text-sm text-muted">No threats yet.</div>`;
  $("sc-banner").className = "hidden mt-6";
  $("sc-sel").innerHTML = "";
  $("sc-step").textContent = "Starting…";
  $("sc-msg").textContent = "";
  setPill(state);
  updateHeader();
  renderStrip();
}

async function startScan() {
  const mode = $("sc-mode").value;
  const btn = $("sc-start");
  btn.disabled = true;
  try {
    let prev = null;
    try { prev = (await api("/scan/status")).run_id; } catch { /* first run */ }
    resetView("running");
    try {
      await api("/scan/start", { method: "POST", body: mode === "dataset" ? {} : { input_mode: mode } });
    } catch (err) {
      if (!/already|409|conflict/i.test(err.message || "")) { toast(err.message, "error"); setPill("failed"); return; }
      toast("A scan is already running, attaching to it", "error");
    }
    if (!MOCK) {
      for (let i = 0; i < 30; i++) {
        const st = await api("/scan/status");
        if (st && st.run_id && st.run_id !== prev) { S.runId = st.run_id; break; }
        await sleep(150);
      }
    }
    await poll();
  } finally {
    btn.disabled = false;
  }
}

async function replay() {
  resetView("replay");
  try { S.runId = (await api("/scan/status")).run_id || null; } catch { S.runId = null; }
  if (!S.runId && !MOCK) { toast("No scan has run yet", "error"); setPill("idle"); return; }
  await poll();
}

$("sc-start").addEventListener("click", startScan);
$("sc-replay").addEventListener("click", replay);
$("sc-speed").addEventListener("change", (e) => { S.speed = e.target.value; });
$("sc-json").addEventListener("change", (e) => { S.inlineJson = e.target.checked; renderConsole(); });
$("sc-filter").addEventListener("change", (e) => { S.filter = e.target.value; renderConsole(); });
$("sc-copy").addEventListener("click", async () => {
  const ev = S.shown.find((x) => x.seq === S.selectedSeq);
  if (!ev) return;
  try { await navigator.clipboard.writeText(JSON.stringify(ev, null, 2)); toast("JSON copied"); }
  catch { toast("Copy not allowed by the browser", "error"); }
});
$("sc-download").addEventListener("click", () => {
  if (!S.shown.length) { toast("Nothing to download yet", "error"); return; }
  const blob = new Blob([JSON.stringify({ run_id: S.runId, events: S.shown }, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `${S.runId || "scan"}.json`;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 0);
});
$("sc-sel").addEventListener("click", () => { S.autoSelect = false; });
consoleEl.addEventListener("click", () => { S.autoSelect = false; });

(async function init() {
  try {
    const res = await api("/agents");
    S.agents = (res && res.agents) || [];
  } catch (err) {
    toast(err.message || "Could not load agents", "error");
  }
  S.agentState = Object.fromEntries(S.agents.map((a) => [a.id, "idle"]));
  renderStrip();
  const params = new URLSearchParams(location.search);
  const mode = params.get("mode");
  if (mode && [...$("sc-mode").options].some((o) => o.value === mode)) $("sc-mode").value = mode;
  const auto = params.get("autostart");
  if (auto === "replay") replay();
  else if (auto === "1") startScan();
})();
