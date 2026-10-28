// static/js/explorer.js — Attack Path Explorer (identity graph). Requires vis-network 9 loaded before this module.
// Features: animated attack path with numbered steps, step-by-step attack playback with camera,
// focus mode, blast-radius halo, force / left-to-right layouts, inspector with evidence JSON,
// all-risky-identities view, PNG export and fullscreen.
import { api, toast, renderLayout, MOCK, keepMock } from "./v21kit.js";
import { highlightJson, escHtml as esc } from "./jsonview.js";
import { computeAttackPath, reachable, pathDurationMinutes, drawFlow, drawStepBadges, drawHalo } from "./graphfx.js";

const KIND = {
  user: { color: "#22D3EE", shape: "dot", size: 26, label: "Identity" },
  session: { color: "#8B5CF6", shape: "hexagon", size: 15, label: "Session" },
  role: { color: "#F59E0B", shape: "diamond", size: 18, label: "Role" },
  key: { color: "#F97316", shape: "triangle", size: 16, label: "Access key" },
  policy: { color: "#EF4444", shape: "square", size: 15, label: "Policy" },
  resource: { color: "#10B981", shape: "star", size: 19, label: "Resource" },
  ip: { color: "#64748B", shape: "dot", size: 9, label: "IP address" },
};
const RED = "#EF4444";
const DIM_NODE = "rgba(100,116,139,0.18)";
const DIM_FONT = "rgba(230,235,242,0.18)";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const G = {
  identity: new URLSearchParams(location.search).get("identity") || "", mode: "identity",
  data: null, alert: null, path: { edgeIndexes: [], nodeIds: [], steps: [] }, blast: new Set(),
  network: null, nodes: null, edges: null, focus: false, showBlast: false, layout: "force",
  playStep: Infinity, playing: false, raf: null, selected: null, evidence: null,
};

const root = await renderLayout("explorer", "Attack path explorer", "How a compromised identity moved from login to impact");
root.innerHTML = `
<section class="bg-panel border border-line rounded-xl p-5">
  <div class="flex flex-col gap-4 lg:flex-row lg:items-center">
    <div class="flex items-center gap-2">
      <label for="g-identity" class="text-xs uppercase tracking-wide text-muted">Identity</label>
      <select id="g-identity" class="bg-panel2 border border-line rounded-lg px-3 py-2 text-sm min-w-[200px]"></select>
    </div>
    <input id="g-search" type="search" placeholder="Find a node (role, key, IP…)" aria-label="Find a node"
      class="bg-panel2 border border-line rounded-lg px-3 py-2 text-sm lg:w-64">
    <div id="g-stats" class="grid grid-cols-3 gap-2 sm:grid-cols-6 lg:ml-auto"></div>
  </div>
  <div class="mt-4 flex flex-wrap items-center gap-2" role="toolbar" aria-label="Graph controls">
    <button id="g-play" class="bg-crit/90 hover:bg-crit text-white rounded-lg px-3.5 py-2 text-sm font-medium">▶ Play attack</button>
    <button id="g-focus" class="border border-line hover:bg-panel2 rounded-lg px-3 py-2 text-sm" aria-pressed="false">Focus attack path</button>
    <button id="g-blast" class="border border-line hover:bg-panel2 rounded-lg px-3 py-2 text-sm" aria-pressed="false">Blast radius</button>
    <div class="inline-flex rounded-lg border border-line overflow-hidden text-sm" role="group" aria-label="Layout">
      <button id="g-lay-force" class="px-3 py-2 bg-panel2">Force</button>
      <button id="g-lay-lr" class="px-3 py-2 hover:bg-panel2">Left → right</button>
    </div>
    <button id="g-global" class="border border-line hover:bg-panel2 rounded-lg px-3 py-2 text-sm" aria-pressed="false">All risky identities</button>
    <span class="ml-auto"></span>
    <button id="g-fit" class="border border-line hover:bg-panel2 rounded-lg px-3 py-2 text-sm">Fit</button>
    <button id="g-png" class="border border-line hover:bg-panel2 rounded-lg px-3 py-2 text-sm">Export PNG</button>
    <button id="g-full" class="border border-line hover:bg-panel2 rounded-lg px-3 py-2 text-sm">Fullscreen</button>
  </div>
</section>

<div class="mt-6 grid gap-6 lg:grid-cols-4">
  <section id="g-stage" class="relative lg:col-span-3 rounded-xl border border-line overflow-hidden"
    style="background:radial-gradient(ellipse at center,#0F1626 0%,#0B0F17 70%)">
    <div id="g-canvas" class="h-[640px] w-full"></div>
    <div id="g-caption" class="pointer-events-none absolute left-4 top-4 hidden max-w-[70%] rounded-lg border border-red-500/40 bg-black/60 px-3 py-2 text-sm backdrop-blur"></div>
    <div id="g-legend" class="pointer-events-none absolute bottom-3 left-3 flex flex-wrap gap-x-3 gap-y-1 rounded-lg border border-line bg-black/50 px-3 py-2 text-[11px] text-muted backdrop-blur"></div>
    <div id="g-empty" class="absolute inset-0 hidden items-center justify-center text-sm text-muted"></div>
  </section>
  <div class="flex flex-col gap-6 min-w-0">
    <section class="bg-panel border border-line rounded-xl p-5">
      <h3 class="text-sm font-semibold">Attack path</h3>
      <div id="g-steps" class="mt-3 text-sm text-muted">Loading…</div>
    </section>
    <section class="bg-panel border border-line rounded-xl p-5 min-w-0">
      <h3 class="text-sm font-semibold">Inspector</h3>
      <div id="g-inspect" class="mt-3 text-sm text-muted">Click a node to inspect it.</div>
    </section>
  </div>
</div>`;

const $ = (id) => document.getElementById(id);

function legend() {
  $("g-legend").innerHTML = Object.values(KIND).map((k) =>
    `<span class="inline-flex items-center gap-1.5"><span class="h-2.5 w-2.5 rounded-full" style="background:${k.color}"></span>${esc(k.label)}</span>`).join("")
    + `<span class="inline-flex items-center gap-1.5"><span class="h-0.5 w-4" style="background:${RED}"></span>Attack path</span>`;
}

function stat(label, value, cls = "") {
  return `<div class="rounded-lg border border-line bg-panel2 px-3 py-2"><div class="text-[10px] uppercase tracking-wide text-muted">${esc(label)}</div>
    <div class="text-base font-semibold tabular-nums ${cls}">${esc(value)}</div></div>`;
}

// Same number as the Identities page (backend: sensitive resources reachable); falls back to the client-side count.
function blastCount() {
  const v = G.mode === "identity" && G.data && Number.isFinite(G.data.blast_radius) ? G.data.blast_radius : G.blast.size;
  return v || 0;
}

function renderStats() {
  const d = G.data || { graph: { nodes: [], edges: [] } };
  const g = d.graph || d;
  const mins = pathDurationMinutes(G.path.steps);
  $("g-stats").innerHTML = stat("Nodes", (g.nodes || []).length) + stat("Edges", (g.edges || []).length)
    + stat("Path steps", G.path.steps.length || "—", G.path.steps.length ? "text-crit" : "")
    + stat("Time to impact", mins == null ? "—" : `${mins} min`, mins != null ? "text-crit" : "")
    + stat("Blast radius", blastCount(), blastCount() ? "text-high" : "")
    + stat("Risk", G.alert ? Math.round(G.alert.risk) : "—", G.alert && G.alert.risk >= 90 ? "text-crit" : "");
}

function renderSteps() {
  if (G.mode === "global") { $("g-steps").innerHTML = `<div class="text-muted">Showing all risky identities. Pick one identity to see its attack path.</div>`; return; }
  if (!G.path.steps.length) { $("g-steps").innerHTML = `<div class="text-muted">No attack path for this identity.</div>`; return; }
  $("g-steps").innerHTML = `<ol class="relative ml-2 border-l border-line">` + G.path.steps.map((s, i) => {
    const active = i < G.playStep;
    const t = s.timestamp ? new Date(s.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "";
    return `<li class="mb-3 ml-4"><button data-step="${i}" class="g-step block w-full text-left rounded-md px-2 py-1 hover:bg-panel2">
      <span class="absolute -left-[9px] mt-1 flex h-4 w-4 items-center justify-center rounded-full text-[10px] font-bold ${active ? "bg-crit text-white" : "bg-panel2 text-muted border border-line"}">${i + 1}</span>
      <span class="block font-mono text-xs ${active ? "text-red-300" : "text-ink"}">${esc(s.action || s.label)}</span>
      <span class="block text-[11px] text-muted">${esc(s.state || s.label)}${t ? " · " + esc(t) : ""}</span></button></li>`;
  }).join("") + `</ol>` + (G.alert ? `<a class="text-xs text-brand2 hover:underline" href="${esc(keepMock(`alert.html?id=${encodeURIComponent(G.alert.alert_id)}`))}">Open alert ${esc(G.alert.alert_id)} →</a>` : "");
}

function nodeStyle(n) {
  const k = KIND[n.kind] || KIND.ip;
  const onPath = G.mode === "identity" && G.path.nodeIds.indexOf(n.id) !== -1 && G.path.nodeIds.indexOf(n.id) < visiblePathNodes();
  const inBlast = G.showBlast && G.blast.has(n.id);
  const dim = G.focus && !onPath && !inBlast && n.id !== `user:${G.identity}`;
  const glow = onPath ? RED : inBlast ? "#F97316" : n.kind === "user" && n.risk >= 70 ? "#22D3EE" : null;
  return {
    id: n.id, label: n.label, shape: k.shape, size: k.size + (onPath ? 3 : 0),
    color: dim ? { background: DIM_NODE, border: DIM_NODE } : { background: k.color, border: onPath ? "#FCA5A5" : "#0B0F17",
      highlight: { background: k.color, border: "#FFFFFF" }, hover: { background: k.color, border: "#E6EBF2" } },
    borderWidth: onPath ? 3 : 1.5,
    font: { color: dim ? DIM_FONT : "#E6EBF2", size: n.kind === "user" ? 14 : 12, face: "Inter, system-ui, sans-serif",
      strokeWidth: 3, strokeColor: "#0B0F17" },
    shadow: glow ? { enabled: true, color: glow, size: onPath ? 26 : 18, x: 0, y: 0 } : { enabled: false },
  };
}

function visiblePathNodes() {
  if (G.playStep === Infinity) return Infinity;
  const ids = new Set();
  G.path.steps.slice(0, G.playStep).forEach((s) => { ids.add(s.from); ids.add(s.to); });
  return ids.size;
}

function edgeStyle(e, i) {
  const rank = G.path.edgeIndexes.indexOf(i);
  const onPath = G.mode === "identity" && rank !== -1 && rank < G.playStep;
  const pending = G.mode === "identity" && rank !== -1 && rank >= G.playStep;
  const dim = G.focus && !onPath;
  const red = onPath || (G.mode === "global" && e.suspicious);
  return {
    id: i, from: e.source, to: e.target, label: red ? e.label : undefined, title: `${e.label}${e.event_id ? " · " + e.event_id : ""}`,
    arrows: { to: { enabled: true, scaleFactor: 0.6 } },
    color: { color: red ? RED : pending ? "rgba(239,68,68,0.35)" : dim ? "rgba(51,65,85,0.25)" : "#334155", highlight: "#FCA5A5", hover: "#94A3B8" },
    width: red ? 3.5 : 1, dashes: pending ? [6, 6] : false,
    smooth: red ? false : { enabled: true, type: "continuous", roundness: 0.4 },
    font: { size: red ? 11 : 0, color: "#FCA5A5", strokeWidth: 3, strokeColor: "#0B0F17", align: "top" },
  };
}

function restyle() {
  if (!G.nodes) return;
  const g = graphData();
  G.nodes.update(g.nodes.map(nodeStyle));
  G.edges.update(g.edges.map(edgeStyle));
}

function graphData() {
  if (!G.data) return { nodes: [], edges: [] };
  return G.mode === "global" ? G.data : G.data.graph;
}

function pathPairs() {
  if (G.mode !== "identity") return [];
  return G.path.steps.slice(0, Math.min(G.path.steps.length, G.playStep)).map((s) => [s.from, s.to]);
}

function startAnimation() {
  cancelAnimationFrame(G.raf);
  const tick = () => {
    if (G.network && !document.hidden && (pathPairs().length || G.showBlast)) G.network.redraw();
    G.raf = requestAnimationFrame(tick);
  };
  G.raf = requestAnimationFrame(tick);
}

function build() {
  const g = graphData();
  $("g-empty").classList.add("hidden");
  if (G.network) { G.network.destroy(); G.network = null; }
  if (!g.nodes || !g.nodes.length) {
    $("g-empty").textContent = "No graph data for this identity.";
    $("g-empty").classList.remove("hidden");
    $("g-empty").classList.add("flex");
    return;
  }
  G.nodes = new vis.DataSet(g.nodes.map(nodeStyle));
  G.edges = new vis.DataSet(g.edges.map(edgeStyle));
  const options = {
    autoResize: true,
    interaction: { hover: true, tooltipDelay: 120, navigationButtons: false, keyboard: false },
    physics: { enabled: true, solver: "barnesHut", stabilization: { iterations: 300, fit: true },
      barnesHut: { gravitationalConstant: -9000, springLength: 130, springConstant: 0.03, avoidOverlap: 0.4 } },
    layout: layoutOptions(),
    nodes: { shapeProperties: { interpolation: false } },
  };
  G.network = new vis.Network($("g-canvas"), { nodes: G.nodes, edges: G.edges }, options);
  G.network.once("stabilizationIterationsDone", () => {
    G.network.setOptions({ physics: { enabled: false } });
    G.network.fit({ animation: { duration: 600, easingFunction: "easeInOutQuad" } });
  });
  G.network.on("afterDrawing", (ctx) => {
    const t = performance.now();
    const pairs = pathPairs();
    const ids = [...new Set(pairs.flat()), ...(G.showBlast ? [`user:${G.identity}`] : [])];
    const pos = ids.length ? G.network.getPositions(ids) : {};
    if (G.showBlast && G.mode === "identity") drawHalo(ctx, pos[`user:${G.identity}`], t);
    if (pairs.length) {
      drawFlow(ctx, pairs, pos, t);
      const order = [];
      pairs.forEach(([a, b]) => { if (!order.includes(a)) order.push(a); if (!order.includes(b)) order.push(b); });
      drawStepBadges(ctx, order, pos);
    }
  });
  G.network.on("click", (params) => {
    if (params.nodes && params.nodes.length) inspect(params.nodes[0]);
  });
  startAnimation();
}

function layoutOptions() {
  return G.layout === "lr"
    ? { hierarchical: { enabled: true, direction: "LR", sortMethod: "directed", levelSeparation: 190, nodeSpacing: 90, shakeTowards: "roots" } }
    : { hierarchical: { enabled: false }, improvedLayout: true };
}

function setLayout(kind) {
  G.layout = kind;
  $("g-lay-force").className = `px-3 py-2 ${kind === "force" ? "bg-panel2" : "hover:bg-panel2"}`;
  $("g-lay-lr").className = `px-3 py-2 ${kind === "lr" ? "bg-panel2" : "hover:bg-panel2"}`;
  build();
}

async function loadEvidence() {
  if (G.evidence || !G.alert) return G.evidence || [];
  try { G.evidence = (await api(`/alerts/${encodeURIComponent(G.alert.alert_id)}/events`)) || []; }
  catch { G.evidence = []; }
  return G.evidence;
}

async function inspect(nodeId) {
  const g = graphData();
  const n = g.nodes.find((x) => x.id === nodeId);
  if (!n) return;
  G.selected = nodeId;
  const k = KIND[n.kind] || KIND.ip;
  const rel = g.edges.filter((e) => e.source === nodeId || e.target === nodeId);
  const rows = rel.slice(0, 12).map((e) => {
    const out = e.source === nodeId;
    const other = out ? e.target : e.source;
    const on = G.path.steps.some((s) => s.event_id && s.event_id === e.event_id);
    return `<li class="flex items-center gap-2 py-1 ${on ? "text-red-300" : ""}">
      <span class="text-muted">${out ? "→" : "←"}</span><span class="font-mono text-[11px]">${esc(e.label)}</span>
      <button class="g-goto truncate text-left hover:underline" data-node="${esc(other)}">${esc(other.split(":").slice(1).join(":") || other)}</button>
      ${e.event_id ? `<button class="g-ev ml-auto font-mono text-[10px] text-brand2 hover:underline" data-ev="${esc(e.event_id)}">${esc(e.event_id)}</button>` : ""}</li>`;
  }).join("");
  $("g-inspect").innerHTML = `
    <div class="flex items-center gap-2"><span class="h-3 w-3 rounded-full" style="background:${k.color}"></span>
      <span class="font-semibold text-ink truncate">${esc(n.label)}</span>
      <span class="ml-auto rounded-full bg-panel2 px-2 py-0.5 text-[11px]">${esc(k.label)}</span></div>
    <div class="mt-1 font-mono text-[11px] text-muted break-all">${esc(n.id)}</div>
    ${n.risk ? `<div class="mt-2 text-xs">Risk <span class="font-semibold text-crit">${esc(Math.round(n.risk))}</span></div>` : ""}
    ${G.blast.has(n.id) ? `<div class="mt-1 text-xs text-high">Reachable from this identity (blast radius)</div>` : ""}
    <ul class="mt-3 text-xs">${rows || `<li class="text-muted">No connections.</li>`}</ul>
    ${rel.length > 12 ? `<div class="text-[11px] text-muted">+${rel.length - 12} more</div>` : ""}
    <pre id="g-ev-json" class="mt-3 hidden max-h-64 overflow-auto rounded-lg border border-line p-3 font-mono text-[11px] leading-5 whitespace-pre-wrap" style="background:#05070C"></pre>`;
  if (G.network) G.network.selectNodes([nodeId]);
}

$("g-inspect").addEventListener("click", async (e) => {
  const go = e.target.closest(".g-goto");
  if (go) { focusNode(go.dataset.node); inspect(go.dataset.node); return; }
  const evb = e.target.closest(".g-ev");
  if (!evb) return;
  const box = $("g-ev-json");
  const evs = await loadEvidence();
  const ev = evs.find((x) => x.event_id === evb.dataset.ev);
  box.classList.remove("hidden");
  box.innerHTML = ev ? highlightJson(ev) : `<span class="text-slate-500">Event ${esc(evb.dataset.ev)} is not part of this alert's evidence.</span>`;
});

$("g-steps").addEventListener("click", (e) => {
  const b = e.target.closest(".g-step");
  if (!b) return;
  const s = G.path.steps[Number(b.dataset.step)];
  if (s) { focusNode(s.to); inspect(s.to); }
});

function focusNode(id, scale = 1.25) {
  if (G.network && G.nodes && G.nodes.get(id)) {
    G.network.focus(id, { scale, animation: { duration: 700, easingFunction: "easeInOutQuad" } });
  }
}

function caption(i) {
  const s = G.path.steps[i];
  if (!s) { $("g-caption").classList.add("hidden"); return; }
  const t = s.timestamp ? new Date(s.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "";
  $("g-caption").innerHTML = `<span class="mr-2 rounded bg-crit px-1.5 py-0.5 text-[11px] font-bold text-white">STEP ${i + 1}/${G.path.steps.length}</span>`
    + `<span class="font-mono text-red-200">${esc(s.action || s.label)}</span>`
    + `<span class="text-muted"> · ${esc(s.state || "")}${t ? " · " + esc(t) : ""}</span>`;
  $("g-caption").classList.remove("hidden");
}

async function play() {
  if (G.mode !== "identity" || !G.path.steps.length) { toast("No attack path to play for this identity", "error"); return; }
  if (G.playing) { G.playing = false; return; }
  G.playing = true;
  $("g-play").textContent = "❚❚ Pause";
  G.playStep = 0;
  restyle(); renderSteps();
  focusNode(G.path.steps[0].from, 1.1);
  await sleep(800);
  for (let i = 0; i < G.path.steps.length && G.playing; i++) {
    G.playStep = i + 1;
    restyle(); renderSteps(); caption(i);
    focusNode(G.path.steps[i].to, 1.3);
    await sleep(1500);
  }
  G.playing = false;
  G.playStep = Infinity;
  restyle(); renderSteps();
  $("g-play").textContent = "▶ Play attack";
  setTimeout(() => $("g-caption").classList.add("hidden"), 2500);
  if (G.network) G.network.fit({ animation: { duration: 700, easingFunction: "easeInOutQuad" } });
}

function toggle(btn, key) {
  G[key] = !G[key];
  $(btn).setAttribute("aria-pressed", String(G[key]));
  $(btn).classList.toggle("bg-panel2", G[key]);
  $(btn).classList.toggle("ring-1", G[key]);
  $(btn).classList.toggle("ring-brand2", G[key]);
  restyle();
  renderStats();
}

async function loadIdentity(id) {
  G.mode = "identity";
  G.identity = id;
  G.evidence = null;
  G.playStep = Infinity;
  $("g-global").setAttribute("aria-pressed", "false");
  $("g-global").classList.remove("bg-panel2", "ring-1", "ring-brand2");
  $("g-steps").textContent = "Loading…";
  try {
    G.data = await api(`/identities/${encodeURIComponent(id)}/attack`);
  } catch (err) {
    toast(err.message || "Could not load the graph", "error");
    G.data = null;
  }
  G.alert = (G.data && G.data.alert) || null;
  const edges = (G.data && G.data.graph && G.data.graph.edges) || [];
  G.path = computeAttackPath(edges, G.alert);
  G.blast = new Set([...reachable(edges, `user:${id}`)].filter((nid) => nid.startsWith("res:")));
  const url = new URL(location.href);
  url.searchParams.set("identity", id);
  history.replaceState(null, "", url);
  build(); renderStats(); renderSteps();
  $("g-inspect").innerHTML = `<div class="text-muted">Click a node to inspect it.</div>`;
}

async function loadGlobal() {
  G.mode = "global";
  G.path = { edgeIndexes: [], nodeIds: [], steps: [] };
  G.blast = new Set();
  G.alert = null;
  try { G.data = await api("/graph/global?top=8"); }
  catch (err) { toast(err.message || "Could not load the global graph", "error"); G.data = null; }
  $("g-global").setAttribute("aria-pressed", "true");
  $("g-global").classList.add("bg-panel2", "ring-1", "ring-brand2");
  build(); renderStats(); renderSteps();
}

$("g-play").addEventListener("click", play);
$("g-focus").addEventListener("click", () => toggle("g-focus", "focus"));
$("g-blast").addEventListener("click", () => toggle("g-blast", "showBlast"));
$("g-lay-force").addEventListener("click", () => setLayout("force"));
$("g-lay-lr").addEventListener("click", () => setLayout("lr"));
$("g-global").addEventListener("click", () => (G.mode === "global" ? loadIdentity(G.identity) : loadGlobal()));
$("g-fit").addEventListener("click", () => G.network && G.network.fit({ animation: { duration: 500, easingFunction: "easeInOutQuad" } }));
$("g-identity").addEventListener("change", (e) => loadIdentity(e.target.value));
$("g-search").addEventListener("keydown", (e) => {
  if (e.key !== "Enter") return;
  const q = e.target.value.trim().toLowerCase();
  const hit = graphData().nodes.find((n) => n.label.toLowerCase().includes(q) || n.id.toLowerCase().includes(q));
  if (hit) { focusNode(hit.id, 1.5); inspect(hit.id); } else toast(`No node matches "${q}"`, "error");
});
$("g-png").addEventListener("click", () => {
  const canvas = $("g-canvas").querySelector("canvas");
  if (!canvas) { toast("Nothing to export yet", "error"); return; }
  const out = document.createElement("canvas");
  out.width = canvas.width; out.height = canvas.height;
  const c = out.getContext("2d");
  c.fillStyle = "#0B0F17"; c.fillRect(0, 0, out.width, out.height);
  c.drawImage(canvas, 0, 0);
  const a = document.createElement("a");
  a.href = out.toDataURL("image/png");
  a.download = `attack-path-${G.mode === "global" ? "all" : G.identity || "graph"}.png`;
  document.body.appendChild(a); a.click(); a.remove();
});
$("g-full").addEventListener("click", async () => {
  const stage = $("g-stage");
  try {
    if (document.fullscreenElement) await document.exitFullscreen();
    else await stage.requestFullscreen();
  } catch {
    stage.classList.toggle("fixed"); stage.classList.toggle("inset-0"); stage.classList.toggle("z-50");
  }
  setTimeout(() => G.network && G.network.fit(), 200);
});
document.addEventListener("fullscreenchange", () => {
  $("g-canvas").style.height = document.fullscreenElement ? "100vh" : "";
  $("g-full").textContent = document.fullscreenElement ? "Exit fullscreen" : "Fullscreen";
  setTimeout(() => G.network && G.network.fit(), 200);
});

(async function init() {
  legend();
  if (typeof vis === "undefined") {
    $("g-empty").textContent = "Graph library failed to load (vis-network).";
    $("g-empty").classList.remove("hidden"); $("g-empty").classList.add("flex");
    return;
  }
  let ids = [];
  try { ids = (await api("/identities")) || []; } catch (err) { toast(err.message || "Could not load identities", "error"); }
  ids.sort((a, b) => (b.risk || 0) - (a.risk || 0));
  $("g-identity").innerHTML = ids.map((r) => `<option value="${esc(r.identity_id)}">${esc(r.identity_id)} · risk ${esc(Math.round(r.risk || 0))}</option>`).join("");
  const first = G.identity || (ids[0] && ids[0].identity_id) || "";
  if (G.identity && !ids.some((r) => r.identity_id === G.identity)) {
    $("g-identity").insertAdjacentHTML("afterbegin", `<option value="${esc(G.identity)}">${esc(G.identity)}</option>`);
  }
  $("g-identity").value = first;
  if (first) await loadIdentity(first);
  else { $("g-empty").textContent = "No identities yet. Run a scan first."; $("g-empty").classList.remove("hidden"); $("g-empty").classList.add("flex"); }
  if (new URLSearchParams(location.search).get("play") === "1") play();
})();
