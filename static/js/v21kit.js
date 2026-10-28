// static/js/v21kit.js — shared helpers for the v2.1 pages.
// Own API client (with ?mock=1 fixtures named v21_*.json) so v2.1 pages never depend on the v1 api.js details.
// toast() and renderLayout() reuse your ui.js / layout.js when available and fall back safely otherwise.
const UI = await import("./ui.js").catch(() => ({}));
const LAYOUT = await import("./layout.js").catch(() => ({}));

export const MOCK = new URLSearchParams(location.search).get("mock") === "1";
export const keepMock = (url) => (MOCK ? url + (url.includes("?") ? "&" : "?") + "mock=1" : url);
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const MOCK_MAP = [
  [/^\/agents$/, "v21_agents"], [/^\/scan\/status$/, "v21_scan_status"], [/^\/scan\/trace$/, "v21_scan_trace"],
  [/^\/inputs$/, "v21_inputs"], [/^\/identities$/, "v21_identities"], [/^\/identities\/[^/]+\/attack$/, "v21_graph_attack"],
  [/^\/graph\/global$/, "v21_graph_global"], [/^\/alerts\/[^/]+\/events$/, "v21_events"],
  [/^\/analytics\/detectors$/, "v21_analytics_detectors"], [/^\/analytics\/heatmap\/time$/, "v21_analytics_heatmap_time"],
  [/^\/analytics\/heatmap\/identities$/, "v21_analytics_heatmap_identities"],
  [/^\/notifications$/, "v21_notifications"], [/^\/notifications\/status$/, "v21_notifications_status"],
];

/** GET/POST/DELETE /api<path>. Returns JSON or throws Error("<error>: <detail>"). */
export async function api(path, { method = "GET", body } = {}) {
  if (MOCK) {
    if (method !== "GET") return { status: "mocked", detail: "mock mode" };
    const p = path.split("?")[0];
    const hit = MOCK_MAP.find(([re]) => re.test(p));
    if (!hit) throw new Error(`mock: no fixture for ${p}`);
    const r = await fetch(`/mock/${hit[1]}.json`);
    if (!r.ok) throw new Error(`mock: ${hit[1]}.json is missing`);
    return r.json();
  }
  let res;
  try {
    res = await fetch(`/api${path}`, {
      method,
      headers: body !== undefined ? { "Content-Type": "application/json" } : {},
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new Error("network: Cannot reach the server. Is it running?");
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`${data.error || res.status}: ${data.detail || res.statusText}`);
  return data;
}

let toastBox = null;
export function toast(message, type = "success") {
  try { if (typeof UI.toast === "function") return UI.toast(message, type); } catch { /* fall back */ }
  if (!toastBox) {
    toastBox = document.createElement("div");
    toastBox.style.cssText = "position:fixed;right:16px;bottom:16px;z-index:60;display:flex;flex-direction:column;gap:8px;max-width:360px";
    document.body.appendChild(toastBox);
  }
  const t = document.createElement("div");
  t.textContent = String(message);
  t.style.cssText = `padding:10px 14px;border-radius:10px;font:13px Inter,system-ui,sans-serif;color:#E6EBF2;`
    + `background:${type === "error" ? "#7F1D1D" : "#064E3B"};border:1px solid ${type === "error" ? "#EF4444" : "#10B981"}`;
  toastBox.appendChild(t);
  setTimeout(() => t.remove(), 4000);
}

/** Uses your layout.js renderLayout(active, title, subtitle); always resolves to the content element. */
export async function renderLayout(active, title, subtitle) {
  let el = null;
  try {
    if (typeof LAYOUT.renderLayout === "function") el = await LAYOUT.renderLayout(active, title, subtitle);
  } catch (err) {
    console.warn("renderLayout failed, using fallback", err);
  }
  if (el instanceof HTMLElement) return el;
  el = document.getElementById("content") || document.querySelector("main");
  if (!el) {
    const host = document.getElementById("app") || document.body;
    host.insertAdjacentHTML("beforeend", `<header class="max-w-7xl mx-auto px-6 pt-6"><h1 class="text-xl font-semibold"></h1>`
      + `<p class="text-sm text-muted"></p></header>`);
    host.querySelector("header h1").textContent = title || "";
    host.querySelector("header p").textContent = subtitle || "";
    el = document.createElement("main");
    el.className = "max-w-7xl mx-auto px-6 py-6";
    host.appendChild(el);
  }
  return el;
}
