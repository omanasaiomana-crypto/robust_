// static/js/notifications.js — admin email alerts: status, test email, history with previews.
import { api, toast, renderLayout, keepMock } from "./v21kit.js";
import { escHtml as esc } from "./jsonview.js";

const root = await renderLayout("notifications", "Notifications", "Email alerts sent to the security admin");
root.innerHTML = `
<section id="nt-status" class="bg-panel border border-line rounded-xl p-5"><div class="h-16 animate-pulse rounded bg-panel2"></div></section>
<section class="mt-6 bg-panel border border-line rounded-xl p-5 min-w-0">
  <h3 class="text-sm font-semibold">History</h3><div id="nt-list" class="mt-4 overflow-x-auto"></div></section>`;
const $ = (id) => document.getElementById(id);
const MODE = { outbox: ["Outbox (demo)", "bg-cyan-400/15 text-cyan-300"], smtp: ["SMTP", "bg-emerald-500/15 text-emerald-300"], off: ["Off", "bg-panel2 text-muted"] };
const STATUS = { sent: "bg-emerald-500/15 text-emerald-300", outbox: "bg-cyan-400/15 text-cyan-300", failed: "bg-red-500/15 text-red-300",
  rate_limited: "bg-amber-500/15 text-amber-300" };
let open = null;
let rows = [];

async function loadStatus() {
  try {
    const s = await api("/notifications/status");
    const [label, cls] = MODE[s.mode] || MODE.off;
    const dt = (k, v) => `<div><dt class="text-[10px] uppercase tracking-wide text-muted">${esc(k)}</dt><dd class="mt-0.5 text-sm">${v}</dd></div>`;
    $("nt-status").innerHTML = `<div class="flex flex-col gap-4 lg:flex-row lg:items-start">
      <div class="flex-1"><span class="rounded-full px-2 py-0.5 text-xs font-medium ${cls}">${esc(label)}</span>
        <dl class="mt-4 grid gap-4 sm:grid-cols-4">
          ${dt("Recipients", s.recipients && s.recipients.length ? esc(s.recipients.join(", ")) : '<span class="text-amber-300">No recipients configured</span>')}
          ${dt("SMTP server", esc(s.smtp_host || "—"))}${dt("Threshold", `Risk ≥ ${esc(s.min_risk)}`)}
          ${dt("Sent this hour", `${esc(s.sent_last_hour)} / ${esc(s.max_per_hour)}`)}</dl></div>
      <button id="nt-test" class="bg-brand hover:bg-blue-500 text-white rounded-lg px-3.5 py-2 text-sm font-medium">✉ Send test email</button></div>
      <p class="mt-4 text-xs text-muted">Configure in .env (see .env.example). Outbox mode works offline; emails are saved and shown here.</p>`;
    $("nt-test").onclick = sendTest;
  } catch (err) {
    $("nt-status").innerHTML = `<div class="text-sm text-red-300">${esc(err.message)}</div>`;
  }
}

async function sendTest() {
  const b = $("nt-test");
  b.disabled = true;
  try {
    const r = await api("/notifications/test", { method: "POST" });
    const msg = { sent: ["Test email sent", "success"], outbox: ["Saved to outbox (demo mode)", "success"], mocked: ["Mock mode: nothing sent", "success"],
      off: ["Email is turned off (EMAIL_MODE=off)", "error"] }[r.status] || [`${r.status}: ${r.detail || ""}`, "error"];
    toast(msg[0], msg[1]);
  } catch (err) {
    toast(err.message, "error");
  } finally {
    b.disabled = false;
    loadStatus();
    loadList();
  }
}

function renderList() {
  if (!rows.length) { $("nt-list").innerHTML = `<div class="py-6 text-center text-sm text-muted">No emails yet. A digest is sent when an alert reaches the risk threshold.</div>`; return; }
  $("nt-list").innerHTML = `<table class="w-full text-sm"><thead><tr class="text-left text-[11px] uppercase tracking-wide text-muted">
      <th class="py-2 pr-3">Time</th><th class="pr-3">Kind</th><th class="pr-3">Status</th><th class="pr-3">Subject</th><th class="pr-3">Recipients</th><th>Alerts</th></tr></thead>
    <tbody>${rows.map((r, i) => `<tr class="nt-row cursor-pointer border-t border-line hover:bg-panel2" data-i="${i}" tabindex="0">
        <td class="py-2 pr-3 whitespace-nowrap text-muted">${esc(new Date(r.created_at).toLocaleString())}</td>
        <td class="pr-3"><span class="rounded bg-panel2 px-1.5 py-0.5 text-[11px] capitalize">${esc(r.kind)}</span></td>
        <td class="pr-3"><span class="rounded-full px-2 py-0.5 text-[11px] ${STATUS[r.status] || "bg-panel2 text-muted"}">${esc(r.status)}</span></td>
        <td class="pr-3 max-w-md truncate" title="${esc(r.subject)}">${esc(r.subject)}</td>
        <td class="pr-3 text-muted">${esc(r.recipients)}</td>
        <td class="whitespace-nowrap">${(r.alert_ids || []).slice(0, 3).map((a) => `<a class="text-cyan-300 hover:underline mr-1" href="${esc(keepMock(`alert.html?id=${encodeURIComponent(a)}`))}">${esc(a)}</a>`).join("")}${(r.alert_ids || []).length > 3 ? "…" : ""}</td></tr>
      ${open === i ? `<tr><td colspan="6" class="pb-4"><div class="text-xs text-muted">${esc(r.detail)}</div>
        <pre class="mt-2 max-h-80 overflow-auto whitespace-pre-wrap rounded-lg border border-line bg-panel2 p-4 font-mono text-xs">${esc(r.body_text)}</pre></td></tr>` : ""}`).join("")}</tbody></table>`;
}

async function loadList() {
  try { rows = (await api("/notifications?limit=50")) || []; renderList(); }
  catch (err) { $("nt-list").innerHTML = `<div class="text-sm text-red-300">${esc(err.message)}</div>`; }
}
const toggle = (el) => { const i = Number(el.dataset.i); open = open === i ? null : i; renderList(); };
$("nt-list").addEventListener("click", (e) => { const tr = e.target.closest(".nt-row"); if (tr && !e.target.closest("a")) toggle(tr); });
$("nt-list").addEventListener("keydown", (e) => { const tr = e.target.closest(".nt-row"); if (tr && e.key === "Enter") toggle(tr); });

loadStatus();
loadList();
