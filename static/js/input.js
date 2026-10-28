// static/js/input.js — input-only data entry: paste / upload logs or add one event, then scan only that input.
import { api, toast, renderLayout, keepMock } from "./v21kit.js";
import { highlightJson, escHtml as esc } from "./jsonview.js";

const root = await renderLayout("input", "Input data", "Add your own logs or single events, then scan only them");
const field = (id, label, attrs = "") => `<label class="flex flex-col gap-1 text-xs text-muted">${esc(label)}
  <input id="${id}" ${attrs} class="bg-panel2 border border-line rounded-lg px-3 py-2 text-sm text-ink"></label>`;
const EVENT_NAMES = ["ConsoleLogin", "CreateAccessKey", "AttachUserPolicy", "PutUserPolicy", "AssumeRole", "GetSecretValue",
  "StopLogging", "DeleteTrail", "ListBuckets", "CreateUser"];

root.innerHTML = `
<div class="grid gap-6 lg:grid-cols-3">
  <section class="lg:col-span-2 bg-panel border border-line rounded-xl p-5">
    <div class="flex gap-2 border-b border-line pb-3" role="tablist">
      <button id="tab-paste" class="in-tab rounded-lg px-3 py-1.5 text-sm bg-panel2" data-tab="paste">Paste or upload</button>
      <button id="tab-form" class="in-tab rounded-lg px-3 py-1.5 text-sm hover:bg-panel2" data-tab="form">Single event</button>
    </div>
    <div id="panel-paste" class="mt-4">
      <label class="flex items-center gap-2 text-sm text-muted">Source
        <select id="in-source" class="bg-panel2 border border-line rounded-lg px-3 py-2 text-sm text-ink">
          <option value="auto">Auto-detect</option><option value="cloudtrail">AWS CloudTrail</option><option value="okta">Okta System Log</option></select></label>
      <label id="in-drop" class="mt-4 flex cursor-pointer flex-col items-center justify-center gap-2 rounded-xl border-2 border-dashed border-line p-8 text-center hover:border-cyan-400/60">
        <span class="text-2xl">⇪</span><span class="text-sm">Drop .json / .jsonl files here or click to choose</span>
        <span class="text-xs text-muted" id="in-limit"></span>
        <input id="in-file" type="file" accept=".json,.jsonl,.txt" multiple class="hidden"></label>
      <textarea id="in-text" spellcheck="false" class="mt-4 h-56 w-full rounded-lg border border-line p-3 font-mono text-xs text-ink" style="background:#05070C"
        placeholder='{"Records":[{"eventID":"1","eventTime":"2026-10-28T04:00:00Z","eventName":"AttachUserPolicy","eventSource":"iam.amazonaws.com","sourceIPAddress":"185.220.101.4","userIdentity":{"userName":"svc-report"}}]}'></textarea>
      <button id="in-paste" class="mt-3 bg-brand hover:bg-blue-500 text-white rounded-lg px-3.5 py-2 text-sm font-medium">Add pasted records</button>
      <div id="in-result" class="mt-4"></div>
    </div>
    <div id="panel-form" class="mt-4 hidden">
      <div class="flex flex-wrap gap-2" id="in-presets">
        <button data-preset="blr" class="border border-line hover:bg-panel2 rounded-lg px-3 py-1.5 text-xs">Login · Bengaluru</button>
        <button data-preset="fra" class="border border-line hover:bg-panel2 rounded-lg px-3 py-1.5 text-xs">Login · Frankfurt +30 min</button>
        <button data-preset="admin" class="border border-line hover:bg-panel2 rounded-lg px-3 py-1.5 text-xs">Attach AdministratorAccess</button>
        <button data-preset="stoplog" class="border border-line hover:bg-panel2 rounded-lg px-3 py-1.5 text-xs">Stop CloudTrail logging</button>
      </div>
      <label class="mt-4 flex items-center gap-2 text-sm text-muted">Event type
        <select id="f-kind" class="bg-panel2 border border-line rounded-lg px-3 py-2 text-sm text-ink">
          <option value="okta_login">Okta login</option><option value="okta_logout">Okta logout</option><option value="cloudtrail_api">AWS API call</option></select></label>
      <div class="mt-4 grid gap-3 sm:grid-cols-2">
        ${field("f-user", "User *", 'placeholder="anita.rao or anita.rao@corp.example"')}
        ${field("f-ip", "Source IP *", 'placeholder="49.207.12.8"')}
        ${field("f-time", "Time (local; empty = now)", 'type="datetime-local" step="1"')}
        ${field("f-label", "Label (optional, e.g. impossible_travel)")}
      </div>
      <div id="f-okta" class="mt-3 grid gap-3 sm:grid-cols-2">
        <label class="flex flex-col gap-1 text-xs text-muted">Outcome<select id="f-outcome" class="bg-panel2 border border-line rounded-lg px-3 py-2 text-sm text-ink"><option>SUCCESS</option><option>FAILURE</option></select></label>
        ${field("f-session", "Session id (optional)")}${field("f-city", "City")}${field("f-country", "Country")}
        ${field("f-lat", "Latitude", 'inputmode="decimal"')}${field("f-lon", "Longitude", 'inputmode="decimal"')}
      </div>
      <div id="f-aws" class="mt-3 hidden grid gap-3 sm:grid-cols-2">
        ${field("f-event", "Event name *", 'list="f-events"')}<datalist id="f-events">${EVENT_NAMES.map((n) => `<option value="${n}">`).join("")}</datalist>
        ${field("f-source", "Event source", 'placeholder="iam.amazonaws.com"')}${field("f-region", "Region", 'placeholder="ap-south-1"')}
        ${field("f-key", "Access key id (optional)")}${field("f-resource", "Resource / ARN (optional)")}
      </div>
      <div id="f-error" class="mt-3 text-sm text-red-300"></div>
      <button id="f-submit" class="mt-3 bg-brand hover:bg-blue-500 text-white rounded-lg px-3.5 py-2 text-sm font-medium">Add event</button>
      <pre id="f-out" class="mt-4 hidden max-h-72 overflow-auto rounded-lg border border-line p-3 font-mono text-[11.5px] leading-5 whitespace-pre-wrap" style="background:#05070C"></pre>
    </div>
  </section>
  <div class="flex flex-col gap-6">
    <section class="bg-panel border border-line rounded-xl p-5">
      <div class="flex items-center"><h3 class="text-sm font-semibold">Your input data</h3>
        <button id="in-clear" class="ml-auto rounded-lg bg-red-600/90 hover:bg-red-600 px-3 py-1.5 text-xs text-white">Clear all</button></div>
      <div id="in-totals" class="mt-3 grid grid-cols-3 gap-2"></div>
      <ul id="in-files" class="mt-3 flex flex-col gap-2 text-xs"></ul>
    </section>
    <section class="bg-panel border border-line rounded-xl p-5">
      <h3 class="text-sm font-semibold">Scan it</h3>
      <div class="mt-3 flex flex-col gap-2">
        <button id="in-scan-only" class="bg-red-600/90 hover:bg-red-600 text-white rounded-lg px-3.5 py-2 text-sm font-medium">Scan input only</button>
        <button id="in-scan-merge" class="border border-line hover:bg-panel2 rounded-lg px-3.5 py-2 text-sm">Scan dataset + input</button>
      </div>
      <p id="in-hint" class="mt-2 text-xs text-amber-300"></p>
      <p class="mt-3 text-xs text-muted">Input-only scans look at nothing else. Detectors that need history (dormant accounts, ML baseline)
        may report nothing on very small inputs; use Dataset + input for those.</p>
    </section>
  </div>
</div>`;
const $ = (id) => document.getElementById(id);
let limits = { max_bytes: 5_000_000, max_records: 50_000 };
let lastPresetTime = null;

function tab(name) {
  for (const t of ["paste", "form"]) {
    $(`panel-${t}`).classList.toggle("hidden", t !== name);
    $(`tab-${t}`).className = `in-tab rounded-lg px-3 py-1.5 text-sm ${t === name ? "bg-panel2" : "hover:bg-panel2"}`;
  }
}
document.querySelectorAll(".in-tab").forEach((b) => b.addEventListener("click", () => tab(b.dataset.tab)));

function kindChanged() {
  const aws = $("f-kind").value === "cloudtrail_api";
  $("f-okta").classList.toggle("hidden", aws);
  $("f-aws").classList.toggle("hidden", !aws);
}
$("f-kind").addEventListener("change", kindChanged);

async function loadList() {
  try {
    const d = await api("/inputs");
    limits = d.limits || limits;
    $("in-limit").textContent = `Up to ${(limits.max_bytes / 1e6).toFixed(0)} MB and ${limits.max_records.toLocaleString()} records per upload`;
    const t = d.totals || {};
    const stat = (label, v) => `<div class="rounded-lg border border-line bg-panel2 p-2"><div class="text-[10px] uppercase tracking-wide text-muted">${esc(label)}</div><div class="text-lg font-semibold tabular-nums">${esc(v ?? 0)}</div></div>`;
    $("in-totals").innerHTML = stat("CloudTrail", t.cloudtrail) + stat("Okta", t.okta) + stat("Total", d.total_records);
    $("in-files").innerHTML = (d.files || []).map((f) => `<li class="flex items-center gap-2 rounded-lg border border-line bg-panel2 px-2 py-1.5">
        <span class="rounded px-1.5 py-0.5 text-[10px] ${f.source === "okta" ? "bg-violet-500/20 text-violet-300" : "bg-amber-500/20 text-amber-300"}">${esc(f.source)}</span>
        <span class="min-w-0 flex-1 truncate font-mono" title="${esc(f.file)}">${esc(f.file)}</span>
        <span class="tabular-nums text-muted">${esc(f.records)} · ${esc((f.bytes / 1024).toFixed(1))} KB</span></li>`).join("")
      || `<li class="text-muted">No input yet. Paste logs, drop files or add a single event.</li>`;
    const empty = !d.total_records;
    $("in-scan-only").disabled = empty;
    $("in-scan-merge").disabled = empty;
    $("in-scan-only").classList.toggle("opacity-50", empty);
    $("in-scan-merge").classList.toggle("opacity-50", empty);
    $("in-hint").textContent = empty ? "Add data first." : "";
  } catch (err) {
    $("in-files").innerHTML = `<li class="text-red-300">${esc(err.message)}</li>`;
  }
}

function showResult(r) {
  const a = r.accepted || {};
  $("in-result").innerHTML = `<div class="rounded-lg border border-line bg-panel2 p-3 text-sm">
    Accepted: <b>${esc(a.cloudtrail ?? 0)}</b> CloudTrail · <b>${esc(a.okta ?? 0)}</b> Okta · Rejected: <b class="${r.rejected ? "text-red-300" : ""}">${esc(r.rejected ?? 0)}</b>
    ${(r.errors || []).length ? `<ul class="mt-2 list-disc pl-5 text-xs text-red-300">${r.errors.map((e) => `<li>${esc(e)}</li>`).join("")}</ul>` : ""}</div>`;
}

async function upload(content, filename) {
  const r = await api("/inputs/upload", { method: "POST", body: { content, source: $("in-source").value, filename } });
  if (r.status === "mocked") { toast("Mock mode: upload not stored"); return; }
  showResult(r);
  toast(`Added ${(r.accepted?.cloudtrail || 0) + (r.accepted?.okta || 0)} records`);
}

async function handleFiles(files) {
  for (const f of files) {
    if (f.size > limits.max_bytes) { toast(`${f.name} is larger than ${(limits.max_bytes / 1e6).toFixed(0)} MB`, "error"); continue; }
    try { await upload(await f.text(), f.name); } catch (err) { toast(`${f.name}: ${err.message}`, "error"); }
  }
  loadList();
}
$("in-file").addEventListener("change", (e) => { handleFiles([...e.target.files]); e.target.value = ""; });
const drop = $("in-drop");
drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("border-cyan-400"); });
drop.addEventListener("dragleave", () => drop.classList.remove("border-cyan-400"));
drop.addEventListener("drop", (e) => { e.preventDefault(); drop.classList.remove("border-cyan-400"); handleFiles([...e.dataTransfer.files]); });
$("in-paste").addEventListener("click", async () => {
  const text = $("in-text").value;
  if (!text.trim()) { toast("Paste some JSON first", "error"); return; }
  if (new Blob([text]).size > limits.max_bytes) { toast("Pasted content is too large", "error"); return; }
  try { await upload(text, "paste"); $("in-text").value = ""; loadList(); }
  catch (err) { $("in-result").innerHTML = `<div class="rounded-lg border border-red-500/40 bg-red-500/10 p-3 text-sm text-red-300">${esc(err.message)}</div>`; }
});

const toLocalInput = (d) => new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 19);
const PRESETS = {
  blr: { kind: "okta_login", "f-user": "anita.rao", "f-ip": "49.207.12.8", "f-city": "Bengaluru", "f-country": "India", "f-lat": "12.97", "f-lon": "77.59", "f-label": "" },
  fra: { kind: "okta_login", "f-user": "anita.rao", "f-ip": "91.64.18.2", "f-city": "Frankfurt", "f-country": "Germany", "f-lat": "50.11", "f-lon": "8.68", "f-label": "impossible_travel", plus: 30 },
  admin: { kind: "cloudtrail_api", "f-user": "svc-report", "f-ip": "185.220.101.4", "f-event": "AttachUserPolicy", "f-source": "iam.amazonaws.com", "f-region": "ap-south-1", "f-resource": "arn:aws:iam::aws:policy/AdministratorAccess", "f-label": "privilege_escalation" },
  stoplog: { kind: "cloudtrail_api", "f-user": "dev.kumar", "f-ip": "177.71.200.9", "f-event": "StopLogging", "f-source": "cloudtrail.amazonaws.com", "f-region": "sa-east-1", "f-resource": "", "f-label": "unusual_api" },
};
$("in-presets").addEventListener("click", (e) => {
  const b = e.target.closest("[data-preset]");
  if (!b) return;
  const p = PRESETS[b.dataset.preset];
  $("f-kind").value = p.kind;
  kindChanged();
  for (const [k, v] of Object.entries(p)) if (k.startsWith("f-")) $(k).value = v;
  const base = p.plus && lastPresetTime ? new Date(lastPresetTime.getTime() + p.plus * 60000) : new Date(Date.now() - 45 * 60000);
  if (!p.plus) lastPresetTime = base;
  $("f-time").value = toLocalInput(base);
  $("f-error").textContent = "";
});

function formFields() {
  const v = (id) => $(id).value.trim();
  const fields = { user: v("f-user"), ip: v("f-ip"), label: v("f-label") };
  if (v("f-time")) fields.time = new Date(v("f-time")).toISOString().replace(".000Z", "Z");
  if ($("f-kind").value === "cloudtrail_api") {
    Object.assign(fields, { event_name: v("f-event"), event_source: v("f-source"), region: v("f-region"),
      access_key_id: v("f-key"), resource: v("f-resource") });
  } else {
    Object.assign(fields, { outcome: $("f-outcome").value, session_id: v("f-session"), city: v("f-city"),
      country: v("f-country"), lat: v("f-lat"), lon: v("f-lon") });
  }
  return Object.fromEntries(Object.entries(fields).filter(([, x]) => x !== ""));
}
$("f-submit").addEventListener("click", async () => {
  $("f-error").textContent = "";
  const btn = $("f-submit");
  btn.disabled = true;
  try {
    const r = await api("/inputs/manual", { method: "POST", body: { kind: $("f-kind").value, fields: formFields() } });
    toast(r.status === "mocked" ? "Mock mode: event not stored" : "Event added");
    if (r.record) { $("f-out").classList.remove("hidden"); $("f-out").innerHTML = highlightJson(r.record); }
    loadList();
  } catch (err) {
    $("f-error").textContent = err.message.replace(/^validation_error:\s*/, "");
  } finally {
    btn.disabled = false;
  }
});

$("in-clear").addEventListener("click", async () => {
  if (!window.confirm("Delete all input data?")) return;
  try { const r = await api("/inputs", { method: "DELETE" }); toast(`Removed ${r.removed ?? 0} file(s)`); loadList(); }
  catch (err) { toast(err.message, "error"); }
});
$("in-scan-only").addEventListener("click", () => { location.href = keepMock("scan.html?autostart=1&mode=only"); });
$("in-scan-merge").addEventListener("click", () => { location.href = keepMock("scan.html?autostart=1&mode=merge"); });

kindChanged();
loadList();
