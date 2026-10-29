// static/js/input.js — Input data entry: sample datasets, drag & drop upload, paste editor, and single events.
import { api, toast, renderLayout, keepMock } from "./v21kit.js";
import { highlightJson, escHtml as esc } from "./jsonview.js";

const root = await renderLayout(
  "input",
  "Input Data & Custom Logs",
  "Add your own logs, load curated multi-stage attack scenarios, or craft custom events, then scan them"
);

const field = (id, label, attrs = "") => `
  <label class="flex flex-col gap-1 text-xs text-muted">
    <span class="font-medium">${esc(label)}</span>
    <input id="${id}" ${attrs} class="bg-panel2 border border-line rounded-lg px-3 py-2 text-sm text-ink focus:border-brand outline-none transition-colors">
  </label>
`;

const EVENT_NAMES = [
  "ConsoleLogin", "CreateAccessKey", "AttachUserPolicy", "PutUserPolicy",
  "AssumeRole", "GetSecretValue", "StopLogging", "DeleteTrail", "ListBuckets", "CreateUser"
];

root.innerHTML = `
<!-- Top Banner: Ready-to-Use Sample Datasets & Attack Scenarios -->
<section class="bg-panel border border-line rounded-xl p-5 shadow-sm mb-6">
  <div class="flex flex-col md:flex-row md:items-center justify-between gap-3 pb-4 border-b border-line">
    <div>
      <div class="flex items-center gap-2">
        <h3 class="text-sm font-semibold text-ink">Sample Datasets for Upload & Testing</h3>
        <span class="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
          Ready to Test
        </span>
      </div>
      <p class="text-xs text-muted mt-0.5">
        Need data to test? Click <b>Quick-Load</b> to inject sample threats instantly, or <b>Download JSON</b> to test manual drag & drop uploading.
      </p>
    </div>
    <div class="text-xs text-muted font-mono hidden sm:block">
      Files also on Desktop: <code class="text-ink bg-panel2 px-1.5 py-0.5 rounded border border-line">IdentityShield_Sample_Data</code>
    </div>
  </div>

  <div id="sample-cards-grid" class="mt-4 grid grid-cols-1 md:grid-cols-3 gap-4">
    <div class="h-32 animate-pulse rounded bg-panel2"></div>
    <div class="h-32 animate-pulse rounded bg-panel2"></div>
    <div class="h-32 animate-pulse rounded bg-panel2"></div>
  </div>
</section>

<!-- Main Workspace: Data Entry (Left) & Current Data Inbox (Right) -->
<div class="grid gap-6 lg:grid-cols-12">
  <!-- Left Column: Paste / Upload / Single Event -->
  <section class="lg:col-span-8 bg-panel border border-line rounded-xl p-5 shadow-sm">
    <div class="flex gap-2 border-b border-line pb-3" role="tablist">
      <button id="tab-paste" class="in-tab rounded-lg px-3.5 py-1.5 text-xs font-semibold bg-panel2 text-ink border border-line" data-tab="paste">
        📁 Upload or Paste Logs
      </button>
      <button id="tab-form" class="in-tab rounded-lg px-3.5 py-1.5 text-xs font-semibold hover:bg-panel2 text-muted border border-transparent" data-tab="form">
        ⚡ Craft Single Event
      </button>
    </div>

    <!-- Panel 1: Paste or File Upload -->
    <div id="panel-paste" class="mt-4">
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <label class="flex items-center gap-2 text-xs text-muted font-medium">
          <span>Target Source:</span>
          <select id="in-source" class="bg-panel2 border border-line rounded-lg px-2.5 py-1.5 text-xs text-ink focus:border-brand outline-none">
            <option value="auto">Auto-detect (Recommended)</option>
            <option value="cloudtrail">AWS CloudTrail Log</option>
            <option value="okta">Okta System Log</option>
          </select>
        </label>

        <div class="flex items-center gap-2">
          <span class="text-[11px] text-muted">Insert template:</span>
          <button id="btn-tpl-attack" class="px-2 py-1 rounded bg-panel2 hover:bg-line border border-line text-[11px] text-cyan-300 transition-colors">
            Attack Pair
          </button>
          <button id="btn-tpl-ct" class="px-2 py-1 rounded bg-panel2 hover:bg-line border border-line text-[11px] text-amber-300 transition-colors">
            CloudTrail
          </button>
          <button id="btn-tpl-okta" class="px-2 py-1 rounded bg-panel2 hover:bg-line border border-line text-[11px] text-emerald-300 transition-colors">
            Okta
          </button>
        </div>
      </div>

      <!-- Drag and Drop Box -->
      <label
        id="in-drop"
        class="mt-4 flex cursor-pointer flex-col items-center justify-center gap-2 rounded-xl border-2 border-dashed border-line p-6 text-center hover:border-brand/60 transition-colors bg-panel2/30"
      >
        <span class="text-3xl text-brand">⇪</span>
        <div>
          <span class="text-xs font-semibold text-ink">Drop log files here or click to browse</span>
          <span class="block text-[11px] text-muted mt-0.5">Supports <b>.json</b>, <b>.jsonl</b>, <b>.csv</b>, and <b>.txt</b></span>
        </div>
        <span class="text-[10px] text-muted font-mono" id="in-limit">Up to 5 MB per upload</span>
        <input id="in-file" type="file" accept=".json,.jsonl,.txt,.csv" multiple class="hidden">
      </label>

      <!-- Paste Text Area -->
      <div class="mt-4">
        <div class="flex items-center justify-between mb-1.5">
          <span class="text-xs text-muted font-medium">Or paste JSON / JSONL / CSV records directly:</span>
          <button id="btn-clear-text" class="text-[11px] text-muted hover:text-ink hover:underline">Clear text</button>
        </div>
        <textarea
          id="in-text"
          spellcheck="false"
          class="h-52 w-full rounded-lg border border-line p-3 font-mono text-xs text-ink focus:border-brand outline-none leading-relaxed transition-colors"
          style="background:#05070C"
          placeholder='{"Records": [{"eventID": "1", "eventTime": "2026-10-28T04:00:00Z", "eventName": "AttachUserPolicy", "eventSource": "iam.amazonaws.com", "sourceIPAddress": "185.220.101.4", "userIdentity": {"userName": "svc-report"}}]}'
        ></textarea>
      </div>

      <div class="mt-3 flex items-center justify-between">
        <button
          id="in-paste"
          class="bg-brand hover:bg-blue-500 text-white rounded-lg px-4 py-2 text-xs font-semibold shadow-sm transition-colors flex items-center gap-2"
        >
          <span>📥</span>
          <span>Add pasted records to inbox</span>
        </button>
      </div>

      <div id="in-result" class="mt-4"></div>
    </div>

    <!-- Panel 2: Single Event Form -->
    <div id="panel-form" class="mt-4 hidden">
      <div class="p-3 rounded-lg bg-panel2/60 border border-line mb-4">
        <span class="block text-xs font-semibold text-ink mb-1.5">Quick Attack Presets:</span>
        <div class="flex flex-wrap gap-2" id="in-presets">
          <button data-preset="blr" class="border border-line hover:bg-panel2 rounded-lg px-2.5 py-1 text-xs text-ink font-mono transition-colors">
            1. Anita Rao (Login · Bengaluru)
          </button>
          <button data-preset="fra" class="border border-line hover:bg-panel2 rounded-lg px-2.5 py-1 text-xs text-amber-300 font-mono transition-colors">
            2. Anita Rao (Login · Frankfurt +30 min)
          </button>
          <button data-preset="admin" class="border border-line hover:bg-panel2 rounded-lg px-2.5 py-1 text-xs text-red-300 font-mono transition-colors">
            3. svc-report (Attach AdministratorAccess)
          </button>
          <button data-preset="stoplog" class="border border-line hover:bg-panel2 rounded-lg px-2.5 py-1 text-xs text-cyan-300 font-mono transition-colors">
            4. dev.kumar (Stop CloudTrail Logging)
          </button>
        </div>
      </div>

      <label class="flex items-center gap-2 text-xs text-muted font-medium mb-3">
        <span>Event Type:</span>
        <select id="f-kind" class="bg-panel2 border border-line rounded-lg px-2.5 py-1.5 text-xs text-ink">
          <option value="okta_login">Okta Authentication (user.session.start)</option>
          <option value="okta_logout">Okta Sign-out (user.session.end)</option>
          <option value="cloudtrail_api">AWS CloudTrail API Call</option>
        </select>
      </label>

      <div class="grid gap-3 sm:grid-cols-2">
        ${field("f-user", "User / Identity *", 'placeholder="anita.rao or svc-report"')}
        ${field("f-ip", "Source IP Address *", 'placeholder="49.207.12.8"')}
        ${field("f-time", "Timestamp (empty = current time)", 'type="datetime-local" step="1"')}
        ${field("f-label", "Attack Label (optional)", 'placeholder="impossible_travel"')}
      </div>

      <div id="f-okta" class="mt-3 grid gap-3 sm:grid-cols-2">
        <label class="flex flex-col gap-1 text-xs text-muted">
          <span class="font-medium">Authentication Outcome</span>
          <select id="f-outcome" class="bg-panel2 border border-line rounded-lg px-3 py-2 text-sm text-ink">
            <option>SUCCESS</option>
            <option>FAILURE</option>
          </select>
        </label>
        ${field("f-session", "External Session ID (optional)")}
        ${field("f-city", "City (e.g. Frankfurt or Bengaluru)")}
        ${field("f-country", "Country (e.g. Germany or India)")}
        ${field("f-lat", "Latitude (e.g. 50.11)", 'inputmode="decimal"')}
        ${field("f-lon", "Longitude (e.g. 8.68)", 'inputmode="decimal"')}
      </div>

      <div id="f-aws" class="mt-3 hidden grid gap-3 sm:grid-cols-2">
        ${field("f-event", "API Event Name *", 'list="f-events" placeholder="AttachUserPolicy"')}
        <datalist id="f-events">${EVENT_NAMES.map((n) => `<option value="${n}">`).join("")}</datalist>
        ${field("f-source", "AWS Service", 'placeholder="iam.amazonaws.com"')}
        ${field("f-region", "AWS Region", 'placeholder="ap-south-1"')}
        ${field("f-key", "Access Key ID (optional)")}
        ${field("f-resource", "Resource ARN (optional)", 'placeholder="arn:aws:iam::aws:policy/AdministratorAccess"')}
      </div>

      <div id="f-error" class="mt-3 text-xs text-red-300"></div>

      <button id="f-submit" class="mt-4 bg-brand hover:bg-blue-500 text-white rounded-lg px-4 py-2 text-xs font-semibold shadow-sm transition-colors">
        ⚡ Add Single Event to Inbox
      </button>

      <pre id="f-out" class="mt-4 hidden max-h-60 overflow-auto rounded-lg border border-line p-3 font-mono text-[11px] leading-5 whitespace-pre-wrap" style="background:#05070C"></pre>
    </div>
  </section>

  <!-- Right Column: Current Input Data & Scan Launcher -->
  <div class="lg:col-span-4 flex flex-col gap-6">
    <!-- Current Inbox Status -->
    <section class="bg-panel border border-line rounded-xl p-5 shadow-sm">
      <div class="flex items-center justify-between pb-3 border-b border-line">
        <h3 class="text-sm font-semibold text-ink">Current Input Data Inbox</h3>
        <button id="in-clear" class="rounded-lg bg-red-600/20 hover:bg-red-600/30 text-red-300 border border-red-500/30 px-2.5 py-1 text-xs font-medium transition-colors">
          Clear all
        </button>
      </div>

      <div id="in-totals" class="mt-4 grid grid-cols-3 gap-2"></div>
      <ul id="in-files" class="mt-4 flex flex-col gap-2 text-xs"></ul>
    </section>

    <!-- Scan Launcher -->
    <section class="bg-panel border border-line rounded-xl p-5 shadow-sm">
      <div class="flex items-center justify-between pb-2 border-b border-line">
        <h3 class="text-sm font-semibold text-ink">Launch Agent Scan</h3>
        <span class="text-[10px] text-muted uppercase font-mono">15 Agents</span>
      </div>

      <p class="text-xs text-muted mt-3 leading-relaxed">
        Execute detection pipeline against your loaded records.
      </p>

      <div class="mt-4 flex flex-col gap-2.5">
        <button
          id="in-scan-only"
          class="bg-brand hover:bg-blue-500 text-white rounded-lg px-3.5 py-2.5 text-xs font-semibold shadow-sm transition-colors flex items-center justify-center gap-2"
        >
          <span>🚀</span>
          <span>Scan input data only</span>
        </button>

        <button
          id="in-scan-merge"
          class="border border-line hover:bg-panel2 rounded-lg px-3.5 py-2.5 text-xs font-medium text-ink transition-colors flex items-center justify-center gap-2"
        >
          <span>🔄</span>
          <span>Scan dataset + input merged</span>
        </button>
      </div>

      <p id="in-hint" class="mt-2.5 text-xs text-amber-300 font-medium"></p>
      <p class="mt-2 text-[11px] text-muted leading-snug">
        <b>Tip:</b> "Input data only" runs multi-agent detection strictly against your uploaded files. Detectors like ML baseline or dormant accounts that require historical depth can also be merged with the baseline.
      </p>
    </section>
  </div>
</div>
`;

const $ = (id) => document.getElementById(id);
let limits = { max_bytes: 5_000_000, max_records: 50_000 };
let lastPresetTime = null;

// Tab switcher
function tab(name) {
  for (const t of ["paste", "form"]) {
    $(`panel-${t}`).classList.toggle("hidden", t !== name);
    $(`tab-${t}`).className = `in-tab rounded-lg px-3.5 py-1.5 text-xs font-semibold ${
      t === name ? "bg-panel2 text-ink border border-line" : "text-muted hover:bg-panel2 border border-transparent"
    }`;
  }
}
document.querySelectorAll(".in-tab").forEach((b) => b.addEventListener("click", () => tab(b.dataset.tab)));

function kindChanged() {
  const aws = $("f-kind").value === "cloudtrail_api";
  $("f-okta").classList.toggle("hidden", aws);
  $("f-aws").classList.toggle("hidden", !aws);
}
$("f-kind").addEventListener("change", kindChanged);

// 1. Load and Render Sample Dataset Cards
async function loadSamplesList() {
  const grid = $("sample-cards-grid");
  try {
    const res = await api("/inputs/samples");
    const samples = res.samples || [];
    if (!samples.length) {
      grid.innerHTML = `<div class="col-span-full text-xs text-muted">No sample datasets found.</div>`;
      return;
    }

    grid.innerHTML = samples
      .map((s) => `
        <div class="p-3.5 rounded-xl bg-panel2/60 border border-line hover:border-brand/40 transition-colors flex flex-col justify-between shadow-sm">
          <div>
            <div class="flex items-center justify-between gap-2 mb-1.5">
              <span class="text-xs font-bold text-ink truncate">${esc(s.name)}</span>
              <span class="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-brand/15 text-brand border border-brand/30">
                ${esc(s.records)} records
              </span>
            </div>
            <p class="text-[11px] text-muted leading-snug">${esc(s.description)}</p>
          </div>

          <div class="mt-3 pt-2.5 border-t border-line/60 flex items-center justify-between gap-2">
            <button
              class="btn-quick-load px-2.5 py-1.5 rounded-lg bg-emerald-500/15 hover:bg-emerald-500/25 text-emerald-300 border border-emerald-500/30 text-[11px] font-semibold transition-colors flex items-center gap-1"
              data-sample="${esc(s.id)}"
            >
              <span>⚡</span>
              <span>Quick-Load</span>
            </button>

            <div class="flex items-center gap-1.5">
              <button
                class="btn-view-sample px-2 py-1 rounded bg-panel hover:bg-panel2 text-[11px] text-cyan-300 font-mono transition-colors"
                data-sample="${esc(s.id)}"
                title="Paste this sample into the editor"
              >
                📋 View
              </button>
              <a
                href="${esc(s.url)}"
                download="${esc(s.filename)}"
                class="px-2 py-1 rounded bg-panel hover:bg-panel2 text-[11px] text-muted hover:text-ink font-mono transition-colors"
                title="Download JSON file for manual upload"
              >
                ⬇ JSON
              </a>
            </div>
          </div>
        </div>
      `)
      .join("");

    // Wire up Quick-Load buttons
    grid.querySelectorAll(".btn-quick-load").forEach((b) => {
      b.addEventListener("click", async () => {
        const id = b.dataset.sample;
        b.disabled = true;
        const originalText = b.innerHTML;
        b.innerHTML = `<span class="animate-spin inline-block">⌛</span> <span>Loading...</span>`;
        try {
          const r = await api("/inputs/load-sample", { method: "POST", body: { sample: id } });
          showResult(r);
          toast(`Loaded ${(r.accepted?.cloudtrail || 0) + (r.accepted?.okta || 0)} sample records`);
          loadList();
        } catch (err) {
          toast(err.message, "error");
        } finally {
          b.disabled = false;
          b.innerHTML = originalText;
        }
      });
    });

    // Wire up View in Paste area buttons
    grid.querySelectorAll(".btn-view-sample").forEach((b) => {
      b.addEventListener("click", async () => {
        const id = b.dataset.sample;
        const s = samples.find((x) => x.id === id);
        if (!s) return;
        try {
          const resp = await fetch(s.url);
          const data = await resp.json();
          $("in-text").value = JSON.stringify(data, null, 2);
          tab("paste");
          toast(`Loaded ${s.name} into editor`);
          $("in-text").focus();
        } catch (err) {
          toast(`Could not load preview: ${err.message}`, "error");
        }
      });
    });
  } catch (err) {
    grid.innerHTML = `<div class="col-span-full text-xs text-red-300">${esc(err.message)}</div>`;
  }
}

// 2. Load and Render Input Records Inbox Status
async function loadList() {
  try {
    const d = await api("/inputs");
    limits = d.limits || limits;
    $("in-limit").textContent = `Up to ${(limits.max_bytes / 1e6).toFixed(0)} MB and ${limits.max_records.toLocaleString()} records per upload`;
    const t = d.totals || {};
    const stat = (label, v) => `
      <div class="rounded-lg border border-line bg-panel2 p-2.5 text-center">
        <div class="text-[10px] uppercase tracking-wide text-muted font-medium">${esc(label)}</div>
        <div class="text-base font-bold tabular-nums text-ink mt-0.5">${esc(v ?? 0)}</div>
      </div>
    `;
    $("in-totals").innerHTML = stat("CloudTrail", t.cloudtrail) + stat("Okta", t.okta) + stat("Total", d.total_records);

    $("in-files").innerHTML =
      (d.files || [])
        .map(
          (f) => `
        <li class="flex items-center justify-between gap-2 rounded-lg border border-line bg-panel2 px-2.5 py-2">
          <div class="flex items-center gap-2 min-w-0">
            <span class="rounded px-1.5 py-0.5 text-[10px] font-bold uppercase font-mono ${
              f.source === "okta" ? "bg-violet-500/20 text-violet-300 border border-violet-500/30" : "bg-amber-500/20 text-amber-300 border border-amber-500/30"
            }">
              ${esc(f.source)}
            </span>
            <span class="truncate font-mono text-xs text-ink" title="${esc(f.file)}">${esc(f.file)}</span>
          </div>
          <span class="tabular-nums text-muted text-[11px] font-mono flex-shrink-0">
            ${esc(f.records)} rec · ${(f.bytes / 1024).toFixed(1)} KB
          </span>
        </li>
      `
        )
        .join("") ||
      `<li class="text-muted text-xs py-3 text-center">No input data loaded. Click Quick-Load above, paste JSON, or drop files here.</li>`;

    const empty = !d.total_records;
    $("in-scan-only").disabled = empty;
    $("in-scan-merge").disabled = empty;
    $("in-scan-only").classList.toggle("opacity-50", empty);
    $("in-scan-merge").classList.toggle("opacity-50", empty);
    $("in-hint").textContent = empty ? "Load sample data or upload logs above to enable scanning." : "";
  } catch (err) {
    $("in-files").innerHTML = `<li class="text-red-300 text-xs">${esc(err.message)}</li>`;
  }
}

// 3. Show Upload / Paste Results
function showResult(r) {
  const a = r.accepted || {};
  const totalAcc = (a.cloudtrail ?? 0) + (a.okta ?? 0);
  $("in-result").innerHTML = `
    <div class="rounded-xl border border-line bg-panel2 p-3.5 text-xs shadow-sm">
      <div class="flex items-center gap-2 font-medium">
        <span class="text-emerald-400 font-bold">✓ Processed:</span>
        <span class="text-ink">Accepted: <b>${esc(a.cloudtrail ?? 0)}</b> CloudTrail · <b>${esc(a.okta ?? 0)}</b> Okta</span>
        <span class="text-muted">|</span>
        <span class="${r.rejected ? "text-red-300 font-bold" : "text-muted"}">Rejected: ${esc(r.rejected ?? 0)}</span>
      </div>
      ${
        (r.errors || []).length
          ? `<ul class="mt-2 list-disc pl-5 text-[11px] text-red-300 leading-snug">${r.errors.map((e) => `<li>${esc(e)}</li>`).join("")}</ul>`
          : ""
      }
    </div>
  `;
}

// 4. File Upload Handler
async function upload(content, filename) {
  const r = await api("/inputs/upload", {
    method: "POST",
    body: { content, source: $("in-source").value, filename },
  });
  if (r.status === "mocked") {
    toast("Mock mode: upload processed");
    return;
  }
  showResult(r);
  toast(`Added ${(r.accepted?.cloudtrail || 0) + (r.accepted?.okta || 0)} records`);
}

async function handleFiles(files) {
  for (const f of files) {
    if (f.size > limits.max_bytes) {
      toast(`${f.name} is larger than ${(limits.max_bytes / 1e6).toFixed(0)} MB`, "error");
      continue;
    }
    try {
      await upload(await f.text(), f.name);
    } catch (err) {
      toast(`${f.name}: ${err.message}`, "error");
    }
  }
  loadList();
}

$("in-file").addEventListener("change", (e) => {
  handleFiles([...e.target.files]);
  e.target.value = "";
});

const drop = $("in-drop");
drop.addEventListener("dragover", (e) => {
  e.preventDefault();
  drop.classList.add("border-brand");
});
drop.addEventListener("dragleave", () => drop.classList.remove("border-brand"));
drop.addEventListener("drop", (e) => {
  e.preventDefault();
  drop.classList.remove("border-brand");
  handleFiles([...e.dataTransfer.files]);
});

// 5. Paste Button Handler
$("in-paste").addEventListener("click", async () => {
  const text = $("in-text").value;
  if (!text.trim()) {
    toast("Paste some JSON or CSV records first", "error");
    return;
  }
  if (new Blob([text]).size > limits.max_bytes) {
    toast("Pasted content is too large", "error");
    return;
  }
  try {
    await upload(text, "pasted_records");
    $("in-text").value = "";
    loadList();
  } catch (err) {
    $("in-result").innerHTML = `<div class="rounded-xl border border-red-500/40 bg-red-500/10 p-3 text-xs text-red-300">${esc(err.message)}</div>`;
  }
});

$("btn-clear-text").addEventListener("click", () => {
  $("in-text").value = "";
});

// Quick Template Inserters
$("btn-tpl-attack").addEventListener("click", async () => {
  try {
    const resp = await fetch("/api/inputs/samples/sample_attack_scenario.json");
    const data = await resp.json();
    $("in-text").value = JSON.stringify(data.slice(0, 4), null, 2);
    toast("Inserted sample attack pair");
  } catch (err) {
    toast("Could not insert template", "error");
  }
});

$("btn-tpl-ct").addEventListener("click", () => {
  $("in-text").value = JSON.stringify({
    Records: [
      {
        eventID: "ct-sample-1",
        eventTime: new Date().toISOString(),
        eventName: "AttachUserPolicy",
        eventSource: "iam.amazonaws.com",
        awsRegion: "ap-south-1",
        sourceIPAddress: "185.220.101.4",
        userIdentity: { userName: "svc-report" },
        requestParameters: { policyArn: "arn:aws:iam::aws:policy/AdministratorAccess" }
      }
    ]
  }, null, 2);
  toast("Inserted CloudTrail template");
});

$("btn-tpl-okta").addEventListener("click", () => {
  $("in-text").value = JSON.stringify([
    {
      uuid: "okta-sample-1",
      published: new Date().toISOString(),
      eventType: "user.session.start",
      actor: { alternateId: "anita.rao@corp.example" },
      outcome: { result: "SUCCESS" },
      client: {
        ipAddress: "91.64.18.2",
        geographicalContext: { country: "Germany", city: "Frankfurt", geolocation: { lat: 50.11, lon: 8.68 } }
      }
    }
  ], null, 2);
  toast("Inserted Okta template");
});

// 6. Single Event Form & Presets
const toLocalInput = (d) => new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 19);

const PRESETS = {
  blr: {
    kind: "okta_login",
    "f-user": "anita.rao",
    "f-ip": "49.207.12.8",
    "f-city": "Bengaluru",
    "f-country": "India",
    "f-lat": "12.97",
    "f-lon": "77.59",
    "f-label": ""
  },
  fra: {
    kind: "okta_login",
    "f-user": "anita.rao",
    "f-ip": "91.64.18.2",
    "f-city": "Frankfurt",
    "f-country": "Germany",
    "f-lat": "50.11",
    "f-lon": "8.68",
    "f-label": "impossible_travel",
    plus: 30
  },
  admin: {
    kind: "cloudtrail_api",
    "f-user": "svc-report",
    "f-ip": "185.220.101.4",
    "f-event": "AttachUserPolicy",
    "f-source": "iam.amazonaws.com",
    "f-region": "ap-south-1",
    "f-resource": "arn:aws:iam::aws:policy/AdministratorAccess",
    "f-label": "privilege_escalation"
  },
  stoplog: {
    kind: "cloudtrail_api",
    "f-user": "dev.kumar",
    "f-ip": "177.71.200.9",
    "f-event": "StopLogging",
    "f-source": "cloudtrail.amazonaws.com",
    "f-region": "sa-east-1",
    "f-resource": "",
    "f-label": "unusual_api"
  },
};

$("in-presets").addEventListener("click", (e) => {
  const b = e.target.closest("[data-preset]");
  if (!b) return;
  const p = PRESETS[b.dataset.preset];
  $("f-kind").value = p.kind;
  kindChanged();
  for (const [k, v] of Object.entries(p)) {
    if (k.startsWith("f-") && $(k)) $(k).value = v;
  }
  const base = p.plus && lastPresetTime ? new Date(lastPresetTime.getTime() + p.plus * 60000) : new Date(Date.now() - 45 * 60000);
  if (!p.plus) lastPresetTime = base;
  $("f-time").value = toLocalInput(base);
  $("f-error").textContent = "";
  toast(`Selected preset: ${b.textContent.trim()}`);
});

function formFields() {
  const v = (id) => $(id).value.trim();
  const fields = { user: v("f-user"), ip: v("f-ip"), label: v("f-label") };
  if (v("f-time")) fields.time = new Date(v("f-time")).toISOString().replace(".000Z", "Z");
  if ($("f-kind").value === "cloudtrail_api") {
    Object.assign(fields, {
      event_name: v("f-event"),
      event_source: v("f-source"),
      region: v("f-region"),
      access_key_id: v("f-key"),
      resource: v("f-resource"),
    });
  } else {
    Object.assign(fields, {
      outcome: $("f-outcome").value,
      session_id: v("f-session"),
      city: v("f-city"),
      country: v("f-country"),
      lat: v("f-lat"),
      lon: v("f-lon"),
    });
  }
  return Object.fromEntries(Object.entries(fields).filter(([, x]) => x !== ""));
}

$("f-submit").addEventListener("click", async () => {
  $("f-error").textContent = "";
  const btn = $("f-submit");
  btn.disabled = true;
  try {
    const r = await api("/inputs/manual", { method: "POST", body: { kind: $("f-kind").value, fields: formFields() } });
    toast(r.status === "mocked" ? "Mock mode: event recorded" : "Single event added to inbox");
    if (r.record) {
      $("f-out").classList.remove("hidden");
      $("f-out").innerHTML = highlightJson(r.record);
    }
    loadList();
  } catch (err) {
    $("f-error").textContent = err.message.replace(/^validation_error:\s*/, "");
  } finally {
    btn.disabled = false;
  }
});

// Clear All Input Data
$("in-clear").addEventListener("click", async () => {
  if (!window.confirm("Clear all input records from the inbox?")) return;
  try {
    const r = await api("/inputs", { method: "DELETE" });
    toast(`Removed ${r.removed ?? 0} file(s)`);
    $("in-result").innerHTML = "";
    loadList();
  } catch (err) {
    toast(err.message, "error");
  }
});

// Scan Navigation
$("in-scan-only").addEventListener("click", () => {
  location.href = keepMock("scan.html?autostart=1&mode=only");
});

$("in-scan-merge").addEventListener("click", () => {
  location.href = keepMock("scan.html?autostart=1&mode=merge");
});

// Initialize
kindChanged();
loadSamplesList();
loadList();
