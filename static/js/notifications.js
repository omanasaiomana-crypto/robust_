// static/js/notifications.js — admin email alerts: status, test email, reports download, agent attribution, heatmap & history.
import { api, toast, renderLayout, keepMock } from "./v21kit.js";
import { escHtml as esc } from "./jsonview.js";

const root = await renderLayout(
  "notifications",
  "Notifications & Threat Reports",
  "Security alerts, executive incident reports, multi-agent detection attribution & threat heatmaps"
);

root.innerHTML = `
<!-- Top Grid: Email Alert Status & Executive Report Downloads -->
<div class="grid grid-cols-1 lg:grid-cols-12 gap-6">
  <!-- Alert Engine Status -->
  <section id="nt-status" class="lg:col-span-7 bg-panel border border-line rounded-xl p-5 shadow-sm">
    <div class="h-28 animate-pulse rounded bg-panel2"></div>
  </section>

  <!-- Executive Attack Reports Download Card -->
  <section class="lg:col-span-5 bg-panel border border-line rounded-xl p-5 shadow-sm flex flex-col justify-between">
    <div>
      <div class="flex items-center justify-between gap-2">
        <div class="flex items-center gap-2">
          <div class="w-8 h-8 rounded-lg bg-emerald-500/15 border border-emerald-500/30 flex items-center justify-center text-emerald-400 font-bold text-sm">
            📄
          </div>
          <div>
            <h3 class="text-sm font-semibold text-ink">Executive Attack Reports</h3>
            <p class="text-[11px] text-muted">Complete threat forensics with matrix heatmaps</p>
          </div>
        </div>
        <span class="px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase tracking-wider bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
          Ready
        </span>
      </div>

      <p class="text-xs text-muted mt-3 leading-relaxed">
        Export the executive-ready investigation summary detailing all 5 multi-stage attack chains, MITRE tactics, agent evidence, and identity heatmaps.
      </p>

      <div class="mt-3 grid grid-cols-2 gap-2 text-[11px] text-muted font-mono">
        <div class="flex items-center gap-1.5"><span class="text-emerald-400 font-bold">✓</span> 5 Attack Chains</div>
        <div class="flex items-center gap-1.5"><span class="text-emerald-400 font-bold">✓</span> Threat Heatmaps</div>
        <div class="flex items-center gap-1.5"><span class="text-emerald-400 font-bold">✓</span> MITRE T1078/T1098</div>
        <div class="flex items-center gap-1.5"><span class="text-emerald-400 font-bold">✓</span> Cryptographic Audit</div>
      </div>
    </div>

    <div class="mt-5 pt-4 border-t border-line flex flex-col sm:flex-row items-center gap-3">
      <a
        href="/api/reports/download/docx"
        download="IdentityShield_Attack_Summary_With_Heatmaps.docx"
        class="w-full sm:w-auto flex-1 inline-flex items-center justify-center gap-2 px-3.5 py-2.5 rounded-lg bg-emerald-500/15 hover:bg-emerald-500/25 text-emerald-300 border border-emerald-500/30 font-medium text-xs transition-colors shadow-sm"
        title="Download Word Report (.docx)"
      >
        <span>📄 Download Word (.docx)</span>
        <span class="text-[10px] opacity-75 font-mono">~40 KB</span>
      </a>

      <a
        href="/api/reports/download/html"
        download="IdentityShield_Attack_Summary_With_Heatmaps.html"
        class="w-full sm:w-auto flex-1 inline-flex items-center justify-center gap-2 px-3.5 py-2.5 rounded-lg bg-cyan-400/15 hover:bg-cyan-400/25 text-cyan-300 border border-cyan-400/30 font-medium text-xs transition-colors shadow-sm"
        title="Download Interactive HTML Report (.html)"
      >
        <span>🌐 Interactive HTML (.html)</span>
        <span class="text-[10px] opacity-75 font-mono">~9 KB</span>
      </a>
    </div>
  </section>
</div>

<!-- Section: Which Agents Caught What (Agent Detection Attribution) -->
<section class="mt-6 bg-panel border border-line rounded-xl p-5 shadow-sm min-w-0">
  <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-4 border-b border-line">
    <div>
      <div class="flex items-center gap-2">
        <h3 class="text-sm font-semibold text-ink">Agent Detection Attribution — Which Agents Caught What</h3>
        <span class="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-brand/15 text-brand border border-brand/30">
          6 Active Agents
        </span>
      </div>
      <p class="text-xs text-muted mt-0.5">
        Multi-agent detection nodes showing exactly which agent intercepted each attack pattern, victim identity, and MITRE technique
      </p>
    </div>
    <a
      href="${keepMock('/agents.html')}"
      class="text-xs text-brand hover:underline font-medium inline-flex items-center gap-1 self-start sm:self-auto"
    >
      <span>Inspect All Agents</span>
      <span>→</span>
    </a>
  </div>

  <div id="nt-agent-attribution" class="mt-4 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
    <div class="h-28 animate-pulse rounded bg-panel2"></div>
    <div class="h-28 animate-pulse rounded bg-panel2"></div>
    <div class="h-28 animate-pulse rounded bg-panel2"></div>
  </div>
</section>

<!-- Section: Identity x Attack Pattern Heatmap Matrix -->
<section class="mt-6 bg-panel border border-line rounded-xl p-5 shadow-sm min-w-0">
  <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-line">
    <div>
      <div class="flex items-center gap-2">
        <h3 class="text-sm font-semibold text-ink">Identity Threat Heatmap Matrix</h3>
        <span class="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-crit/15 text-crit border border-crit/30">
          Live Threat Correlation
        </span>
      </div>
      <p class="text-xs text-muted mt-0.5">
        Multi-dimensional correlation mapping compromised identities against intercepted MITRE ATT&CK patterns
      </p>
    </div>

    <!-- Heatmap Legend -->
    <div class="flex items-center gap-2 text-[11px] font-mono flex-wrap">
      <span class="text-muted text-[10px] uppercase font-semibold">Intensity:</span>
      <span class="px-2 py-0.5 rounded bg-panel2 text-muted/60 border border-line">0 None</span>
      <span class="px-2 py-0.5 rounded bg-amber-400/20 text-amber-200 border border-amber-400/40">1 Low</span>
      <span class="px-2 py-0.5 rounded bg-orange-500/30 text-orange-200 border border-orange-500/40">2 Med</span>
      <span class="px-2 py-0.5 rounded bg-red-500/35 text-red-200 font-bold border border-red-500/50">≥3 Crit</span>
    </div>
  </div>

  <div id="nt-heatmap" class="mt-4 overflow-x-auto">
    <div class="h-32 animate-pulse rounded bg-panel2"></div>
  </div>
</section>

<!-- Section: Email Alert Outbox & History -->
<section class="mt-6 bg-panel border border-line rounded-xl p-5 shadow-sm min-w-0">
  <div class="flex items-center justify-between gap-2 pb-3 border-b border-line">
    <div>
      <h3 class="text-sm font-semibold text-ink">Alert Email History & Outbox</h3>
      <p class="text-xs text-muted mt-0.5">Automated security digests dispatched to administrators when high-risk thresholds are reached</p>
    </div>
  </div>
  <div id="nt-list" class="mt-4 overflow-x-auto">
    <div class="h-24 animate-pulse rounded bg-panel2"></div>
  </div>
</section>
`;

const $ = (id) => document.getElementById(id);
const MODE = {
  outbox: ["Outbox (demo)", "bg-cyan-400/15 text-cyan-300 border border-cyan-400/30"],
  smtp: ["SMTP", "bg-emerald-500/15 text-emerald-300 border border-emerald-500/30"],
  off: ["Off", "bg-panel2 text-muted border border-line"],
};
const STATUS = {
  sent: "bg-emerald-500/15 text-emerald-300",
  outbox: "bg-cyan-400/15 text-cyan-300",
  failed: "bg-red-500/15 text-red-300",
  rate_limited: "bg-amber-500/15 text-amber-300",
};

let open = null;
let rows = [];

// 1. Alert Status Loader
async function loadStatus() {
  try {
    const s = await api("/notifications/status");
    const [label, cls] = MODE[s.mode] || MODE.off;
    const dt = (k, v) => `<div><dt class="text-[10px] uppercase tracking-wide text-muted font-medium">${esc(k)}</dt><dd class="mt-0.5 text-sm font-semibold text-ink">${v}</dd></div>`;
    $("nt-status").innerHTML = `
      <div class="flex flex-col gap-4 lg:flex-row lg:items-start justify-between">
        <div class="flex-1">
          <div class="flex items-center gap-2">
            <span class="rounded-full px-2.5 py-0.5 text-xs font-medium ${cls}">${esc(label)}</span>
            <span class="text-xs text-muted">Admin Incident Alert Dispatcher</span>
          </div>
          <dl class="mt-4 grid gap-4 sm:grid-cols-4">
            ${dt("Recipients", s.recipients && s.recipients.length ? `<span class="font-mono text-xs text-cyan-300">${esc(s.recipients.join(", "))}</span>` : '<span class="text-amber-300 text-xs">No recipients configured</span>')}
            ${dt("SMTP Server", `<span class="font-mono text-xs">${esc(s.smtp_host || "—")}</span>`)}
            ${dt("Threshold", `<span class="text-xs font-mono text-amber-300">Risk ≥ ${esc(s.min_risk)}</span>`)}
            ${dt("Sent this hour", `<span class="font-mono text-xs">${esc(s.sent_last_hour)} / ${esc(s.max_per_hour)}</span>`)}
          </dl>
        </div>
        <button
          id="nt-test"
          class="bg-brand hover:bg-blue-500 text-white rounded-lg px-4 py-2 text-xs font-semibold shadow-sm transition-colors flex items-center gap-2 flex-shrink-0"
        >
          <span>✉</span>
          <span>Send test email</span>
        </button>
      </div>
      <p class="mt-4 text-xs text-muted border-t border-line pt-3">
        Configured in <code class="text-ink font-mono">.env</code>. Outbox mode works offline without external credentials; notification digests are stored and previewable below.
      </p>
    `;
    $("nt-test").onclick = sendTest;
  } catch (err) {
    $("nt-status").innerHTML = `<div class="text-sm text-red-300">${esc(err.message)}</div>`;
  }
}

// 2. Send Test Email
async function sendTest() {
  const b = $("nt-test");
  if (!b) return;
  b.disabled = true;
  b.innerHTML = `<span class="animate-spin inline-block">⌛</span> <span>Sending...</span>`;
  try {
    const r = await api("/notifications/test", { method: "POST" });
    const msg = {
      sent: ["Test email sent via SMTP", "success"],
      outbox: ["Saved to outbox (demo mode)", "success"],
      mocked: ["Mock mode: nothing sent", "success"],
      off: ["Email is turned off (EMAIL_MODE=off)", "error"],
    }[r.status] || [`${r.status}: ${r.detail || ""}`, "error"];
    toast(msg[0], msg[1]);
  } catch (err) {
    toast(err.message, "error");
  } finally {
    b.disabled = false;
    b.innerHTML = `<span>✉</span> <span>Send test email</span>`;
    loadStatus();
    loadList();
  }
}

// 3. Render Agent Attribution ("Which Agents Caught What")
async function loadAgentAttribution() {
  const target = $("nt-agent-attribution");
  if (!target) return;
  try {
    const res = await api("/analytics/agent-map");
    const agents = res.agents || [];
    if (!agents.length) {
      target.innerHTML = `<div class="col-span-full py-4 text-sm text-muted">No agent detections recorded.</div>`;
      return;
    }

    target.innerHTML = agents
      .map((ag) => {
        const victimTags = (ag.victims || [])
          .map(
            (v) =>
              `<a href="${keepMock(`/identities.html?search=${encodeURIComponent(v)}`)}" class="px-1.5 py-0.5 rounded bg-panel font-mono text-[11px] text-brand hover:underline">${esc(v)}</a>`
          )
          .join(" ");
        const mitreTags = (ag.mitre || [])
          .map(
            (m) =>
              `<span class="px-1.5 py-0.5 rounded bg-panel2 font-mono text-[10px] text-muted border border-line">${esc(m)}</span>`
          )
          .join(" ");

        return `
          <div class="p-4 rounded-xl bg-panel2/60 border border-line hover:border-brand/40 transition-colors flex flex-col justify-between shadow-sm">
            <div>
              <div class="flex items-center justify-between gap-2 mb-2">
                <div class="flex items-center gap-1.5 min-w-0">
                  <span class="px-1.5 py-0.5 rounded bg-brand/15 text-brand font-mono text-[10px] font-bold">
                    [${esc(ag.agent_num.toString().padStart(2, "0"))}]
                  </span>
                  <span class="text-xs font-bold text-ink truncate">${esc(ag.name)}</span>
                </div>
                <span class="px-2 py-0.5 rounded-full bg-crit/15 text-crit text-[10px] font-semibold tracking-wider uppercase flex-shrink-0 border border-crit/30">
                  Caught Threat
                </span>
              </div>
              <p class="text-[11px] text-muted leading-relaxed">${esc(ag.evidence)}</p>
            </div>

            <div class="mt-3.5 pt-2.5 border-t border-line/60 flex items-center justify-between gap-2 flex-wrap">
              <div class="flex items-center gap-1 flex-wrap">
                <span class="text-[10px] uppercase font-mono text-muted/60">Victim:</span>
                ${victimTags}
              </div>
              <div class="flex items-center gap-1 flex-wrap">
                ${mitreTags}
              </div>
            </div>
          </div>
        `;
      })
      .join("");
  } catch (err) {
    target.innerHTML = `<div class="col-span-full text-xs text-red-300 py-2">${esc(err.message)}</div>`;
  }
}

// 4. Render Threat Heatmap Matrix
async function loadHeatmap() {
  const target = $("nt-heatmap");
  if (!target) return;
  try {
    const hm = await api("/analytics/heatmap/identities");
    const idents = hm.identities || [];
    const risks = hm.risk || [];
    const patterns = hm.patterns || [];
    const patternNames = hm.pattern_names || [];
    const cells = hm.cells || [];

    if (!idents.length) {
      target.innerHTML = `<div class="py-4 text-center text-sm text-muted">No heatmap data available.</div>`;
      return;
    }

    let tableHtml = `
      <table class="w-full border-collapse text-xs">
        <thead>
          <tr class="border-b border-line text-left text-muted font-mono text-[11px]">
            <th class="py-2.5 px-3 bg-panel2 font-semibold">Compromised Identity</th>
            <th class="py-2.5 px-3 bg-panel2 text-center font-semibold">Risk & Band</th>
            ${patterns.map((p, idx) => `<th class="py-2.5 px-3 bg-panel2 text-center font-bold" title="${esc(patternNames[idx] || p)}">${esc(p)}<div class="text-[9px] font-normal text-muted truncate max-w-[80px]">${esc(patternNames[idx] || '')}</div></th>`).join('')}
          </tr>
        </thead>
        <tbody class="divide-y divide-line">
    `;

    idents.forEach((idName, rIdx) => {
      const rVal = risks[rIdx] || 0;
      let riskBadgeClass = "bg-panel2 text-muted";
      let bandLabel = "MONITOR";
      if (rVal >= 90) {
        riskBadgeClass = "bg-crit/20 text-crit border border-crit/40";
        bandLabel = "REVOKE";
      } else if (rVal >= 70) {
        riskBadgeClass = "bg-warn/20 text-warn border border-warn/40";
        bandLabel = "RESTRICT";
      } else if (rVal >= 40) {
        riskBadgeClass = "bg-cyan-400/20 text-cyan-300 border border-cyan-400/40";
        bandLabel = "STEP-UP";
      }

      tableHtml += `
        <tr class="hover:bg-panel2/40 transition-colors">
          <td class="py-2.5 px-3 font-semibold text-ink font-mono">
            <a href="${keepMock(`/explorer.html?identity=${encodeURIComponent(idName)}`)}" class="text-brand hover:underline font-bold">
              ${esc(idName)}
            </a>
          </td>
          <td class="py-2.5 px-3 text-center whitespace-nowrap">
            <span class="px-2 py-0.5 rounded text-[11px] font-bold font-mono ${riskBadgeClass}">
              ${rVal.toFixed(1)} · ${bandLabel}
            </span>
          </td>
      `;

      (cells[rIdx] || []).forEach((val) => {
        let cellCls = "bg-panel2/40 text-muted/50";
        if (val >= 3) cellCls = "bg-red-500/35 text-red-200 font-bold border border-red-500/40";
        else if (val === 2) cellCls = "bg-orange-500/30 text-orange-200 font-bold border border-orange-500/30";
        else if (val === 1) cellCls = "bg-amber-400/20 text-amber-200 font-medium border border-amber-400/30";

        tableHtml += `<td class="py-2.5 px-3 text-center ${cellCls} font-mono">${val}</td>`;
      });

      tableHtml += `</tr>`;
    });

    tableHtml += `</tbody></table>`;
    target.innerHTML = tableHtml;
  } catch (err) {
    target.innerHTML = `<div class="text-xs text-red-300 py-2">${esc(err.message)}</div>`;
  }
}

// 5. Render Email History List
function renderList() {
  if (!rows.length) {
    $("nt-list").innerHTML = `<div class="py-6 text-center text-sm text-muted">No emails yet. A digest is automatically sent when an alert reaches the risk threshold.</div>`;
    return;
  }
  $("nt-list").innerHTML = `
    <table class="w-full text-sm">
      <thead>
        <tr class="text-left text-[11px] uppercase tracking-wide text-muted">
          <th class="py-2.5 pr-3">Time</th>
          <th class="pr-3">Kind</th>
          <th class="pr-3">Status</th>
          <th class="pr-3">Subject</th>
          <th class="pr-3">Recipients</th>
          <th>Alerts</th>
        </tr>
      </thead>
      <tbody>
        ${rows
          .map(
            (r, i) => `
          <tr class="nt-row cursor-pointer border-t border-line hover:bg-panel2 transition-colors" data-i="${i}" tabindex="0">
            <td class="py-2.5 pr-3 whitespace-nowrap text-muted font-mono text-xs">${esc(new Date(r.created_at).toLocaleString())}</td>
            <td class="pr-3"><span class="rounded bg-panel2 px-1.5 py-0.5 text-[11px] capitalize font-medium">${esc(r.kind)}</span></td>
            <td class="pr-3"><span class="rounded-full px-2 py-0.5 text-[11px] font-semibold ${STATUS[r.status] || "bg-panel2 text-muted"}">${esc(r.status)}</span></td>
            <td class="pr-3 max-w-md truncate font-medium text-ink" title="${esc(r.subject)}">${esc(r.subject)}</td>
            <td class="pr-3 text-muted text-xs font-mono">${esc(r.recipients)}</td>
            <td class="whitespace-nowrap">
              ${(r.alert_ids || [])
                .slice(0, 3)
                .map((a) => `<a class="text-cyan-300 hover:underline mr-1 font-mono text-xs" href="${esc(keepMock(`alert.html?id=${encodeURIComponent(a)}`))}">${esc(a)}</a>`)
                .join("")}
              ${(r.alert_ids || []).length > 3 ? "…" : ""}
            </td>
          </tr>
          ${
            open === i
              ? `<tr>
                  <td colspan="6" class="pb-4 pt-1">
                    <div class="text-xs text-muted mb-1 font-mono">${esc(r.detail || "")}</div>
                    <pre class="mt-1 max-h-80 overflow-auto whitespace-pre-wrap rounded-lg border border-line bg-panel2 p-4 font-mono text-xs text-ink leading-relaxed">${esc(r.body_text)}</pre>
                  </td>
                </tr>`
              : ""
          }
        `
          )
          .join("")}
      </tbody>
    </table>
  `;
}

async function loadList() {
  try {
    rows = (await api("/notifications?limit=50")) || [];
    renderList();
  } catch (err) {
    $("nt-list").innerHTML = `<div class="text-sm text-red-300">${esc(err.message)}</div>`;
  }
}

const toggle = (el) => {
  const i = Number(el.dataset.i);
  open = open === i ? null : i;
  renderList();
};

$("nt-list").addEventListener("click", (e) => {
  const tr = e.target.closest(".nt-row");
  if (tr && !e.target.closest("a")) toggle(tr);
});

$("nt-list").addEventListener("keydown", (e) => {
  const tr = e.target.closest(".nt-row");
  if (tr && e.key === "Enter") toggle(tr);
});

// Run all loaders in parallel
loadStatus();
loadAgentAttribution();
loadHeatmap();
loadList();
