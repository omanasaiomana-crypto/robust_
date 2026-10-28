/**
 * Alert investigation detail page:
 * - Header with risk ring, band, confidence, blast radius, containment actions
 * - Left column: why flagged reasons, counterfactual table, attack chain stepper, predicted next step
 * - Right column: evidence events table, analyst feedback loop, quick graph/timeline links
 */
import { api, esc, fmtTime, qs } from './api.js';
import { renderLayout } from './layout.js';
import {
  bandBadge,
  button,
  confirmModal,
  emptyState,
  errorState,
  mitreChip,
  patternChip,
  riskRing,
  skeleton,
  table,
  toast,
} from './ui.js';

const isMock = qs('mock') === '1';
const querySuffix = isMock ? '?mock=1' : '';
const alertId = qs('id');

const content = renderLayout('alerts', 'Alert Investigation', `Session Threat Analysis`);

const STATE_EXPLANATIONS = {
  Impact: 'Data destruction, log tampering, or exfiltration.',
  RoleAssume: 'Privilege assumption or lateral movement to high-value roles.',
  PermGrant: 'IAM policy attachment or permission escalation.',
  CredCreate: 'Secondary access key or credential generation for persistence.',
  TrustChange: 'Modifying trust relationships to maintain backdoor access.',
  IdentityCreate: 'Creating shadow IAM users or service roles.',
  Recon: 'Reconnaissance against account resources and identity inventory.',
  End: 'Sequence termination or post-exploitation cleanup.',
};

if (!alertId) {
  if (content) {
    content.innerHTML = `
      <div class="space-y-4">
        ${emptyState('No Alert ID specified. Please select an alert from the queue.')}
        <div class="text-center">
          <a href="/alerts.html${querySuffix}" class="inline-flex items-center px-4 py-2 rounded-lg bg-brand text-white text-sm font-medium hover:bg-blue-500 transition-colors">
            ← Back to Alert Queue
          </a>
        </div>
      </div>
    `;
  }
} else if (content) {
  content.innerHTML = `
    <!-- Top back link -->
    <div class="mb-2">
      <a href="/alerts.html${querySuffix}" class="text-xs font-medium text-brand hover:underline inline-flex items-center gap-1.5">
        ← Back to Alert Queue
      </a>
    </div>

    <!-- Alert Header Skeleton -->
    <div id="alert-header-card" class="bg-panel border border-line rounded-xl p-6 shadow-sm">
      ${skeleton(3)}
    </div>

    <!-- Two-column Body Grid -->
    <div class="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
      <!-- Left Column (Reasons, Counterfactuals, Chain, Prediction) -->
      <div id="left-column" class="lg:col-span-7 space-y-6">
        <div class="bg-panel border border-line rounded-xl p-5 shadow-sm">${skeleton(4)}</div>
      </div>

      <!-- Right Column (Evidence Events, Feedback, Links) -->
      <div id="right-column" class="lg:col-span-5 space-y-6">
        <div class="bg-panel border border-line rounded-xl p-5 shadow-sm">${skeleton(4)}</div>
      </div>
    </div>
  `;

  loadAlertData();
}

async function loadAlertData() {
  const headerCard = document.getElementById('alert-header-card');
  const leftCol = document.getElementById('left-column');
  const rightCol = document.getElementById('right-column');

  try {
    const [alert, events] = await Promise.all([
      api(`/alerts/${encodeURIComponent(alertId)}`),
      api(`/alerts/${encodeURIComponent(alertId)}/events`),
    ]);

    renderHeader(headerCard, alert);
    renderLeftColumn(leftCol, alert);
    renderRightColumn(rightCol, alert, events);
  } catch (err) {
    if (headerCard) {
      headerCard.innerHTML = errorState(err.message, 'btn-retry-alert');
      const retryBtn = document.getElementById('btn-retry-alert');
      if (retryBtn) retryBtn.onclick = () => loadAlertData();
    }
  }
}

function renderHeader(container, alert) {
  if (!container) return;

  const isRevoke = alert.band === 'revoke';
  const isApplied = alert.action_status === 'applied';
  const isDismissed = alert.action_status === 'dismissed';

  // Action button label
  let recLabel = 'Apply Recommended';
  if (alert.recommended_action === 'restrict') recLabel = 'Restrict Access';
  else if (alert.recommended_action === 'step_up') recLabel = 'Enforce Step-Up MFA';
  else if (alert.recommended_action === 'monitor') recLabel = 'Flag for Monitoring';

  const mitreHtml = alert.mitre && alert.mitre.length > 0 ? alert.mitre.map((m) => mitreChip(m)).join(' ') : '—';

  container.innerHTML = `
    <div class="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6">
      <!-- Left: Gauge + Details -->
      <div class="flex flex-col sm:flex-row items-start sm:items-center gap-5 min-w-0">
        ${riskRing(alert.risk, alert.band, 96)}
        
        <div class="space-y-1.5 min-w-0">
          <div class="flex items-center gap-3 flex-wrap">
            <h2 class="text-xl sm:text-2xl font-bold font-mono text-ink tracking-tight">${esc(alert.identity_id)}</h2>
            ${bandBadge(alert.band)}
            <span class="text-xs font-mono px-2 py-0.5 rounded bg-panel2 border border-line text-muted">${esc(alert.alert_id)}</span>
            <span class="text-xs capitalize px-2.5 py-0.5 rounded-full font-medium ${
              isApplied
                ? 'bg-ok/15 text-ok border border-ok/30'
                : isDismissed
                ? 'bg-slate-500/15 text-muted border border-line'
                : 'bg-warn/15 text-warn border border-warn/30'
            }">
              Status: ${esc(alert.action_status)}
            </span>
          </div>

          <div class="flex items-center gap-3 text-xs text-muted font-mono flex-wrap">
            <span>Session: <span class="text-ink">${esc(alert.session_id || 'None')}</span></span>
            <span>•</span>
            <span>${fmtTime(alert.first_seen)} → ${fmtTime(alert.last_seen)}</span>
          </div>

          <div class="flex items-center gap-3 text-xs flex-wrap pt-1">
            <span class="inline-flex items-center gap-1.5 text-muted">
              <span class="w-1.5 h-1.5 rounded-full bg-brand"></span>
              Confidence: <span class="font-mono text-ink font-semibold">${Math.round((alert.confidence || 0) * 100)}%</span>
            </span>
            <span class="text-muted">•</span>
            <span class="inline-flex items-center gap-1.5 text-muted">
              Blast Radius: <span class="font-mono text-ink font-semibold">${esc(alert.blast_radius)}</span>
            </span>
            <span class="text-muted">•</span>
            <span class="inline-flex items-center gap-1.5">${mitreHtml}</span>
          </div>
        </div>
      </div>

      <!-- Right: Action Buttons -->
      <div class="flex flex-wrap items-center gap-3 w-full lg:w-auto justify-start lg:justify-end border-t border-line lg:border-t-0 pt-4 lg:pt-0">
        <!-- Apply Recommended Button -->
        <button
          id="btn-apply-action"
          ${isApplied || isDismissed ? 'disabled' : ''}
          class="px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
            isApplied
              ? 'bg-panel2 text-muted border border-line cursor-not-allowed'
              : 'bg-brand hover:bg-blue-500 text-white shadow-sm'
          }"
        >
          ${isApplied ? 'Action Applied' : esc(recLabel)}
        </button>

        <!-- Approve Revoke Button (only when band is revoke) -->
        ${
          isRevoke
            ? `
          <button
            id="btn-approve-revoke"
            ${isApplied ? 'disabled' : ''}
            class="px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
              isApplied
                ? 'bg-panel2 text-muted border border-line cursor-not-allowed hidden'
                : 'bg-crit hover:bg-red-600 text-white shadow-sm'
            }"
          >
            Approve Revoke
          </button>
        `
            : ''
        }

        <!-- Dismiss Button -->
        <button
          id="btn-dismiss-alert"
          ${isApplied || isDismissed ? 'disabled' : ''}
          class="border border-line hover:bg-panel2 text-ink rounded-lg px-4 py-2 text-sm font-medium transition-colors ${
            isDismissed ? 'opacity-50 cursor-not-allowed' : ''
          }"
        >
          ${isDismissed ? 'Dismissed' : 'Dismiss'}
        </button>
      </div>
    </div>
  `;

  // Attach button events
  const applyBtn = document.getElementById('btn-apply-action');
  if (applyBtn && !isApplied && !isDismissed) {
    applyBtn.onclick = async () => {
      applyBtn.disabled = true;
      applyBtn.textContent = 'Applying...';
      try {
        const res = await api(`/alerts/${encodeURIComponent(alert.alert_id)}/action`, {
          method: 'POST',
          body: { action: alert.recommended_action, approved_by: 'analyst' },
        });
        toast(res.detail || 'Containment action applied.', 'success');
        loadAlertData();
      } catch (err) {
        toast(`Action failed: ${err.message}`, 'error');
        applyBtn.disabled = false;
        applyBtn.textContent = recLabel;
      }
    };
  }

  const revokeBtn = document.getElementById('btn-approve-revoke');
  if (revokeBtn && !isApplied) {
    revokeBtn.onclick = async () => {
      const confirmed = await confirmModal(
        'Approve Revoke Containment',
        `Revoking credentials for ${alert.identity_id} will immediately terminate active sessions and quarantine access keys. Are you sure you want to proceed?`
      );
      if (!confirmed) return;

      revokeBtn.disabled = true;
      revokeBtn.textContent = 'Revoking...';
      try {
        const res = await api(`/alerts/${encodeURIComponent(alert.alert_id)}/action`, {
          method: 'POST',
          body: { action: 'revoke', approved_by: 'analyst' },
        });
        toast(res.detail || 'Revoke containment approved and executed.', 'success');
        loadAlertData();
      } catch (err) {
        toast(`Revoke failed: ${err.message}`, 'error');
        revokeBtn.disabled = false;
        revokeBtn.textContent = 'Approve Revoke';
      }
    };
  }

  const dismissBtn = document.getElementById('btn-dismiss-alert');
  if (dismissBtn && !isApplied && !isDismissed) {
    dismissBtn.onclick = async () => {
      dismissBtn.disabled = true;
      try {
        const res = await api(`/alerts/${encodeURIComponent(alert.alert_id)}/action`, {
          method: 'POST',
          body: { action: 'dismiss', approved_by: 'analyst' },
        });
        toast(res.detail || 'Alert dismissed.', 'success');
        loadAlertData();
      } catch (err) {
        toast(`Dismiss failed: ${err.message}`, 'error');
        dismissBtn.disabled = false;
      }
    };
  }
}

function renderLeftColumn(container, alert) {
  if (!container) return;

  // 1. Why this was flagged
  const reasonsHtml =
    alert.reasons && alert.reasons.length > 0
      ? `
      <ul class="space-y-3">
        ${alert.reasons
          .map(
            (r, i) => `
          <li class="flex items-start gap-3 text-sm text-ink leading-relaxed">
            <span class="flex-shrink-0 w-6 h-6 rounded-full bg-panel2 border border-line flex items-center justify-center text-xs font-mono font-medium text-muted mt-0.5">
              ${i + 1}
            </span>
            <span class="flex-1">${esc(r)}</span>
          </li>
        `
          )
          .join('')}
      </ul>
    `
      : `<p class="text-sm text-muted">No specific anomaly reasons logged.</p>`;

  // 2. Score without each signal (Counterfactuals)
  let cfTableHtml = '';
  if (alert.counterfactuals && alert.counterfactuals.length > 0) {
    // Sort by largest reduction in risk
    const sortedCfs = [...alert.counterfactuals]
      .map((cf) => ({
        ...cf,
        change: alert.risk - cf.risk,
      }))
      .sort((a, b) => b.change - a.change);

    const cols = [{ label: 'Signal Removed' }, { label: 'Risk' }, { label: 'Change', align: 'right' }];
    const rowsHtml = sortedCfs
      .map((cf) => {
        const diffStr = cf.change > 0 ? `−${cf.change.toFixed(1)}` : `+${Math.abs(cf.change).toFixed(1)}`;
        return `
          <tr class="hover:bg-panel2/60 transition-colors">
            <td class="px-4 py-2.5">
              ${patternChip(cf.without)}
            </td>
            <td class="px-4 py-2.5 font-mono text-xs tabular-nums text-ink">
              ${cf.risk.toFixed(1)}
            </td>
            <td class="px-4 py-2.5 text-right font-mono text-xs tabular-nums text-ok font-semibold">
              ${diffStr}
            </td>
          </tr>
        `;
      })
      .join('');

    cfTableHtml = table(cols, rowsHtml);
  } else {
    cfTableHtml = `<p class="text-xs text-muted py-2">Single signal alert; counterfactual scoring not required.</p>`;
  }

  // 3. Attack Chain vertical stepper
  let chainHtml = '';
  if (alert.chain && alert.chain.length > 0) {
    const totalSteps = alert.chain.length;
    chainHtml = `
      <div class="relative pl-6 space-y-6 before:absolute before:left-2.5 before:top-3 before:bottom-3 before:w-0.5 before:bg-line">
        ${alert.chain
          .map((step, idx) => {
            const isLast = idx === totalSteps - 1;
            const dotColor = isLast ? 'bg-crit border-crit ring-4 ring-crit/20' : 'bg-panel2 border-line text-muted';
            return `
              <div class="relative flex items-start gap-3">
                <span class="absolute -left-6 top-1 w-5 h-5 rounded-full border-2 ${dotColor} flex items-center justify-center text-[10px] font-mono font-bold">
                  ${idx + 1}
                </span>
                <div class="flex-1 bg-panel2/40 border border-line rounded-lg p-3 ${isLast ? 'border-crit/50 bg-crit/5' : ''}">
                  <div class="flex items-center justify-between gap-2 mb-1">
                    <span class="text-xs font-bold font-mono text-ink">${esc(step.state)}</span>
                    <span class="text-[11px] font-mono text-muted">${fmtTime(step.timestamp)}</span>
                  </div>
                  <div class="text-xs font-mono text-muted">
                    Action: <span class="text-brand font-semibold">${esc(step.action)}</span>
                  </div>
                  ${isLast ? `<span class="inline-block mt-2 text-[10px] font-mono font-bold text-crit uppercase tracking-wider">Current Escalation Stage</span>` : ''}
                </div>
              </div>
            `;
          })
          .join('')}
      </div>
    `;
  } else {
    chainHtml = `<p class="text-xs text-muted py-2">No escalation state sequence detected for this session.</p>`;
  }

  // 4. Predicted Next Step Callout
  let predCalloutHtml = '';
  if (alert.prediction) {
    const nextSt = alert.prediction.next_state;
    const probPct = Math.round(alert.prediction.probability * 100);
    const expl = STATE_EXPLANATIONS[nextSt] || 'Next potential attack tactic.';

    predCalloutHtml = `
      <div class="border-l-4 border-brand2 bg-brand2/10 p-4 rounded-r-xl space-y-1">
        <div class="flex items-center justify-between">
          <span class="text-xs uppercase tracking-wider font-bold text-brand2">Markov Predicted Next Tactic</span>
          <span class="text-xs font-mono font-semibold text-brand2 tabular-nums">${probPct}% likelihood</span>
        </div>
        <div class="text-sm font-bold font-mono text-ink">
          Next likely: ${esc(nextSt)} (${probPct}%)
        </div>
        <p class="text-xs text-muted leading-relaxed">${esc(expl)}</p>
      </div>
    `;
  } else {
    predCalloutHtml = `
      <div class="border-l-4 border-muted/50 bg-panel2 p-3.5 rounded-r-xl">
        <span class="text-xs text-muted">Markov chain next-state prediction requires active multi-step escalation chains.</span>
      </div>
    `;
  }

  container.innerHTML = `
    <!-- Why Flagged -->
    <div class="bg-panel border border-line rounded-xl p-5 shadow-sm space-y-4">
      <h3 class="text-sm font-semibold text-ink">Why This Was Flagged</h3>
      ${reasonsHtml}
    </div>

    <!-- Score Without Each Signal -->
    <div class="bg-panel border border-line rounded-xl p-5 shadow-sm space-y-4">
      <h3 class="text-sm font-semibold text-ink">Score Without Each Signal (Counterfactuals)</h3>
      ${cfTableHtml}
    </div>

    <!-- Attack Chain -->
    <div class="bg-panel border border-line rounded-xl p-5 shadow-sm space-y-4">
      <h3 class="text-sm font-semibold text-ink">Attack Chain Progression</h3>
      ${chainHtml}
    </div>

    <!-- Predicted Next Step -->
    ${predCalloutHtml}
  `;
}

function renderRightColumn(container, alert, events) {
  if (!container) return;

  const evIdsSet = new Set(alert.evidence_event_ids || []);

  // 1. Evidence Events Table
  let eventsTableHtml = '';
  if (events && events.length > 0) {
    const cols = [
      { label: 'Time' },
      { label: 'Source' },
      { label: 'Action' },
      { label: 'IP / Location' },
      { label: 'Event ID', align: 'right' },
    ];

    const rowsHtml = events
      .map((ev) => {
        const isCited = evIdsSet.has(ev.event_id);
        const loc = [ev.city, ev.country, ev.region].filter(Boolean).join(', ') || '—';
        const srcBadge =
          ev.source === 'okta'
            ? `<span class="px-1.5 py-0.5 rounded text-[10px] font-mono font-medium bg-blue-500/15 text-blue-400 border border-blue-500/30">Okta</span>`
            : `<span class="px-1.5 py-0.5 rounded text-[10px] font-mono font-medium bg-amber-500/15 text-amber-400 border border-amber-500/30">AWS</span>`;

        return `
          <tr class="${isCited ? 'bg-brand/10 border-l-2 border-brand font-medium' : 'hover:bg-panel2/60'} transition-colors">
            <td class="px-4 py-2.5 whitespace-nowrap text-xs font-mono text-muted">
              ${fmtTime(ev.timestamp)}
            </td>
            <td class="px-4 py-2.5">
              ${srcBadge}
            </td>
            <td class="px-4 py-2.5">
              <span class="font-mono text-xs text-ink ${isCited ? 'font-bold' : ''}">${esc(ev.action)}</span>
            </td>
            <td class="px-4 py-2.5 text-xs text-muted">
              <div>${esc(ev.src_ip || '—')}</div>
              <div class="text-[10px] text-muted/80">${esc(loc)}</div>
            </td>
            <td class="px-4 py-2.5 text-right font-mono text-[11px] text-muted">
              ${esc(ev.event_id)}
            </td>
          </tr>
        `;
      })
      .join('');

    eventsTableHtml = table(cols, rowsHtml);
  } else {
    eventsTableHtml = `<p class="text-sm text-muted py-6 text-center">No evidence events logged for this session.</p>`;
  }

  // 2. Analyst Feedback Card
  const feedbackStatus = alert.feedback
    ? alert.feedback === 'tp'
      ? `<span class="px-2 py-0.5 rounded text-xs font-medium bg-ok/15 text-ok border border-ok/30">Confirmed True Positive</span>`
      : `<span class="px-2 py-0.5 rounded text-xs font-medium bg-warn/15 text-warn border border-warn/30">Flagged False Positive</span>`
    : `<span class="text-xs text-muted">Pending analyst review</span>`;

  // 3. Quick Links
  const graphUrl = `/graph.html?identity=${encodeURIComponent(alert.identity_id)}${querySuffix}`;
  const timelineUrl = `/timeline.html?session=${encodeURIComponent(alert.session_id || '')}${querySuffix}`;

  container.innerHTML = `
    <!-- Evidence Events Table Card -->
    <div class="bg-panel border border-line rounded-xl p-5 shadow-sm space-y-4">
      <div class="flex items-center justify-between">
        <h3 class="text-sm font-semibold text-ink">Evidence Events (${events ? events.length : 0})</h3>
        <span class="text-xs text-muted font-mono">${evIdsSet.size} cited</span>
      </div>
      <div class="max-h-96 overflow-y-auto rounded-lg">
        ${eventsTableHtml}
      </div>
    </div>

    <!-- Analyst Feedback Card -->
    <div class="bg-panel border border-line rounded-xl p-5 shadow-sm space-y-4">
      <div class="flex items-center justify-between">
        <h3 class="text-sm font-semibold text-ink">Analyst Feedback</h3>
        <div id="feedback-status-badge">${feedbackStatus}</div>
      </div>
      <p class="text-xs text-muted leading-relaxed">
        Submitting feedback retrains the scoring weights for these detected patterns via online reinforcement.
      </p>
      <div class="flex items-center gap-3">
        <button
          id="btn-feedback-tp"
          class="flex-1 px-4 py-2 rounded-lg text-sm font-medium border border-ok/40 hover:bg-ok/15 text-ok transition-colors flex items-center justify-center gap-2"
        >
          <span>✓</span>
          <span>True Positive</span>
        </button>
        <button
          id="btn-feedback-fp"
          class="flex-1 px-4 py-2 rounded-lg text-sm font-medium border border-line hover:bg-panel2 text-muted hover:text-ink transition-colors flex items-center justify-center gap-2"
        >
          <span>✗</span>
          <span>False Positive</span>
        </button>
      </div>
    </div>

    <!-- Quick Investigation Links -->
    <div class="bg-panel border border-line rounded-xl p-5 shadow-sm space-y-3">
      <h3 class="text-sm font-semibold text-ink">Deep-Dive Pivot Links</h3>
      <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <a
          href="${graphUrl}"
          class="p-3 rounded-lg border border-line bg-panel2/50 hover:bg-panel2 hover:border-brand/50 transition-colors flex items-center justify-between text-xs font-medium text-ink group"
        >
          <span>Open Identity Graph</span>
          <span class="text-brand group-hover:translate-x-0.5 transition-transform">→</span>
        </a>
        <a
          href="${timelineUrl}"
          class="p-3 rounded-lg border border-line bg-panel2/50 hover:bg-panel2 hover:border-brand/50 transition-colors flex items-center justify-between text-xs font-medium text-ink group"
        >
          <span>Replay Timeline</span>
          <span class="text-brand group-hover:translate-x-0.5 transition-transform">→</span>
        </a>
      </div>
    </div>
  `;

  // Attach feedback buttons
  const tpBtn = document.getElementById('btn-feedback-tp');
  const fpBtn = document.getElementById('btn-feedback-fp');

  const sendFeedback = async (label) => {
    if (tpBtn) tpBtn.disabled = true;
    if (fpBtn) fpBtn.disabled = true;

    try {
      const updatedAlert = await api(`/alerts/${encodeURIComponent(alert.alert_id)}/feedback`, {
        method: 'POST',
        body: { label },
      });
      toast(`Feedback saved. Risk updated to ${updatedAlert.risk.toFixed(1)}.`, 'success');
      loadAlertData();
    } catch (err) {
      toast(`Feedback failed: ${err.message}`, 'error');
      if (tpBtn) tpBtn.disabled = false;
      if (fpBtn) fpBtn.disabled = false;
    }
  };

  if (tpBtn) tpBtn.onclick = () => sendFeedback('tp');
  if (fpBtn) fpBtn.onclick = () => sendFeedback('fp');
}
