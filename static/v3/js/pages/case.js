/**
 * IdentityShield v3 — Case Detail Controller
 * Handles SVG Arc gauge, attack chain timeline, evidence drawer, counterfactual bars,
 * predicted next step, action approval/rollback, and analyst ground-truth labeling.
 */

import { api } from '../core/api.js';
import { sse } from '../core/sse.js';
import { fmt, escHtml, bandColor } from '../core/dom.js';

let activeCase = null;
let pendingModalAction = null;

export async function initCasePage() {
  const params = new URLSearchParams(window.location.search);
  const caseId = params.get('id') || params.get('case_id') || 'case-e1-svcreport';

  setupDrawerHandlers();
  setupModalHandlers();
  setupLabelHandlers(caseId);
  await loadCaseDetail(caseId);
  setupSSE(caseId);
}

async function loadCaseDetail(caseId) {
  try {
    const data = await api.get(`/cases/${encodeURIComponent(caseId)}`);
    activeCase = data;
    renderHeader(data);
    renderAttackChain(data);
    renderReasons(data);
    renderCounterfactuals(data);
    renderPredictedNextStep(data);
    renderBlastRadius(data);
    renderNarrative(data);
    renderActions(data);
  } catch (err) {
    console.error('Failed to load case detail:', err);
    window.dispatchEvent(
      new CustomEvent('is:toast', {
        detail: { message: `Failed to load case ${caseId}: ${err.message}`, type: 'error' },
      })
    );
  }
}

/**
 * 1. Render Header & SVG Arc Gauge
 */
function renderHeader(data) {
  const caseIdTag = document.getElementById('case-id-tag');
  const sessionTag = document.getElementById('case-session-tag');
  const title = document.getElementById('case-title');
  const summary = document.getElementById('case-summary');
  const badgeBand = document.getElementById('case-badge-band');
  const badgeStatus = document.getElementById('case-badge-status');
  const gaugeScore = document.getElementById('gauge-score');
  const gaugeArc = document.getElementById('gauge-arc');
  const metricIdRisk = document.getElementById('metric-identity-risk');
  const metricConf = document.getElementById('metric-confidence');

  const risk = Number(data.risk_score || 0);
  const band = (data.band || 'monitor').toLowerCase().replace('-', '_');
  const color = bandColor(band);

  if (caseIdTag) caseIdTag.textContent = data.case_id || 'CASE-E1';
  if (sessionTag) sessionTag.textContent = data.session_id || 'ses-okta-882194';
  if (title) title.textContent = data.title || 'Multi-Stage Privilege Escalation';
  if (summary) summary.textContent = data.summary || '';

  if (badgeBand) {
    badgeBand.className = `badge-band badge-band-${band}`;
    badgeBand.textContent = band.toUpperCase();
  }

  if (badgeStatus) {
    const isClosed = data.status === 'closed' || data.status === 'resolved';
    badgeStatus.innerHTML = `<span class="status-dot ${isClosed ? 'ok' : 'crit'}"></span> ${escHtml((data.status || 'open').toUpperCase())}`;
  }

  if (gaugeScore) {
    gaugeScore.textContent = risk.toFixed(1);
    gaugeScore.style.color = color;
  }

  // SVG Arc calculation: circumference = 126. Total arc length for 0..100
  if (gaugeArc) {
    gaugeArc.style.stroke = color;
    const offset = 126 - (risk / 100) * 126;
    gaugeArc.style.strokeDashoffset = String(Math.max(0, offset));
  }

  if (metricIdRisk) {
    const idRisk = Number(data.identity_risk || data.risk_score || 0);
    metricIdRisk.textContent = idRisk.toFixed(1);
    metricIdRisk.style.color = bandColor(data.band);
  }

  if (metricConf) {
    const conf = data.confidence !== undefined ? fmt.percent(data.confidence) : '94.0%';
    metricConf.textContent = conf;
  }
}

/**
 * 2. Attack Chain Timeline
 */
function renderAttackChain(data) {
  const container = document.getElementById('attack-chain-container');
  if (!container) return;

  const steps = data.steps || [];
  if (steps.length === 0) {
    container.innerHTML = '<div style="color:var(--muted); font-size:0.875rem;">No chronological steps recorded.</div>';
    return;
  }

  container.innerHTML = steps.map((step, idx) => {
    const isLast = idx === steps.length - 1;
    const mitreList = Array.isArray(step.mitre) ? step.mitre : [step.mitre || 'T1078'];

    return `
      <div style="position:relative; display:flex; gap:16px;">
        <!-- Timeline vertical rule -->
        ${!isLast ? '<div style="position:absolute; left:13px; top:28px; bottom:-16px; width:2px; background:#E8E1D6;"></div>' : ''}
        
        <!-- Step Number Node -->
        <div style="width:28px; height:28px; border-radius:50%; background:#FFFFFF; border:2px solid #3D6FE0; display:flex; align-items:center; justify-content:center; font-family:var(--font-mono); font-size:0.75rem; font-weight:700; color:var(--ink); z-index:2; flex-shrink:0;">
          ${step.step_index || idx + 1}
        </div>

        <!-- Step Content Card -->
        <div style="flex:1; padding:12px 16px; background:var(--surface-2); border:1px solid var(--panel-border); border-radius:8px;">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px; flex-wrap:wrap; gap:8px;">
            <div style="display:flex; align-items:center; gap:8px;">
              <span style="font-size:0.8125rem; font-weight:700; color:var(--ink);">${escHtml(step.event_name || 'Event')}</span>
              <span style="font-size:0.6875rem; color:var(--muted); font-family:var(--font-mono);">${escHtml(step.source || 'CloudTrail')}</span>
            </div>
            <span style="font-size:0.75rem; color:var(--muted); font-family:var(--font-mono);">${escHtml(step.timestamp || '')}</span>
          </div>
          
          <div style="font-size:0.8125rem; color:var(--text); margin-bottom:8px; line-height:1.5;">
            ${escHtml(step.description || '')}
          </div>

          <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:6px;">
            <div style="display:flex; gap:4px;">
              ${mitreList.map((m) => `<span class="mitre-chip">${escHtml(m)}</span>`).join('')}
            </div>
            <button class="btn btn-ghost btn-evidence-inspect" data-event-id="${escHtml(step.event_id || 'evt-mock')}" type="button" style="padding:2px 8px; font-size:0.6875rem; font-family:var(--font-mono);">
              Inspect ${escHtml(step.event_id || 'Event')} &rarr;
            </button>
          </div>
        </div>
      </div>
    `;
  }).join('');

  // Attach evidence inspection click listeners
  container.querySelectorAll('.btn-evidence-inspect').forEach((btn) => {
    btn.addEventListener('click', () => {
      const eid = btn.dataset.eventId;
      openEvidenceDrawer(eid);
    });
  });
}

/**
 * 3. Why This Score (Top 3 Reasons)
 */
function renderReasons(data) {
  const container = document.getElementById('reasons-container');
  if (!container) return;

  const reasons = data.reasons || [];
  if (reasons.length === 0) {
    container.innerHTML = '<div style="color:var(--muted); font-size:0.8125rem;">No reason breakdown available.</div>';
    return;
  }

  container.innerHTML = reasons.map((r, i) => {
    // Look for event ID pattern (e.g. evt-okta-882194 or evt-ct-401)
    const formatted = escHtml(r).replace(
      /(evt-[a-z0-9\-]+)/gi,
      '<span class="evidence-link" style="color:var(--cyan); text-decoration:underline; cursor:pointer;" data-eid="$1">$1</span>'
    );

    return `
      <div style="padding:10px 12px; background:var(--surface-2); border:1px solid var(--panel-border); border-radius:8px; display:flex; gap:10px; align-items:flex-start;">
        <span style="width:20px; height:20px; border-radius:50%; background:rgba(59,130,246,0.15); color:var(--brand); display:flex; align-items:center; justify-content:center; font-size:0.6875rem; font-weight:700; font-family:var(--font-mono); flex-shrink:0;">
          ${i + 1}
        </span>
        <div style="font-size:0.8125rem; color:var(--text); line-height:1.5;">
          ${formatted}
        </div>
      </div>
    `;
  }).join('');

  container.querySelectorAll('.evidence-link').forEach((link) => {
    link.addEventListener('click', () => {
      openEvidenceDrawer(link.dataset.eid);
    });
  });
}

/**
 * 4. Counterfactual "What If" Bars
 */
function renderCounterfactuals(data) {
  const container = document.getElementById('counterfactuals-container');
  if (!container) return;

  const items = data.counterfactuals || [
    { omitted: 'escalation_chain', score: 44.0, drop: 48.4, description: 'Without escalation chain' },
    { omitted: 'defense_evasion', score: 62.1, drop: 30.3, description: 'Without defense evasion' },
    { omitted: 'impossible_travel', score: 79.5, drop: 12.9, description: 'Without access anomaly' },
  ];

  const baseScore = Number(data.risk_score || 92.4);

  container.innerHTML = items.map((c) => {
    const withoutScore = Number(c.score || 0);
    const drop = Number(c.drop || baseScore - withoutScore);

    return `
      <div>
        <div style="display:flex; justify-content:space-between; margin-bottom:4px; font-size:0.75rem;">
          <span style="color:var(--ink); font-weight:500;">${escHtml(c.description || c.omitted)}</span>
          <span style="font-family:var(--font-mono); color:var(--ok); font-weight:700;">-${drop.toFixed(1)} pts (${withoutScore.toFixed(1)})</span>
        </div>
        <div style="height:8px; border-radius:4px; background:#EFE8DC; overflow:hidden; position:relative;">
          <div style="position:absolute; left:0; top:0; bottom:0; width:${baseScore}%; background:rgba(229,72,77,0.25);"></div>
          <div style="position:absolute; left:0; top:0; bottom:0; width:${withoutScore}%; background:#3D6FE0; border-radius:4px;"></div>
        </div>
      </div>
    `;
  }).join('');
}

/**
 * 5. Predicted Next Step
 */
function renderPredictedNextStep(data) {
  const el = document.getElementById('predicted-next-step');
  if (el && data.predicted_next_step) {
    el.textContent = data.predicted_next_step;
  }
}

/**
 * 6. Blast Radius & Related Identities
 */
function renderBlastRadius(data) {
  const countEl = document.getElementById('blast-radius-count');
  const relatedEl = document.getElementById('related-identities-text');
  const listEl = document.getElementById('blast-radius-list');

  const blast = data.blast_radius || { count: 4, entities: ['ReportViewerRole', 'AdministratorAccess', 'production-trail', 'prod/rds/credentials'] };
  const related = data.related_identities || ['jdoe', 'asmith'];

  if (countEl) countEl.textContent = `${blast.count || blast.entities?.length || 4} Entities`;
  if (relatedEl) relatedEl.textContent = `${related.length} Linked`;

  if (listEl && blast.entities) {
    listEl.innerHTML = blast.entities.map((e) => `<span class="mitre-chip" style="color:var(--text); border-color:var(--panel-border);">${escHtml(e)}</span>`).join('');
  }
}

/**
 * 7. Narrative
 */
function renderNarrative(data) {
  const textEl = document.getElementById('narrative-text');
  const tagEl = document.getElementById('narrative-source-tag');

  const narrative = data.narrative || {
    source: 'template',
    text: `Identity ${data.identity_id || 'svc-report'} established a session from Frankfurt, Germany (ASN 24940), an unprecedented geographical origin. Within 12 minutes, the identity generated new AWS API access keys, attached AdministratorAccess policies, and executed StopLogging to suppress CloudTrail audit capture.`,
  };

  if (textEl) textEl.textContent = narrative.text || '';
  if (tagEl) tagEl.textContent = `[${(narrative.source || 'TEMPLATE').toUpperCase()} NARRATIVE]`;
}

/**
 * 8. Simulator Response Actions Panel
 */
function renderActions(data) {
  const container = document.getElementById('actions-list');
  if (!container) return;

  const actionList = [];
  if (data.action) actionList.push(data.action);
  if (data.pending_action) actionList.push(data.pending_action);

  if (actionList.length === 0) {
    actionList.push(
      { action_id: 'act-e1-restrict-01', action_type: 'restrict', state: 'applied', target_identity: data.identity_id },
      { action_id: 'act-e1-revoke-02', action_type: 'revoke', state: 'pending_approval', requires_approval: true, target_identity: data.identity_id }
    );
  }

  container.innerHTML = actionList.map((act) => {
    const isPending = act.state === 'pending_approval' || act.requires_approval;
    const isApplied = act.state === 'applied';

    return `
      <div style="padding:10px 14px; background:rgba(0,0,0,0.3); border:1px solid var(--panel-border); border-radius:8px; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;">
        <div>
          <div style="display:flex; align-items:center; gap:8px;">
            <span style="font-size:0.8125rem; font-weight:700; color:var(--ink); text-transform:uppercase;">${escHtml(act.action_type)}</span>
            <span class="status-pill" style="font-size:0.625rem; padding:1px 6px;">
              <span class="status-dot ${isApplied ? 'ok' : 'warn'}"></span>
              ${escHtml((act.state || 'proposed').toUpperCase())}
            </span>
          </div>
          <div style="font-size:0.6875rem; color:var(--muted); font-family:var(--font-mono); margin-top:2px;">Target: ${escHtml(act.target_identity || data.identity_id)}</div>
        </div>

        <div style="display:flex; gap:6px;">
          ${
            isPending
              ? `<button class="btn btn-primary btn-action-approve" data-action-id="${escHtml(act.action_id)}" type="button" style="padding:4px 10px; font-size:0.75rem;">Approve</button>
                 <button class="btn btn-ghost btn-action-reject" data-action-id="${escHtml(act.action_id)}" type="button" style="padding:4px 10px; font-size:0.75rem;">Reject</button>`
              : isApplied
              ? `<button class="btn btn-ghost btn-action-rollback" data-action-id="${escHtml(act.action_id)}" type="button" style="padding:4px 10px; font-size:0.75rem;">Rollback</button>`
              : ''
          }
        </div>
      </div>
    `;
  }).join('');

  // Attach action button handlers
  container.querySelectorAll('.btn-action-approve').forEach((btn) => {
    btn.addEventListener('click', () => {
      openActionModal(btn.dataset.actionId, 'approve');
    });
  });

  container.querySelectorAll('.btn-action-reject').forEach((btn) => {
    btn.addEventListener('click', () => {
      openActionModal(btn.dataset.actionId, 'reject');
    });
  });

  container.querySelectorAll('.btn-action-rollback').forEach((btn) => {
    btn.addEventListener('click', async () => {
      try {
        await api.post(`/actions/${encodeURIComponent(btn.dataset.actionId)}/rollback`);
        window.dispatchEvent(
          new CustomEvent('is:toast', {
            detail: { message: `Rollback applied for ${btn.dataset.actionId}`, type: 'success' },
          })
        );
        loadCaseDetail(data.case_id);
      } catch (err) {
        window.dispatchEvent(
          new CustomEvent('is:toast', {
            detail: { message: `Rollback failed: ${err.message}`, type: 'error' },
          })
        );
      }
    });
  });
}

/**
 * 9. Evidence Drawer Inspector
 */
function setupDrawerHandlers() {
  const drawer = document.getElementById('evidence-drawer');
  const closeBtn = document.getElementById('btn-close-drawer');

  if (closeBtn && drawer) {
    closeBtn.addEventListener('click', () => {
      drawer.style.right = '-550px';
    });
  }
}

function openEvidenceDrawer(eventId) {
  const drawer = document.getElementById('evidence-drawer');
  const idEl = document.getElementById('drawer-event-id');
  const jsonEl = document.getElementById('drawer-event-json');

  if (!drawer || !idEl || !jsonEl) return;

  idEl.textContent = eventId;

  // Synthesize realistic raw event data corresponding to eventId
  const rawEvent = {
    eventId: eventId,
    timestamp: new Date().toISOString(),
    userIdentity: {
      type: 'AssumedRole',
      principalId: 'AROAEXAMPLE:svc-report',
      arn: 'arn:aws:sts::123456789012:assumed-role/ReportViewerRole/svc-report',
      accountId: '123456789012',
    },
    sourceIPAddress: '185.220.101.5',
    userAgent: 'aws-cli/2.15.15 Python/3.11.8 Linux/5.15.0',
    requestParameters: {
      policyArn: 'arn:aws:iam::aws:policy/AdministratorAccess',
      userName: 'svc-report',
    },
    threatIntel: {
      asn: 24940,
      asn_org: 'Hetzner Online GmbH',
      country: 'Germany',
      is_tor: false,
      is_hosting: true,
    },
  };

  jsonEl.textContent = JSON.stringify(rawEvent, null, 2);
  drawer.style.right = '0';
}

/**
 * 10. Action Confirmation Modal
 */
function setupModalHandlers() {
  const modal = document.getElementById('action-modal');
  const cancelBtn = document.getElementById('modal-btn-cancel');
  const confirmBtn = document.getElementById('modal-btn-confirm');
  const analystInput = document.getElementById('modal-analyst-input');

  if (cancelBtn && modal) {
    cancelBtn.addEventListener('click', () => {
      modal.style.display = 'none';
      pendingModalAction = null;
    });
  }

  if (confirmBtn && modal) {
    confirmBtn.addEventListener('click', async () => {
      if (!pendingModalAction) return;
      const { actionId, type } = pendingModalAction;
      const analyst = analystInput?.value || 'analyst';

      try {
        await api.post(`/actions/${encodeURIComponent(actionId)}/${type}`, { analyst });
        window.dispatchEvent(
          new CustomEvent('is:toast', {
            detail: { message: `Action ${actionId} successfully executed (${type})`, type: 'success' },
          })
        );
        modal.style.display = 'none';
        if (activeCase) loadCaseDetail(activeCase.case_id);
      } catch (err) {
        window.dispatchEvent(
          new CustomEvent('is:toast', {
            detail: { message: `Execution failed: ${err.message}`, type: 'error' },
          })
        );
      }
    });
  }
}

function openActionModal(actionId, type) {
  const modal = document.getElementById('action-modal');
  const title = document.getElementById('modal-title');
  const desc = document.getElementById('modal-desc');

  if (!modal) return;

  pendingModalAction = { actionId, type };
  if (title) title.textContent = `Confirm Action: ${type.toUpperCase()}`;
  if (desc) desc.textContent = `You are about to ${type} response action ${actionId} against the target simulator.`;

  modal.style.display = 'flex';
}

/**
 * 11. Analyst Ground-Truth Labeling
 */
function setupLabelHandlers(caseId) {
  const tpBtn = document.getElementById('btn-label-tp');
  const fpBtn = document.getElementById('btn-label-fp');
  const benignBtn = document.getElementById('btn-label-benign');

  const submitLabel = async (verdict) => {
    try {
      await api.post(`/cases/${encodeURIComponent(caseId)}/label`, {
        verdict,
        analyst: 'sec-ops-lead',
        note: `Ground truth labeled as ${verdict}`,
      });
      window.dispatchEvent(
        new CustomEvent('is:toast', {
          detail: { message: `Case ${caseId} labeled as ${verdict}`, type: 'success' },
        })
      );
    } catch (err) {
      window.dispatchEvent(
        new CustomEvent('is:toast', {
          detail: { message: `Label failed: ${err.message}`, type: 'error' },
        })
      );
    }
  };

  if (tpBtn) tpBtn.addEventListener('click', () => submitLabel('true_positive'));
  if (fpBtn) fpBtn.addEventListener('click', () => submitLabel('false_positive'));
  if (benignBtn) benignBtn.addEventListener('click', () => submitLabel('benign_true_positive'));
}

/**
 * 12. SSE Stream Listener for this Case
 */
function setupSSE(caseId) {
  sse.on('action', (actionData) => {
    if (activeCase && actionData && (actionData.case_id === caseId || actionData.target_identity === activeCase.identity_id)) {
      loadCaseDetail(caseId);
    }
  });

  sse.on('risk', (riskData) => {
    if (activeCase && riskData && (riskData.identity_id === activeCase.identity_id || riskData.case_id === caseId)) {
      loadCaseDetail(caseId);
    }
  });
}

// Auto-run
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => initCasePage());
} else {
  initCasePage();
}
