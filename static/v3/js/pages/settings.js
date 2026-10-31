/**
 * IdentityShield v3 — Settings Page Controller
 * Handles analyst token persistence, config versions rollback, rule suppressions,
 * thresholds, and playbook review.
 */

import { api } from '../core/api.js';
import { fmt, escHtml } from '../core/dom.js';

export async function initSettingsPage() {
  setupTokenManagement();
  await loadConfigVersions();
  await loadThresholdsAndPlaybooks();
}

/**
 * 1. Analyst Token Storage Handlers
 */
function setupTokenManagement() {
  const tokenInput = document.getElementById('input-analyst-token');
  const saveBtn = document.getElementById('btn-save-token');
  const clearBtn = document.getElementById('btn-clear-token');

  // Load existing token if set
  if (tokenInput) {
    tokenInput.value = api.getAnalystToken();
  }

  if (saveBtn && tokenInput) {
    saveBtn.addEventListener('click', () => {
      const val = tokenInput.value.trim();
      api.setAnalystToken(val);
      window.dispatchEvent(
        new CustomEvent('is:toast', {
          detail: { message: 'Analyst token saved to localStorage', type: 'success' },
        })
      );
    });
  }

  if (clearBtn && tokenInput) {
    clearBtn.addEventListener('click', () => {
      tokenInput.value = '';
      api.setAnalystToken('');
      window.dispatchEvent(
        new CustomEvent('is:toast', {
          detail: { message: 'Analyst token cleared', type: 'info' },
        })
      );
    });
  }
}

/**
 * 2. Config Versions & Rollback
 */
async function loadConfigVersions() {
  const container = document.getElementById('config-versions-list');
  if (!container) return;

  try {
    const versions = await api.get('/config/versions');
    const list = Array.isArray(versions) ? versions : [];

    if (list.length === 0) {
      container.innerHTML = '<div style="color:var(--muted); font-size:0.8125rem;">No historical versions recorded.</div>';
      return;
    }

    container.innerHTML = list.map((v) => {
      const isActive = v.is_active;

      return `
        <div style="padding:12px; background:rgba(0,0,0,0.25); border:1px solid ${isActive ? 'var(--brand)' : 'var(--panel-border)'}; border-radius:8px; display:flex; justify-content:space-between; align-items:center;">
          <div>
            <div style="display:flex; align-items:center; gap:8px;">
              <span style="font-family:var(--font-mono); font-weight:700; color:var(--ink);">v${v.version}</span>
              ${isActive ? '<span class="status-pill" style="font-size:0.625rem; color:var(--cyan);"><span class="status-dot ok"></span> ACTIVE</span>' : ''}
              <span style="font-size:0.6875rem; color:var(--muted); font-family:var(--font-mono);">${fmt.timeAgo(v.timestamp)}</span>
            </div>
            <div style="font-size:0.8125rem; color:var(--text); margin-top:2px;">${escHtml(v.description || 'Config snapshot')}</div>
            <div style="font-size:0.6875rem; color:var(--muted); font-family:var(--font-mono); margin-top:2px;">By: ${escHtml(v.author || 'system')}</div>
          </div>

          <div>
            ${
              !isActive
                ? `<button class="btn btn-ghost btn-rollback" data-version="${v.version}" type="button" style="padding:4px 10px; font-size:0.75rem;">Rollback</button>`
                : ''
            }
          </div>
        </div>
      `;
    }).join('');

    container.querySelectorAll('.btn-rollback').forEach((btn) => {
      btn.addEventListener('click', async () => {
        const ver = btn.dataset.version;
        try {
          await api.post(`/config/rollback/${ver}`);
          window.dispatchEvent(
            new CustomEvent('is:toast', {
              detail: { message: `Configuration rolled back to v${ver}`, type: 'success' },
            })
          );
          loadConfigVersions();
        } catch (err) {
          window.dispatchEvent(
            new CustomEvent('is:toast', {
              detail: { message: `Rollback failed: ${err.message}`, type: 'error' },
            })
          );
        }
      });
    });
  } catch (err) {
    console.error('Failed to load config versions:', err);
  }
}

/**
 * 3. Core Thresholds & Playbooks
 */
async function loadThresholdsAndPlaybooks() {
  const threshGrid = document.getElementById('thresholds-grid');
  const playList = document.getElementById('playbooks-list');
  const supList = document.getElementById('suppressions-list');

  try {
    const [cfg, playbooks] = await Promise.all([
      api.get('/config').catch(() => null),
      api.get('/playbooks').catch(() => []),
    ]);

    // Thresholds
    if (threshGrid) {
      const thresholds = cfg?.thresholds || {
        session_risk_step_up: 50,
        session_risk_restrict: 70,
        session_risk_revoke: 90,
        identity_decay_halflife_hours: 24,
        friction_budget_units: 2,
        friction_budget_window_hours: 8,
      };

      threshGrid.innerHTML = Object.entries(thresholds).map(([k, v]) => `
        <div style="padding:10px 12px; background:rgba(0,0,0,0.25); border:1px solid var(--panel-border); border-radius:6px;">
          <div style="font-size:0.6875rem; color:var(--muted); font-family:var(--font-mono);">${escHtml(k)}</div>
          <div style="font-size:1.125rem; font-weight:700; color:var(--ink); font-family:var(--font-mono); margin-top:2px;">${v}</div>
        </div>
      `).join('');
    }

    // Suppressions
    if (supList) {
      const sups = cfg?.proposed_suppressions || [
        { suppression_id: 'sup-001', identity_id: 'backup-worker-svc', detection_id: 'D-ACC-03', reason: 'Scheduled off-hours maintenance worker' },
      ];

      supList.innerHTML = sups.map((s) => `
        <div style="padding:10px 12px; background:rgba(0,0,0,0.25); border:1px solid var(--panel-border); border-radius:8px;">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <span style="font-weight:700; color:var(--ink); font-size:0.8125rem;">${escHtml(s.identity_id)}</span>
            <span class="mitre-chip">${escHtml(s.detection_id)}</span>
          </div>
          <div style="font-size:0.75rem; color:var(--muted); margin:4px 0 8px 0;">${escHtml(s.reason)}</div>
          <div style="display:flex; gap:6px;">
            <button class="btn btn-primary" type="button" style="padding:3px 8px; font-size:0.6875rem;">Approve Suppression</button>
            <button class="btn btn-ghost" type="button" style="padding:3px 8px; font-size:0.6875rem;">Reject</button>
          </div>
        </div>
      `).join('');
    }

    // Playbooks
    if (playList) {
      const pList = Array.isArray(playbooks) ? playbooks : [];
      playList.innerHTML = pList.map((p) => `
        <div style="padding:10px 12px; background:rgba(0,0,0,0.25); border:1px solid var(--panel-border); border-radius:8px;">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <span style="font-weight:700; color:var(--cyan); font-family:var(--font-mono); font-size:0.8125rem;">${escHtml(p.id)}: ${escHtml(p.name)}</span>
            <span style="font-size:0.6875rem; color:var(--muted); font-family:var(--font-mono);">Cost: ${p.friction_budget || 1} units</span>
          </div>
          <div style="font-size:0.75rem; color:var(--muted); font-family:var(--font-mono); margin:4px 0;">Condition: ${escHtml(p.condition)}</div>
          <div style="display:flex; gap:4px;">
            ${(p.actions || []).map((a) => `<span class="badge-band badge-band-${a}" style="font-size:0.625rem; padding:1px 6px;">${escHtml(a)}</span>`).join('')}
          </div>
        </div>
      `).join('');
    }
  } catch (err) {
    console.error('Failed to load thresholds & playbooks:', err);
  }
}

// Auto-run
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => initSettingsPage());
} else {
  initSettingsPage();
}
