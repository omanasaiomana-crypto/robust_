/**
 * Identity Hygiene page: prevention and posture assessment.
 * Surfaces dormant privileged accounts and toxic paths to administrator roles.
 */
import { api, esc, fmtNum, fmtTime, qs } from './api.js';
import { renderLayout } from './layout.js';
import { bandBadge, emptyState, errorState, skeleton, table } from './ui.js';

const isMock = qs('mock') === '1';
const querySuffix = isMock ? '?mock=1' : '';

const content = renderLayout('hygiene', 'Identity Hygiene', 'Dormant privileged credentials and toxic escalation paths');

if (content) {
  content.innerHTML = `
    <div class="space-y-6">
      <!-- Card 1: Dormant Privileged Accounts -->
      <div class="bg-panel border border-line rounded-xl p-5 shadow-sm space-y-4">
        <div>
          <h3 class="text-sm font-semibold text-ink">Dormant privileged accounts</h3>
          <p class="text-xs text-muted mt-0.5">High-privilege accounts inactive for 30+ days before unexpected reactivation.</p>
        </div>
        <div id="dormant-container">
          ${skeleton(3)}
        </div>
      </div>

      <!-- Card 2: Paths to Admin -->
      <div class="bg-panel border border-line rounded-xl p-5 shadow-sm space-y-4">
        <div>
          <h3 class="text-sm font-semibold text-ink">Paths to admin</h3>
          <p class="text-xs text-muted mt-0.5">Discovered role assumption, token grant, and policy chains providing routes to administrator privileges.</p>
        </div>
        <div id="paths-container">
          ${skeleton(4)}
        </div>
      </div>
    </div>
  `;

  loadHygiene();
}

function getInitials(name) {
  if (!name) return '??';
  const parts = name.split(/[\.\-_ ]+/).filter(Boolean);
  if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
  return name.slice(0, 2).toUpperCase();
}

function renderPrivilegeDots(level) {
  const lvl = Math.max(1, Math.min(5, Number(level) || 1));
  const dots = [];
  for (let i = 1; i <= 5; i++) {
    const isFilled = i <= lvl;
    let dotColor = 'bg-line';
    if (isFilled) {
      if (lvl >= 4) dotColor = 'bg-crit';
      else if (lvl === 3) dotColor = 'bg-warn';
      else dotColor = 'bg-brand';
    }
    dots.push(`<span class="w-2 h-2 rounded-full ${dotColor} inline-block" title="Level ${lvl}"></span>`);
  }
  return `
    <div class="flex items-center gap-1.5" title="Privilege Level ${lvl}/5">
      ${dots.join('')}
      <span class="text-[11px] font-mono text-muted ml-1">${lvl}/5</span>
    </div>
  `;
}

function formatNodeChip(rawNodeId) {
  const node = String(rawNodeId);
  let kind = 'resource';
  let label = node;

  if (node.includes(':')) {
    const idx = node.indexOf(':');
    kind = node.slice(0, idx);
    label = node.slice(idx + 1);
  }

  let colorClasses = 'bg-panel2 border-line text-ink';
  if (kind === 'user') colorClasses = 'bg-cyan-950/60 border-cyan-800/50 text-cyan-400';
  else if (kind === 'session') colorClasses = 'bg-purple-950/60 border-purple-800/50 text-purple-400';
  else if (kind === 'role') colorClasses = 'bg-amber-950/60 border-amber-800/50 text-amber-400';
  else if (kind === 'key') colorClasses = 'bg-orange-950/60 border-orange-800/50 text-orange-400';
  else if (kind === 'policy') colorClasses = 'bg-red-950/60 border-red-800/50 text-red-400';
  else if (kind === 'resource') colorClasses = 'bg-emerald-950/60 border-emerald-800/50 text-emerald-400';
  else if (kind === 'ip') colorClasses = 'bg-slate-900 border-slate-700 text-slate-300';

  return `<span class="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono font-medium border ${colorClasses}">${esc(label)}</span>`;
}

async function loadHygiene() {
  const dormantEl = document.getElementById('dormant-container');
  const pathsEl = document.getElementById('paths-container');

  try {
    const data = await api('/hygiene');
    const dormantList = data.dormant_admins || [];
    const pathsList = data.escalation_paths || [];

    // 1. Render Dormant Privileged Accounts
    if (dormantEl) {
      if (dormantList.length === 0) {
        dormantEl.innerHTML = emptyState('No dormant privileged accounts');
      } else {
        const cols = [
          { label: 'Identity' },
          { label: 'Privilege Level' },
          { label: 'Days Idle', align: 'right' },
          { label: 'Last Activity' },
          { label: 'Risk Badge' },
          { label: 'Action', align: 'right' },
        ];

        const rowsHtml = dormantList
          .map((item) => {
            const riskBand =
              item.risk != null
                ? item.risk >= 90
                  ? 'revoke'
                  : item.risk >= 70
                  ? 'restrict'
                  : item.risk >= 40
                  ? 'step_up'
                  : 'monitor'
                : item.privilege_level >= 5
                ? 'revoke'
                : item.privilege_level >= 4
                ? 'restrict'
                : 'step_up';

            const initials = getInitials(item.identity_id);
            const graphUrl = `/graph.html?identity=${encodeURIComponent(item.identity_id)}${querySuffix}`;

            return `
              <tr class="hover:bg-panel2/60 transition-colors">
                <td class="px-4 py-3">
                  <div class="flex items-center gap-3">
                    <div class="w-8 h-8 rounded-full bg-panel2 border border-line flex items-center justify-center text-xs font-mono font-bold text-ink flex-shrink-0">
                      ${esc(initials)}
                    </div>
                    <span class="font-mono text-xs font-semibold text-ink">${esc(item.identity_id)}</span>
                  </div>
                </td>
                <td class="px-4 py-3">
                  ${renderPrivilegeDots(item.privilege_level)}
                </td>
                <td class="px-4 py-3 text-right font-mono text-xs tabular-nums text-warn font-semibold">
                  ${fmtNum(item.gap_days)} days
                </td>
                <td class="px-4 py-3">
                  <div class="text-xs font-mono text-ink">${fmtTime(item.last_seen)}</div>
                  <div class="text-[11px] font-mono text-muted/80">${esc(item.action || '')}</div>
                </td>
                <td class="px-4 py-3">
                  ${bandBadge(riskBand)}
                </td>
                <td class="px-4 py-3 text-right">
                  <a href="${graphUrl}" class="px-2.5 py-1 rounded text-xs font-medium text-brand hover:underline inline-flex items-center gap-1">
                    Graph →
                  </a>
                </td>
              </tr>
            `;
          })
          .join('');

        dormantEl.innerHTML = table(cols, rowsHtml);
      }
    }

    // 2. Render Paths to Admin
    if (pathsEl) {
      if (pathsList.length === 0) {
        pathsEl.innerHTML = emptyState('No paths to admin discovered.');
      } else {
        const cols = [
          { label: 'Identity' },
          { label: 'Risk Band' },
          { label: 'Escalation Chain' },
          { label: 'Graph View', align: 'right' },
        ];

        const rowsHtml = pathsList
          .map((item) => {
            const riskBand =
              item.risk >= 90 ? 'revoke' : item.risk >= 70 ? 'restrict' : item.risk >= 40 ? 'step_up' : 'monitor';
            const initials = getInitials(item.identity_id);
            const graphUrl = `/graph.html?identity=${encodeURIComponent(item.identity_id)}${querySuffix}`;

            // Render all discovered paths
            const pathsHtml = (item.paths || [])
              .map((p, idx) => {
                const chips = p.map((node) => formatNodeChip(node));
                return `
                  <div class="flex items-center gap-1.5 flex-wrap py-1">
                    <span class="text-[10px] font-mono font-bold text-crit/80 uppercase mr-1">#${idx + 1}</span>
                    ${chips.join('<span class="text-brand font-bold text-xs">→</span>')}
                  </div>
                `;
              })
              .join('');

            return `
              <tr class="hover:bg-panel2/60 transition-colors">
                <td class="px-4 py-3.5 align-top">
                  <div class="flex items-center gap-3">
                    <div class="w-8 h-8 rounded-full bg-panel2 border border-line flex items-center justify-center text-xs font-mono font-bold text-ink flex-shrink-0">
                      ${esc(initials)}
                    </div>
                    <div>
                      <span class="font-mono text-xs font-semibold text-ink">${esc(item.identity_id)}</span>
                      <div class="text-[11px] font-mono text-muted">${(item.paths || []).length} route${(item.paths || []).length === 1 ? '' : 's'}</div>
                    </div>
                  </div>
                </td>
                <td class="px-4 py-3.5 align-top">
                  ${bandBadge(riskBand)}
                </td>
                <td class="px-4 py-3.5 align-top">
                  <div class="space-y-1">
                    ${pathsHtml || '<span class="text-xs text-muted">No explicit paths</span>'}
                  </div>
                </td>
                <td class="px-4 py-3.5 align-top text-right">
                  <a
                    href="${graphUrl}"
                    class="px-3 py-1.5 rounded-lg text-xs font-medium bg-panel2 border border-line hover:bg-line text-brand hover:text-ink transition-colors inline-flex items-center gap-1.5 shadow-sm"
                  >
                    <span>View in Graph</span>
                    <span>→</span>
                  </a>
                </td>
              </tr>
            `;
          })
          .join('');

        pathsEl.innerHTML = table(cols, rowsHtml);
      }
    }
  } catch (err) {
    if (dormantEl) dormantEl.innerHTML = errorState(err.message, 'btn-retry-hygiene');
    if (pathsEl) pathsEl.innerHTML = '';
    const retryBtn = document.getElementById('btn-retry-hygiene');
    if (retryBtn) retryBtn.onclick = () => loadHygiene();
  }
}
