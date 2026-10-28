/**
 * Identities management page: searchable list of monitored human and service accounts
 * with risk bars, privilege level dot rating, blast radius, and pivot to graph.
 */
import { api, esc, fmtNum, qs } from './api.js';
import { renderLayout } from './layout.js';
import { bandBadge, emptyState, errorState, riskBar, skeleton, table } from './ui.js';

const isMock = qs('mock') === '1';
const querySuffix = isMock ? '?mock=1' : '';

const content = renderLayout('identities', 'Identities', 'Monitored human and service account identities');

if (content) {
  content.innerHTML = `
    <!-- Top Filter Bar -->
    <div class="bg-panel border border-line rounded-xl p-4 shadow-sm flex flex-col sm:flex-row items-center justify-between gap-4">
      <div class="w-full sm:w-80">
        <label class="sr-only" for="search-identities">Search Identities</label>
        <input
          id="search-identities"
          type="text"
          placeholder="Filter identities..."
          class="w-full bg-panel2 border border-line rounded-lg px-3 py-2 text-sm text-ink placeholder-muted/60 focus:border-brand focus:outline-none font-mono"
        />
      </div>

      <div id="identities-count" class="text-xs text-muted font-medium w-full sm:w-auto text-left sm:text-right">
        Loading identities...
      </div>
    </div>

    <!-- Table Container -->
    <div id="identities-table-container">
      ${skeleton(8)}
    </div>
  `;

  loadIdentities();
}

function getInitials(name) {
  if (!name) return '??';
  const parts = name.split(/[\.\-_ ]+/).filter(Boolean);
  if (parts.length >= 2) {
    return (parts[0][0] + parts[1][0]).toUpperCase();
  }
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

async function loadIdentities() {
  const container = document.getElementById('identities-table-container');
  const countEl = document.getElementById('identities-count');
  const searchInput = document.getElementById('search-identities');
  if (!container) return;

  try {
    const identities = await api('/identities');

    const renderFiltered = (filterText = '') => {
      const q = filterText.toLowerCase().trim();
      const filtered = q ? identities.filter((item) => item.identity_id.toLowerCase().includes(q)) : identities;

      if (countEl) {
        countEl.innerHTML = `Showing <span class="text-ink font-semibold font-mono">${filtered.length}</span> of <span class="font-mono">${identities.length}</span> identities`;
      }

      if (filtered.length === 0) {
        container.innerHTML = `
          <div class="bg-panel border border-line rounded-xl p-8 text-center space-y-3">
            ${emptyState('No identities match your search.')}
            <button id="btn-clear-search" class="text-xs text-brand hover:underline font-medium">Clear search</button>
          </div>
        `;
        const clearBtn = document.getElementById('btn-clear-search');
        if (clearBtn) {
          clearBtn.onclick = () => {
            if (searchInput) searchInput.value = '';
            renderFiltered('');
          };
        }
        return;
      }

      const cols = [
        { label: 'Identity' },
        { label: 'Risk Score' },
        { label: 'Severity Band' },
        { label: 'Privilege Level' },
        { label: 'Blast Radius', align: 'right' },
        { label: 'Active Alerts', align: 'right' },
      ];

      const rowsHtml = filtered
        .map((item) => {
          const band =
            item.risk >= 90 ? 'revoke' : item.risk >= 70 ? 'restrict' : item.risk >= 40 ? 'step_up' : 'monitor';
          const initials = getInitials(item.identity_id);

          return `
            <tr
              tabindex="0"
              role="link"
              data-identity-id="${esc(item.identity_id)}"
              class="identity-row hover:bg-panel2/60 cursor-pointer transition-colors focus:bg-panel2 focus:outline-none"
            >
              <td class="px-4 py-3">
                <div class="flex items-center gap-3">
                  <div class="w-8 h-8 rounded-full bg-panel2 border border-line flex items-center justify-center text-xs font-mono font-bold text-ink flex-shrink-0">
                    ${esc(initials)}
                  </div>
                  <div>
                    <span class="font-mono text-xs font-semibold text-ink">${esc(item.identity_id)}</span>
                  </div>
                </div>
              </td>
              <td class="px-4 py-3">
                ${riskBar(item.risk, band)}
              </td>
              <td class="px-4 py-3">
                ${bandBadge(band)}
              </td>
              <td class="px-4 py-3">
                ${renderPrivilegeDots(item.privilege_level)}
              </td>
              <td class="px-4 py-3 text-right font-mono text-xs tabular-nums text-muted">
                ${fmtNum(item.blast_radius)}
              </td>
              <td class="px-4 py-3 text-right font-mono text-xs tabular-nums text-ink font-semibold">
                ${fmtNum(item.alerts)}
              </td>
            </tr>
          `;
        })
        .join('');

      container.innerHTML = table(cols, rowsHtml);

      // Attach row click and keyboard navigation
      container.querySelectorAll('.identity-row').forEach((row) => {
        const uid = row.dataset.identityId;
        const targetUrl = `/graph.html?identity=${encodeURIComponent(uid)}${querySuffix}`;

        row.onclick = () => {
          window.location.href = targetUrl;
        };
        row.onkeydown = (e) => {
          if (e.key === 'Enter') {
            window.location.href = targetUrl;
          }
        };
      });
    };

    renderFiltered('');

    if (searchInput) {
      searchInput.oninput = () => {
        renderFiltered(searchInput.value);
      };
    }
  } catch (err) {
    container.innerHTML = errorState(err.message, 'btn-retry-identities');
    const retryBtn = document.getElementById('btn-retry-identities');
    if (retryBtn) retryBtn.onclick = () => loadIdentities();
  }
}
