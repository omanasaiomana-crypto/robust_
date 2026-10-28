/**
 * Alerts queue page: interactive filter bar, count summary, and accessible table.
 */
import { api, esc, fmtTime, qs } from './api.js';
import { renderLayout } from './layout.js';
import { bandBadge, button, emptyState, errorState, mitreChip, patternChip, riskBar, skeleton, table } from './ui.js';

const isMock = qs('mock') === '1';
const querySuffix = isMock ? '?mock=1' : '';

const content = renderLayout('alerts', 'Alert Queue', 'Prioritized session-level identity threats');

if (content) {
  content.innerHTML = `
    <!-- Filter Bar Card -->
    <div class="bg-panel border border-line rounded-xl p-4 shadow-sm">
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 items-center">
        <!-- Identity Search -->
        <div>
          <label class="block text-xs font-medium text-muted uppercase tracking-wider mb-1.5" for="filter-search">Identity</label>
          <div class="relative">
            <input
              id="filter-search"
              type="text"
              placeholder="Filter by identity..."
              class="w-full bg-panel2 border border-line rounded-lg px-3 py-2 text-sm text-ink placeholder-muted/60 focus:border-brand focus:outline-none font-mono"
            />
          </div>
        </div>

        <!-- Band Select -->
        <div>
          <label class="block text-xs font-medium text-muted uppercase tracking-wider mb-1.5" for="filter-band">Severity Band</label>
          <select id="filter-band" class="w-full bg-panel2 border border-line rounded-lg px-3 py-2 text-sm text-ink focus:border-brand focus:outline-none">
            <option value="">All severity bands</option>
            <option value="revoke">Revoke (≥90)</option>
            <option value="restrict">Restrict (70-89)</option>
            <option value="step_up">Step-up (40-69)</option>
            <option value="monitor">Monitor (&lt;40)</option>
          </select>
        </div>

        <!-- Pattern Select -->
        <div>
          <label class="block text-xs font-medium text-muted uppercase tracking-wider mb-1.5" for="filter-pattern">Attack Pattern</label>
          <select id="filter-pattern" class="w-full bg-panel2 border border-line rounded-lg px-3 py-2 text-sm text-ink focus:border-brand focus:outline-none font-mono">
            <option value="">All patterns</option>
            <option value="P1">P1 Impossible travel</option>
            <option value="P2">P2 Dormant account</option>
            <option value="P3">P3 Privilege escalation</option>
            <option value="P4">P4 Unusual API</option>
            <option value="P5">P5 Token abuse</option>
            <option value="ML">ML Behavior anomaly</option>
          </select>
        </div>

        <!-- Min Risk Range Slider -->
        <div>
          <div class="flex items-center justify-between mb-1.5">
            <label class="text-xs font-medium text-muted uppercase tracking-wider" for="filter-risk">Min Risk</label>
            <span id="risk-val" class="text-xs font-mono font-semibold text-ink tabular-nums">0</span>
          </div>
          <input
            id="filter-risk"
            type="range"
            min="0"
            max="100"
            value="0"
            class="w-full h-2 bg-line rounded-lg appearance-none cursor-pointer accent-brand"
          />
        </div>
      </div>
    </div>

    <!-- Summary Count Bar -->
    <div class="flex items-center justify-between px-1">
      <div id="alert-summary" class="text-xs font-medium text-muted">
        Loading alerts...
      </div>
    </div>

    <!-- Alerts Table Wrapper -->
    <div id="alerts-table-container">
      ${skeleton(6)}
    </div>
  `;

  initAlertsPage();
}

function truncateSession(s) {
  if (!s) return '—';
  const str = String(s);
  if (str.length <= 20) return str;
  return str.slice(0, 9) + '…' + str.slice(-8);
}

function initAlertsPage() {
  const searchInput = document.getElementById('filter-search');
  const bandSelect = document.getElementById('filter-band');
  const patternSelect = document.getElementById('filter-pattern');
  const riskSlider = document.getElementById('filter-risk');
  const riskVal = document.getElementById('risk-val');

  // Initialize values from URL query params
  const initialSearch = qs('identity') || '';
  const initialBand = qs('band') || '';
  const initialPattern = qs('pattern') || '';
  const initialMinRisk = qs('min_risk') || '0';

  if (searchInput) searchInput.value = initialSearch;
  if (bandSelect) bandSelect.value = initialBand;
  if (patternSelect) patternSelect.value = initialPattern;
  if (riskSlider) {
    riskSlider.value = initialMinRisk;
    if (riskVal) riskVal.textContent = initialMinRisk;
  }

  const updateFiltersAndFetch = () => {
    const ident = searchInput ? searchInput.value.trim() : '';
    const band = bandSelect ? bandSelect.value : '';
    const pattern = patternSelect ? patternSelect.value : '';
    const minRisk = riskSlider ? riskSlider.value : '0';

    if (riskVal) riskVal.textContent = minRisk;

    // Update URL query parameters without reloading
    const params = new URLSearchParams();
    if (isMock) params.set('mock', '1');
    if (ident) params.set('identity', ident);
    if (band) params.set('band', band);
    if (pattern) params.set('pattern', pattern);
    if (Number(minRisk) > 0) params.set('min_risk', minRisk);

    const newUrl = `${window.location.pathname}${params.toString() ? '?' + params.toString() : ''}`;
    window.history.replaceState(null, '', newUrl);

    fetchAndRenderAlerts({ identity: ident, band, pattern, min_risk: minRisk });
  };

  let debounceTimer;
  if (searchInput) {
    searchInput.oninput = () => {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(updateFiltersAndFetch, 250);
    };
  }

  if (bandSelect) bandSelect.onchange = updateFiltersAndFetch;
  if (patternSelect) patternSelect.onchange = updateFiltersAndFetch;
  if (riskSlider) {
    riskSlider.oninput = () => {
      if (riskVal) riskVal.textContent = riskSlider.value;
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(updateFiltersAndFetch, 100);
    };
  }

  // Initial fetch
  fetchAndRenderAlerts({
    identity: initialSearch,
    band: initialBand,
    pattern: initialPattern,
    min_risk: initialMinRisk,
  });
}

async function fetchAndRenderAlerts({ identity = '', band = '', pattern = '', min_risk = '0' } = {}) {
  const container = document.getElementById('alerts-table-container');
  const summaryEl = document.getElementById('alert-summary');
  if (!container) return;

  const params = new URLSearchParams();
  if (identity) params.set('identity', identity);
  if (band) params.set('band', band);
  if (pattern) params.set('pattern', pattern);
  if (Number(min_risk) > 0) params.set('min_risk', min_risk);

  const queryStr = params.toString() ? `?${params.toString()}` : '';

  try {
    const alerts = await api(`/alerts${queryStr}`);
    const totalCount = alerts.length;
    const criticalCount = alerts.filter((a) => a.band === 'revoke').length;

    if (summaryEl) {
      summaryEl.innerHTML = `Showing <span class="text-ink font-semibold font-mono">${totalCount}</span> alerts · <span class="text-crit font-semibold font-mono">${criticalCount}</span> critical`;
    }

    if (!alerts || alerts.length === 0) {
      container.innerHTML = `
        <div class="bg-panel border border-line rounded-xl p-8 text-center space-y-4">
          ${emptyState('No alerts match the active filters.')}
          <div>
            ${button('Clear filters', { variant: 'secondary', id: 'btn-clear-filters' })}
          </div>
        </div>
      `;

      const clearBtn = document.getElementById('btn-clear-filters');
      if (clearBtn) {
        clearBtn.onclick = () => {
          const searchInput = document.getElementById('filter-search');
          const bandSelect = document.getElementById('filter-band');
          const patternSelect = document.getElementById('filter-pattern');
          const riskSlider = document.getElementById('filter-risk');
          const riskVal = document.getElementById('risk-val');

          if (searchInput) searchInput.value = '';
          if (bandSelect) bandSelect.value = '';
          if (patternSelect) patternSelect.value = '';
          if (riskSlider) riskSlider.value = 0;
          if (riskVal) riskVal.textContent = '0';

          const params = new URLSearchParams();
          if (isMock) params.set('mock', '1');
          window.history.replaceState(null, '', `${window.location.pathname}${params.toString() ? '?' + params.toString() : ''}`);
          fetchAndRenderAlerts();
        };
      }
      return;
    }

    const cols = [
      { label: 'Risk' },
      { label: 'Band' },
      { label: 'Identity' },
      { label: 'Session' },
      { label: 'Patterns' },
      { label: 'MITRE' },
      { label: 'Recommended' },
      { label: 'Status' },
      { label: 'Last Seen' },
    ];

    const rowsHtml = alerts
      .map((a) => {
        const patternChips = a.patterns ? a.patterns.map((p) => patternChip(p)).join(' ') : '—';
        const mitreChips = a.mitre && a.mitre.length > 0 ? a.mitre.map((m) => mitreChip(m)).join(' ') : '—';

        return `
          <tr
            tabindex="0"
            role="link"
            data-alert-id="${esc(a.alert_id)}"
            class="alert-row cursor-pointer hover:bg-panel2/60 transition-colors focus:bg-panel2 focus:outline-none"
          >
            <td class="px-4 py-3">
              ${riskBar(a.risk, a.band)}
            </td>
            <td class="px-4 py-3">
              ${bandBadge(a.band)}
            </td>
            <td class="px-4 py-3">
              <span class="font-mono text-xs font-semibold text-ink">${esc(a.identity_id)}</span>
            </td>
            <td class="px-4 py-3">
              <span class="font-mono text-[11px] text-muted truncate block max-w-[140px]" title="${esc(a.session_id)}">
                ${esc(truncateSession(a.session_id))}
              </span>
            </td>
            <td class="px-4 py-3">
              <div class="flex items-center gap-1 flex-wrap">${patternChips}</div>
            </td>
            <td class="px-4 py-3">
              <div class="flex items-center gap-1 flex-wrap">${mitreChips}</div>
            </td>
            <td class="px-4 py-3">
              <span class="capitalize text-xs font-mono text-muted">${esc(a.recommended_action)}</span>
            </td>
            <td class="px-4 py-3">
              <span class="capitalize text-[11px] font-mono px-2 py-0.5 rounded bg-panel2 border border-line text-muted">
                ${esc(a.action_status)}
              </span>
            </td>
            <td class="px-4 py-3 text-right">
              <span class="text-xs text-muted font-mono whitespace-nowrap">${fmtTime(a.last_seen)}</span>
            </td>
          </tr>
        `;
      })
      .join('');

    container.innerHTML = table(cols, rowsHtml);

    // Make rows keyboard and click accessible
    container.querySelectorAll('.alert-row').forEach((row) => {
      const aid = row.dataset.alertId;
      const targetUrl = `/alert.html?id=${encodeURIComponent(aid)}${querySuffix}`;

      row.onclick = () => {
        window.location.href = targetUrl;
      };

      row.onkeydown = (e) => {
        if (e.key === 'Enter') {
          window.location.href = targetUrl;
        }
      };
    });
  } catch (err) {
    container.innerHTML = errorState(err.message, 'btn-retry-alerts');
    const retryBtn = document.getElementById('btn-retry-alerts');
    if (retryBtn) {
      retryBtn.onclick = () => fetchAndRenderAlerts({ identity, band, pattern, min_risk });
    }
  }
}
