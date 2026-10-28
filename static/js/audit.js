/**
 * Audit Log page: cryptographically verified tamper-evident decision ledger.
 * Displays SHA-256 chained sequence verification banner, interactive re-verification,
 * and searchable audit trail with agent chips, actions, and hash previews.
 */
import { api, esc, fmtTime, qs } from './api.js';
import { renderLayout } from './layout.js';
import { errorState, skeleton, table, toast } from './ui.js';

const isMock = qs('mock') === '1';
const querySuffix = isMock ? '?mock=1' : '';

const content = renderLayout('audit', 'Audit Log', 'Cryptographically verified tamper-evident decision ledger');

if (content) {
  content.innerHTML = `
    <div class="space-y-6">
      <!-- Top Verification Status Banner -->
      <div id="audit-banner-container">
        ${skeleton(2)}
      </div>

      <!-- Controls & Filter Bar -->
      <div class="bg-panel border border-line rounded-xl p-4 shadow-sm flex flex-col sm:flex-row items-center justify-between gap-4">
        <div class="w-full sm:w-80">
          <label class="sr-only" for="search-audit">Search Audit Records</label>
          <input
            id="search-audit"
            type="text"
            placeholder="Filter by agent, action, detail..."
            class="w-full bg-panel2 border border-line rounded-lg px-3 py-2 text-sm text-ink placeholder-muted/60 focus:border-brand focus:outline-none font-mono"
          />
        </div>

        <div id="audit-count" class="text-xs text-muted font-medium w-full sm:w-auto text-left sm:text-right">
          Loading audit entries...
        </div>
      </div>

      <!-- Audit Entries Table -->
      <div id="audit-table-container">
        ${skeleton(8)}
      </div>
    </div>
  `;

  loadAuditPage();
}

function renderAgentChip(agent) {
  const ag = String(agent || 'system').toLowerCase();
  let colorCls = 'bg-panel2 border-line text-ink';

  if (ag === 'pipeline') colorCls = 'bg-blue-950/60 border-blue-800/50 text-blue-400';
  else if (ag === 'scoring') colorCls = 'bg-cyan-950/60 border-cyan-800/50 text-cyan-400';
  else if (ag === 'response') colorCls = 'bg-amber-950/60 border-amber-800/50 text-amber-400';
  else if (ag === 'feedback') colorCls = 'bg-purple-950/60 border-purple-800/50 text-purple-400';
  else if (ag === 'evaluator') colorCls = 'bg-emerald-950/60 border-emerald-800/50 text-emerald-400';

  return `<span class="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono font-medium border ${colorCls}">${esc(agent)}</span>`;
}

function renderActionBadge(action) {
  const act = String(action || '').toLowerCase();
  let col = 'text-ink';
  if (act === 'revoke' || act === 'restrict') col = 'text-crit font-semibold';
  else if (act === 'step_up') col = 'text-warn font-semibold';
  else if (act === 'monitor') col = 'text-slate-300 font-medium';
  else if (act === 'start' || act === 'end') col = 'text-brand2 font-mono';

  return `<span class="text-xs font-mono ${col}">${esc(action)}</span>`;
}

function renderBanner(verifyData, totalEntries) {
  const bannerEl = document.getElementById('audit-banner-container');
  if (!bannerEl) return;

  const isValid = Boolean(verifyData?.valid);
  const brokenAt = verifyData?.broken_at;

  if (isValid) {
    bannerEl.innerHTML = `
      <div class="bg-ok/10 border border-ok/30 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4 shadow-sm">
        <div class="flex items-center gap-3.5">
          <div class="w-9 h-9 rounded-full bg-ok/20 border border-ok/40 flex items-center justify-center text-ok font-bold text-base flex-shrink-0 shadow-sm">
            ✓
          </div>
          <div>
            <h4 class="text-sm font-semibold text-ok">Audit chain intact · ${totalEntries} entries verified</h4>
            <p class="text-xs text-muted mt-0.5">SHA-256 cryptographic hash sequence verified without tampering or broken links.</p>
          </div>
        </div>

        <button
          id="btn-verify-again"
          class="px-3.5 py-2 rounded-lg text-xs font-semibold bg-panel2 border border-line hover:bg-line text-ink transition-colors flex items-center gap-2 self-start sm:self-auto shadow-sm"
        >
          <span id="verify-spinner" class="hidden animate-spin">⟳</span>
          <span>Verify again</span>
        </button>
      </div>
    `;
  } else {
    bannerEl.innerHTML = `
      <div class="bg-crit/10 border border-crit/30 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4 shadow-sm">
        <div class="flex items-center gap-3.5">
          <div class="w-9 h-9 rounded-full bg-crit/20 border border-crit/40 flex items-center justify-center text-crit font-bold text-base flex-shrink-0 shadow-sm">
            ✗
          </div>
          <div>
            <h4 class="text-sm font-semibold text-crit">Audit chain broken at entry #${esc(brokenAt ?? 'unknown')}</h4>
            <p class="text-xs text-muted mt-0.5">Cryptographic integrity check failed. Block hash does not match expected parent chain.</p>
          </div>
        </div>

        <button
          id="btn-verify-again"
          class="px-3.5 py-2 rounded-lg text-xs font-semibold bg-panel2 border border-line hover:bg-line text-ink transition-colors flex items-center gap-2 self-start sm:self-auto shadow-sm"
        >
          <span id="verify-spinner" class="hidden animate-spin">⟳</span>
          <span>Verify again</span>
        </button>
      </div>
    `;
  }

  // Bind Verify Again action
  const verifyBtn = document.getElementById('btn-verify-again');
  const spinner = document.getElementById('verify-spinner');
  if (verifyBtn) {
    verifyBtn.onclick = async () => {
      verifyBtn.disabled = true;
      if (spinner) spinner.classList.remove('hidden');
      try {
        const freshVerify = await api('/audit/verify');
        renderBanner(freshVerify, totalEntries);
        if (freshVerify.valid) {
          toast(`Audit chain intact · All ${totalEntries} entries verified`, 'success');
        } else {
          toast(`Audit chain broken at entry #${freshVerify.broken_at}`, 'error');
        }
      } catch (err) {
        toast(`Verification check failed: ${err.message}`, 'error');
      } finally {
        verifyBtn.disabled = false;
        if (spinner) spinner.classList.add('hidden');
      }
    };
  }
}

async function loadAuditPage() {
  const tableContainer = document.getElementById('audit-table-container');
  const countEl = document.getElementById('audit-count');
  const searchInput = document.getElementById('search-audit');

  try {
    const [verifyData, entries] = await Promise.all([api('/audit/verify'), api('/audit')]);

    const auditList = Array.isArray(entries) ? entries : [];
    renderBanner(verifyData, auditList.length);

    const cols = [
      { label: 'Seq', align: 'center' },
      { label: 'Timestamp' },
      { label: 'Agent' },
      { label: 'Action' },
      { label: 'Detail' },
      { label: 'Hash (SHA-256)' },
    ];

    const renderFiltered = (filterText = '') => {
      const q = filterText.toLowerCase().trim();
      const filtered = q
        ? auditList.filter(
            (it) =>
              String(it.seq).includes(q) ||
              String(it.agent || '').toLowerCase().includes(q) ||
              String(it.action || '').toLowerCase().includes(q) ||
              String(it.detail || '').toLowerCase().includes(q) ||
              String(it.hash || '').toLowerCase().includes(q)
          )
        : auditList;

      if (countEl) {
        countEl.innerHTML = `Showing <span class="text-ink font-semibold font-mono">${filtered.length}</span> of <span class="font-mono">${auditList.length}</span> entries`;
      }

      if (filtered.length === 0) {
        tableContainer.innerHTML = `
          <div class="bg-panel border border-line rounded-xl p-8 text-center text-muted">
            <p class="text-sm">No audit records match your search query.</p>
          </div>
        `;
        return;
      }

      const rowsHtml = filtered
        .map((it) => {
          const shortHash = (it.hash || '').slice(0, 12);
          const fullHash = it.hash || '';

          return `
            <tr class="hover:bg-panel2/60 transition-colors">
              <td class="px-4 py-3 text-center font-mono text-xs text-muted tabular-nums">
                #${esc(it.seq)}
              </td>
              <td class="px-4 py-3 font-mono text-xs text-muted whitespace-nowrap">
                ${fmtTime(it.timestamp)}
              </td>
              <td class="px-4 py-3">
                ${renderAgentChip(it.agent)}
              </td>
              <td class="px-4 py-3">
                ${renderActionBadge(it.action)}
              </td>
              <td class="px-4 py-3">
                <div class="max-w-md truncate text-xs text-ink/90 font-sans" title="${esc(it.detail || '')}">
                  ${esc(it.detail || '—')}
                </div>
              </td>
              <td class="px-4 py-3">
                <span class="font-mono text-xs text-brand2 hover:underline cursor-help" title="Full SHA-256 hash: ${esc(fullHash)}">
                  ${esc(shortHash)}…
                </span>
              </td>
            </tr>
          `;
        })
        .join('');

      tableContainer.innerHTML = table(cols, rowsHtml);
    };

    renderFiltered('');

    if (searchInput) {
      searchInput.oninput = () => {
        renderFiltered(searchInput.value);
      };
    }
  } catch (err) {
    if (tableContainer) {
      tableContainer.innerHTML = errorState(err.message, 'btn-retry-audit');
      const retryBtn = document.getElementById('btn-retry-audit');
      if (retryBtn) retryBtn.onclick = () => loadAuditPage();
    }
  }
}
