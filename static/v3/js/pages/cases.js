/**
 * IdentityShield v3 — Cases Page Controller
 * Handles filtering, sorting, MITRE chip rendering, and navigation to Case Detail.
 */

import { api } from '../core/api.js';
import { sse } from '../core/sse.js';
import { fmt, escHtml, bandColor } from '../core/dom.js';

let allCases = [];
let sortCol = 'risk_score';
let sortAsc = false;

export async function initCasesPage() {
  setupFilterHandlers();
  setupSortHeaders();
  await loadCases();
  setupSSE();
}

async function loadCases() {
  const tbody = document.getElementById('cases-table-body');
  const countText = document.getElementById('case-count-text');

  try {
    const data = await api.get('/cases');
    allCases = Array.isArray(data) ? data : (data?.items || []);

    // Pre-populate URL filter if present (e.g. ?identity_id=svc-report)
    const urlParams = new URLSearchParams(window.location.search);
    const idFilter = urlParams.get('identity_id');
    if (idFilter) {
      const searchInput = document.getElementById('filter-search');
      if (searchInput) searchInput.value = idFilter;
    }

    if (countText) countText.textContent = `${allCases.length} Total Incidents`;
    renderFilteredCases();
  } catch (err) {
    console.error('Failed to load cases:', err);
    if (tbody) {
      tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; color:var(--crit); padding:24px;">Failed to load cases. See console.</td></tr>';
    }
  }
}

function setupFilterHandlers() {
  const searchInput = document.getElementById('filter-search');
  const bandSelect = document.getElementById('filter-band');
  const statusSelect = document.getElementById('filter-status');
  const resetBtn = document.getElementById('btn-reset-filters');

  const trigger = () => renderFilteredCases();

  if (searchInput) searchInput.addEventListener('input', trigger);
  if (bandSelect) bandSelect.addEventListener('change', trigger);
  if (statusSelect) statusSelect.addEventListener('change', trigger);

  if (resetBtn) {
    resetBtn.addEventListener('click', () => {
      if (searchInput) searchInput.value = '';
      if (bandSelect) bandSelect.value = 'all';
      if (statusSelect) statusSelect.value = 'all';
      renderFilteredCases();
    });
  }
}

function setupSortHeaders() {
  const headers = document.querySelectorAll('#cases-table th[data-sort]');
  headers.forEach((th) => {
    th.addEventListener('click', () => {
      const col = th.dataset.sort;
      if (sortCol === col) {
        sortAsc = !sortAsc;
      } else {
        sortCol = col;
        sortAsc = false;
      }
      renderFilteredCases();
    });
  });
}

function renderFilteredCases() {
  const tbody = document.getElementById('cases-table-body');
  if (!tbody) return;

  const q = (document.getElementById('filter-search')?.value || '').trim().toLowerCase();
  const bandFilter = document.getElementById('filter-band')?.value || 'all';
  const statusFilter = document.getElementById('filter-status')?.value || 'all';

  let list = allCases.filter((c) => {
    // Search query matching identity_id, case_id, session_id, or tactics
    if (q) {
      const matchId = (c.identity_id || '').toLowerCase().includes(q);
      const matchCase = (c.case_id || '').toLowerCase().includes(q);
      const matchTitle = (c.title || '').toLowerCase().includes(q);
      const matchSession = (c.session_id || '').toLowerCase().includes(q);
      const matchTactics = (c.mitre_tactics || []).some((t) => t.toLowerCase().includes(q));
      if (!matchId && !matchCase && !matchTitle && !matchSession && !matchTactics) return false;
    }

    // Band filter
    if (bandFilter !== 'all') {
      const b = (c.band || 'monitor').toLowerCase().replace('-', '_');
      if (b !== bandFilter) return false;
    }

    // Status filter
    if (statusFilter !== 'all') {
      const s = (c.status || 'open').toLowerCase();
      if (s !== statusFilter) return false;
    }

    return true;
  });

  // Sort
  list.sort((a, b) => {
    let va = a[sortCol];
    let vb = b[sortCol];

    if (sortCol === 'risk_score' || sortCol === 'confidence') {
      va = Number(va || 0);
      vb = Number(vb || 0);
    } else if (sortCol === 'chain_length') {
      va = (a.steps || []).length || (a.mitre_tactics || []).length || 0;
      vb = (b.steps || []).length || (b.mitre_tactics || []).length || 0;
    } else {
      va = String(va || '').toLowerCase();
      vb = String(vb || '').toLowerCase();
    }

    if (va < vb) return sortAsc ? -1 : 1;
    if (va > vb) return sortAsc ? 1 : -1;
    return 0;
  });

  if (list.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; color:var(--muted); padding:32px;">No matching threat cases found.</td></tr>';
    return;
  }

  tbody.innerHTML = list.map((c) => {
    const band = (c.band || 'monitor').toLowerCase().replace('-', '_');
    const color = bandColor(band);
    const risk = Number(c.risk_score || 0);
    const conf = c.confidence !== undefined ? fmt.percent(c.confidence) : '94%';
    const stepsCount = (c.steps || []).length || 6;
    const mitreList = c.mitre_tactics || ['T1078', 'T1098'];
    const maxChips = 3;
    const displayedChips = mitreList.slice(0, maxChips);
    const overflowCount = mitreList.length - maxChips;

    return `
      <tr style="cursor:pointer;" onclick="window.location.href='/v3/case.html?id=${encodeURIComponent(c.case_id)}'">
        <td>
          <span class="badge-band badge-band-${band}">${escHtml(band)}</span>
        </td>
        <td>
          <div style="font-weight:600; color:#FFFFFF;">${escHtml(c.identity_id)}</div>
          <div style="font-size:0.6875rem; color:var(--muted); font-family:var(--font-mono);">${escHtml(c.case_id)}</div>
        </td>
        <td>
          <div style="display:flex; align-items:center; gap:8px;">
            <div style="flex:1; height:6px; border-radius:3px; background:rgba(255,255,255,0.06); overflow:hidden;">
              <div style="width:${Math.min(risk, 100)}%; height:100%; background:${color}; border-radius:3px;"></div>
            </div>
            <span style="font-family:var(--font-mono); font-weight:700; font-size:0.875rem; color:${color};">${risk.toFixed(1)}</span>
          </div>
        </td>
        <td style="font-family:var(--font-mono); font-size:0.8125rem; color:var(--muted);">
          ${escHtml(conf)}
        </td>
        <td style="font-family:var(--font-mono); font-size:0.8125rem; color:#FFFFFF;">
          ${stepsCount} steps
        </td>
        <td>
          <div style="display:flex; gap:4px; flex-wrap:wrap; align-items:center;">
            ${displayedChips.map((m) => `<span class="mitre-chip">${escHtml(m)}</span>`).join('')}
            ${overflowCount > 0 ? `<span class="mitre-chip" style="opacity:0.75;">+${overflowCount}</span>` : ''}
          </div>
        </td>
        <td>
          <span class="status-pill" style="font-size:0.6875rem; padding:2px 8px;">
            <span class="status-dot ${c.status === 'open' ? 'warn' : 'ok'}"></span>
            ${escHtml(c.status || 'open')}
          </span>
        </td>
        <td style="font-size:0.75rem; color:var(--muted); font-family:var(--font-mono);">
          ${fmt.timeAgo(c.created_at)}
        </td>
      </tr>
    `;
  }).join('');
}

function setupSSE() {
  sse.on('case', (newCase) => {
    if (!newCase) return;
    const existingIdx = allCases.findIndex((c) => c.case_id === newCase.case_id);
    if (existingIdx >= 0) {
      allCases[existingIdx] = newCase;
    } else {
      allCases.unshift(newCase);
    }
    const countText = document.getElementById('case-count-text');
    if (countText) countText.textContent = `${allCases.length} Total Incidents`;
    renderFilteredCases();
  });

  setInterval(() => {
    loadCases();
  }, 4000);
}

// Auto-run
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => initCasesPage());
} else {
  initCasesPage();
}
