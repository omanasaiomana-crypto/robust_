/**
 * Notifications page: email delivery status, test email, and delivery history.
 */
import { api, esc, fmtTime, qs } from './api.js';
import { card, emptyState, errorState, renderLayout, skeleton, toast } from './ui.js';

const isMock = qs('mock') === '1';
const querySuffix = isMock ? '?mock=1' : '';

let currentlyExpandedId = null;

function renderModePill(mode) {
  const m = (mode || 'outbox').toLowerCase();
  if (m === 'smtp') {
    return `<span class="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-semibold bg-ok/15 text-ok border border-ok/30">SMTP</span>`;
  }
  if (m === 'off') {
    return `<span class="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-semibold bg-muted/15 text-muted border border-muted/30">Off</span>`;
  }
  return `<span class="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-semibold bg-brand2/15 text-brand2 border border-brand2/30">Outbox (demo)</span>`;
}

function renderStatusBadge(status) {
  const s = (status || '').toLowerCase();
  if (s === 'sent') {
    return `<span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-ok/15 text-ok border border-ok/30">Sent</span>`;
  }
  if (s === 'outbox') {
    return `<span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-brand2/15 text-brand2 border border-brand2/30">Outbox</span>`;
  }
  if (s === 'failed') {
    return `<span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-crit/15 text-crit border border-crit/30">Failed</span>`;
  }
  if (s === 'rate_limited') {
    return `<span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-warn/15 text-warn border border-warn/30">Rate limited</span>`;
  }
  return `<span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-panel2 text-muted border border-line">${esc(status)}</span>`;
}

function renderKindChip(kind) {
  const k = (kind || 'digest').toLowerCase();
  if (k === 'digest') {
    return `<span class="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium bg-panel2 border border-line text-ink">Digest</span>`;
  }
  if (k === 'manual') {
    return `<span class="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium bg-brand/15 border border-brand/30 text-brand">Manual</span>`;
  }
  return `<span class="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium bg-muted/15 border border-muted/30 text-muted">Test</span>`;
}

function renderStatusCard(statusData) {
  if (!statusData) return '';
  const recipients = statusData.recipients || [];
  const recipientsHtml = recipients.length > 0
    ? `<span class="font-mono text-ink">${esc(recipients.join(', '))}</span>`
    : `<span class="text-warn font-medium">No recipients configured</span>`;

  return `
    <div class="bg-panel border border-line rounded-xl p-5 shadow-sm space-y-4">
      <div class="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-4 border-b border-line">
        <div class="flex items-center gap-3">
          ${renderModePill(statusData.mode)}
          <span class="text-sm font-semibold text-ink">Email Alert Notifier</span>
        </div>
        <button id="btn-send-test" class="inline-flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-medium bg-brand hover:bg-blue-500 text-white shadow-sm transition-colors focus:outline-none">
          <svg class="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
          </svg>
          <span>Send test email</span>
        </button>
      </div>

      <div class="grid grid-cols-1 md:grid-cols-4 gap-4 text-xs">
        <div>
          <div class="text-muted font-medium mb-1">Recipients</div>
          <div>${recipientsHtml}</div>
        </div>
        <div>
          <div class="text-muted font-medium mb-1">SMTP Server</div>
          <div class="font-mono text-ink">${esc(statusData.smtp_host || '—')}</div>
        </div>
        <div>
          <div class="text-muted font-medium mb-1">Alert Threshold</div>
          <div class="text-ink font-semibold">Risk ≥ ${esc(statusData.min_risk ?? 70)}</div>
        </div>
        <div>
          <div class="text-muted font-medium mb-1">Sent this hour</div>
          <div class="text-ink font-semibold tabular-nums">${esc(statusData.sent_last_hour ?? 0)} / ${esc(statusData.max_per_hour ?? 10)}</div>
        </div>
      </div>

      <div class="pt-3 border-t border-line text-xs text-muted flex items-center justify-between">
        <span>Configure in <code class="text-ink bg-panel2 px-1.5 py-0.5 rounded border border-line">.env</code> (see <code class="text-ink">.env.example</code>). Outbox mode works offline.</span>
      </div>
    </div>
  `;
}

function renderHistoryTable(records) {
  if (!records || records.length === 0) {
    return emptyState('No emails yet. A digest is sent when an alert reaches the risk threshold.');
  }

  const rows = records.map((r) => {
    const alertIds = r.alert_ids || [];
    const alertLinks = alertIds.length > 0
      ? alertIds
          .map((id) => `<a href="/alert.html?id=${encodeURIComponent(id)}${querySuffix}" class="text-brand hover:underline font-mono text-xs" onclick="event.stopPropagation()">${esc(id)}</a>`)
          .join(', ')
      : '<span class="text-muted">—</span>';

    return `
      <tr class="hover:bg-panel2/60 cursor-pointer transition-colors border-b border-line group" data-notify-id="${esc(r.id)}" tabindex="0" role="button" aria-expanded="false">
        <td class="px-4 py-3 whitespace-nowrap text-xs font-mono text-muted">${esc(fmtTime(r.created_at))}</td>
        <td class="px-4 py-3 whitespace-nowrap">${renderKindChip(r.kind)}</td>
        <td class="px-4 py-3 whitespace-nowrap">${renderStatusBadge(r.status)}</td>
        <td class="px-4 py-3 max-w-md truncate text-xs text-ink font-medium" title="${esc(r.subject)}">${esc(r.subject)}</td>
        <td class="px-4 py-3 max-w-xs truncate text-xs text-muted font-mono" title="${esc(r.recipients)}">${esc(r.recipients)}</td>
        <td class="px-4 py-3 text-xs whitespace-nowrap">${alertLinks}</td>
        <td class="px-4 py-3 text-right">
          <svg class="w-4 h-4 text-muted transform group-hover:text-ink transition-transform inline-block chevron-${esc(r.id)}" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
          </svg>
        </td>
      </tr>
      <tr id="detail-${esc(r.id)}" class="hidden bg-panel2/40 border-b border-line">
        <td colspan="7" class="px-5 py-4 space-y-3">
          <div class="text-xs text-muted flex items-center justify-between">
            <span>Status detail: <b class="text-ink">${esc(r.detail || 'None')}</b></span>
            <span class="font-mono text-[11px] text-muted">Notification ID: ${esc(r.id)}</span>
          </div>
          <div>
            <div class="text-[11px] uppercase tracking-wide text-muted font-medium mb-1">Plain-text email body (never rendered as HTML)</div>
            <pre class="whitespace-pre-wrap font-mono text-xs bg-panel2 border border-line rounded-lg p-4 max-h-80 overflow-auto text-ink selection:bg-brand/30">${esc(r.body_text || '')}</pre>
          </div>
        </td>
      </tr>
    `;
  }).join('');

  return `
    <div class="overflow-x-auto rounded-lg border border-line">
      <table class="w-full text-left border-collapse text-sm">
        <thead class="bg-panel2 sticky-th border-b border-line">
          <tr>
            <th class="px-4 py-3 text-xs uppercase tracking-wider font-semibold text-muted whitespace-nowrap">Time</th>
            <th class="px-4 py-3 text-xs uppercase tracking-wider font-semibold text-muted whitespace-nowrap">Kind</th>
            <th class="px-4 py-3 text-xs uppercase tracking-wider font-semibold text-muted whitespace-nowrap">Status</th>
            <th class="px-4 py-3 text-xs uppercase tracking-wider font-semibold text-muted whitespace-nowrap">Subject</th>
            <th class="px-4 py-3 text-xs uppercase tracking-wider font-semibold text-muted whitespace-nowrap">Recipients</th>
            <th class="px-4 py-3 text-xs uppercase tracking-wider font-semibold text-muted whitespace-nowrap">Alerts</th>
            <th class="px-4 py-3"></th>
          </tr>
        </thead>
        <tbody>
          ${rows}
        </tbody>
      </table>
    </div>
  `;
}

export async function initNotifications() {
  const container = renderLayout(
    'notifications',
    'Notifications',
    'Email alerts sent to the security admin'
  );
  if (!container) return;

  container.innerHTML = `
    <div class="space-y-6">
      <div id="section-status">${skeleton(3)}</div>
      <div id="section-history" class="space-y-3">
        <div class="flex items-center justify-between">
          <h3 class="text-sm font-semibold text-ink">Notification History</h3>
          <span class="text-xs text-muted">Latest 50 deliveries</span>
        </div>
        <div id="history-table-wrapper">${skeleton(6)}</div>
      </div>
    </div>
  `;

  await loadAll();
}

async function loadAll() {
  const [statusRes, historyRes] = await Promise.allSettled([
    api.get('/notifications/status'),
    api.get('/notifications?limit=50'),
  ]);

  const secStatus = document.getElementById('section-status');
  const secHist = document.getElementById('history-table-wrapper');

  if (statusRes.status === 'fulfilled') {
    if (secStatus) secStatus.innerHTML = renderStatusCard(statusRes.value);
    attachTestButton();
  } else {
    if (secStatus) secStatus.innerHTML = errorState(statusRes.reason?.message || 'Failed to load status');
  }

  if (historyRes.status === 'fulfilled') {
    if (secHist) secHist.innerHTML = renderHistoryTable(historyRes.value);
    attachRowExpansion();
  } else {
    if (secHist) secHist.innerHTML = errorState(historyRes.reason?.message || 'Failed to load history');
  }
}

function attachTestButton() {
  const btn = document.getElementById('btn-send-test');
  if (!btn) return;

  btn.addEventListener('click', async () => {
    btn.disabled = true;
    const origHtml = btn.innerHTML;
    btn.innerHTML = `<span class="inline-block animate-spin mr-1">⏳</span> Sending…`;

    try {
      const res = await api.post('/notifications/test');
      const st = (res?.status || '').toLowerCase();

      if (st === 'sent') {
        toast('Test email sent successfully', 'success');
      } else if (st === 'outbox') {
        toast('Saved to outbox (demo mode)', 'success');
      } else if (st === 'off') {
        toast('Email is turned off (EMAIL_MODE=off)', 'error');
      } else {
        toast(`Email delivery ${st}: ${res?.detail || 'unknown error'}`, 'error');
      }
      await loadAll();
    } catch (err) {
      toast(`Failed to send test email: ${err.message}`, 'error');
    } finally {
      btn.disabled = false;
      btn.innerHTML = origHtml;
    }
  });
}

function attachRowExpansion() {
  const rows = document.querySelectorAll('tr[data-notify-id]');
  rows.forEach((row) => {
    const nid = row.getAttribute('data-notify-id');
    const toggle = () => {
      const detailRow = document.getElementById(`detail-${nid}`);
      const chevron = document.querySelector(`.chevron-${nid}`);
      if (!detailRow) return;

      const isOpening = detailRow.classList.contains('hidden');

      // Close previously open detail row if different
      if (currentlyExpandedId && currentlyExpandedId !== nid) {
        const prevDetail = document.getElementById(`detail-${currentlyExpandedId}`);
        const prevChevron = document.querySelector(`.chevron-${currentlyExpandedId}`);
        if (prevDetail) prevDetail.classList.add('hidden');
        if (prevChevron) prevChevron.classList.remove('rotate-180');
        const prevRow = document.querySelector(`tr[data-notify-id="${currentlyExpandedId}"]`);
        if (prevRow) prevRow.setAttribute('aria-expanded', 'false');
      }

      if (isOpening) {
        detailRow.classList.remove('hidden');
        if (chevron) chevron.classList.add('rotate-180');
        row.setAttribute('aria-expanded', 'true');
        currentlyExpandedId = nid;
      } else {
        detailRow.classList.add('hidden');
        if (chevron) chevron.classList.remove('rotate-180');
        row.setAttribute('aria-expanded', 'false');
        currentlyExpandedId = null;
      }
    };

    row.addEventListener('click', toggle);
    row.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        toggle();
      }
    });
  });
}

// Auto-run on load
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initNotifications);
} else {
  initNotifications();
}
