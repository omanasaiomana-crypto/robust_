/**
 * Reusable UI component library for IdentityShield.
 * All dynamic parameters are escaped with esc() to ensure zero XSS.
 */
import { esc } from './api.js';

const BAND_CONFIG = {
  monitor: { label: 'Monitor', text: 'text-slate-300', bg: 'bg-slate-500/15', border: 'border-slate-500/30', color: '#94A3B8' },
  step_up: { label: 'Step-up', text: 'text-warn', bg: 'bg-warn/15', border: 'border-warn/30', color: '#F59E0B' },
  restrict: { label: 'Restrict', text: 'text-high', bg: 'bg-high/15', border: 'border-high/30', color: '#F97316' },
  revoke: { label: 'Revoke', text: 'text-crit', bg: 'bg-crit/15', border: 'border-crit/30', color: '#EF4444' },
};

const PATTERN_NAMES = {
  P1: 'P1 Impossible travel',
  P2: 'P2 Dormant account',
  P3: 'P3 Privilege escalation',
  P4: 'P4 Unusual API',
  P5: 'P5 Token abuse',
  ML: 'ML Behavior anomaly',
};

export function card(title, bodyHtml, actionHtml = '') {
  return `
    <div class="bg-panel border border-line rounded-xl p-5 shadow-sm">
      <div class="flex items-center justify-between mb-4">
        <h3 class="text-sm font-semibold text-ink">${esc(title)}</h3>
        ${actionHtml ? `<div>${actionHtml}</div>` : ''}
      </div>
      <div>${bodyHtml}</div>
    </div>
  `;
}

export function statCard(label, value, note = '') {
  return `
    <div class="bg-panel border border-line rounded-xl p-5 shadow-sm flex flex-col justify-between">
      <div class="text-xs uppercase tracking-wide text-muted font-medium mb-1">${esc(label)}</div>
      <div class="text-3xl font-semibold tabular-nums text-ink tracking-tight">${esc(value)}</div>
      ${note ? `<div class="text-xs text-muted mt-2 font-normal">${esc(note)}</div>` : ''}
    </div>
  `;
}

export function bandBadge(band) {
  const b = (band || 'monitor').toLowerCase();
  const cfg = BAND_CONFIG[b] || BAND_CONFIG.monitor;
  return `<span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border ${cfg.bg} ${cfg.text} ${cfg.border}">${esc(cfg.label)}</span>`;
}

export function patternChip(code) {
  const name = PATTERN_NAMES[code] || code;
  return `<span class="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono font-medium bg-panel2 border border-line text-ink">${esc(name)}</span>`;
}

export function mitreChip(id) {
  return `<span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-medium bg-brand2/10 border border-brand2/30 text-brand2">${esc(id)}</span>`;
}

export function riskRing(risk, band, size = 72) {
  const rVal = Math.max(0, Math.min(100, Number(risk) || 0));
  const b = (band || 'monitor').toLowerCase();
  const cfg = BAND_CONFIG[b] || BAND_CONFIG.monitor;

  const stroke = Math.max(4, Math.round(size / 12));
  const radius = (size - stroke * 2) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (rVal / 100) * circumference;
  const center = size / 2;
  const fontSize = Math.round(size * 0.28);

  return `
    <div class="relative inline-flex items-center justify-center flex-shrink-0" style="width: ${size}px; height: ${size}px;">
      <svg width="${size}" height="${size}" class="transform -rotate-90">
        <circle
          cx="${center}"
          cy="${center}"
          r="${radius}"
          stroke="#1F2A3C"
          stroke-width="${stroke}"
          fill="transparent"
        />
        <circle
          cx="${center}"
          cy="${center}"
          r="${radius}"
          stroke="${cfg.color}"
          stroke-width="${stroke}"
          stroke-dasharray="${circumference}"
          stroke-dashoffset="${offset}"
          stroke-linecap="round"
          fill="transparent"
          class="transition-all duration-500 ease-out"
        />
      </svg>
      <span class="absolute font-semibold tabular-nums text-ink" style="font-size: ${fontSize}px;">
        ${Math.round(rVal)}
      </span>
    </div>
  `;
}

export function riskBar(risk, band) {
  const rVal = Math.max(0, Math.min(100, Number(risk) || 0));
  const b = (band || 'monitor').toLowerCase();
  const cfg = BAND_CONFIG[b] || BAND_CONFIG.monitor;

  return `
    <div class="flex items-center gap-2">
      <div class="w-16 bg-line rounded-full h-1.5 overflow-hidden flex-shrink-0">
        <div class="h-full rounded-full" style="width: ${rVal}%; background-color: ${cfg.color};"></div>
      </div>
      <span class="text-xs tabular-nums text-muted font-medium w-8 text-right">${rVal.toFixed(1)}</span>
    </div>
  `;
}

export function table(columns, rowsHtml) {
  return `
    <div class="overflow-x-auto rounded-lg border border-line">
      <table class="w-full text-left border-collapse text-sm">
        <thead class="bg-panel2 sticky-th border-b border-line">
          <tr>
            ${columns
              .map(
                (col) =>
                  `<th class="px-4 py-3 text-xs uppercase tracking-wider font-semibold text-muted whitespace-nowrap ${
                    col.align === 'right' ? 'text-right' : ''
                  }">${esc(col.label || col)}</th>`
              )
              .join('')}
          </tr>
        </thead>
        <tbody class="divide-y divide-line">
          ${rowsHtml || `<tr><td colspan="${columns.length}" class="px-4 py-8 text-center text-muted">No data available</td></tr>`}
        </tbody>
      </table>
    </div>
  `;
}

export function button(label, { variant = 'primary', id = '', attrs = '' } = {}) {
  let baseStyle = 'inline-flex items-center justify-center rounded-lg px-3.5 py-2 text-sm font-medium transition-colors focus:outline-none';
  if (variant === 'primary') {
    baseStyle += ' bg-brand hover:bg-blue-500 text-white shadow-sm';
  } else if (variant === 'secondary') {
    baseStyle += ' border border-line hover:bg-panel2 text-ink';
  } else if (variant === 'danger') {
    baseStyle += ' bg-crit/90 hover:bg-crit text-white shadow-sm';
  } else if (variant === 'ghost') {
    baseStyle += ' hover:bg-panel2 text-muted hover:text-ink';
  }

  const idAttr = id ? `id="${esc(id)}"` : '';
  return `<button ${idAttr} class="${baseStyle}" ${attrs}>${esc(label)}</button>`;
}

export function skeleton(lines = 4) {
  return `
    <div class="space-y-3 w-full py-2">
      <div class="skeleton-box h-6 w-1/3"></div>
      ${Array.from({ length: lines })
        .map(() => `<div class="skeleton-box h-4 w-full"></div>`)
        .join('')}
    </div>
  `;
}

export function emptyState(message) {
  return `
    <div class="p-12 text-center border border-dashed border-line rounded-xl bg-panel/30">
      <div class="inline-flex items-center justify-center w-12 h-12 rounded-full bg-panel2 text-muted mb-3">
        <svg class="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4" />
        </svg>
      </div>
      <p class="text-sm text-muted font-medium">${esc(message)}</p>
    </div>
  `;
}

export function errorState(message, retryId = 'btn-retry') {
  return `
    <div class="p-6 border border-crit/30 rounded-xl bg-crit/5 text-center">
      <div class="inline-flex items-center justify-center w-10 h-10 rounded-full bg-crit/15 text-crit mb-3">
        <svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
        </svg>
      </div>
      <p class="text-sm font-semibold text-ink mb-1">Failed to load content</p>
      <p class="text-xs text-muted mb-4 max-w-md mx-auto font-mono">${esc(message)}</p>
      ${button('Retry', { variant: 'secondary', id: retryId })}
    </div>
  `;
}

export function toast(message, type = 'success') {
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    container.className = 'fixed bottom-4 right-4 z-50 flex flex-col gap-2 max-w-sm';
    document.body.appendChild(container);
  }

  const el = document.createElement('div');
  const isOk = type === 'success';
  const borderCol = isOk ? 'border-ok/40' : 'border-crit/40';
  const textCol = isOk ? 'text-ok' : 'text-crit';
  const bgCol = 'bg-panel';

  el.className = `p-4 rounded-xl shadow-lg border ${borderCol} ${bgCol} text-sm flex items-start gap-3 transition-opacity duration-300`;
  el.innerHTML = `
    <span class="${textCol} mt-0.5">
      ${isOk ? '✓' : '⚠'}
    </span>
    <span class="text-ink flex-1">${esc(message)}</span>
  `;

  container.appendChild(el);

  setTimeout(() => {
    el.style.opacity = '0';
    setTimeout(() => el.remove(), 300);
  }, 4000);
}

export function confirmModal(title, message) {
  return new Promise((resolve) => {
    const overlay = document.createElement('div');
    overlay.className = 'fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm';

    overlay.innerHTML = `
      <div class="bg-panel border border-line rounded-xl p-6 max-w-md w-full shadow-2xl">
        <h4 class="text-base font-semibold text-ink mb-2">${esc(title)}</h4>
        <p class="text-sm text-muted mb-6">${esc(message)}</p>
        <div class="flex items-center justify-end gap-3">
          <button id="modal-cancel" class="border border-line hover:bg-panel2 text-ink rounded-lg px-4 py-2 text-sm font-medium transition-colors">Cancel</button>
          <button id="modal-confirm" class="bg-crit hover:bg-red-600 text-white rounded-lg px-4 py-2 text-sm font-medium transition-colors">Confirm</button>
        </div>
      </div>
    `;

    document.body.appendChild(overlay);

    const cleanup = (val) => {
      window.removeEventListener('keydown', handleKey);
      overlay.remove();
      resolve(val);
    };

    const handleKey = (e) => {
      if (e.key === 'Escape') cleanup(false);
      if (e.key === 'Enter') cleanup(true);
    };

    window.addEventListener('keydown', handleKey);
    overlay.querySelector('#modal-cancel').onclick = () => cleanup(false);
    overlay.querySelector('#modal-confirm').onclick = () => cleanup(true);
  });
}
