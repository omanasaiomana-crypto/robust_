/**
 * IdentityShield v3 — DOM & Formatting Utilities
 * PRD §2 Rule 8 & Context.md Section 18: Untrusted data safety & formatting.
 */

/**
 * Escapes unsafe characters in untrusted strings: & < > " ' `
 * @param {*} str - Raw string or value
 * @returns {string} Sanitized string safe for HTML interpolation
 */
export function escHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
    .replace(/`/g, '&#96;');
}

/**
 * Safe DOM element creator that strictly avoids innerHTML for text content.
 * @param {string} tag - HTML element tag name
 * @param {Object} [attrs={}] - Attributes, dataset, or event listeners (e.g. { class: '...', dataset: { id: '...' }, on: { click: fn } })
 * @param {Array|Node|string|number} [children=[]] - Children elements or text (strings strictly set via textContent)
 * @returns {HTMLElement}
 */
export function el(tag, attrs = {}, children = []) {
  const element = document.createElement(tag);

  if (attrs) {
    for (const [key, val] of Object.entries(attrs)) {
      if (val === undefined || val === null) continue;

      if (key === 'class' || key === 'className') {
        element.className = val;
      } else if (key === 'style' && typeof val === 'object') {
        Object.assign(element.style, val);
      } else if (key === 'dataset' && typeof val === 'object') {
        for (const [dKey, dVal] of Object.entries(val)) {
          element.dataset[dKey] = dVal;
        }
      } else if (key === 'on' && typeof val === 'object') {
        for (const [event, handler] of Object.entries(val)) {
          element.addEventListener(event, handler);
        }
      } else {
        element.setAttribute(key, val);
      }
    }
  }

  const childList = Array.isArray(children) ? children : [children];
  for (const child of childList) {
    if (child === null || child === undefined) continue;

    if (child instanceof Node) {
      element.appendChild(child);
    } else {
      // Golden Rule 8: text content ONLY, never innerHTML
      const textNode = document.createTextNode(String(child));
      element.appendChild(textNode);
    }
  }

  return element;
}

/**
 * Formatting helpers for timestamps, numbers, percentages, durations
 */
export const fmt = {
  /**
   * Human-readable relative time (e.g. "just now", "14s ago", "3m ago", "2h ago", "5d ago")
   */
  timeAgo(timestamp) {
    if (!timestamp) return '—';
    const date = typeof timestamp === 'number'
      ? new Date(timestamp > 1e11 ? timestamp : timestamp * 1000)
      : new Date(timestamp);
    if (isNaN(date.getTime())) return String(timestamp);

    const now = Date.now();
    const diffSec = Math.floor((now - date.getTime()) / 1000);

    if (diffSec < 5) return 'just now';
    if (diffSec < 60) return `${diffSec}s ago`;
    const diffMin = Math.floor(diffSec / 60);
    if (diffMin < 60) return `${diffMin}m ago`;
    const diffHour = Math.floor(diffMin / 60);
    if (diffHour < 24) return `${diffHour}h ago`;
    const diffDays = Math.floor(diffHour / 24);
    return `${diffDays}d ago`;
  },

  /**
   * Formats a number with comma separators and optional decimal places
   */
  number(n, decimals = 0) {
    if (n === null || n === undefined || isNaN(n)) return '0';
    return Number(n).toLocaleString('en-US', {
      minimumFractionDigits: decimals,
      maximumFractionDigits: decimals,
    });
  },

  /**
   * Formats a ratio (0..1) or percentage (0..100) to string e.g. "98.2%"
   */
  percent(val, decimals = 1) {
    if (val === null || val === undefined || isNaN(val)) return '0.0%';
    const pct = val <= 1.0 && val > 0 ? val * 100 : Number(val);
    return `${pct.toFixed(decimals)}%`;
  },

  /**
   * Formats duration in milliseconds or seconds (e.g. "42ms" or "1.24s")
   */
  ms(val) {
    if (val === null || val === undefined || isNaN(val)) return '0ms';
    const num = Number(val);
    if (num < 1000) return `${Math.round(num)}ms`;
    return `${(num / 1000).toFixed(2)}s`;
  },

  /**
   * Short ISO date string (YYYY-MM-DD HH:MM:SS UTC)
   */
  date(timestamp) {
    if (!timestamp) return '—';
    const date = typeof timestamp === 'number'
      ? new Date(timestamp > 1e11 ? timestamp : timestamp * 1000)
      : new Date(timestamp);
    if (isNaN(date.getTime())) return String(timestamp);
    return date.toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
  },
};

/**
 * Returns hex color code for a given response/risk band
 * @param {string} band - 'monitor' | 'step_up' | 'restrict' | 'revoke'
 * @returns {string} Hex color code
 */
export function bandColor(band) {
  if (!band) return '#94A3B8';
  const norm = String(band).toLowerCase().replace('-', '_');
  switch (norm) {
    case 'monitor':
      return '#64748B';
    case 'step_up':
      return '#F59E0B';
    case 'restrict':
      return '#F97316';
    case 'revoke':
      return '#EF4444';
    default:
      return '#94A3B8';
  }
}
