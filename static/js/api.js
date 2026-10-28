/**
 * API client and utility helpers for IdentityShield.
 * Supports transparent ?mock=1 fallback to static mock JSON.
 */

export function esc(value) {
  if (value === null || value === undefined) return '';
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function qs(name) {
  return new URLSearchParams(window.location.search).get(name);
}

export function fmtTime(iso) {
  if (!iso) return '—';
  try {
    const d = new Date(iso);
    if (isNaN(d.getTime())) return String(iso);
    return d.toLocaleString(undefined, {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    });
  } catch {
    return String(iso);
  }
}

export function fmtNum(n) {
  if (n === null || n === undefined || isNaN(n)) return '—';
  return Number(n).toLocaleString();
}

function mockPathFor(path) {
  const clean = path.replace(/^\/api/, '').split('?')[0];
  if (clean === '/health') return '/mock/health.json';
  if (clean === '/summary') return '/mock/summary.json';
  if (clean === '/alerts') return '/mock/alerts.json';
  if (/^\/alerts\/[^/]+\/events$/.test(clean)) return '/mock/events.json';
  if (/^\/alerts\/[^/]+$/.test(clean)) return '/mock/alert.json';
  if (clean === '/identities') return '/mock/identities.json';
  if (/^\/identities\/[^/]+\/graph$/.test(clean)) return '/mock/graph.json';
  if (/^\/sessions\/[^/]+\/timeline$/.test(clean)) return '/mock/timeline.json';
  if (clean === '/hygiene') return '/mock/hygiene.json';
  if (clean === '/metrics') return '/mock/metrics.json';
  if (clean === '/audit/verify') return '/mock/audit_verify.json';
  if (clean === '/audit') return '/mock/audit.json';
  if (clean === '/weights') return '/mock/weights.json';
  return `/mock${clean}.json`;
}

export async function api(path, { method = 'GET', body = null } = {}) {
  const isMock = qs('mock') === '1';

  if (isMock) {
    if (method.toUpperCase() === 'POST') {
      return { status: 'mocked', detail: 'mock mode' };
    }
    const mockUrl = mockPathFor(path);
    const res = await fetch(mockUrl);
    if (!res.ok) {
      throw new Error(`mock_not_found: Mock file ${mockUrl} not found`);
    }
    return await res.json();
  }

  const endpoint = path.startsWith('/api') ? path : `/api${path.startsWith('/') ? '' : '/'}${path}`;
  const opts = {
    method,
    headers: { 'Accept': 'application/json' },
  };

  if (body !== null) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = typeof body === 'string' ? body : JSON.stringify(body);
  }

  const res = await fetch(endpoint, opts);
  let data;
  try {
    data = await res.json();
  } catch {
    data = null;
  }

  if (!res.ok) {
    if (data && data.error && data.detail) {
      throw new Error(`${data.error}: ${data.detail}`);
    }
    if (data && data.detail) {
      throw new Error(String(data.detail));
    }
    throw new Error(`http_error_${res.status}: ${res.statusText}`);
  }

  return data;
}
