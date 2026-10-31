/**
 * IdentityShield v3 — API Client Module
 * Supports timeout (10s), analyst token injection, toast error reporting, and ?mock=1 offline mode.
 */

class ApiClient {
  constructor(baseUrl = '/api/v3', timeoutMs = 60000) {
    this.baseUrl = baseUrl;
    this.timeoutMs = timeoutMs;
    this._checkMockMode();
  }

  _checkMockMode() {
    try {
      const params = new URLSearchParams(window.location.search);
      const urlMock = params.get('mock') === '1';
      if (urlMock) {
        localStorage.setItem('identityshield_mock', '1');
        this.isMock = true;
      } else {
        this.isMock = localStorage.getItem('identityshield_mock') === '1';
      }
    } catch {
      this.isMock = false;
    }
  }

  getAnalystToken() {
    try {
      return localStorage.getItem('analyst_token') || '';
    } catch {
      return '';
    }
  }

  setAnalystToken(token) {
    try {
      if (token) {
        localStorage.setItem('analyst_token', token);
      } else {
        localStorage.removeItem('analyst_token');
      }
    } catch (e) {
      console.warn('Failed to access localStorage for analyst_token', e);
    }
  }

  _toast(message, type = 'error') {
    window.dispatchEvent(
      new CustomEvent('is:toast', {
        detail: { message, type },
      })
    );
  }

  _getMockPath(endpoint) {
    const clean = endpoint.split('?')[0].replace(/^\/+/, '');
    if (clean === 'health') return '/v3/mock/health.json';
    if (clean === 'agents') return '/v3/mock/agents.json';
    if (clean === 'identities') return '/v3/mock/identities.json';
    if (clean.startsWith('identities/')) return '/v3/mock/identities.json';
    if (clean === 'cases') return '/v3/mock/cases.json';
    if (clean.startsWith('cases/')) return '/v3/mock/case_detail.json';
    if (clean === 'actions') return '/v3/mock/actions.json';
    if (clean.startsWith('graph/')) return '/v3/mock/graph.json';
    if (clean.startsWith('geo/')) return '/v3/mock/geo.json';
    if (clean === 'metrics/kpi' || clean === 'metrics/perf') return '/v3/mock/metrics.json';
    if (clean.startsWith('metrics/')) return '/v3/mock/metrics.json';
    if (clean === 'playbooks') return '/v3/mock/playbooks.json';
    if (clean === 'run/status') return '/v3/mock/run_status.json';
    if (clean === 'config') return '/v3/mock/config.json';
    if (clean === 'config/versions') return '/v3/mock/config_versions.json';
    if (clean === 'audit') return '/v3/mock/audit.json';
    if (clean === 'audit/verify') return '/v3/mock/audit_verify.json';
    return `/v3/mock/${clean.replace(/\//g, '_')}.json`;
  }

  async request(endpoint, options = {}) {
    const isMutating = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(
      (options.method || 'GET').toUpperCase()
    );

    if (this.isMock) {
      if (isMutating) {
        this._toast(`[Mock] Action simulated successfully for ${endpoint}`, 'info');
        return { status: 'ok', mock: true, timestamp: Date.now() };
      }
      const mockUrl = this._getMockPath(endpoint);
      try {
        const resp = await fetch(mockUrl);
        if (!resp.ok) {
          throw new Error(`Mock file ${mockUrl} returned status ${resp.status}`);
        }
        return await resp.json();
      } catch (err) {
        this._toast(`Mock fetch failed: ${err.message}`, 'error');
        throw err;
      }
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeoutMs);

    const headers = new Headers(options.headers || {});
    if (!headers.has('Accept')) {
      headers.set('Accept', 'application/json');
    }

    if (isMutating) {
      const token = this.getAnalystToken();
      if (token && !headers.has('X-Analyst-Token')) {
        headers.set('X-Analyst-Token', token);
      }
      if (options.body && typeof options.body === 'object' && !(options.body instanceof FormData)) {
        if (!headers.has('Content-Type')) {
          headers.set('Content-Type', 'application/json');
        }
        options.body = JSON.stringify(options.body);
      }
    }

    const url = endpoint.startsWith('http')
      ? endpoint
      : `${this.baseUrl}${endpoint.startsWith('/') ? '' : '/'}${endpoint}`;

    try {
      const resp = await fetch(url, {
        ...options,
        headers,
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!resp.ok) {
        let errDetail = `HTTP ${resp.status} ${resp.statusText}`;
        try {
          const errJson = await resp.json();
          errDetail = errJson.detail || errJson.error || errDetail;
        } catch {
          // ignore parsing error if not JSON
        }

        this._toast(errDetail, 'error');
        const error = new Error(errDetail);
        error.status = resp.status;
        throw error;
      }

      const contentType = resp.headers.get('content-type') || '';
      if (contentType.includes('application/json')) {
        return await resp.json();
      }
      return await resp.text();
    } catch (err) {
      clearTimeout(timeoutId);
      if (err.name === 'AbortError') {
        const msg = `Request timed out after ${this.timeoutMs / 1000}s`;
        this._toast(msg, 'error');
        throw new Error(msg);
      }
      throw err;
    }
  }

  get(endpoint, options = {}) {
    return this.request(endpoint, { ...options, method: 'GET' });
  }

  post(endpoint, body = null, options = {}) {
    return this.request(endpoint, { ...options, method: 'POST', body });
  }

  delete(endpoint, options = {}) {
    return this.request(endpoint, { ...options, method: 'DELETE' });
  }
}

export const api = new ApiClient();
export default api;
