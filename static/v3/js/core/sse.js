/**
 * IdentityShield v3 — Server-Sent Events (SSE) Client
 * Connects to /api/v3/stream with auto-reconnect backoff (1s -> 10s),
 * typed event dispatching, and a realistic mock-mode generator.
 */

import { api } from './api.js';

class SSEClient {
  constructor(endpoint = '/api/v3/stream') {
    this.endpoint = endpoint;
    this.source = null;
    this.listeners = new Map();
    this.reconnectAttempts = 0;
    this.reconnectTimer = null;
    this.mockTimer = null;
    this.isConnected = false;
  }

  /**
   * Register a typed event listener
   * @param {string} event - 'trace' | 'risk' | 'case' | 'action' | 'metrics' | 'heartbeat' | 'connected'
   * @param {Function} callback
   */
  on(event, callback) {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }
    this.listeners.get(event).add(callback);
    return () => this.off(event, callback);
  }

  /**
   * Remove a typed event listener
   */
  off(event, callback) {
    if (this.listeners.has(event)) {
      this.listeners.get(event).delete(callback);
    }
  }

  /**
   * Dispatch typed payload to registered listeners
   */
  emit(event, data) {
    if (this.listeners.has(event)) {
      for (const cb of this.listeners.get(event)) {
        try {
          cb(data);
        } catch (err) {
          console.error(`Error in SSE listener for '${event}':`, err);
        }
      }
    }
  }

  connect() {
    if (api.isMock) {
      this._startMockMode();
      return;
    }

    if (this.source) {
      this.disconnect();
    }

    try {
      this.source = new EventSource(this.endpoint);

      this.source.onopen = () => {
        this.isConnected = true;
        this.reconnectAttempts = 0;
        this.emit('connected', { status: 'connected', timestamp: Date.now() });
      };

      this.source.onerror = () => {
        this.isConnected = false;
        if (this.source) {
          this.source.close();
          this.source = null;
        }
        this._scheduleReconnect();
      };

      // Register standard typed events
      const knownEvents = ['trace', 'risk', 'case', 'action', 'metrics', 'connected'];
      for (const evtName of knownEvents) {
        this.source.addEventListener(evtName, (msg) => {
          try {
            const data = JSON.parse(msg.data);
            this.emit(evtName, data);
          } catch {
            this.emit(evtName, msg.data);
          }
        });
      }

      // Default message handler
      this.source.onmessage = (msg) => {
        try {
          const data = JSON.parse(msg.data);
          this.emit('message', data);
        } catch {
          this.emit('message', msg.data);
        }
      };
    } catch (err) {
      console.warn('Failed to initialize EventSource:', err);
      this._scheduleReconnect();
    }
  }

  _scheduleReconnect() {
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.reconnectAttempts++;
    // Exponential backoff 1s to 10s
    const delay = Math.min(1000 * Math.pow(1.5, this.reconnectAttempts - 1), 10000);
    this.reconnectTimer = setTimeout(() => {
      this.connect();
    }, delay);
  }

  _startMockMode() {
    this.isConnected = true;
    setTimeout(() => {
      this.emit('connected', { status: 'mock_connected', timestamp: Date.now() });
    }, 100);

    const mockAgents = [
      'a01_collector', 'a02_normalizer', 'a03_context', 'a04_correlation',
      'a05_access', 'a06_session', 'a07_credentials', 'a08_privesc',
      'a09_evasion', 'a10_ml', 'a11_campaign', 'a12_fusion',
      'a13_investigation', 'a14_response', 'a15_feedback'
    ];

    const mockActions = [
      'Replayed Okta login for svc-report',
      'Normalized identity -> svc-report@identityshield.internal',
      'Threat intel: ASN 16509 (AWS Hosting) detected for user login',
      'Graph linked Okta session to AWS AssumeRole',
      'D-ACC-01: Impossible travel flagged NYC -> FRA',
      'D-PE-08: Full privilege escalation chain matched',
      'Risk fusion: Identity risk updated to 92.4 (Band: RESTRICT)',
      'Investigation: Generated 6-step attack case with MITRE T1078'
    ];

    let step = 0;
    this.mockTimer = setInterval(() => {
      const agent = mockAgents[step % mockAgents.length];
      const action = mockActions[step % mockActions.length];
      step++;

      this.emit('trace', {
        agent_id: agent,
        state: 'running',
        message: action,
        data: { step, eps: (Math.random() * 15 + 30).toFixed(1) },
        timestamp: new Date().toISOString()
      });

      if (step % 5 === 0) {
        this.emit('metrics', {
          eps: (Math.random() * 12 + 35).toFixed(1),
          active_sessions: 14,
          high_risk_identities: 2,
          timestamp: Date.now()
        });
      }

      if (step % 10 === 0) {
        this.emit('heartbeat', {
          server_time: new Date().toISOString(),
          uptime: step * 2
        });
      }
    }, 2500);
  }

  disconnect() {
    if (this.source) {
      this.source.close();
      this.source = null;
    }
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.mockTimer) {
      clearInterval(this.mockTimer);
      this.mockTimer = null;
    }
    this.isConnected = false;
  }
}

export const sse = new SSEClient();
export default sse;
