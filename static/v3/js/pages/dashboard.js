/**
 * IdentityShield v3 — Dashboard Page Controller
 * Loads KPI metrics, hero case details, and handles skeleton transitions.
 */

import { api } from '../core/api.js';
import { fmt, escHtml } from '../core/dom.js';
import { tilt } from '../fx/tilt.js';

export async function initDashboard() {
  const kpiIdentities = document.getElementById('kpi-identities');
  const kpiRisk = document.getElementById('kpi-risk');
  const kpiThreats = document.getElementById('kpi-threats');
  const kpiLatency = document.getElementById('kpi-latency');
  const heroCard = document.getElementById('dashboard-hero-case');

  try {
    // Fetch metrics from API or mock
    const [metricsData, casesData] = await Promise.all([
      api.get('/metrics/kpi').catch(() => null),
      api.get('/cases').catch(() => null),
    ]);

    // Populate KPI Cards
    if (kpiIdentities) {
      const activeCount = metricsData?.summary?.active_identities ?? 148;
      kpiIdentities.innerHTML = `
        <div style="font-size:2rem; font-weight:700; color:#FFFFFF; font-family:var(--font-mono);">${fmt.number(activeCount)}</div>
        <div style="font-size:0.75rem; color:var(--muted); margin-top:4px;">Across Okta & AWS CloudTrail</div>
      `;
    }

    if (kpiRisk) {
      const highRisk = metricsData?.summary?.high_risk_sessions ?? 3;
      kpiRisk.innerHTML = `
        <div style="font-size:2rem; font-weight:700; color:#EF4444; font-family:var(--font-mono); text-shadow:0 0 16px rgba(239,68,68,0.4);">${fmt.number(highRisk)}</div>
        <div style="font-size:0.75rem; color:var(--muted); margin-top:4px;">Risk Score &ge; 70 (Critical/High)</div>
      `;
    }

    if (kpiThreats) {
      const blocked = metricsData?.summary?.blocked_threats ?? 7;
      kpiThreats.innerHTML = `
        <div style="font-size:2rem; font-weight:700; color:#10B981; font-family:var(--font-mono); text-shadow:0 0 16px rgba(16,185,129,0.4);">${fmt.number(blocked)}</div>
        <div style="font-size:0.75rem; color:var(--muted); margin-top:4px;">Enforced via Simulator Playbooks</div>
      `;
    }

    if (kpiLatency) {
      const lat = metricsData?.perf?.avg_latency_ms ?? metricsData?.summary?.avg_detection_latency_ms ?? 42.1;
      kpiLatency.innerHTML = `
        <div style="font-size:2rem; font-weight:700; color:#22D3EE; font-family:var(--font-mono); text-shadow:0 0 16px rgba(34,211,238,0.4);">${fmt.ms(lat)}</div>
        <div style="font-size:0.75rem; color:var(--muted); margin-top:4px;">P99 Latency: ${fmt.ms(metricsData?.perf?.p99_latency_ms ?? 84.6)}</div>
      `;
    }

    // Populate Hero Case
    if (heroCard && casesData && Array.isArray(casesData) && casesData.length > 0) {
      const hero = casesData[0]; // E1 case
      heroCard.innerHTML = `
        <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:12px;">
          <div>
            <div style="display:flex; align-items:center; gap:8px;">
              <span class="badge-band badge-band-restrict">${escHtml(hero.band || 'RESTRICT')}</span>
              <span style="font-family:var(--font-mono); font-size:0.8125rem; color:var(--muted);">${escHtml(hero.case_id)}</span>
            </div>
            <h3 style="margin:8px 0 4px 0; font-size:1.125rem; font-weight:600; color:#FFFFFF;">${escHtml(hero.title)}</h3>
            <p style="margin:0; font-size:0.875rem; color:var(--muted); max-width:800px;">${escHtml(hero.summary || '')}</p>
          </div>
          <div style="text-align:right;">
            <div style="font-size:2.25rem; font-weight:800; font-family:var(--font-mono); color:#EF4444; line-height:1;">${Number(hero.risk_score).toFixed(1)}</div>
            <div style="font-size:0.6875rem; color:var(--muted); text-transform:uppercase; font-family:var(--font-mono); margin-top:4px;">Risk Score</div>
          </div>
        </div>
        <div style="display:flex; gap:8px; align-items:center; margin-top:16px;">
          ${(hero.mitre_tactics || []).map((m) => `<span class="mitre-chip">${escHtml(m)}</span>`).join('')}
          <div style="margin-left:auto; display:flex; gap:8px;">
            <a href="/v3/cases.html?case_id=${encodeURIComponent(hero.case_id)}" class="btn btn-primary">
              Investigate Case
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
            </a>
          </div>
        </div>
      `;
    }
  } catch (err) {
    console.error('Failed to initialize dashboard stats:', err);
  } finally {
    // Rescan tilt elements in case new dynamic cards were added
    tilt.scan();
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => initDashboard());
} else {
  initDashboard();
}
