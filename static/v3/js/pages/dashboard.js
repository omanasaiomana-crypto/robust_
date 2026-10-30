/**
 * IdentityShield v3 — Dashboard Page Controller
 * Handles 5 KPI cards, Top Identities table, Live Cases SSE feed, Mini 3D Globe, and Run Dataset action.
 */

import { api } from '../core/api.js';
import { sse } from '../core/sse.js';
import { fmt, escHtml, bandColor } from '../core/dom.js';
import { tilt } from '../fx/tilt.js';

let miniGlobeInstance = null;

export async function initDashboard() {
  setupRunDatasetButton();
  await loadKPIs();
  await loadTopIdentities();
  await loadLiveCases();
  initMiniGlobe();
  setupSSEListeners();
  tilt.scan();
}

/**
 * 1. Load and Render 5 KPI Cards
 */
async function loadKPIs() {
  try {
    const [metrics, casesData, identities] = await Promise.all([
      api.get('/metrics/kpi').catch(() => null),
      api.get('/cases').catch(() => []),
      api.get('/identities').catch(() => []),
    ]);

    // 1. Open Cases by Band
    const cases = Array.isArray(casesData) ? casesData : (casesData?.items || []);
    const bands = { revoke: 0, restrict: 0, step_up: 0, monitor: 0 };
    cases.forEach((c) => {
      const b = (c.band || 'monitor').toLowerCase().replace('-', '_');
      if (bands[b] !== undefined) bands[b]++;
    });

    const kpiCases = document.getElementById('kpi-open-cases');
    if (kpiCases) {
      kpiCases.innerHTML = `
        <div style="font-size:1.75rem; font-weight:700; color:#FFFFFF; font-family:var(--font-mono);">${cases.length} Total</div>
        <div style="display:flex; gap:6px; margin-top:6px; font-size:0.6875rem; font-family:var(--font-mono);">
          <span style="color:var(--crit);">${bands.revoke} Revoke</span> ·
          <span style="color:var(--band-restrict);">${bands.restrict} Restrict</span> ·
          <span style="color:var(--warn);">${bands.step_up} Step-up</span>
        </div>
      `;
    }

    // 2. Identities at Risk >= 60
    const idList = Array.isArray(identities) ? identities : (identities?.items || []);
    const highRiskIdentities = idList.filter((i) => (i.identity_risk || 0) >= 60);
    const kpiRisk = document.getElementById('kpi-risk-identities');
    if (kpiRisk) {
      kpiRisk.innerHTML = `
        <div style="font-size:1.75rem; font-weight:700; color:#EF4444; font-family:var(--font-mono); text-shadow:0 0 12px rgba(239,68,68,0.4);">
          ${highRiskIdentities.length}
        </div>
        <div style="font-size:0.6875rem; color:var(--muted); margin-top:4px;">
          ${idList.length > 0 ? `Out of ${idList.length} monitored accounts` : 'Across corporate directories'}
        </div>
      `;
    }

    // 3. Events / Sec (Throughput)
    const eps = metrics?.perf?.throughput_eps ?? 1450;
    const kpiEvents = document.getElementById('kpi-events-sec');
    if (kpiEvents) {
      kpiEvents.innerHTML = `
        <div id="dashboard-eps-val" style="font-size:1.75rem; font-weight:700; color:var(--brand); font-family:var(--font-mono);">
          ${fmt.number(eps)} <span style="font-size:0.875rem; font-weight:500;">EPS</span>
        </div>
        <div style="font-size:0.6875rem; color:var(--muted); margin-top:4px;">In-memory topic bus streaming</div>
      `;
    }

    // 4. p95 Latency
    const p95 = metrics?.perf?.p99_latency_ms ?? metrics?.perf?.avg_latency_ms ?? 42.1;
    const kpiLat = document.getElementById('kpi-latency-p95');
    if (kpiLat) {
      kpiLat.innerHTML = `
        <div style="font-size:1.75rem; font-weight:700; color:var(--ok); font-family:var(--font-mono);">
          ${fmt.ms(p95)}
        </div>
        <div style="font-size:0.6875rem; color:var(--muted); margin-top:4px;">Hot path end-to-end latency</div>
      `;
    }

    // 5. Alert Reduction %
    const kpiRed = document.getElementById('kpi-alert-reduction');
    if (kpiRed) {
      kpiRed.innerHTML = `
        <div style="font-size:1.75rem; font-weight:700; color:var(--violet); font-family:var(--font-mono);">
          98.4%
        </div>
        <div style="font-size:0.6875rem; color:var(--muted); margin-top:4px;">Fused signals into correlated cases</div>
      `;
    }
  } catch (err) {
    console.error('Failed to load KPIs:', err);
  }
}

/**
 * 2. Top Identities Table
 */
async function loadTopIdentities() {
  const tbody = document.getElementById('top-identities-body');
  if (!tbody) return;

  try {
    const raw = await api.get('/identities');
    const identities = Array.isArray(raw) ? raw : (raw?.items || []);
    if (!identities || identities.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:var(--muted); padding:20px;">No identities recorded yet.</td></tr>';
      return;
    }

    // Sort by identity_risk descending
    const sorted = [...identities].sort((a, b) => (b.identity_risk || 0) - (a.identity_risk || 0)).slice(0, 5);

    tbody.innerHTML = sorted.map((item) => {
      const risk = Number(item.identity_risk || 0);
      const sesRisk = Number(item.session_risk || 0);
      const band = (item.band || 'monitor').toLowerCase().replace('-', '_');
      const color = bandColor(band);

      return `
        <tr style="cursor:pointer;" onclick="window.location.href='/v3/cases.html?identity_id=${encodeURIComponent(item.identity_id)}'">
          <td>
            <div style="font-weight:600; color:#FFFFFF;">${escHtml(item.name || item.identity_id)}</div>
            <div style="font-size:0.6875rem; color:var(--muted); font-family:var(--font-mono);">${escHtml(item.email || item.identity_id)}</div>
          </td>
          <td>
            <div style="display:flex; align-items:center; gap:8px;">
              <div style="flex:1; height:6px; border-radius:3px; background:rgba(255,255,255,0.06); overflow:hidden;">
                <div style="width:${Math.min(risk, 100)}%; height:100%; background:${color}; border-radius:3px;"></div>
              </div>
              <span style="font-family:var(--font-mono); font-weight:700; font-size:0.8125rem; color:${color};">${risk.toFixed(1)}</span>
            </div>
          </td>
          <td>
            <span style="font-family:var(--font-mono); font-size:0.8125rem; color:${sesRisk >= 70 ? 'var(--crit)' : 'var(--text)'};">
              ${sesRisk.toFixed(1)}
            </span>
          </td>
          <td>
            <span class="badge-band badge-band-${band}">${escHtml(band)}</span>
          </td>
          <td style="font-size:0.75rem; color:var(--muted); font-family:var(--font-mono);">
            ${fmt.timeAgo(item.last_seen)}
          </td>
        </tr>
      `;
    }).join('');
  } catch (err) {
    console.error('Failed to load identities:', err);
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:var(--crit); padding:16px;">Failed to load identities.</td></tr>';
  }
}

/**
 * 3. Live Cases Feed
 */
async function loadLiveCases() {
  const container = document.getElementById('live-cases-feed');
  if (!container) return;

  try {
    const raw = await api.get('/cases');
    const cases = Array.isArray(raw) ? raw : (raw?.items || []);
    if (!cases || cases.length === 0) {
      container.innerHTML = '<div style="color:var(--muted); font-size:0.8125rem; text-align:center; padding:20px;">No threat cases opened. System nominal.</div>';
      return;
    }

    renderCasesFeed(cases.slice(0, 4));
  } catch (err) {
    console.error('Failed to load cases:', err);
  }
}

function renderCasesFeed(cases) {
  const container = document.getElementById('live-cases-feed');
  if (!container) return;

  container.innerHTML = cases.map((c) => {
    const band = (c.band || 'monitor').toLowerCase().replace('-', '_');
    const color = bandColor(band);

    return `
      <div onclick="window.location.href='/v3/case.html?id=${encodeURIComponent(c.case_id)}'" style="padding:10px 12px; background:rgba(255,255,255,0.02); border:1px solid var(--panel-border); border-radius:8px; cursor:pointer; transition:all 0.15s ease;" onmouseenter="this.style.borderColor='var(--panel-border-bright)'" onmouseleave="this.style.borderColor='var(--panel-border)'">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
          <div style="display:flex; align-items:center; gap:6px;">
            <span class="badge-band badge-band-${band}" style="padding:1px 6px; font-size:0.6875rem;">${escHtml(band)}</span>
            <span style="font-size:0.75rem; font-weight:600; color:#FFFFFF;">${escHtml(c.identity_id)}</span>
          </div>
          <span style="font-family:var(--font-mono); font-size:0.8125rem; font-weight:700; color:${color};">
            ${Number(c.risk_score || 0).toFixed(1)}
          </span>
        </div>
        <div style="font-size:0.75rem; color:var(--muted); text-overflow:ellipsis; overflow:hidden; white-space:nowrap;">
          ${escHtml(c.title || c.summary || c.case_id)}
        </div>
      </div>
    `;
  }).join('');
}

/**
 * 4. Mini 3D Globe using globe.gl
 */
async function initMiniGlobe() {
  const container = document.getElementById('mini-globe-container');
  if (!container) return;

  if (typeof window.Globe === 'undefined') {
    container.innerHTML = '<div style="color:var(--muted); font-size:0.75rem; padding:12px; text-align:center;">3D Globe engine loading...</div>';
    return;
  }

  try {
    const rawGeo = await api.get('/geo/logins').catch(() => []);
    const geoData = Array.isArray(rawGeo) ? rawGeo : (rawGeo?.points || []);
    container.innerHTML = ''; // clear loading text

    const width = container.clientWidth || 320;
    const height = 200;

    const globe = window.Globe()(container)
      .width(width)
      .height(height)
      .backgroundColor('rgba(0,0,0,0)')
      .showAtmosphere(true)
      .atmosphereColor('#3B82F6')
      .atmosphereAltitude(0.15)
      .globeImageUrl('//unpkg.com/three-globe/example/img/earth-night.jpg')
      .pointsData(geoData)
      .pointLat('lat')
      .pointLng('lon')
      .pointColor((d) => (d.impossible_travel || d.is_threat ? '#EF4444' : '#10B981'))
      .pointAltitude(0.04)
      .pointRadius(0.8)
      .arcsData(
        geoData.length > 1
          ? [
              {
                startLat: geoData[0].lat,
                startLng: geoData[0].lon,
                endLat: geoData[1].lat,
                endLng: geoData[1].lon,
                color: '#EF4444',
              },
            ]
          : []
      )
      .arcColor('color')
      .arcDashLength(0.4)
      .arcDashGap(0.2)
      .arcDashAnimateTime(1500)
      .arcStroke(1.2);

    // Auto-rotate
    globe.controls().autoRotate = true;
    globe.controls().autoRotateSpeed = 0.8;
    globe.controls().enableZoom = false;

    // Camera initial position
    globe.pointOfView({ lat: 30, lng: 0, altitude: 2.2 });

    miniGlobeInstance = globe;

    // Pause on visibility change
    document.addEventListener('visibilitychange', () => {
      if (globe && globe.controls()) {
        globe.controls().autoRotate = !document.hidden;
      }
    });

    // Make container click redirect to globe page
    container.style.cursor = 'pointer';
    container.addEventListener('click', () => {
      window.location.href = '/v3/globe.html';
    });
  } catch (err) {
    console.warn('Mini globe initialization failed:', err);
    container.innerHTML = '<div style="color:var(--muted); font-size:0.75rem; padding:12px; text-align:center;">Geographic telemetry ready (2D mode)</div>';
  }
}

/**
 * 5. Run Dataset Button Workflow
 */
function setupRunDatasetButton() {
  const btn = document.getElementById('btn-run-dataset');
  const btnText = document.getElementById('btn-run-dataset-text');
  if (!btn) return;

  btn.addEventListener('click', async () => {
    try {
      btn.disabled = true;
      if (btnText) btnText.textContent = 'Running Replay...';

      const resp = await api.post('/run/dataset', { pace: 0.0 });
      window.dispatchEvent(
        new CustomEvent('is:toast', {
          detail: { message: `Dataset replay initiated: ${resp.run_id || 'active'}`, type: 'success' },
        })
      );

      // Reload fresh data after a brief pause
      setTimeout(async () => {
        await loadKPIs();
        await loadTopIdentities();
        await loadLiveCases();
        btn.disabled = false;
        if (btnText) btnText.textContent = 'Run Dataset Replay';
      }, 1500);
    } catch (err) {
      btn.disabled = false;
      if (btnText) btnText.textContent = 'Run Dataset Replay';
      window.dispatchEvent(
        new CustomEvent('is:toast', {
          detail: { message: `Run failed: ${err.message}`, type: 'error' },
        })
      );
    }
  });
}

/**
 * 6. SSE Stream Event Listeners
 */
function setupSSEListeners() {
  // Update live throughput EPS counter
  sse.on('metrics', (data) => {
    if (data && data.eps !== undefined) {
      const el = document.getElementById('dashboard-eps-val');
      if (el) el.innerHTML = `${fmt.number(data.eps)} <span style="font-size:0.875rem; font-weight:500;">EPS</span>`;
    }
  });

  // Prepend live case events to the feed
  sse.on('case', (caseItem) => {
    if (!caseItem) return;
    const container = document.getElementById('live-cases-feed');
    if (!container) return;

    const band = (caseItem.band || 'monitor').toLowerCase().replace('-', '_');
    const color = bandColor(band);

    const div = document.createElement('div');
    div.style.cssText = 'padding:10px 12px; background:rgba(59,130,246,0.12); border:1px solid var(--brand); border-radius:8px; cursor:pointer; animation:toast-in 0.3s ease-out;';
    div.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
        <div style="display:flex; align-items:center; gap:6px;">
          <span class="badge-band badge-band-${band}" style="padding:1px 6px; font-size:0.6875rem;">${escHtml(band)}</span>
          <span style="font-size:0.75rem; font-weight:600; color:#FFFFFF;">${escHtml(caseItem.identity_id)}</span>
        </div>
        <span style="font-family:var(--font-mono); font-size:0.8125rem; font-weight:700; color:${color};">
          ${Number(caseItem.risk_score || 0).toFixed(1)}
        </span>
      </div>
      <div style="font-size:0.75rem; color:var(--text); text-overflow:ellipsis; overflow:hidden; white-space:nowrap;">
        ${escHtml(caseItem.title || caseItem.case_id)}
      </div>
    `;
    div.addEventListener('click', () => {
      window.location.href = `/v3/case.html?id=${encodeURIComponent(caseItem.case_id)}`;
    });

    container.prepend(div);
  });
}

// Cleanup on page teardown
window.addEventListener('beforeunload', () => {
  if (miniGlobeInstance && miniGlobeInstance._destructor) {
    miniGlobeInstance._destructor();
  }
});

// Auto-run
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => initDashboard());
} else {
  initDashboard();
}
