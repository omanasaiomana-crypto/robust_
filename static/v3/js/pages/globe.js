/**
 * IdentityShield v3 — Geographic Login Globe Controller
 * Renders globe.gl with dark texture, login points, animated impossible-travel arcs,
 * identity filtering, and incident event side panel.
 */

import { api } from '../core/api.js';
import { escHtml } from '../core/dom.js';

let globeInstance = null;
let allGeoData = [];

export async function initGlobePage() {
  setupControls();
  await loadGeoData();
}

async function loadGeoData() {
  const container = document.getElementById('globe-container');
  if (!container) return;

  try {
    const data = await api.get('/geo/logins');
    allGeoData = Array.isArray(data) ? data : (data?.points || []);
    renderGlobe(container, allGeoData);
    renderSideLists(allGeoData);
  } catch (err) {
    console.error('Failed to load geo data:', err);
    container.innerHTML = '<div style="padding:40px; text-align:center; color:var(--muted);">Geographic data unavailable.</div>';
  }
}

function renderGlobe(container, geoList) {
  if (typeof window.Globe === 'undefined') {
    container.innerHTML = '<div style="padding:40px; text-align:center; color:var(--muted);">3D Globe engine not loaded.</div>';
    return;
  }

  try {
    container.innerHTML = '';
    const width = container.clientWidth || 800;
    const height = container.clientHeight || 600;

    // Arcs for consecutive logins of svc-report (Frankfurt <-> New York)
    const arcData = [
      {
        startLat: 40.7128,
        startLng: -74.006,
        endLat: 50.1109,
        endLng: 8.6821,
        color: '#E5484D',
        name: 'svc-report: NYC → Frankfurt (6,200 km in 15m, 24,800 km/h)',
      },
    ];

    const globe = window.Globe()(container)
      .width(width)
      .height(height)
      .backgroundColor('rgba(0,0,0,0)')
      .showAtmosphere(true)
      .atmosphereColor('#BFD4FF')
      .atmosphereAltitude(0.12)
      .globeImageUrl('//unpkg.com/three-globe/example/img/earth-night.jpg')
      // Login Points
      .pointsData(geoList)
      .pointLat('lat')
      .pointLng('lon')
      .pointColor((d) => (d.impossible_travel || d.is_threat ? '#E5484D' : '#F08A4B'))
      .pointAltitude((d) => (d.impossible_travel ? 0.08 : 0.03))
      .pointRadius((d) => Math.max(0.6, Math.min(2.5, (d.count || 1) * 0.15)))
      .pointLabel((d) => `
        <div style="background:var(--surface); border:1px solid var(--border); box-shadow:var(--panel-shadow); padding:8px 12px; border:1px solid rgba(148,163,184,0.3); border-radius:6px; font-family:sans-serif; font-size:12px; color:var(--ink);">
          <div style="font-weight:700; color:${d.impossible_travel ? '#E5484D' : '#F08A4B'}; font-size:11px;">${d.impossible_travel ? 'IMPOSSIBLE TRAVEL ORIGIN' : 'TRUSTED INGRESS'}</div>
          <div>${escHtml(d.city || 'Unknown')}, ${escHtml(d.country || '')}</div>
          <div style="font-family:monospace; font-size:11px; color:#94A3B8; margin-top:2px;">IP: ${escHtml(d.ip || '')} (${escHtml(d.asn || '')})</div>
          <div style="margin-top:2px; color:#22D3EE;">Identity: ${escHtml(d.identity_id || '')}</div>
        </div>
      `)
      // Animated Arcs
      .arcsData(arcData)
      .arcColor((d) => d.color || (d.impossible_travel ? '#E5484D' : '#3D6FE0'))
      .arcAltitude(0.25)
      .arcStroke(1.5)
      .arcDashLength(0.4)
      .arcDashGap(0.2)
      .arcDashAnimateTime(1600)
      .arcLabel((d) => `<span style="font-family:monospace; font-size:11px; color:#EF4444;">${escHtml(d.name)}</span>`);

    globe.controls().autoRotate = true;
    globe.controls().autoRotateSpeed = 0.6;
    globe.pointOfView({ lat: 45, lng: -20, altitude: 2.1 });

    globeInstance = globe;

    // Pause on hidden
    document.addEventListener('visibilitychange', () => {
      if (globe && globe.controls()) {
        globe.controls().autoRotate = !document.hidden;
      }
    });

    window.addEventListener('resize', () => {
      if (globe && container) {
        globe.width(container.clientWidth);
        globe.height(container.clientHeight);
      }
    });
  } catch (err) {
    console.warn('3D Globe initialization error:', err);
  }
}

function renderSideLists(geoList) {
  const eventsList = document.getElementById('globe-events-list');
  const locList = document.getElementById('globe-locations-list');

  const impossible = geoList.filter((g) => g.impossible_travel || g.is_threat);

  if (eventsList) {
    if (impossible.length === 0) {
      eventsList.innerHTML = '<div style="color:var(--muted); font-size:0.8125rem;">No impossible travel anomalies detected.</div>';
    } else {
      eventsList.innerHTML = impossible.map((item) => `
        <div style="padding:12px; background:rgba(239,68,68,0.1); border:1px solid rgba(239,68,68,0.3); border-radius:8px;">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
            <span class="badge-band badge-band-revoke" style="font-size:0.625rem; padding:1px 6px;">D-ACC-01</span>
            <span style="font-family:var(--font-mono); font-size:0.75rem; color:#EF4444; font-weight:700;">VELOCITY ANOMALY</span>
          </div>
          <div style="font-weight:700; color:var(--ink); font-size:0.875rem;">${escHtml(item.identity_id)}</div>
          <div style="font-size:0.75rem; color:var(--text); margin-top:2px;">
            New login from ${escHtml(item.city)}, ${escHtml(item.country)} (IP: ${escHtml(item.ip)}) within 15 min of New York login.
          </div>
          <a href="/v3/case.html?id=case-e1-svcreport" class="btn btn-danger" style="margin-top:10px; width:100%; justify-content:center; padding:5px 8px; font-size:0.75rem;">
            Investigate Case E1 &rarr;
          </a>
        </div>
      `).join('');
    }
  }

  if (locList) {
    locList.innerHTML = geoList.map((loc) => `
      <div style="display:flex; justify-content:space-between; align-items:center; padding:8px 10px; background:rgba(255,255,255,0.02); border:1px solid var(--panel-border); border-radius:6px; font-size:0.75rem;">
        <div>
          <div style="font-weight:600; color:var(--ink);">${escHtml(loc.city)}, ${escHtml(loc.country)}</div>
          <div style="color:var(--muted); font-family:var(--font-mono); font-size:0.6875rem;">${escHtml(loc.asn || 'AS-Internal')}</div>
        </div>
        <span class="status-pill" style="font-size:0.625rem; color:${loc.impossible_travel ? 'var(--crit)' : 'var(--ok)'};">
          ${loc.count || 1} logins
        </span>
      </div>
    `).join('');
  }
}

function setupControls() {
  const select = document.getElementById('select-globe-identity');
  const toggleBtn = document.getElementById('btn-toggle-rotate');

  if (select) {
    select.addEventListener('change', () => {
      const id = select.value;
      if (!globeInstance) return;

      if (id === 'all') {
        globeInstance.pointsData(allGeoData);
      } else {
        const filtered = allGeoData.filter((g) => (g.identity_id || '').toLowerCase() === id.toLowerCase());
        globeInstance.pointsData(filtered);
      }
    });
  }

  if (toggleBtn) {
    toggleBtn.addEventListener('click', () => {
      if (globeInstance && globeInstance.controls()) {
        const cur = globeInstance.controls().autoRotate;
        globeInstance.controls().autoRotate = !cur;
      }
    });
  }
}

// Cleanup on unload
window.addEventListener('beforeunload', () => {
  if (globeInstance && globeInstance._destructor) {
    globeInstance._destructor();
  }
});

// Auto-run
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => initGlobePage());
} else {
  initGlobePage();
}
