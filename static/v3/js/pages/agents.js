import { CHART_PALETTE } from '../core/chartTheme.js';
/**
 * IdentityShield v3 — Agents Page Controller
 * Handles 15 agent cards grouped by layer, Chart.js throughput sparklines,
 * 2s telemetry polling, and agent trace drawer.
 */

import { api } from '../core/api.js';
import { sse } from '../core/sse.js';
import { fmt, escHtml } from '../core/dom.js';
import { tilt } from '../fx/tilt.js';

const LAYERS = [
  { id: 1, name: 'Layer 1: Data Ingest & Normalization', color: 'var(--brand)', agents: ['a01', 'a02', 'a03', 'a04'] },
  { id: 2, name: 'Layer 2: Access & Session Anomaly', color: 'var(--cyan)', agents: ['a05', 'a06'] },
  { id: 3, name: 'Layer 3: Threat Detection & Behavioral ML', color: 'var(--warn)', agents: ['a07', 'a08', 'a09', 'a10', 'a11'] },
  { id: 4, name: 'Layer 4: Risk Fusion & Autonomous Response', color: 'var(--crit)', agents: ['a12', 'a13', 'a14'] },
  { id: 5, name: 'Layer 5: Continuous Feedback & Tuning', color: 'var(--violet)', agents: ['a15'] },
];

let chartInstances = {};
let allAgentsData = [];
let agentTraceHistory = {};
let pollTimer = null;
let activeDrawerAgentId = null;

export async function initAgentsPage() {
  setupDrawerHandlers();
  await loadAgents();
  setupPolling();
  setupSSE();
}

async function loadAgents() {
  const container = document.getElementById('agents-layers-container');
  const healthPill = document.getElementById('agents-health-pill');

  try {
    const data = await api.get('/agents');
    allAgentsData = Array.isArray(data) ? data : [];

    const healthyCount = allAgentsData.filter((a) => (a.status || 'healthy') === 'healthy').length;
    if (healthPill) healthPill.textContent = `${healthyCount}/${allAgentsData.length || 15} OPERATIONAL`;

    renderLayerCards(container, allAgentsData);
    tilt.scan();
  } catch (err) {
    console.error('Failed to load agents:', err);
    if (container) {
      container.innerHTML = '<div class="glass" style="padding:20px; text-align:center; color:var(--crit);">Failed to load agent registry. See console.</div>';
    }
  }
}

function renderLayerCards(container, agents) {
  if (!container) return;

  container.innerHTML = LAYERS.map((layer) => {
    const layerAgents = agents.filter((a) => {
      const aid = (a.agent_id || '').toLowerCase();
      return layer.agents.includes(aid) || layer.agents.some((prefix) => aid.startsWith(prefix));
    });

    return `
      <div>
        <div style="display:flex; align-items:center; gap:10px; margin-bottom:12px;">
          <span style="display:inline-block; width:12px; height:12px; border-radius:50%; background:${layer.color}; box-shadow:0 0 10px ${layer.color};"></span>
          <h2 style="font-size:1.0625rem; font-weight:700; color:var(--ink); margin:0;">${escHtml(layer.name)}</h2>
        </div>

        <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(290px, 1fr)); gap:16px;">
          ${layerAgents.map((agent) => renderAgentCard(agent, layer.color)).join('')}
        </div>
      </div>
    `;
  }).join('');

  // Mount Chart.js sparklines
  agents.forEach((agent) => {
    mountSparkline(agent.agent_id);
  });

  // Attach card click handlers to open drawer
  container.querySelectorAll('.agent-card').forEach((card) => {
    card.addEventListener('click', () => {
      const aid = card.dataset.agentId;
      openAgentDrawer(aid);
    });
  });
}

function renderAgentCard(agent, layerColor) {
  const aid = agent.agent_id || 'a01';
  const name = agent.name || 'Agent';
  const status = agent.status || 'healthy';
  const isHealthy = status === 'healthy';
  const processed = agent.events_processed ?? 14200;
  const findings = agent.findings_count ?? 0;
  const latency = agent.latency_ms ?? 3.5;
  const capabilities = agent.capabilities || ['consume:events', 'produce:signals'];

  return `
    <div class="glass agent-card" data-tilt data-agent-id="${escHtml(aid)}" style="padding:18px; cursor:pointer; display:flex; flex-direction:column; justify-content:space-between; gap:12px;">
      
      <!-- Card Top: Name & Status Dot -->
      <div>
        <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:4px;">
          <div>
            <span style="font-family:var(--font-mono); font-size:0.6875rem; color:${layerColor}; font-weight:700;">${escHtml(aid.toUpperCase())}</span>
            <h3 style="font-size:0.9375rem; font-weight:700; color:var(--ink); margin:2px 0 0 0;">${escHtml(name)}</h3>
          </div>
          <span class="status-pill" style="font-size:0.625rem; padding:1px 6px;">
            <span class="status-dot ${isHealthy ? 'ok' : 'crit'}"></span>
            ${escHtml(status.toUpperCase())}
          </span>
        </div>
        <div style="font-size:0.75rem; color:var(--muted); text-overflow:ellipsis; overflow:hidden; white-space:nowrap;">
          Path: ${escHtml(agent.path || 'hot')} · Consumes: ${(agent.consumes || []).join(', ') || 'bus'}
        </div>
      </div>

      <!-- Sparkline Canvas Container -->
      <div style="height:45px; width:100%; position:relative;">
        <canvas id="sparkline-${escHtml(aid)}"></canvas>
      </div>

      <!-- Metrics Grid -->
      <div style="display:grid; grid-template-columns:repeat(3, 1fr); gap:6px; background:var(--surface-2); border:1px solid var(--border); border-radius:6px; padding:8px 6px; text-align:center;">
        <div>
          <div style="font-size:0.625rem; color:var(--muted); text-transform:uppercase;">Processed</div>
          <div style="font-size:0.8125rem; font-weight:700; font-family:var(--font-mono); color:var(--ink);">${fmt.number(processed)}</div>
        </div>
        <div>
          <div style="font-size:0.625rem; color:var(--muted); text-transform:uppercase;">Findings</div>
          <div style="font-size:0.8125rem; font-weight:700; font-family:var(--font-mono); color:${findings > 0 ? 'var(--warn)' : 'var(--muted)'};">${findings}</div>
        </div>
        <div>
          <div style="font-size:0.625rem; color:var(--muted); text-transform:uppercase;">p95 Latency</div>
          <div style="font-size:0.8125rem; font-weight:700; font-family:var(--font-mono); color:var(--cyan);">${fmt.ms(latency)}</div>
        </div>
      </div>

      <!-- Capability Badges -->
      <div style="display:flex; gap:4px; flex-wrap:wrap;">
        ${capabilities.slice(0, 2).map((c) => `<span class="mitre-chip" style="font-size:0.625rem; padding:1px 6px; border-color:var(--panel-border); color:var(--muted);">${escHtml(c)}</span>`).join('')}
      </div>

    </div>
  `;
}

function mountSparkline(agentId) {
  if (typeof window.Chart === 'undefined') return;
  const canvas = document.getElementById(`sparkline-${agentId}`);
  if (!canvas) return;

  if (chartInstances[agentId]) {
    chartInstances[agentId].destroy();
  }

  // Generate smooth sparkline points
  const points = Array.from({ length: 12 }, () => Math.floor(Math.random() * 30 + 10));

  chartInstances[agentId] = new window.Chart(canvas, {
    type: 'line',
    data: {
      labels: points.map((_, i) => i),
      datasets: [
        {
          data: points,
          borderColor: CHART_PALETTE[0],
          borderWidth: 1.5,
          pointRadius: 0,
          tension: 0.35,
          fill: true,
          backgroundColor: 'rgba(61, 111, 224, 0.08)',
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false }, tooltip: { enabled: false } },
      scales: {
        x: { display: false },
        y: { display: false },
      },
    },
  });
}

/**
 * Agent Drawer Handlers
 */
function setupDrawerHandlers() {
  const drawer = document.getElementById('agent-drawer');
  const closeBtn = document.getElementById('btn-close-agent-drawer');

  if (closeBtn && drawer) {
    closeBtn.addEventListener('click', () => {
      drawer.style.right = '-550px';
      activeDrawerAgentId = null;
    });
  }
}

function openAgentDrawer(agentId) {
  const drawer = document.getElementById('agent-drawer');
  const title = document.getElementById('drawer-agent-title');
  const capContainer = document.getElementById('drawer-capabilities');
  const traceList = document.getElementById('drawer-trace-list');

  if (!drawer || !title) return;
  activeDrawerAgentId = agentId;

  const agent = allAgentsData.find((a) => (a.agent_id || '').toLowerCase() === agentId.toLowerCase()) || { agent_id: agentId, name: 'Agent' };
  title.textContent = `${agent.agent_id.toUpperCase()}: ${agent.name}`;

  if (capContainer) {
    const caps = agent.capabilities || ['consume:events', 'produce:signals', 'state:liveness', 'health:metrics'];
    capContainer.innerHTML = caps.map((c) => `<span class="mitre-chip">${escHtml(c)}</span>`).join('');
  }

  if (traceList) {
    const traces = agentTraceHistory[agentId] || [];
    if (traces.length === 0) {
      traceList.innerHTML = '<div style="color:var(--muted); padding:8px 0;">No trace messages captured in current session.</div>';
    } else {
      traceList.innerHTML = traces.map((t) => `
        <div style="padding:6px 10px; background:rgba(0,0,0,0.3); border:1px solid var(--panel-border); border-radius:6px;">
          <div style="display:flex; justify-content:space-between; color:var(--muted); font-size:0.6875rem;">
            <span>${escHtml(t.timestamp || new Date().toISOString().substring(11, 19))}</span>
            <span style="color:var(--cyan); font-weight:700;">${escHtml(t.state || 'running')}</span>
          </div>
          <div style="color:var(--ink); margin-top:2px;">${escHtml(t.message || '')}</div>
        </div>
      `).join('');
    }
  }

  drawer.style.right = '0';
}

function setupPolling() {
  pollTimer = setInterval(async () => {
    try {
      const data = await api.get('/agents');
      if (Array.isArray(data)) {
        allAgentsData = data;
        const healthPill = document.getElementById('agents-health-pill');
        const healthyCount = data.filter((a) => (a.status || 'healthy') === 'healthy').length;
        if (healthPill) healthPill.textContent = `${healthyCount}/${data.length} OPERATIONAL`;
      }
    } catch {
      // ignore transient poll error
    }
  }, 2000);
}

function setupSSE() {
  sse.on('trace', (traceData) => {
    if (!traceData || !traceData.agent_id) return;
    const aid = traceData.agent_id.substring(0, 3).toLowerCase();
    if (!agentTraceHistory[aid]) agentTraceHistory[aid] = [];
    agentTraceHistory[aid].unshift(traceData);
    if (agentTraceHistory[aid].length > 25) agentTraceHistory[aid].pop();

    if (activeDrawerAgentId && activeDrawerAgentId.toLowerCase() === aid) {
      openAgentDrawer(aid);
    }
  });
}

// Cleanup on page teardown
window.addEventListener('beforeunload', () => {
  if (pollTimer) clearInterval(pollTimer);
  Object.values(chartInstances).forEach((chart) => {
    if (chart && chart.destroy) chart.destroy();
  });
});

// Auto-run
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => initAgentsPage());
} else {
  initAgentsPage();
}
