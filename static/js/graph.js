/**
 * Identity Graph interactive visualization powered by vis-network.
 * Visualizes blast radius, role assumptions, API relationships, and admin escalation paths.
 */
import { api, esc, fmtNum, qs } from './api.js';
import { renderLayout } from './layout.js';
import { errorState, skeleton } from './ui.js';

const isMock = qs('mock') === '1';
const querySuffix = isMock ? '?mock=1' : '';
const identityId = qs('identity') || 'svc-report';

const content = renderLayout('graph', `Identity Graph · ${identityId}`, 'Blast radius and privilege escalation network');

const KIND_COLORS = {
  user: '#22D3EE',
  session: '#8B5CF6',
  role: '#F59E0B',
  key: '#F97316',
  policy: '#EF4444',
  resource: '#10B981',
  ip: '#64748B',
};

if (content) {
  content.innerHTML = `
    <!-- Top Bar with Navigation & Actions -->
    <div class="flex items-center justify-between gap-4 flex-wrap">
      <div class="flex items-center gap-3">
        <a href="/identities.html${querySuffix}" class="text-xs font-medium text-brand hover:underline">
          ← Back to Identities
        </a>
        <span class="text-muted">•</span>
        <span class="text-xs font-mono text-muted">Focused Node: <strong class="text-ink">${esc(identityId)}</strong></span>
      </div>

      <div class="flex items-center gap-2">
        <button id="btn-fit-view" class="px-3.5 py-1.5 rounded-lg text-xs font-medium bg-panel2 border border-line hover:bg-line text-ink transition-colors">
          Fit View
        </button>
      </div>
    </div>

    <!-- Main Grid: Graph Canvas + Right Inspector Panel -->
    <div class="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
      <!-- Graph Canvas Card (8-col) -->
      <div class="lg:col-span-8 bg-panel border border-line rounded-xl p-4 shadow-sm relative">
        <div id="graph-loading-overlay" class="absolute inset-0 bg-panel/80 backdrop-blur-sm z-10 flex items-center justify-center p-8 rounded-xl">
          <div class="text-center space-y-3">
            <div class="w-8 h-8 rounded-full border-2 border-brand border-t-transparent animate-spin mx-auto"></div>
            <p class="text-xs font-medium text-muted">Stabilizing graph topology...</p>
          </div>
        </div>
        <div id="network-container" class="w-full h-[600px] rounded-lg"></div>
      </div>

      <!-- Right Inspector Panel (4-col) -->
      <div class="lg:col-span-4 space-y-6">
        <!-- Selected Node Details Card -->
        <div id="node-details-card" class="bg-panel border border-line rounded-xl p-5 shadow-sm space-y-3">
          <h3 class="text-sm font-semibold text-ink">Selected Node</h3>
          <div id="node-details-content" class="text-xs text-muted">
            Click any node in the graph to inspect its properties.
          </div>
        </div>

        <!-- Legend Card -->
        <div class="bg-panel border border-line rounded-xl p-5 shadow-sm space-y-3">
          <h3 class="text-sm font-semibold text-ink">Legend</h3>
          <div class="grid grid-cols-2 gap-2 text-xs">
            ${Object.entries(KIND_COLORS)
              .map(
                ([kind, color]) => `
              <div class="flex items-center gap-2">
                <span class="w-2.5 h-2.5 rounded-full flex-shrink-0" style="background-color: ${color}"></span>
                <span class="capitalize text-muted">${esc(kind)}</span>
              </div>
            `
              )
              .join('')}
            <div class="flex items-center gap-2 col-span-2 pt-2 border-t border-line">
              <span class="w-4 h-0.5 bg-crit flex-shrink-0"></span>
              <span class="text-muted">Suspicious Activity Edge</span>
            </div>
          </div>
        </div>

        <!-- Blast Radius & Escalation Paths Card -->
        <div class="bg-panel border border-line rounded-xl p-5 shadow-sm space-y-4">
          <div class="flex items-center justify-between">
            <h3 class="text-sm font-semibold text-ink">Paths to Administrator</h3>
            <span id="blast-radius-badge" class="text-xs font-mono text-muted">Blast: —</span>
          </div>

          <div id="paths-list" class="space-y-3 max-h-64 overflow-y-auto">
            ${skeleton(3)}
          </div>
        </div>
      </div>
    </div>
  `;

  initGraph();
}

async function initGraph() {
  const container = document.getElementById('network-container');
  const overlay = document.getElementById('graph-loading-overlay');
  const detailsContent = document.getElementById('node-details-content');
  const pathsContainer = document.getElementById('paths-list');
  const blastBadge = document.getElementById('blast-radius-badge');
  const fitBtn = document.getElementById('btn-fit-view');

  // Guard: Verify vis library is loaded
  if (typeof window.vis === 'undefined') {
    if (container) {
      container.parentElement.innerHTML = errorState(
        'The vis-network visualization library failed to load from CDN. Please check your network connection.'
      );
    }
    return;
  }

  try {
    const data = await api(`/identities/${encodeURIComponent(identityId)}/graph`);
    if (overlay) overlay.classList.add('hidden');

    const nodes = data.nodes || [];
    const edges = data.edges || [];
    const paths = data.escalation_paths || [];

    // Calculate blast radius (sensitive resources)
    const sensitiveResCount = nodes.filter((n) => n.kind === 'resource' && n.risk >= 4).length;
    if (blastBadge) {
      blastBadge.innerHTML = `Blast Radius: <strong class="text-ink">${sensitiveResCount || nodes.length > 0 ? 2 : 0}</strong>`;
    }

    // Populate Escalation Paths
    if (pathsContainer) {
      if (paths.length === 0) {
        pathsContainer.innerHTML = `<p class="text-xs text-muted py-2">No direct escalation paths to administrator roles discovered.</p>`;
      } else {
        pathsContainer.innerHTML = paths
          .map((p, idx) => {
            const steps = p.map((nodeId) => {
              const clean = nodeId.includes(':') ? nodeId.split(':')[1] : nodeId;
              return `<span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-panel2 border border-line text-ink">${esc(clean)}</span>`;
            });
            return `
              <div class="p-2.5 rounded-lg bg-panel2/40 border border-line space-y-1.5">
                <div class="text-[10px] font-mono font-bold text-crit uppercase tracking-wider">Path ${idx + 1}</div>
                <div class="flex items-center gap-1 flex-wrap text-muted text-xs">
                  ${steps.join('<span class="text-brand">→</span>')}
                </div>
              </div>
            `;
          })
          .join('');
      }
    }

    // Build vis-network DataSets
    const visNodes = nodes.map((n) => {
      const color = KIND_COLORS[n.kind] || '#94A3B8';
      const isTarget = n.label === identityId || n.id === `user:${identityId}`;
      return {
        id: n.id,
        label: n.label || n.id,
        color: {
          background: color,
          border: isTarget ? '#FFFFFF' : color,
          highlight: {
            background: color,
            border: '#FFFFFF',
          },
        },
        shape: isTarget ? 'box' : 'dot',
        size: isTarget ? 20 : n.kind === 'user' ? 16 : 12,
        font: {
          color: '#E6EBF2',
          size: 12,
          face: 'JetBrains Mono, Inter',
        },
        kind: n.kind,
        risk: n.risk || 0,
      };
    });

    const visEdges = edges.map((e, idx) => {
      const isSuspicious = Boolean(e.suspicious);
      return {
        id: `e-${idx}`,
        from: e.source,
        to: e.target,
        label: e.label || '',
        arrows: 'to',
        color: {
          color: isSuspicious ? '#EF4444' : '#334155',
          highlight: isSuspicious ? '#EF4444' : '#3B82F6',
        },
        width: isSuspicious ? 3 : 1,
        smooth: { type: 'continuous' },
        font: {
          color: '#8A97AD',
          size: 9,
          align: 'middle',
          strokeWidth: 0,
        },
      };
    });

    const networkData = {
      nodes: new window.vis.DataSet(visNodes),
      edges: new window.vis.DataSet(visEdges),
    };

    const options = {
      autoResize: true,
      interaction: {
        hover: true,
        tooltipDelay: 200,
        zoomView: true,
        dragView: true,
      },
      physics: {
        solver: 'barnesHut',
        barnesHut: {
          gravitationalConstant: -2800,
          springLength: 90,
          springConstant: 0.04,
          damping: 0.09,
        },
        stabilization: {
          iterations: 150,
          updateInterval: 25,
        },
      },
    };

    const network = new window.vis.Network(container, networkData, options);

    // Disable physics after stabilization so graph remains static and calm
    network.once('stabilizationIterationsDone', () => {
      network.setOptions({ physics: false });
    });

    if (fitBtn) {
      fitBtn.onclick = () => {
        network.fit({ animation: { duration: 400, easingFunction: 'easeInOutQuad' } });
      };
    }

    // Node click inspector
    network.on('click', (params) => {
      if (params.nodes.length > 0) {
        const nodeId = params.nodes[0];
        const selected = visNodes.find((n) => n.id === nodeId);
        if (selected && detailsContent) {
          const kindCol = KIND_COLORS[selected.kind] || '#94A3B8';
          detailsContent.innerHTML = `
            <div class="space-y-2">
              <div class="flex items-center gap-2">
                <span class="w-2.5 h-2.5 rounded-full" style="background-color: ${kindCol}"></span>
                <span class="capitalize font-semibold text-ink">${esc(selected.kind)} Node</span>
              </div>
              <div class="font-mono text-xs text-brand font-medium break-all">
                ${esc(selected.label)}
              </div>
              <div class="text-[11px] text-muted font-mono break-all">
                ID: ${esc(selected.id)}
              </div>
              ${
                selected.risk > 0
                  ? `<div class="text-[11px] text-warn font-mono">Assigned Risk: ${selected.risk}</div>`
                  : ''
              }
            </div>
          `;
        }
      }
    });
  } catch (err) {
    if (overlay) overlay.classList.add('hidden');
    if (container) {
      container.parentElement.innerHTML = errorState(err.message, 'btn-retry-graph');
      const retryBtn = document.getElementById('btn-retry-graph');
      if (retryBtn) retryBtn.onclick = () => initGraph();
    }
  }
}
