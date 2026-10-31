/**
 * IdentityShield v3 — 3D Attack Graph Controller
 * Renders 3d-force-graph with colored nodes, directional red particles along attack paths,
 * camera fly-to on node click, side inspector panel, and 2D vis-network fallback.
 */

import { api } from '../core/api.js';
import { escHtml } from '../core/dom.js';

let graphInstance = null;
let rawGraphData = null;

const NODE_COLORS = {
  identity: '#3D6FE0',
  session: '#6D4FD8',
  ip: '#475569',
  key: '#A16207',
  role: '#C2410C',
  resource: '#0F8A6A',
  sensitive_resource: '#C81E1E',
};

export async function initGraphPage() {
  setupControls();
  await populateIdentityDropdown();
  await loadGraph('global');
}

async function populateIdentityDropdown() {
  const select = document.getElementById('select-graph-identity');
  if (!select) return;

  try {
    const events = await api.get('/events?limit=100');
    const eventList = Array.isArray(events) ? events : (events?.items || []);
    const identities = new Set();

    // Default primary scenarios
    identities.add('svc-report');
    identities.add('jdoe');
    identities.add('asmith');

    for (const ev of eventList) {
      if (ev.identity_id) identities.add(ev.identity_id);
      if (ev.raw_principal) {
        const rp = String(ev.raw_principal);
        const name = rp.includes('/') ? rp.split('/').pop() : (rp.includes('@') ? rp.split('@')[0] : rp);
        if (name && !name.startsWith('arn:')) identities.add(name);
      }
    }

    const currentVal = select.value || 'global';
    select.innerHTML = '<option value="global">Global Attack Graph (All Ingested Logs)</option>';

    for (const id of Array.from(identities).sort()) {
      const opt = document.createElement('option');
      opt.value = id;
      opt.textContent = id === 'svc-report' ? 'svc-report (Hero Attack Chain)' : id;
      if (id === currentVal) opt.selected = true;
      select.appendChild(opt);
    }
  } catch (err) {
    console.warn('Failed to populate identity dropdown:', err);
  }
}

async function loadGraph(identityId = 'global') {
  const container = document.getElementById('graph-canvas-container');
  if (!container) return;

  try {
    const endpoint = identityId === 'global' ? '/graph/global' : `/identities/${encodeURIComponent(identityId)}/graph`;
    const data = await api.get(endpoint);
    rawGraphData = data;
    render3DGraph(container, data);
  } catch (err) {
    console.error('Failed to load graph data:', err);
    render2DVisFallback(container);
  }
}

function render3DGraph(container, data) {
  if (typeof window.ForceGraph3D === 'undefined') {
    render2DVisFallback(container, data);
    return;
  }

  try {
    container.innerHTML = '';
    const width = container.clientWidth || 800;
    const height = container.clientHeight || 600;

    const graph = window.ForceGraph3D()(container)
      .width(width)
      .height(height)
      .backgroundColor('#FFFFFF')
      .graphData(data)
      // Node styling
      .nodeLabel((node) => `
        <div style="background:var(--surface); border:1px solid var(--border); box-shadow:var(--panel-shadow); padding:8px 12px; border:1px solid rgba(148,163,184,0.3); border-radius:6px; font-family:sans-serif; font-size:12px; color:var(--ink);">
          <div style="font-weight:700; color:${NODE_COLORS[node.kind || node.type] || '#3B82F6'}; text-transform:uppercase; font-size:10px;">${escHtml(node.kind || node.type || 'Entity')}</div>
          <div style="margin-top:2px;">${escHtml(node.name || node.id)}</div>
          <div style="margin-top:4px; font-family:monospace; color:#EF4444;">Risk: ${Number(node.risk || 0).toFixed(1)}</div>
        </div>
      `)
      .nodeColor((node) => NODE_COLORS[node.kind || node.type] || '#3B82F6')
      .nodeVal((node) => Math.max(4, (node.risk || 20) / 4))
      .nodeOpacity(0.9)
      // Edge styling: directional particles along attack paths
      .linkWidth((link) => (link.is_attack_path ? 2.5 : 1))
      .linkColor((link) => link.color || (link.is_attack_path ? '#E5484D' : (link.source?.kind === 'identity' || link.target?.kind === 'role' ? '#3D6FE0' : '#CBD5E1')))
      .linkDirectionalParticles((link) => (link.is_attack_path ? 4 : 0))
      .linkDirectionalParticleWidth(2.5)
      .linkDirectionalParticleSpeed(0.008)
      .linkDirectionalParticleColor(() => '#E5484D')
      .linkLabel((link) => `<span style="font-family:monospace; font-size:11px; color:#3D6FE0; font-weight:600;">${escHtml(link.label || '')}</span>`)
      // Click interaction: camera fly-to and inspector update
      .onNodeClick((node) => {
        // Fly-to
        const distance = 140;
        const distRatio = 1 + distance / Math.hypot(node.x, node.y, node.z);
        graph.cameraPosition(
          { x: node.x * distRatio, y: node.y * distRatio, z: node.z * distRatio },
          node,
          1500
        );
        inspectNode(node);
      });

    // Initial camera position
    graph.cameraPosition({ z: 350 });

    graphInstance = graph;

    // Window resize
    window.addEventListener('resize', () => {
      if (graph && container) {
        graph.width(container.clientWidth);
        graph.height(container.clientHeight);
      }
    });
  } catch (err) {
    console.warn('3D Force Graph WebGL failed, falling back to 2D:', err);
    render2DVisFallback(container, data);
  }
}

/**
 * 2D Vis-Network Fallback
 */
function render2DVisFallback(container, data) {
  if (typeof window.vis === 'undefined' || !window.vis.Network) {
    container.innerHTML = '<div style="padding:30px; text-align:center; color:var(--muted);">Graph rendering unavailable.</div>';
    return;
  }

  container.innerHTML = '';
  const nodes = (data?.nodes || []).map((n) => ({
    id: n.id,
    label: n.name || n.id,
    color: NODE_COLORS[n.kind || n.type] || '#3B82F6',
    font: { color: '#FFFFFF', size: 12 },
  }));

  const edges = (data?.links || []).map((l) => ({
    from: l.source?.id || l.source,
    to: l.target?.id || l.target,
    label: l.label,
    color: l.is_attack_path ? '#EF4444' : '#64748B',
    arrows: 'to',
  }));

  const net = new window.vis.Network(
    container,
    { nodes: new window.vis.DataSet(nodes), edges: new window.vis.DataSet(edges) },
    {
      physics: { stabilization: true },
      nodes: { shape: 'dot', size: 16 },
    }
  );

  net.on('click', (params) => {
    if (params.nodes.length > 0) {
      const nid = params.nodes[0];
      const node = (data?.nodes || []).find((n) => n.id === nid);
      if (node) inspectNode(node);
    }
  });
}

function inspectNode(node) {
  const title = document.getElementById('panel-node-title');
  const details = document.getElementById('panel-node-details');
  const linkedCard = document.getElementById('panel-linked-case');
  const btnInvestigate = document.getElementById('panel-btn-investigate');

  if (title) title.textContent = node.name || node.id;

  if (details) {
    details.innerHTML = `
      <div style="display:flex; justify-content:space-between; padding:8px 0; border-bottom:1px solid rgba(148,163,184,0.1);">
        <span style="color:var(--muted);">Entity Type:</span>
        <span style="font-weight:700; color:${NODE_COLORS[node.kind || node.type] || '#3B82F6'}; text-transform:uppercase;">${escHtml(node.kind || node.type || 'Entity')}</span>
      </div>
      <div style="display:flex; justify-content:space-between; padding:8px 0; border-bottom:1px solid rgba(148,163,184,0.1);">
        <span style="color:var(--muted);">Entity ID:</span>
        <span style="font-family:var(--font-mono); color:var(--ink);">${escHtml(node.id)}</span>
      </div>
      <div style="display:flex; justify-content:space-between; padding:8px 0; border-bottom:1px solid rgba(148,163,184,0.1);">
        <span style="color:var(--muted);">Risk Score:</span>
        <span style="font-family:var(--font-mono); font-weight:700; color:${node.is_threat ? 'var(--crit)' : 'var(--ok)'};">${Number(node.risk || 0).toFixed(1)}</span>
      </div>
      <div style="display:flex; justify-content:space-between; padding:8px 0;">
        <span style="color:var(--muted);">Attack Path:</span>
        <span style="color:${node.is_threat ? 'var(--crit)' : 'var(--muted)'}; font-weight:600;">${node.is_threat ? 'ACTIVE PARTICIPANT' : 'BENIGN'}</span>
      </div>
    `;
  }

  if (linkedCard) {
    if (node.is_threat || (node.id || '').includes('svc-report')) {
      linkedCard.style.display = 'block';
      if (btnInvestigate) btnInvestigate.href = `/v3/case.html?id=case-e1-svcreport`;
    } else {
      linkedCard.style.display = 'none';
    }
  }
}

function setupControls() {
  const selectIdentity = document.getElementById('select-graph-identity');
  const chkOnlyAttack = document.getElementById('chk-only-attack');
  const btnReset = document.getElementById('btn-reset-camera');
  const btnScreenshot = document.getElementById('btn-screenshot-graph');

  if (selectIdentity) {
    selectIdentity.addEventListener('change', () => {
      loadGraph(selectIdentity.value);
    });
  }

  if (chkOnlyAttack) {
    chkOnlyAttack.addEventListener('change', () => {
      if (!rawGraphData || !graphInstance) return;
      if (chkOnlyAttack.checked) {
        const attackNodes = rawGraphData.nodes.filter((n) => n.is_threat);
        const attackLinks = rawGraphData.links.filter((l) => l.is_attack_path);
        graphInstance.graphData({ nodes: attackNodes, links: attackLinks });
      } else {
        graphInstance.graphData(rawGraphData);
      }
    });
  }

  const btnRefresh = document.getElementById('btn-refresh-graph');
  if (btnRefresh) {
    btnRefresh.addEventListener('click', async () => {
      btnRefresh.disabled = true;
      btnRefresh.innerHTML = `
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="animate-spin"><path d="M23 4v6h-6"/><path d="M1 20v-6h6"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>
        Refreshing...
      `;
      try {
        await populateIdentityDropdown();
        await loadGraph(selectIdentity ? selectIdentity.value : 'global');
      } finally {
        btnRefresh.disabled = false;
        btnRefresh.innerHTML = `
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M23 4v6h-6"/><path d="M1 20v-6h6"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>
          Refresh Live
        `;
      }
    });
  }

  if (btnReset && graphInstance) {
    btnReset.addEventListener('click', () => {
      graphInstance.cameraPosition({ x: 0, y: 0, z: 350 }, { x: 0, y: 0, z: 0 }, 1000);
    });
  }

  if (btnScreenshot) {
    btnScreenshot.addEventListener('click', () => {
      const canvas = document.querySelector('#graph-canvas-container canvas');
      if (!canvas) return;

      const link = document.createElement('a');
      link.download = `identityshield-graph-${Date.now()}.png`;
      link.href = canvas.toDataURL('image/png');
      link.click();

      window.dispatchEvent(
        new CustomEvent('is:toast', {
          detail: { message: '3D Graph screenshot saved to downloads', type: 'success' },
        })
      );
    });
  }
}

// Cleanup on unload
window.addEventListener('beforeunload', () => {
  if (graphInstance && graphInstance._destructor) {
    graphInstance._destructor();
  }
});

// Auto-run
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => initGraphPage());
} else {
  initGraphPage();
}
