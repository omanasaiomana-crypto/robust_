/**
 * IdentityShield v3 — Live Page Controller
 * Renders 15-Agent 3D Constellation (Three.js with 2D SVG fallback),
 * traveling message particles, interactive terminal trace log, and dataset replay controls.
 */

import { api } from '../core/api.js';
import { sse } from '../core/sse.js';
import { fmt, escHtml } from '../core/dom.js';

// 15 Canonical Agent Definitions & Layer Rings
const AGENT_NODES = [
  // Layer 1: Data (Ring Radius 140)
  { id: 'a01', name: 'Collector', layer: 1, ringRadius: 140, angle: 0 },
  { id: 'a02', name: 'Normalizer', layer: 1, ringRadius: 140, angle: Math.PI * 0.5 },
  { id: 'a03', name: 'Context Intel', layer: 1, ringRadius: 140, angle: Math.PI },
  { id: 'a04', name: 'Correlation', layer: 1, ringRadius: 140, angle: Math.PI * 1.5 },

  // Layer 2: Access Detection (Ring Radius 220)
  { id: 'a05', name: 'Access Anomaly', layer: 2, ringRadius: 220, angle: Math.PI * 0.25 },
  { id: 'a06', name: 'Session Integrity', layer: 2, ringRadius: 220, angle: Math.PI * 1.25 },

  // Layer 3: Threat Detection (Ring Radius 300)
  { id: 'a07', name: 'Credentials', layer: 3, ringRadius: 300, angle: 0 },
  { id: 'a08', name: 'Privilege Esc', layer: 3, ringRadius: 300, angle: Math.PI * 0.4 },
  { id: 'a09', name: 'Defense Evasion', layer: 3, ringRadius: 300, angle: Math.PI * 0.8 },
  { id: 'a10', name: 'Behavioral ML', layer: 3, ringRadius: 300, angle: Math.PI * 1.2 },
  { id: 'a11', name: 'Campaign', layer: 3, ringRadius: 300, angle: Math.PI * 1.6 },

  // Layer 4: Decision (Ring Radius 380)
  { id: 'a12', name: 'Risk Fusion', layer: 4, ringRadius: 380, angle: Math.PI * 0.3 },
  { id: 'a13', name: 'Investigation', layer: 4, ringRadius: 380, angle: Math.PI * 0.9 },
  { id: 'a14', name: 'Response', layer: 4, ringRadius: 380, angle: Math.PI * 1.5 },

  // Layer 5: Learning (Ring Radius 450)
  { id: 'a15', name: 'Feedback & Tuning', layer: 5, ringRadius: 450, angle: Math.PI * 0.7 },
];

let threeScene = null;
let threeCamera = null;
let threeRenderer = null;
let threeRafId = null;
let nodeMeshes = {};
let travelingParticles = [];

let isPaused = false;
let traceCount = 0;
let counters = { events: 0, signals: 0, cases: 0, threats: 0 };

export async function initLivePage() {
  setupPaceAndRunControls();
  setupTraceControls();
  initConstellation();
  setupSSE();
}

/**
 * 1. Initialize 3D Constellation (with 2D SVG fallback)
 */
function initConstellation() {
  const container = document.getElementById('constellation-container');
  if (!container) return;

  if (typeof window.THREE === 'undefined') {
    render2DSvgFallback(container);
    return;
  }

  try {
    const width = container.clientWidth || 600;
    const height = container.clientHeight || 500;

    const scene = new window.THREE.Scene();
    const camera = new window.THREE.PerspectiveCamera(50, width / height, 1, 3000);
    camera.position.set(0, -180, 750);
    camera.lookAt(0, 0, 0);

    const renderer = new window.THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    container.innerHTML = '';
    container.appendChild(renderer.domElement);

    threeScene = scene;
    threeCamera = camera;
    threeRenderer = renderer;

    // Ambient & Point Lighting
    scene.add(new window.THREE.AmbientLight(0xffffff, 0.8));
    const pointLight = new window.THREE.PointLight(0x22d3ee, 2, 800);
    pointLight.position.set(0, 0, 200);
    scene.add(pointLight);

    // 1. Render 5 Concentric Layer Rings
    const ringRadii = [140, 220, 300, 380, 450];
    const ringColors = [0x3b82f6, 0x22d3ee, 0xf59e0b, 0xef4444, 0x8b5cf6];

    ringRadii.forEach((r, idx) => {
      const ringGeom = new window.THREE.RingGeometry(r - 1, r + 1, 64);
      const ringMat = new window.THREE.MeshBasicMaterial({
        color: ringColors[idx],
        side: window.THREE.DoubleSide,
        transparent: true,
        opacity: 0.18,
      });
      const ringMesh = new window.THREE.Mesh(ringGeom, ringMat);
      scene.add(ringMesh);
    });

    // 2. Render 15 Agent Sphere Nodes with Sprite Labels
    AGENT_NODES.forEach((agent) => {
      const x = Math.cos(agent.angle) * agent.ringRadius;
      const y = Math.sin(agent.angle) * agent.ringRadius;

      // Outer glow sphere
      const sphereGeom = new window.THREE.SphereGeometry(14, 24, 24);
      const sphereMat = new window.THREE.MeshStandardMaterial({
        color: 0x3b82f6,
        emissive: 0x1d4ed8,
        emissiveIntensity: 0.4,
        roughness: 0.3,
        metalness: 0.8,
      });
      const sphere = new window.THREE.Mesh(sphereGeom, sphereMat);
      sphere.position.set(x, y, 0);
      scene.add(sphere);

      // Text label sprite
      const canvas = document.createElement('canvas');
      canvas.width = 256;
      canvas.height = 64;
      const ctx = canvas.getContext('2d');
      ctx.fillStyle = '#E5E7EB';
      ctx.font = 'bold 24px Inter, sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText(`${agent.id.toUpperCase()}: ${agent.name}`, 128, 40);

      const texture = new window.THREE.CanvasTexture(canvas);
      const spriteMat = new window.THREE.SpriteMaterial({ map: texture, transparent: true, opacity: 0.85 });
      const sprite = new window.THREE.Sprite(spriteMat);
      sprite.position.set(x, y - 26, 5);
      sprite.scale.set(64, 16, 1);
      scene.add(sprite);

      nodeMeshes[agent.id] = {
        mesh: sphere,
        sprite,
        agent,
        x,
        y,
        baseColor: 0x3b82f6,
        state: 'idle',
        pulse: 0,
      };
    });

    // Handle mouse drag orbit
    let isDragging = false;
    let prevMouseX = 0;
    let prevMouseY = 0;

    container.addEventListener('mousedown', (e) => {
      isDragging = true;
      prevMouseX = e.clientX;
      prevMouseY = e.clientY;
    });

    window.addEventListener('mouseup', () => (isDragging = false));

    window.addEventListener('mousemove', (e) => {
      if (!isDragging) return;
      const dx = e.clientX - prevMouseX;
      const dy = e.clientY - prevMouseY;
      prevMouseX = e.clientX;
      prevMouseY = e.clientY;

      scene.rotation.z += dx * 0.005;
      scene.rotation.x += dy * 0.005;
    });

    // Resize handler
    const onResize = () => {
      if (!container || !renderer || !camera) return;
      const w = container.clientWidth;
      const h = container.clientHeight;
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      renderer.setSize(w, h);
    };
    window.addEventListener('resize', onResize);

    // Animation Loop
    const animate = () => {
      threeRafId = requestAnimationFrame(animate);

      // Gentle auto-rotation
      if (!isDragging) {
        scene.rotation.z += 0.001;
      }

      // Animate pulsing agent nodes
      Object.values(nodeMeshes).forEach((node) => {
        if (node.state === 'running') {
          node.pulse += 0.08;
          const s = 1 + Math.sin(node.pulse) * 0.2;
          node.mesh.scale.set(s, s, s);
        } else if (node.state === 'finding') {
          node.mesh.material.color.setHex(0xf59e0b);
          node.mesh.material.emissive.setHex(0xd97706);
        } else if (node.state === 'threat') {
          node.mesh.material.color.setHex(0xef4444);
          node.mesh.material.emissive.setHex(0xb91c1c);
          node.mesh.scale.set(1.4, 1.4, 1.4);
        } else {
          node.mesh.scale.set(1, 1, 1);
          node.mesh.material.color.setHex(0x3b82f6);
          node.mesh.material.emissive.setHex(0x1d4ed8);
        }
      });

      // Animate traveling particles between nodes
      for (let i = travelingParticles.length - 1; i >= 0; i--) {
        const p = travelingParticles[i];
        p.progress += 0.035;

        if (p.progress >= 1.0) {
          scene.remove(p.mesh);
          travelingParticles.splice(i, 1);
        } else {
          p.mesh.position.x = p.startX + (p.targetX - p.startX) * p.progress;
          p.mesh.position.y = p.startY + (p.targetY - p.startY) * p.progress;
          p.mesh.position.z = Math.sin(p.progress * Math.PI) * 40; // arc up
        }
      }

      renderer.render(scene, camera);
    };

    animate();
  } catch (err) {
    console.warn('Three.js constellation failed, using 2D SVG fallback:', err);
    render2DSvgFallback(container);
  }
}

/**
 * 2D SVG Fallback if WebGL fails
 */
function render2DSvgFallback(container) {
  container.innerHTML = `
    <svg viewBox="-500 -500 1000 1000" style="width:100%; height:100%;">
      <circle r="140" fill="none" stroke="#3B82F6" stroke-width="2" opacity="0.25" />
      <circle r="220" fill="none" stroke="#22D3EE" stroke-width="2" opacity="0.25" />
      <circle r="300" fill="none" stroke="#F59E0B" stroke-width="2" opacity="0.25" />
      <circle r="380" fill="none" stroke="#EF4444" stroke-width="2" opacity="0.25" />
      <circle r="450" fill="none" stroke="#8B5CF6" stroke-width="2" opacity="0.25" />
      ${AGENT_NODES.map((a) => {
        const x = Math.cos(a.angle) * a.ringRadius;
        const y = Math.sin(a.angle) * a.ringRadius;
        return `
          <g transform="translate(${x}, ${y})">
            <circle r="14" fill="#3B82F6" />
            <text y="26" text-anchor="middle" fill="#E5E7EB" font-size="12" font-family="monospace">${escHtml(a.id.toUpperCase())}</text>
          </g>
        `;
      }).join('')}
    </svg>
  `;
}

/**
 * Spawn traveling particle when message moves between agents
 */
function spawnParticle(fromAgentId, toAgentId) {
  if (!threeScene) return;
  const fromNode = nodeMeshes[fromAgentId];
  const toNode = nodeMeshes[toAgentId];
  if (!fromNode || !toNode) return;

  const geom = new window.THREE.SphereGeometry(4, 12, 12);
  const mat = new window.THREE.MeshBasicMaterial({ color: 0x22d3ee });
  const pMesh = new window.THREE.Mesh(geom, mat);
  pMesh.position.set(fromNode.x, fromNode.y, 0);
  threeScene.add(pMesh);

  travelingParticles.push({
    mesh: pMesh,
    startX: fromNode.x,
    startY: fromNode.y,
    targetX: toNode.x,
    targetY: toNode.y,
    progress: 0,
  });
}

/**
 * 2. Setup Terminal Trace Controls & Rendering
 */
function setupTraceControls() {
  const pauseBtn = document.getElementById('btn-pause-trace');
  const clearBtn = document.getElementById('btn-clear-trace');
  const logContainer = document.getElementById('terminal-trace-log');

  if (pauseBtn) {
    pauseBtn.addEventListener('click', () => {
      isPaused = !isPaused;
      pauseBtn.textContent = isPaused ? 'Resume' : 'Pause';
      pauseBtn.classList.toggle('btn-primary', isPaused);
    });
  }

  if (clearBtn && logContainer) {
    clearBtn.addEventListener('click', () => {
      logContainer.innerHTML = '';
      traceCount = 0;
    });
  }
}

function appendTraceLine(trace) {
  if (isPaused) return;

  const container = document.getElementById('terminal-trace-log');
  if (!container) return;

  traceCount++;
  const agentId = (trace.agent_id || 'a01').substring(0, 3).toLowerCase();
  const state = trace.state || 'running';
  const time = trace.timestamp ? trace.timestamp.substring(11, 19) : new Date().toISOString().substring(11, 19);

  // Trigger agent node animation
  if (nodeMeshes[agentId]) {
    nodeMeshes[agentId].state = state;
    setTimeout(() => {
      if (nodeMeshes[agentId]) nodeMeshes[agentId].state = 'idle';
    }, 1200);

    // Spawn message particle to downstream agent
    const agentNum = parseInt(agentId.replace('a', ''), 10);
    if (!isNaN(agentNum) && agentNum < 15) {
      const nextId = `a${String(agentNum + 1).padStart(2, '0')}`;
      spawnParticle(agentId, nextId);
    }
  }

  // Update Counters
  counters.events++;
  if (state === 'finding') counters.signals++;
  if (state === 'threat' || (trace.message || '').includes('Case')) counters.cases++;
  if (state === 'threat') counters.threats++;
  updateCountersUI();

  // Color mapping
  let levelColor = 'var(--muted)';
  let levelBadge = 'INFO';
  if (state === 'running') {
    levelColor = 'var(--cyan)';
    levelBadge = 'RUN';
  } else if (state === 'finding') {
    levelColor = 'var(--warn)';
    levelBadge = 'FIND';
  } else if (state === 'threat') {
    levelColor = 'var(--crit)';
    levelBadge = 'THREAT';
  }

  const row = document.createElement('div');
  row.style.cssText = 'padding:4px 8px; border-radius:4px; display:flex; gap:8px; align-items:baseline; cursor:pointer; transition:background 0.1s;';
  row.onmouseenter = () => (row.style.background = 'rgba(255,255,255,0.05)');
  row.onmouseleave = () => (row.style.background = 'transparent');

  row.innerHTML = `
    <span style="color:var(--muted); font-size:0.6875rem;">${time}</span>
    <span style="color:${levelColor}; font-weight:700; font-size:0.6875rem;">[${levelBadge}]</span>
    <span style="color:var(--brand); font-weight:600; font-size:0.6875rem;">[${escHtml(trace.agent_id || agentId)}]</span>
    <span style="color:#FFFFFF; flex:1; word-break:break-all;">${escHtml(trace.message || 'Processing event batch')}</span>
  `;

  row.addEventListener('click', () => {
    const inspector = document.getElementById('trace-inspector');
    if (inspector) {
      inspector.innerHTML = `
        <div style="color:var(--cyan); margin-bottom:4px; font-weight:700;">Trace Event Inspector (${escHtml(trace.agent_id || '')})</div>
        <pre style="margin:0; white-space:pre-wrap; word-break:break-all;">${escHtml(JSON.stringify(trace, null, 2))}</pre>
      `;
    }
  });

  container.appendChild(row);

  // Keep max 200 items in log
  if (container.children.length > 200) {
    container.removeChild(container.firstChild);
  }

  container.scrollTop = container.scrollHeight;
}

function updateCountersUI() {
  const ev = document.getElementById('cnt-events');
  const sig = document.getElementById('cnt-signals');
  const cas = document.getElementById('cnt-cases');
  const thr = document.getElementById('cnt-threats');

  if (ev) ev.textContent = fmt.number(counters.events);
  if (sig) sig.textContent = fmt.number(counters.signals);
  if (cas) cas.textContent = fmt.number(counters.cases);
  if (thr) thr.textContent = fmt.number(counters.threats);
}

/**
 * 3. Setup Pace & Dataset Replay Controls
 */
function setupPaceAndRunControls() {
  const btnScan = document.getElementById('btn-start-scan');
  const btnReplay = document.getElementById('btn-replay-last');
  const selectPace = document.getElementById('select-pace');
  const statusPill = document.getElementById('live-status-pill');
  const statusText = document.getElementById('live-status-text');

  const executeReplay = async () => {
    const pace = parseFloat(selectPace?.value || '0.0');
    try {
      if (statusText) statusText.textContent = 'LIVE · SIMULATING';
      if (statusPill) statusPill.style.background = 'rgba(239, 68, 68, 0.2)';

      const resp = await api.post('/run/dataset', { pace });
      window.dispatchEvent(
        new CustomEvent('is:toast', {
          detail: { message: `Replay active: ${resp.run_id || 'e1_attack'}`, type: 'success' },
        })
      );
    } catch (err) {
      window.dispatchEvent(
        new CustomEvent('is:toast', {
          detail: { message: `Replay trigger failed: ${err.message}`, type: 'error' },
        })
      );
      if (statusText) statusText.textContent = 'LIVE · STREAMING';
    }
  };

  if (btnScan) btnScan.addEventListener('click', executeReplay);
  if (btnReplay) btnReplay.addEventListener('click', executeReplay);
}

/**
 * 4. SSE Stream Wiring
 */
function setupSSE() {
  sse.on('trace', (traceData) => {
    if (traceData) appendTraceLine(traceData);
  });
}

// Cleanup on unload
window.addEventListener('beforeunload', () => {
  if (threeRafId) cancelAnimationFrame(threeRafId);
  if (threeRenderer) threeRenderer.dispose();
});

// Auto-run
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => initLivePage());
} else {
  initLivePage();
}
