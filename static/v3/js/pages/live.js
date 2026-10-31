/**
 * IdentityShield v3 — Live Page Controller
 * Renders 15-Agent 3D Constellation (Three.js with 2D SVG fallback),
 * traveling message particles, interactive terminal trace log, and dataset replay controls.
 */

import { api } from '../core/api.js';
import { sse } from '../core/sse.js';
import { fmt, escHtml } from '../core/dom.js';

// 15 Canonical Agent Definitions & 4 Pipeline Layers
const AGENT_NODES = [
  // Layer 0: Data (blue, radius 150) - 4 agents
  { id: 'a01', num: 1, name: 'Collector', shortName: '1 Collector', layer: 'Data', ringRadius: 150, angle: 0 },
  { id: 'a02', num: 2, name: 'Normalizer', shortName: '2 Normalizer', layer: 'Data', ringRadius: 150, angle: Math.PI * 0.5 },
  { id: 'a03', num: 3, name: 'Context', shortName: '3 Context', layer: 'Data', ringRadius: 150, angle: Math.PI },
  { id: 'a04', num: 4, name: 'Correlation', shortName: '4 Correlation', layer: 'Data', ringRadius: 150, angle: Math.PI * 1.5 },

  // Layer 1: Detection (purple, radius 240) - 7 agents
  { id: 'a05', num: 5, name: 'Access', shortName: '5 Access', layer: 'Detection', ringRadius: 240, angle: 0 },
  { id: 'a06', num: 6, name: 'Session', shortName: '6 Session', layer: 'Detection', ringRadius: 240, angle: (Math.PI * 2 / 7) * 1 },
  { id: 'a07', num: 7, name: 'Credentials', shortName: '7 Credentials', layer: 'Detection', ringRadius: 240, angle: (Math.PI * 2 / 7) * 2 },
  { id: 'a08', num: 8, name: 'Escalation', shortName: '8 Escalation', layer: 'Detection', ringRadius: 240, angle: (Math.PI * 2 / 7) * 3 },
  { id: 'a09', num: 9, name: 'Evasion', shortName: '9 Evasion', layer: 'Detection', ringRadius: 240, angle: (Math.PI * 2 / 7) * 4 },
  { id: 'a10', num: 10, name: 'Behavior ML', shortName: '10 Behavior ML', layer: 'Detection', ringRadius: 240, angle: (Math.PI * 2 / 7) * 5 },
  { id: 'a11', num: 11, name: 'Campaign', shortName: '11 Campaign', layer: 'Detection', ringRadius: 240, angle: (Math.PI * 2 / 7) * 6 },

  // Layer 2: Decision (orange, radius 330) - 3 agents
  { id: 'a12', num: 12, name: 'Risk Fusion', shortName: '12 Risk Fusion', layer: 'Decision', ringRadius: 330, angle: 0 },
  { id: 'a13', num: 13, name: 'Investigation', shortName: '13 Investigation', layer: 'Decision', ringRadius: 330, angle: (Math.PI * 2 / 3) * 1 },
  { id: 'a14', num: 14, name: 'Response', shortName: '14 Response', layer: 'Decision', ringRadius: 330, angle: (Math.PI * 2 / 3) * 2 },

  // Layer 3: Learning (green, radius 420) - 1 agent
  { id: 'a15', num: 15, name: 'Feedback', shortName: '15 Feedback', layer: 'Learning', ringRadius: 420, angle: 0 },
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
  setupFileUploadSimulation();
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
    scene.add(new window.THREE.HemisphereLight(0xffffff, 0xf6f1e9, 0.95));
    const dirLight = new window.THREE.DirectionalLight(0xffffff, 0.6);
    dirLight.position.set(100, 200, 300);
    scene.add(dirLight);

    // 1. Render 4 Concentric Pipeline Layer Rings (Data, Detection, Decision, Learning)
    const ringRadii = [150, 240, 330, 420];
    const ringColors = [0x3d6fe0, 0x8b5cf6, 0xf97316, 0x10b981];
    const ringLabels = ['DATA', 'DETECTION', 'DECISION', 'LEARNING'];

    ringRadii.forEach((r, idx) => {
      const ringGeom = new window.THREE.RingGeometry(r - 1.5, r + 1.5, 96);
      const ringMat = new window.THREE.MeshBasicMaterial({
        color: ringColors[idx],
        side: window.THREE.DoubleSide,
        transparent: true,
        opacity: 0.45,
      });
      const ringMesh = new window.THREE.Mesh(ringGeom, ringMat);
      scene.add(ringMesh);

      // Ring Caption Sprite at top
      const cCanvas = document.createElement('canvas');
      cCanvas.width = 256;
      cCanvas.height = 64;
      const cCtx = cCanvas.getContext('2d');
      cCtx.fillStyle = '#6B7280';
      cCtx.font = 'bold 20px monospace';
      cCtx.textAlign = 'center';
      cCtx.fillText(ringLabels[idx], 128, 40);

      const cTex = new window.THREE.CanvasTexture(cCanvas);
      const cMat = new window.THREE.SpriteMaterial({ map: cTex, transparent: true, opacity: 0.75 });
      const cSprite = new window.THREE.Sprite(cMat);
      cSprite.position.set(0, r + 16, 0);
      cSprite.scale.set(60, 15, 1);
      scene.add(cSprite);
    });

    // 2. Render 15 Agent Sphere Nodes with Exact Names & Number
    AGENT_NODES.forEach((agent) => {
      const x = Math.cos(agent.angle) * agent.ringRadius;
      const y = Math.sin(agent.angle) * agent.ringRadius;

      // Node layer color mapping
      let nodeColorHex = 0x3d6fe0; // Data (blue)
      if (agent.layer === 'Detection') { nodeColorHex = 0x8b5cf6; } // Detection (purple)
      else if (agent.layer === 'Decision') { nodeColorHex = 0xf97316; } // Decision (orange)
      else if (agent.layer === 'Learning') { nodeColorHex = 0x10b981; } // Learning (green)

      const sphereGeom = new window.THREE.SphereGeometry(14, 24, 24);
      const sphereMat = new window.THREE.MeshStandardMaterial({
        color: nodeColorHex,
        emissive: nodeColorHex,
        emissiveIntensity: 0.25,
        roughness: 0.35,
        metalness: 0.15,
      });
      const sphere = new window.THREE.Mesh(sphereGeom, sphereMat);
      sphere.position.set(x, y, 0);
      scene.add(sphere);

      // Text label sprite with 12px UI font & short name (e.g. "8 Escalation")
      const canvas = document.createElement('canvas');
      canvas.width = 256;
      canvas.height = 64;
      const ctx = canvas.getContext('2d');
      ctx.fillStyle = '#FFFFFF';
      ctx.font = 'bold 22px Inter, sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText(agent.shortName, 128, 40);

      const texture = new window.THREE.CanvasTexture(canvas);
      const spriteMat = new window.THREE.SpriteMaterial({ map: texture, transparent: true, opacity: 0.9 });
      const sprite = new window.THREE.Sprite(spriteMat);
      sprite.position.set(x, y - 24, 5);
      sprite.scale.set(64, 16, 1);
      scene.add(sprite);

      nodeMeshes[agent.id] = {
        mesh: sphere,
        sprite,
        agent,
        x,
        y,
        baseColor: nodeColorHex,
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
          node.mesh.material.color.setHex(0xfff3c4);
          node.mesh.material.color.setHex(0xfff3c4);
        } else if (node.state === 'threat') {
          node.mesh.material.color.setHex(0xe5484d);
          node.mesh.material.color.setHex(0xe5484d);
          node.mesh.scale.set(1.4, 1.4, 1.4);
        } else {
          node.mesh.scale.set(1, 1, 1);
          node.mesh.material.color.setHex(node.baseColor || 0xdce8ff);
          
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
  row.onmouseenter = () => (row.style.background = 'rgba(0,0,0,0.04)');
  row.onmouseleave = () => (row.style.background = 'transparent');

  row.innerHTML = `
    <span style="color:var(--muted); font-size:0.6875rem;">${time}</span>
    <span style="color:${levelColor}; font-weight:700; font-size:0.6875rem;">[${levelBadge}]</span>
    <span style="color:var(--brand); font-weight:600; font-size:0.6875rem;">[${escHtml(trace.agent_id || agentId)}]</span>
    <span style="color:var(--ink); flex:1; word-break:break-all;">${escHtml(trace.message || 'Processing event batch')}</span>
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

  if (state === 'threat') { row.style.background = '#FFE0E0'; row.style.border = '1px solid #E5484D'; }
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

      const resp = await api.post('/run/dataset', {
        paths: 'tests/v3/fixtures/e1_attack.json',
        pace,
      });
      window.dispatchEvent(
        new CustomEvent('is:toast', {
          detail: { message: `Replay active: ${resp.run_id || 'e1_attack'} (${resp.events || 10} events)`, type: 'success' },
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
 * 4. File Upload & Live Simulation Engine
 */
let currentSimAbort = null;

function triggerAgent(agentId, state, durationMs = 800) {
  if (nodeMeshes[agentId]) {
    nodeMeshes[agentId].state = state;
    setTimeout(() => {
      if (nodeMeshes[agentId] && nodeMeshes[agentId].state === state) {
        nodeMeshes[agentId].state = 'idle';
      }
    }, durationMs);
  }
}

function parseRecordsFromText(text) {
  text = text.trim();
  if (!text) return [];

  // Try JSON
  try {
    const parsed = JSON.parse(text);
    if (Array.isArray(parsed)) return parsed;
    if (parsed && typeof parsed === 'object') {
      if (Array.isArray(parsed.Records)) return parsed.Records;
      if (Array.isArray(parsed.records)) return parsed.records;
      if (Array.isArray(parsed.events)) return parsed.events;
      if (Array.isArray(parsed.data)) return parsed.data;
      return [parsed];
    }
  } catch {}

  // Try JSON Lines
  const lines = text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  const jsonlRecords = [];
  for (const line of lines) {
    try {
      const obj = JSON.parse(line);
      if (obj && typeof obj === 'object') {
        if (obj.event && typeof obj.event === 'object') {
          jsonlRecords.push(obj.event);
        } else {
          jsonlRecords.push(obj);
        }
      }
    } catch {}
  }
  if (jsonlRecords.length > 0) return jsonlRecords;

  // Try CSV
  if (lines.length > 1 && lines[0].includes(',')) {
    const headers = lines[0].split(',').map((h) => h.trim().replace(/^["']|["']$/g, ''));
    const csvRecords = [];
    for (let i = 1; i < lines.length; i++) {
      const vals = lines[i].split(',').map((v) => v.trim().replace(/^["']|["']$/g, ''));
      if (vals.length === headers.length) {
        const row = {};
        headers.forEach((h, idx) => { row[h] = vals[idx]; });
        csvRecords.push(row);
      }
    }
    if (csvRecords.length > 0) return csvRecords;
  }

  return [];
}

async function simulateUploadedRecords(filename, records) {
  if (currentSimAbort) {
    currentSimAbort.aborted = true;
  }
  const simContext = { aborted: false };
  currentSimAbort = simContext;

  const statusPill = document.getElementById('live-status-pill');
  const statusDot = document.getElementById('live-status-dot');
  const statusText = document.getElementById('live-status-text');
  const selectPace = document.getElementById('select-pace');

  if (statusText) statusText.textContent = `SIMULATING · ${filename} (${records.length} events)`;
  if (statusDot) statusDot.className = 'status-dot warn animate-pulse';
  if (statusPill) statusPill.style.background = 'rgba(245, 158, 11, 0.2)';

  window.dispatchEvent(
    new CustomEvent('is:toast', {
      detail: { message: `Simulating ${filename}: streaming ${records.length} events through 15 agents...`, type: 'info' },
    })
  );

  // Fallback to sample events if empty
  if (records.length === 0) {
    records = [
      { event_id: 'ev-01', action: 'ConsoleLogin', identity: 'alice@corp.example', source: 'okta' },
      { event_id: 'ev-02', action: 'AssumeRole', identity: 'alice@corp.example', source: 'cloudtrail' },
      { event_id: 'ev-03', action: 'AttachRolePolicy', identity: 'alice@corp.example', source: 'cloudtrail' },
      { event_id: 'ev-04', action: 'CreateAccessKey', identity: 'alice@corp.example', source: 'cloudtrail' },
      { event_id: 'ev-05', action: 'StopLogging', identity: 'alice@corp.example', source: 'cloudtrail' },
    ];
  }

  for (let idx = 0; idx < records.length; idx++) {
    if (simContext.aborted) break;
    const rec = records[idx];

    const identity =
      rec.identity ||
      rec.user ||
      rec.userName ||
      (rec.actor && (rec.actor.alternateId || rec.actor.id)) ||
      (rec.userIdentity && rec.userIdentity.userName) ||
      'dev@corp.example';
    const action = rec.action || rec.eventName || rec.eventType || 'GetCallerIdentity';
    const source = rec.source || (rec.eventSource ? 'cloudtrail' : rec.eventType ? 'okta' : 'aws');
    const eid = rec.eventID || rec.uuid || rec.id || `evt-${idx + 1}`;

    const paceVal = parseFloat(selectPace?.value || '0.8');
    const stepDelay = Math.max(35, paceVal * 320);

    // 1. Data Layer: Collector (a01) -> Normalizer (a02) -> Correlation (a04)
    triggerAgent('a01', 'running', 400);
    appendTraceLine({ agent_id: 'a01', state: 'running', message: `Collected event ${eid} (${source}) for ${identity}` });
    spawnParticle('a01', 'a02');
    await new Promise((r) => setTimeout(r, stepDelay * 0.5));

    triggerAgent('a02', 'running', 400);
    appendTraceLine({ agent_id: 'a02', state: 'running', message: `Normalized schema & resolved principal ${identity}` });
    spawnParticle('a02', 'a04');
    await new Promise((r) => setTimeout(r, stepDelay * 0.5));

    triggerAgent('a04', 'running', 400);
    appendTraceLine({ agent_id: 'a04', state: 'running', message: `Correlated graph edge for ${action}` });

    // 2. Detection Layer: Route to specific detection agent
    let detId = 'a05';
    let isThreat = false;
    let isFinding = false;

    const actLower = String(action).toLowerCase();
    if (actLower.includes('escalat') || actLower.includes('policy') || actLower.includes('role') || actLower.includes('admin')) {
      detId = 'a08'; // Escalation
      isThreat = true;
    } else if (actLower.includes('key') || actLower.includes('password') || actLower.includes('factor') || actLower.includes('cred')) {
      detId = 'a07'; // Credentials
      isFinding = true;
    } else if (actLower.includes('stop') || actLower.includes('delete') || actLower.includes('trail') || actLower.includes('evas')) {
      detId = 'a09'; // Evasion
      isThreat = true;
    } else if (actLower.includes('session') || actLower.includes('token') || actLower.includes('refresh')) {
      detId = 'a06'; // Session
      isFinding = true;
    } else if (actLower.includes('campaign') || actLower.includes('cluster')) {
      detId = 'a11'; // Campaign
      isThreat = true;
    } else if (actLower.includes('anomaly') || actLower.includes('ml') || actLower.includes('rare')) {
      detId = 'a10'; // Behavior ML
      isFinding = true;
    } else {
      detId = 'a05'; // Access Anomaly
    }

    spawnParticle('a04', detId);
    await new Promise((r) => setTimeout(r, stepDelay * 0.6));

    if (isThreat) {
      triggerAgent(detId, 'threat', 1100);
      appendTraceLine({ agent_id: detId, state: 'threat', message: `[ALERT] Critical attack vector detected: ${action} by ${identity}` });
    } else if (isFinding) {
      triggerAgent(detId, 'finding', 800);
      appendTraceLine({ agent_id: detId, state: 'finding', message: `Behavioral signal flagged: ${action} on ${identity}` });
    } else {
      triggerAgent(detId, 'running', 400);
      appendTraceLine({ agent_id: detId, state: 'running', message: `Rule check evaluated on ${action} - benign` });
    }

    // 3. Decision Layer: a12 Risk Fusion -> a14 Response
    spawnParticle(detId, 'a12');
    await new Promise((r) => setTimeout(r, stepDelay * 0.5));
    triggerAgent('a12', 'running', 400);
    appendTraceLine({ agent_id: 'a12', state: 'running', message: `Calculated multi-factor risk score for ${identity}` });

    if (isThreat) {
      spawnParticle('a12', 'a14');
      await new Promise((r) => setTimeout(r, stepDelay * 0.5));
      triggerAgent('a14', 'threat', 1300);
      appendTraceLine({ agent_id: 'a14', state: 'threat', message: `Executed Containment Playbook PB-01 against session for ${identity}` });
    }

    // 4. Learning Layer: a15 Feedback
    spawnParticle(isThreat ? 'a14' : 'a12', 'a15');
    await new Promise((r) => setTimeout(r, stepDelay * 0.4));
    triggerAgent('a15', 'running', 300);
    appendTraceLine({ agent_id: 'a15', state: 'running', message: `Updated online prior baseline for ${identity}` });

    await new Promise((r) => setTimeout(r, stepDelay));
  }

  if (!simContext.aborted) {
    if (statusText) statusText.textContent = `COMPLETED · ${filename} (${records.length} events)`;
    if (statusDot) statusDot.className = 'status-dot ok';
    if (statusPill) statusPill.style.background = 'rgba(16, 185, 129, 0.2)';

    window.dispatchEvent(
      new CustomEvent('is:toast', {
        detail: { message: `Simulation complete: ${records.length} events processed across 15 agents.`, type: 'success' },
      })
    );
  }
}

function setupFileUploadSimulation() {
  const fileInput = document.getElementById('file-upload-live');
  const uploadLabel = document.getElementById('btn-upload-file-label');
  const uploadText = document.getElementById('btn-upload-text');
  const constellationContainer = document.getElementById('constellation-container');

  const handleFile = async (file) => {
    if (!file) return;
    try {
      if (uploadText) uploadText.textContent = 'Reading...';
      const text = await file.text();
      const records = parseRecordsFromText(text);

      if (uploadText) uploadText.textContent = 'Simulating...';

      // Send to background upload endpoint asynchronously
      api.post('/inputs/upload', {
        content: text,
        filename: file.name,
        source: 'auto',
      }).catch(() => {});

      // Launch full live simulation
      await simulateUploadedRecords(file.name, records);
    } catch (err) {
      window.dispatchEvent(
        new CustomEvent('is:toast', {
          detail: { message: `Failed to simulate file: ${err.message}`, type: 'error' },
        })
      );
    } finally {
      if (uploadText) uploadText.textContent = 'Upload Log File';
      if (fileInput) fileInput.value = '';
    }
  };

  if (fileInput) {
    fileInput.addEventListener('change', (e) => {
      const file = e.target.files && e.target.files[0];
      handleFile(file);
    });
  }

  // Drag and drop onto constellation panel
  if (constellationContainer) {
    const parentPanel = constellationContainer.closest('.glass') || constellationContainer;

    parentPanel.addEventListener('dragover', (e) => {
      e.preventDefault();
      parentPanel.style.outline = '2px dashed var(--brand)';
    });

    parentPanel.addEventListener('dragleave', () => {
      parentPanel.style.outline = 'none';
    });

    parentPanel.addEventListener('drop', (e) => {
      e.preventDefault();
      parentPanel.style.outline = 'none';
      const file = e.dataTransfer.files && e.dataTransfer.files[0];
      handleFile(file);
    });
  }
}

/**
 * 5. SSE Stream Wiring
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
