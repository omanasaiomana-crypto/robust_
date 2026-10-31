/**
 * IdentityShield v3 — "Shield Core" 15-Agent 3D Simulation
 *
 * Implements:
 * 1. 15 canonical agents across 4 pipeline rings (Data, Detection, Decision, Learning).
 * 2. HTML overlay labels projected each frame with Vector3.project + camera, clamped inside container.
 * 3. 4 concentric orbital rings with steady ~40s speed and layer captions.
 * 4. Real agent state polling (/api/v3/agents) with reactive visuals (idle, running pulse, amber finding flash,
 *    red threat ring, error "!" badge) and traveling message particles between layers.
 * 5. Automatic DEMO fallback sequencer when API is unavailable.
 *
 * Exports: mountShieldCore(container, options) -> { pulse(), threat(), destroy() }
 */

import * as THREE from 'three';
import { RoomEnvironment } from 'three/examples/jsm/environments/RoomEnvironment.js';

// 15 Canonical Agent Definitions & Layer Metadata
export const AGENTS_15 = [
  // Layer 0: Data (blue) - 4 agents
  { num: 1, name: 'Collector', shortName: '1 Collector', layer: 'Data', layerIdx: 0, color: 0x3d6fe0, colorHex: '#3D6FE0', bg: 'rgba(61,111,224,0.12)' },
  { num: 2, name: 'Normalizer', shortName: '2 Normalizer', layer: 'Data', layerIdx: 0, color: 0x3d6fe0, colorHex: '#3D6FE0', bg: 'rgba(61,111,224,0.12)' },
  { num: 3, name: 'Context', shortName: '3 Context', layer: 'Data', layerIdx: 0, color: 0x3d6fe0, colorHex: '#3D6FE0', bg: 'rgba(61,111,224,0.12)' },
  { num: 4, name: 'Correlation', shortName: '4 Correlation', layer: 'Data', layerIdx: 0, color: 0x3d6fe0, colorHex: '#3D6FE0', bg: 'rgba(61,111,224,0.12)' },

  // Layer 1: Detection (purple) - 7 agents
  { num: 5, name: 'Access', shortName: '5 Access', layer: 'Detection', layerIdx: 1, color: 0x8b5cf6, colorHex: '#8B5CF6', bg: 'rgba(139,92,246,0.12)' },
  { num: 6, name: 'Session', shortName: '6 Session', layer: 'Detection', layerIdx: 1, color: 0x8b5cf6, colorHex: '#8B5CF6', bg: 'rgba(139,92,246,0.12)' },
  { num: 7, name: 'Credentials', shortName: '7 Credentials', layer: 'Detection', layerIdx: 1, color: 0x8b5cf6, colorHex: '#8B5CF6', bg: 'rgba(139,92,246,0.12)' },
  { num: 8, name: 'Escalation', shortName: '8 Escalation', layer: 'Detection', layerIdx: 1, color: 0x8b5cf6, colorHex: '#8B5CF6', bg: 'rgba(139,92,246,0.12)' },
  { num: 9, name: 'Evasion', shortName: '9 Evasion', layer: 'Detection', layerIdx: 1, color: 0x8b5cf6, colorHex: '#8B5CF6', bg: 'rgba(139,92,246,0.12)' },
  { num: 10, name: 'Behavior ML', shortName: '10 Behavior ML', layer: 'Detection', layerIdx: 1, color: 0x8b5cf6, colorHex: '#8B5CF6', bg: 'rgba(139,92,246,0.12)' },
  { num: 11, name: 'Campaign', shortName: '11 Campaign', layer: 'Detection', layerIdx: 1, color: 0x8b5cf6, colorHex: '#8B5CF6', bg: 'rgba(139,92,246,0.12)' },

  // Layer 2: Decision (orange) - 3 agents
  { num: 12, name: 'Risk Fusion', shortName: '12 Risk Fusion', layer: 'Decision', layerIdx: 2, color: 0xf97316, colorHex: '#F97316', bg: 'rgba(249,115,22,0.12)' },
  { num: 13, name: 'Investigation', shortName: '13 Investigation', layer: 'Decision', layerIdx: 2, color: 0xf97316, colorHex: '#F97316', bg: 'rgba(249,115,22,0.12)' },
  { num: 14, name: 'Response', shortName: '14 Response', layer: 'Decision', layerIdx: 2, color: 0xf97316, colorHex: '#F97316', bg: 'rgba(249,115,22,0.12)' },

  // Layer 3: Learning (green) - 1 agent
  { num: 15, name: 'Feedback', shortName: '15 Feedback', layer: 'Learning', layerIdx: 3, color: 0x10b981, colorHex: '#10B981', bg: 'rgba(16,185,129,0.12)' },
];

export function mountShieldCore(container, options = {}) {
  if (!container) return { pulse: () => {}, threat: () => {}, destroy: () => {} };

  container.setAttribute('aria-hidden', 'true');
  container.style.position = 'relative';
  container.style.overflow = 'hidden';

  const isStill = !!options.still;
  const isReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  // WebGL Availability Check
  const hasWebGL = (() => {
    try {
      const c = document.createElement('canvas');
      return !!(window.WebGLRenderingContext && (c.getContext('webgl') || c.getContext('experimental-webgl')));
    } catch {
      return false;
    }
  })();

  if (!hasWebGL) {
    container.innerHTML = `
      <div style="position:relative; width:100%; height:100%; min-height:280px; display:flex; align-items:center; justify-content:center; overflow:hidden;">
        <svg width="84" height="100" viewBox="0 0 24 28" fill="none" stroke="#3D6FE0" stroke-width="2">
          <path d="M12 2L3 6v8c0 6.5 4.5 11 9 12 4.5-1 9-5.5 9-12V6l-9-4z" fill="#FFFFFF" fill-opacity="0.85"/>
          <path d="M12 9v6m-3-3h6" stroke="#3D6FE0" stroke-width="2" stroke-linecap="round"/>
        </svg>
      </div>
    `;
    return { pulse: () => {}, threat: () => {}, destroy: () => { container.innerHTML = ''; } };
  }

  // --- Three.js Scene Setup ---
  const scene = new THREE.Scene();
  let width = container.clientWidth || 440;
  let height = options.height || container.clientHeight || 340;

  const camera = new THREE.PerspectiveCamera(40, width / height, 0.1, 100);
  camera.position.set(0, 0, 16.5);

  const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, powerPreference: 'high-performance' });
  renderer.setSize(width, height);
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
  renderer.toneMapping = THREE.ACESFilmicToneMapping;
  renderer.toneMappingExposure = 1.0;
  if ('outputColorSpace' in renderer) {
    renderer.outputColorSpace = THREE.SRGBColorSpace;
  }
  container.innerHTML = '';
  container.appendChild(renderer.domElement);

  // Soft Studio Environment with PMREMGenerator
  const pmremGen = new THREE.PMREMGenerator(renderer);
  pmremGen.compileEquirectangularShader();
  const envScene = new RoomEnvironment();
  const envTexture = pmremGen.fromScene(envScene).texture;
  scene.environment = envTexture;

  // Lighting
  const hemiLight = new THREE.HemisphereLight(0xffffff, 0xf6f1e9, 0.9);
  scene.add(hemiLight);

  const warmKeyLight = new THREE.DirectionalLight(0xffe9d6, 1.1);
  warmKeyLight.position.set(-6, 8, 8);
  scene.add(warmKeyLight);

  const coolRimLight = new THREE.DirectionalLight(0xdce8ff, 0.85);
  coolRimLight.position.set(6, -2, -5);
  scene.add(coolRimLight);

  // Root Assembly Group (floats & tilts)
  const rootGroup = new THREE.Group();
  scene.add(rootGroup);

  // Soft Contact Shadow Plane
  const shadowCanvas = document.createElement('canvas');
  shadowCanvas.width = 256;
  shadowCanvas.height = 256;
  const sCtx = shadowCanvas.getContext('2d');
  const radGrad = sCtx.createRadialGradient(128, 128, 10, 128, 128, 120);
  radGrad.addColorStop(0, 'rgba(31, 36, 48, 0.22)');
  radGrad.addColorStop(0.5, 'rgba(31, 36, 48, 0.08)');
  radGrad.addColorStop(1, 'rgba(31, 36, 48, 0)');
  sCtx.fillStyle = radGrad;
  sCtx.fillRect(0, 0, 256, 256);

  const shadowTexture = new THREE.CanvasTexture(shadowCanvas);
  const shadowGeom = new THREE.PlaneGeometry(9, 9);
  const shadowMat = new THREE.MeshBasicMaterial({
    map: shadowTexture,
    transparent: true,
    opacity: 0.85,
    depthWrite: false,
  });
  const shadowMesh = new THREE.Mesh(shadowGeom, shadowMat);
  shadowMesh.rotation.x = -Math.PI / 2;
  shadowMesh.position.y = -3.8;
  rootGroup.add(shadowMesh);

  // Shield Core Geometries (3 nested shells)
  function createShieldShape() {
    const s = new THREE.Shape();
    s.moveTo(0, 2.2);
    s.bezierCurveTo(0.6, 2.2, 1.6, 2.0, 1.9, 1.6);
    s.bezierCurveTo(2.1, 0.8, 2.0, -0.4, 1.6, -1.2);
    s.bezierCurveTo(1.2, -1.9, 0.5, -2.4, 0, -2.8);
    s.bezierCurveTo(-0.5, -2.4, -1.2, -1.9, -1.6, -1.2);
    s.bezierCurveTo(-2.0, -0.4, -2.1, 0.8, -1.9, 1.6);
    s.bezierCurveTo(-1.6, 2.0, -0.6, 2.2, 0, 2.2);
    return s;
  }

  const shieldGeom = new THREE.ExtrudeGeometry(createShieldShape(), {
    depth: 0.35,
    bevelEnabled: true,
    bevelSegments: 6,
    steps: 1,
    bevelSize: 0.12,
    bevelThickness: 0.12,
  });
  shieldGeom.center();

  // Outer Shell
  const outerMat = new THREE.MeshPhysicalMaterial({
    color: 0xffffff,
    metalness: 0.15,
    roughness: 0.12,
    transmission: 0.88,
    thickness: 1.2,
    ior: 1.5,
    reflectivity: 0.5,
    transparent: true,
    opacity: 0.95,
  });
  const outerMesh = new THREE.Mesh(shieldGeom, outerMat);
  rootGroup.add(outerMesh);

  // Mid Metallic Shell
  const midMat = new THREE.MeshStandardMaterial({
    color: 0x3d6fe0,
    metalness: 0.85,
    roughness: 0.28,
  });
  const midMesh = new THREE.Mesh(shieldGeom, midMat);
  midMesh.scale.set(0.92, 0.92, 0.92);
  rootGroup.add(midMesh);

  // Inner Core Shell
  const innerMat = new THREE.MeshStandardMaterial({
    color: 0xdce8ff,
    emissive: 0x3d6fe0,
    emissiveIntensity: 0.45,
    metalness: 0.4,
    roughness: 0.3,
  });
  const innerMesh = new THREE.Mesh(shieldGeom, innerMat);
  innerMesh.scale.set(0.82, 0.82, 0.82);
  rootGroup.add(innerMesh);

  // Shield Core Arcs (Concentric pulse lines)
  const arcMeshes = [];
  [-0.6, 0.0, 0.6].forEach((yOffset) => {
    const arcCurve = new THREE.EllipseCurve(0, yOffset, 1.1, 0.35, Math.PI * 0.15, Math.PI * 0.85, false, 0);
    const pts = arcCurve.getPoints(32).map((p) => new THREE.Vector3(p.x, p.y, 0.24));
    const arcGeom = new THREE.BufferGeometry().setFromPoints(pts);
    const arcMat = new THREE.LineBasicMaterial({
      color: 0x3d6fe0,
      transparent: true,
      opacity: 0.85,
      linewidth: 2,
    });
    const arcLine = new THREE.Line(arcGeom, arcMat);
    rootGroup.add(arcLine);
    arcMeshes.push(arcLine);
  });

  // Threat Ripple Ring Mesh on Shield Surface
  const rippleGeom = new THREE.RingGeometry(0.08, 0.18, 32);
  const rippleMat = new THREE.MeshBasicMaterial({
    color: 0xe5484d,
    side: THREE.DoubleSide,
    transparent: true,
    opacity: 0,
    depthWrite: false,
  });
  const rippleMesh = new THREE.Mesh(rippleGeom, rippleMat);
  rippleMesh.position.set(0, 0, 0.26);
  rootGroup.add(rippleMesh);

  // Scan Line Sweep
  const scanGeom = new THREE.PlaneGeometry(3.6, 0.04);
  const scanMat = new THREE.MeshBasicMaterial({
    color: 0x22d3ee,
    transparent: true,
    opacity: 0.75,
  });
  const scanMesh = new THREE.Mesh(scanGeom, scanMat);
  scanMesh.position.set(0, 1.2, 0.2);
  rootGroup.add(scanMesh);

  // --- HTML Overlay for Labels and Captions ---
  const overlay = document.createElement('div');
  overlay.className = 'shield-labels-overlay';
  container.appendChild(overlay);

  // --- 4 Concentric Pipeline Rings (Data, Detection, Decision, Learning) ---
  const ringsGroup = new THREE.Group();
  // Harmonious orbital tilt
  ringsGroup.rotation.x = 0.26;
  ringsGroup.rotation.y = 0.16;
  rootGroup.add(ringsGroup);

  const RING_CONFIGS = [
    {
      name: 'DATA',
      radius: 3.3,
      speed: 0.0028, // ~40s turn
      color: 0x3d6fe0,
      colorHex: '#3D6FE0',
      agents: AGENTS_15.filter((a) => a.layer === 'Data'),
    },
    {
      name: 'DETECTION',
      radius: 4.3,
      speed: 0.0026,
      color: 0x8b5cf6,
      colorHex: '#8B5CF6',
      agents: AGENTS_15.filter((a) => a.layer === 'Detection'),
    },
    {
      name: 'DECISION',
      radius: 5.3,
      speed: 0.0024,
      color: 0xf97316,
      colorHex: '#F97316',
      agents: AGENTS_15.filter((a) => a.layer === 'Decision'),
    },
    {
      name: 'LEARNING',
      radius: 6.3,
      speed: 0.0022,
      color: 0x10b981,
      colorHex: '#10B981',
      agents: AGENTS_15.filter((a) => a.layer === 'Learning'),
    },
  ];

  const ringObjects = [];
  const agentOrbMap = {}; // agent.num -> { agent, mesh, labelEl, ring, angle, baseColor, state, pulseT }
  const ringCaptionEls = [];

  const orbGeom = new THREE.SphereGeometry(0.18, 16, 16);
  const ringGeomCache = {};

  RING_CONFIGS.forEach((ringSpec, rIdx) => {
    const ringAnchor = new THREE.Group();
    ringsGroup.add(ringAnchor);

    // Torus Ring Track
    const torusGeom = new THREE.TorusGeometry(ringSpec.radius, 0.016, 8, 96);
    const torusMat = new THREE.MeshBasicMaterial({
      color: ringSpec.color,
      transparent: true,
      opacity: 0.35,
    });
    const torusMesh = new THREE.Mesh(torusGeom, torusMat);
    ringAnchor.add(torusMesh);

    // Ring Caption HTML Overlay
    const captionEl = document.createElement('div');
    captionEl.className = 'ring-caption-label';
    captionEl.textContent = ringSpec.name;
    captionEl.style.color = ringSpec.colorHex;
    captionEl.style.borderColor = `${ringSpec.colorHex}44`;
    overlay.appendChild(captionEl);

    // Anchor point for ring caption on the ring track
    const captionAnchorPos = new THREE.Vector3(0, ringSpec.radius, 0);

    ringCaptionEls.push({
      el: captionEl,
      anchorMesh: ringAnchor,
      localPos: captionAnchorPos,
    });

    // Orbs on this ring
    const orbsOnRing = [];
    const count = ringSpec.agents.length;

    ringSpec.agents.forEach((agent, i) => {
      const angle = (i / count) * Math.PI * 2;
      const orbMat = new THREE.MeshStandardMaterial({
        color: ringSpec.color,
        emissive: ringSpec.color,
        emissiveIntensity: 0.25,
        roughness: 0.35,
        metalness: 0.15,
        transparent: true,
        opacity: 0.6,
      });
      const orbMesh = new THREE.Mesh(orbGeom, orbMat);
      orbMesh.position.set(Math.cos(angle) * ringSpec.radius, Math.sin(angle) * ringSpec.radius, 0);
      ringAnchor.add(orbMesh);

      // Threat ring mesh for "threat" state animation
      const threatRingGeom = new THREE.RingGeometry(0.2, 0.24, 24);
      const threatRingMat = new THREE.MeshBasicMaterial({
        color: 0xef4444,
        side: THREE.DoubleSide,
        transparent: true,
        opacity: 0,
      });
      const threatRingMesh = new THREE.Mesh(threatRingGeom, threatRingMat);
      threatRingMesh.visible = false;
      orbMesh.add(threatRingMesh);

      // HTML Overlay Label
      const labelEl = document.createElement('div');
      labelEl.className = 'agent-orb-label';
      labelEl.style.borderColor = agent.colorHex;
      labelEl.textContent = agent.shortName;
      overlay.appendChild(labelEl);

      const orbItem = {
        agent,
        mesh: orbMesh,
        threatRingMesh,
        threatRingMat,
        labelEl,
        ringSpec,
        ringAnchor,
        baseAngle: angle,
        baseColor: ringSpec.color,
        state: 'idle',
        pulseT: 0,
        flashTimer: 0,
        threatTimer: 0,
      };

      orbsOnRing.push(orbItem);
      agentOrbMap[agent.num] = orbItem;
    });

    ringObjects.push({
      anchor: ringAnchor,
      spec: ringSpec,
      orbs: orbsOnRing,
      angle: 0,
    });
  });

  // --- Traveling Message Particles (Data -> Detection -> Decision -> Response) ---
  const travelingParticles = []; // max 20
  const particleGeom = new THREE.SphereGeometry(0.08, 12, 12);
  const particleMat = new THREE.MeshBasicMaterial({
    color: 0x22d3ee,
    transparent: true,
    opacity: 0.95,
  });

  function emitTravelingParticle(fromAgentNum, toAgentNum) {
    if (travelingParticles.length >= 20) return;
    const fromItem = agentOrbMap[fromAgentNum];
    const toItem = agentOrbMap[toAgentNum];
    if (!fromItem || !toItem) return;

    const pMesh = new THREE.Mesh(particleGeom, particleMat.clone());
    scene.add(pMesh);

    travelingParticles.push({
      mesh: pMesh,
      fromOrb: fromItem,
      toOrb: toItem,
      elapsed: 0,
      duration: 0.6, // 600 ms
    });
  }

  // --- Real State Polling & Reactive Visuals ---
  let lastSuccessfulPoll = Date.now();
  let isDemoMode = false;
  let demoCycleTime = 0;
  let pollInterval = null;
  let prevAgentStates = {};

  async function pollAgentStatus() {
    try {
      const res = await fetch('/api/v3/agents');
      if (!res.ok) throw new Error('API error');
      const agentList = await res.json();
      if (!Array.isArray(agentList) || agentList.length === 0) {
        throw new Error('Empty agent list');
      }

      lastSuccessfulPoll = Date.now();
      isDemoMode = false;

      // Map real states to orbs
      agentList.forEach((a) => {
        const num = a.num || (a.agent_id ? parseInt(a.agent_id.replace(/\D/g, ''), 10) : null);
        const item = agentOrbMap[num];
        if (!item) return;

        const rawStatus = (a.status || 'idle').toLowerCase();
        let state = 'idle';
        if (rawStatus === 'running' || rawStatus === 'active') state = 'running';
        else if (rawStatus === 'finding' || rawStatus === 'amber') state = 'finding';
        else if (rawStatus === 'threat' || rawStatus === 'crit' || rawStatus === 'revoked') state = 'threat';
        else if (rawStatus === 'error' || rawStatus === 'degraded' || rawStatus === 'blocked') state = 'error';

        // Detect transition from running to idle / next layer
        if (prevAgentStates[num] === 'running' && state === 'idle') {
          // Send particle to next layer
          const nextTarget = getNextLayerTarget(item.agent.layerIdx);
          if (nextTarget) emitTravelingParticle(num, nextTarget);
        }

        applyOrbState(item, state);
        prevAgentStates[num] = state;
      });
    } catch {
      // If endpoint is unavailable or returns nothing for 5s, switch to DEMO mode
      if (Date.now() - lastSuccessfulPoll >= 5000) {
        isDemoMode = true;
      }
    }
  }

  function getNextLayerTarget(layerIdx) {
    if (layerIdx === 0) {
      // Data -> Detection
      return 5 + Math.floor(Math.random() * 7); // 5..11
    } else if (layerIdx === 1) {
      // Detection -> Decision
      return 12 + Math.floor(Math.random() * 3); // 12..14
    } else if (layerIdx === 2) {
      // Decision -> Learning
      return 15;
    }
    return null;
  }

  function applyOrbState(item, state) {
    if (item.state !== state) {
      if (state === 'finding') item.flashTimer = 0.8;
      if (state === 'threat') item.threatTimer = 1.0;
    }
    item.state = state;

    // Error badge logic on label
    if (state === 'error') {
      item.labelEl.classList.add('is-error');
      item.labelEl.innerHTML = `${item.agent.shortName} <span class="agent-err-badge">!</span>`;
      item.mesh.material.color.setHex(0x6b7280);
      item.mesh.material.emissive.setHex(0x374151);
      item.mesh.material.opacity = 0.6;
    } else {
      item.labelEl.classList.remove('is-error');
      item.labelEl.textContent = item.agent.shortName;

      if (state === 'idle') {
        item.mesh.material.color.setHex(item.baseColor);
        item.mesh.material.emissive.setHex(item.baseColor);
        item.mesh.material.emissiveIntensity = 0.2;
        item.mesh.material.opacity = 0.6;
      } else if (state === 'running') {
        item.mesh.material.color.setHex(item.baseColor);
        item.mesh.material.emissive.setHex(item.baseColor);
        item.mesh.material.emissiveIntensity = 0.75;
        item.mesh.material.opacity = 1.0;
      }
    }
  }

  // Demo Sequencer: Replays one complete pipeline cycle 1..15 continuously
  function tickDemoSequencer(dt) {
    demoCycleTime += dt;
    // 12 second full pipeline loop
    const phase = demoCycleTime % 12.0;

    let activeNum = 1;
    if (phase < 3.0) {
      // Data Layer active
      activeNum = 1 + Math.floor((phase / 3.0) * 4);
    } else if (phase < 7.0) {
      // Detection Layer active
      activeNum = 5 + Math.floor(((phase - 3.0) / 4.0) * 7);
    } else if (phase < 10.0) {
      // Decision Layer active
      activeNum = 12 + Math.floor(((phase - 7.0) / 3.0) * 3);
    } else {
      // Learning Layer active
      activeNum = 15;
    }

    AGENTS_15.forEach((agent) => {
      const item = agentOrbMap[agent.num];
      if (!item) return;

      if (agent.num === activeNum) {
        if (agent.num === 8 && phase > 5.5 && phase < 6.2) {
          applyOrbState(item, 'finding');
        } else if (agent.num === 14 && phase > 9.0 && phase < 9.8) {
          applyOrbState(item, 'threat');
        } else {
          applyOrbState(item, 'running');
        }
      } else {
        applyOrbState(item, 'idle');
      }
    });

    // Send particles on layer boundaries in demo
    const lastEmit = Math.floor(demoCycleTime / 2.5);
    if (!itemEmitTracker[lastEmit]) {
      itemEmitTracker[lastEmit] = true;
      if (activeNum >= 1 && activeNum <= 4) emitTravelingParticle(activeNum, 5 + Math.floor(Math.random() * 7));
      else if (activeNum >= 5 && activeNum <= 11) emitTravelingParticle(activeNum, 12 + Math.floor(Math.random() * 3));
      else if (activeNum >= 12 && activeNum <= 14) emitTravelingParticle(activeNum, 15);
    }
  }
  const itemEmitTracker = {};

  // Start status polling every 1000ms
  pollAgentStatus();
  pollInterval = setInterval(pollAgentStatus, 1000);

  // --- Interaction & Hover Handling ---
  let isHovered = false;
  let targetTiltX = 0;
  let targetTiltY = 0;
  let curTiltX = 0;
  let curTiltY = 0;

  container.addEventListener('mouseenter', () => { isHovered = true; });
  container.addEventListener('mouseleave', () => {
    isHovered = false;
    targetTiltX = 0;
    targetTiltY = 0;
  });

  container.addEventListener('mousemove', (e) => {
    const rect = container.getBoundingClientRect();
    const nx = ((e.clientX - rect.left) / rect.width) * 2 - 1;
    const ny = -(((e.clientY - rect.top) / rect.height) * 2 - 1);
    targetTiltY = nx * 0.16;
    targetTiltX = -ny * 0.16;
  });

  // Pulse & Threat API
  let pulseStartTime = 0;
  function triggerPulse() {
    pulseStartTime = performance.now();
  }
  function triggerThreat() {
    // Flash detection & decision orbs with threat
    [8, 11, 14].forEach((num) => {
      const item = agentOrbMap[num];
      if (item) applyOrbState(item, 'threat');
    });
    rippleMesh.scale.set(1, 1, 1);
    rippleMat.opacity = 0.8;
  }

  container.addEventListener('click', () => {
    triggerPulse();
  });

  // Resize Observer
  const resizeObserver = new ResizeObserver((entries) => {
    for (const entry of entries) {
      const cr = entry.contentRect;
      if (cr.width > 0 && cr.height > 0) {
        width = cr.width;
        height = options.height || cr.height || 340;
        camera.aspect = width / height;
        camera.updateProjectionMatrix();
        renderer.setSize(width, height);
      }
    }
  });
  resizeObserver.observe(container);

  // --- Main Animation Loop ---
  let rafId = null;
  let lastTime = performance.now();

  function renderFrame(now) {
    const dt = Math.min((now - lastTime) / 1000, 0.1);
    lastTime = now;

    if (!isStill && !isReducedMotion) {
      const t = now * 0.001;

      // 1. Float & Yaw
      rootGroup.position.y = Math.sin(t * 1.05) * 0.15;
      rootGroup.rotation.y = Math.sin(t * 0.52) * 0.18;

      // 2. Cursor Tilt Damping
      curTiltX += (targetTiltX - curTiltX) * 0.08;
      curTiltY += (targetTiltY - curTiltY) * 0.08;
      rootGroup.rotation.x = curTiltX;
      rootGroup.rotation.y += curTiltY;

      // 3. Scan Line Sweep
      const scanPhase = (t % 4.0) / 4.0;
      scanMesh.position.y = 1.6 - scanPhase * 3.2;

      // 4. Orbit Rings (same direction per ring, slow steady speed ~40s turn)
      const speedMult = isHovered ? 1.3 : 1.0;
      ringObjects.forEach((ro) => {
        ro.angle += ro.spec.speed * speedMult;
        ro.anchor.rotation.z = ro.angle;
      });

      // 5. Demo sequencer if in demo mode
      if (isDemoMode) {
        tickDemoSequencer(dt);
      }

      // 6. Reactive Orb Animations (pulse, flash, threat)
      AGENTS_15.forEach((agent) => {
        const item = agentOrbMap[agent.num];
        if (!item) return;

        if (item.state === 'running') {
          item.pulseT += dt;
          // gentle pulse: scale 1 -> 1.2 over 0.8s cycle
          const s = 1.0 + (Math.sin(item.pulseT * (Math.PI * 2 / 0.8)) * 0.5 + 0.5) * 0.2;
          item.mesh.scale.set(s, s, s);
        } else if (item.flashTimer > 0) {
          item.flashTimer -= dt;
          item.mesh.material.color.setHex(0xf59e0b); // Amber flash
          item.mesh.material.emissive.setHex(0xf59e0b);
          item.mesh.material.emissiveIntensity = 0.9;
          item.mesh.scale.set(1.25, 1.25, 1.25);
          if (item.flashTimer <= 0) {
            item.mesh.material.color.setHex(item.baseColor);
            item.mesh.material.emissive.setHex(item.baseColor);
            item.mesh.scale.set(1, 1, 1);
          }
        } else if (item.threatTimer > 0) {
          item.threatTimer -= dt;
          const prog = 1.0 - item.threatTimer / 1.0;
          item.mesh.material.color.setHex(0xef4444);
          item.mesh.material.emissive.setHex(0xef4444);
          item.threatRingMesh.visible = true;
          const ringScale = 1.0 + prog * 2.5;
          item.threatRingMesh.scale.set(ringScale, ringScale, 1);
          item.threatRingMat.opacity = Math.max(0, 0.9 - prog);
          if (item.threatTimer <= 0) {
            item.threatRingMesh.visible = false;
            item.mesh.material.color.setHex(item.baseColor);
            item.mesh.material.emissive.setHex(item.baseColor);
          }
        } else {
          item.mesh.scale.set(1, 1, 1);
        }
      });

      // 7. Pulse Effect
      if (pulseStartTime > 0) {
        const pElapsed = now - pulseStartTime;
        if (pElapsed < 700) {
          const arcIdx = Math.floor((pElapsed / 600) * arcMeshes.length);
          arcMeshes.forEach((mesh, idx) => {
            mesh.material.opacity = idx === arcIdx ? 1.0 : 0.4;
          });
        } else {
          pulseStartTime = 0;
          arcMeshes.forEach((m) => { m.material.opacity = 0.85; });
        }
      }

      // 8. Traveling Message Particles
      for (let i = travelingParticles.length - 1; i >= 0; i--) {
        const p = travelingParticles[i];
        p.elapsed += dt;
        const progress = p.elapsed / p.duration;

        if (progress >= 1.0) {
          scene.remove(p.mesh);
          p.mesh.geometry.dispose();
          p.mesh.material.dispose();
          travelingParticles.splice(i, 1);
        } else {
          // Compute start & end world positions
          const pStart = new THREE.Vector3();
          const pEnd = new THREE.Vector3();
          p.fromOrb.mesh.getWorldPosition(pStart);
          p.toOrb.mesh.getWorldPosition(pEnd);

          // Curved 3D arch midpoint
          const pMid = new THREE.Vector3()
            .addVectors(pStart, pEnd)
            .multiplyScalar(0.5)
            .add(new THREE.Vector3(0, 0, 1.2));

          // Quadratic Bezier interpolation
          const tP = progress;
          const oneMinusT = 1 - tP;
          p.mesh.position.set(
            oneMinusT * oneMinusT * pStart.x + 2 * oneMinusT * tP * pMid.x + tP * tP * pEnd.x,
            oneMinusT * oneMinusT * pStart.y + 2 * oneMinusT * tP * pMid.y + tP * tP * pEnd.y,
            oneMinusT * oneMinusT * pStart.z + 2 * oneMinusT * tP * pMid.z + tP * tP * pEnd.z
          );
        }
      }

      // 9. Threat ripple decay
      if (rippleMat.opacity > 0) {
        rippleMat.opacity = Math.max(0, rippleMat.opacity - dt * 0.8);
        const s = rippleMesh.scale.x + dt * 3.0;
        rippleMesh.scale.set(s, s, 1);
      }

      // 10. Update Projected HTML Overlay Labels & Captions
      const worldPos = new THREE.Vector3();
      const shieldCenterZ = 0;

      // Update Agent Labels
      AGENTS_15.forEach((agent) => {
        const item = agentOrbMap[agent.num];
        if (!item || !item.labelEl) return;

        item.mesh.getWorldPosition(worldPos);

        // Hide when behind the shield center unless hovered
        const isBehind = worldPos.z < shieldCenterZ - 0.2;
        if (isBehind && !isHovered) {
          item.labelEl.style.opacity = '0';
          item.labelEl.style.visibility = 'hidden';
        } else {
          const proj = worldPos.clone().project(camera);
          const screenX = (proj.x * 0.5 + 0.5) * width;
          const screenY = (-(proj.y * 0.5) + 0.5) * height;

          // Clamp inside container
          const clampedX = Math.max(48, Math.min(width - 48, screenX));
          const clampedY = Math.max(16, Math.min(height - 16, screenY));

          item.labelEl.style.left = `${clampedX}px`;
          item.labelEl.style.top = `${clampedY}px`;
          item.labelEl.style.opacity = '1';
          item.labelEl.style.visibility = 'visible';
        }
      });

      // Update Ring Captions
      ringCaptionEls.forEach((cap) => {
        worldPos.copy(cap.localPos);
        cap.anchorMesh.localToWorld(worldPos);

        const proj = worldPos.project(camera);
        const screenX = (proj.x * 0.5 + 0.5) * width;
        const screenY = (-(proj.y * 0.5) + 0.5) * height;

        const clampedX = Math.max(40, Math.min(width - 40, screenX));
        const clampedY = Math.max(12, Math.min(height - 12, screenY));

        cap.el.style.left = `${clampedX}px`;
        cap.el.style.top = `${clampedY}px`;
      });
    }

    renderer.render(scene, camera);

    if (!isStill && !isReducedMotion) {
      rafId = requestAnimationFrame(renderFrame);
    }
  }

  rafId = requestAnimationFrame(renderFrame);

  // Destroy / Cleanup Handler
  function destroy() {
    if (rafId) cancelAnimationFrame(rafId);
    if (pollInterval) clearInterval(pollInterval);
    resizeObserver.disconnect();

    travelingParticles.forEach((p) => {
      scene.remove(p.mesh);
      p.mesh.geometry.dispose();
      p.mesh.material.dispose();
    });

    container.innerHTML = '';
  }

  return {
    pulse: triggerPulse,
    threat: triggerThreat,
    destroy,
  };
}
