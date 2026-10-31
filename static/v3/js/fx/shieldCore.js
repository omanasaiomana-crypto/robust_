/**
 * IdentityShield v3 — "Shield Core" Standalone 3D Hero Element
 * Specification: UI_DESIGN.md Section 4
 *
 * Exports: mountShieldCore(container, options) -> { pulse(), threat(), destroy() }
 */

import * as THREE from 'three';
import { RoomEnvironment } from 'three/examples/jsm/environments/RoomEnvironment.js';

export function mountShieldCore(container, options = {}) {
  if (!container) return { pulse: () => {}, threat: () => {}, destroy: () => {} };

  container.setAttribute('aria-hidden', 'true');
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
    // Static CSS Fallback (UI_DESIGN.md §4)
    container.innerHTML = `
      <div style="position:relative; width:100%; height:100%; min-height:280px; display:flex; align-items:center; justify-content:center; overflow:hidden;">
        <div style="position:absolute; width:180px; height:180px; border-radius:50%; background:radial-gradient(circle, #DCE8FF 0%, transparent 70%); filter:blur(24px); opacity:0.8;"></div>
        <div style="position:absolute; width:150px; height:150px; border-radius:50%; background:radial-gradient(circle, #ECE6FF 0%, transparent 70%); filter:blur(20px); transform:translate(30px, -20px); opacity:0.7;"></div>
        <div style="position:absolute; width:140px; height:140px; border-radius:50%; background:radial-gradient(circle, #FFE4D3 0%, transparent 70%); filter:blur(20px); transform:translate(-30px, 25px); opacity:0.7;"></div>
        <svg width="84" height="100" viewBox="0 0 24 28" fill="none" stroke="#3D6FE0" stroke-width="2" style="position:relative; z-index:2; filter:drop-shadow(0 8px 16px rgba(61,111,224,0.25));">
          <path d="M12 2L3 6v8c0 6.5 4.5 11 9 12 4.5-1 9-5.5 9-12V6l-9-4z" fill="#FFFFFF" fill-opacity="0.85"/>
          <path d="M12 9v6m-3-3h6" stroke="#3D6FE0" stroke-width="2" stroke-linecap="round"/>
        </svg>
      </div>
    `;
    return { pulse: () => {}, threat: () => {}, destroy: () => { container.innerHTML = ''; } };
  }

  // --- Three.js Scene Setup ---
  const scene = new THREE.Scene();
  const width = container.clientWidth || 440;
  const height = options.height || container.clientHeight || 340;

  const camera = new THREE.PerspectiveCamera(40, width / height, 0.1, 100);
  camera.position.set(0, 0, 16);

  const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
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

  // Lights (UI_DESIGN.md §4)
  const hemiLight = new THREE.HemisphereLight(0xffffff, 0xf6f1e9, 0.8);
  scene.add(hemiLight);

  const warmKeyLight = new THREE.DirectionalLight(0xffe9d6, 1.0);
  warmKeyLight.position.set(-6, 8, 8);
  scene.add(warmKeyLight);

  const coolRimLight = new THREE.DirectionalLight(0xdce8ff, 0.8);
  coolRimLight.position.set(6, -2, -5);
  scene.add(coolRimLight);

  // Root Assembly Group (floats & tilts)
  const rootGroup = new THREE.Group();
  scene.add(rootGroup);

  // a) Soft Contact Shadow Plane
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
    opacity: 0.9,
    depthWrite: false,
  });
  const shadowMesh = new THREE.Mesh(shadowGeom, shadowMat);
  shadowMesh.rotation.x = -Math.PI / 2;
  shadowMesh.position.y = -3.8;
  scene.add(shadowMesh);

  // b) Pearlescent Glass Shield (Extruded 2D Shape with Bevel)
  const shape = new THREE.Shape();
  // Shield coordinates: top width 4, height 5.2, curved bottom point
  shape.moveTo(-1.9, 2.3);
  shape.lineTo(1.9, 2.3);
  shape.bezierCurveTo(2.1, 2.3, 2.2, 2.1, 2.2, 1.8);
  shape.bezierCurveTo(2.2, 0.2, 1.4, -1.8, 0, -2.7);
  shape.bezierCurveTo(-1.4, -1.8, -2.2, 0.2, -2.2, 1.8);
  shape.bezierCurveTo(-2.2, 2.1, -2.1, 2.3, -1.9, 2.3);

  const extrudeSettings = {
    depth: 0.24,
    bevelEnabled: true,
    bevelSegments: 4,
    steps: 1,
    bevelSize: 0.07,
    bevelThickness: 0.07,
  };

  const shieldGeom = new THREE.ExtrudeGeometry(shape, extrudeSettings);
  shieldGeom.center();

  const shieldMat = new THREE.MeshPhysicalMaterial({
    color: 0xffffff,
    roughness: 0.12,
    metalness: 0.0,
    clearcoat: 1.0,
    clearcoatRoughness: 0.1,
    iridescence: 0.65,
    iridescenceIOR: 1.3,
    transmission: 0.62,
    thickness: 0.45,
    ior: 1.42,
    attenuationColor: new THREE.Color(0xdce8ff),
    transparent: true,
    opacity: 0.95,
  });

  const shieldMesh = new THREE.Mesh(shieldGeom, shieldMat);
  rootGroup.add(shieldMesh);

  // Shield Ripple Ring (Deflection Effect)
  const rippleGeom = new THREE.RingGeometry(0.1, 0.15, 32);
  const rippleMat = new THREE.MeshBasicMaterial({
    color: 0xe5484d,
    transparent: true,
    opacity: 0,
    side: THREE.DoubleSide,
    depthWrite: false,
  });
  const rippleMesh = new THREE.Mesh(rippleGeom, rippleMat);
  rippleMesh.position.set(0, 0, 0.22);
  rootGroup.add(rippleMesh);

  // c) Identity Core (Fingerprint Partial Arcs inside Shield)
  const fpGroup = new THREE.Group();
  fpGroup.position.set(0, 0.1, 0.18);
  rootGroup.add(fpGroup);

  const arcMeshes = [];
  const arcRadii = [0.28, 0.48, 0.68, 0.88, 1.08, 1.28, 1.48];
  arcRadii.forEach((r, idx) => {
    const startAngle = (idx % 2 === 0 ? 0.2 : 0.4) * Math.PI;
    const endAngle = (idx % 2 === 0 ? 1.8 : 1.6) * Math.PI;
    const curve = new THREE.EllipseCurve(0, 0, r, r * 1.15, startAngle, endAngle, false, 0);
    const points = curve.getPoints(36);
    const geom = new THREE.BufferGeometry().setFromPoints(points);

    const mat = new THREE.LineBasicMaterial({
      color: 0x3d6fe0,
      linewidth: 2,
      transparent: true,
      opacity: 0.85,
    });
    const line = new THREE.Line(geom, mat);
    fpGroup.add(line);
    arcMeshes.push(line);
  });

  // Sweeping Scan Line
  const scanGeom = new THREE.PlaneGeometry(3.2, 0.05);
  const scanMat = new THREE.MeshBasicMaterial({
    color: 0x7db9ff,
    transparent: true,
    opacity: 0.6,
    side: THREE.DoubleSide,
    depthWrite: false,
  });
  const scanMesh = new THREE.Mesh(scanGeom, scanMat);
  scanMesh.position.set(0, 1.2, 0.2);
  rootGroup.add(scanMesh);

  // d) 15 Agent Orbs on 4 Tilted Orbit Rings + 1 Oversight Ring
  const ringsGroup = new THREE.Group();
  rootGroup.add(ringsGroup);

  // Ring configurations
  const RING_SPECS = [
    { name: 'Data', count: 4, radius: 3.2, tiltX: 0.35, tiltY: 0.2, speed: 0.007, color: 0xb9d0ff, strong: 0x3d6fe0 },
    { name: 'Detection', count: 7, radius: 4.2, tiltX: -0.45, tiltY: -0.25, speed: -0.0055, color: 0xcdbeff, strong: 0x6d4fd8 },
    { name: 'Decision', count: 3, radius: 5.1, tiltX: 0.25, tiltY: -0.3, speed: 0.0045, color: 0xffc9a8, strong: 0xc2410c },
    { name: 'Learning', count: 1, radius: 5.9, tiltX: -0.3, tiltY: 0.35, speed: -0.0035, color: 0xa9e5d3, strong: 0x0f8a6a },
    { name: 'Oversight', count: 0, radius: 6.6, tiltX: 0.1, tiltY: 0.1, speed: 0.002, color: 0xf7d774, strong: 0xa16207 },
  ];

  const ringObjects = [];
  const orbObjects = [];
  const detectionOrbs = [];

  RING_SPECS.forEach((spec) => {
    const ringAnchor = new THREE.Group();
    ringAnchor.rotation.x = spec.tiltX;
    ringAnchor.rotation.y = spec.tiltY;
    ringsGroup.add(ringAnchor);

    // Torus ring track
    const torusGeom = new THREE.TorusGeometry(spec.radius, 0.018, 8, 64);
    const torusMat = new THREE.MeshBasicMaterial({
      color: spec.color,
      transparent: true,
      opacity: spec.count === 0 ? 0.75 : 0.45,
    });
    const torusMesh = new THREE.Mesh(torusGeom, torusMat);
    ringAnchor.add(torusMesh);

    // Spheres
    const orbs = [];
    const orbGeom = new THREE.SphereGeometry(0.16, 16, 12);
    for (let i = 0; i < spec.count; i++) {
      const angle = (i / spec.count) * Math.PI * 2;
      const orbMat = new THREE.MeshStandardMaterial({
        color: spec.color,
        roughness: 0.45,
        metalness: 0.08,
      });
      const orb = new THREE.Mesh(orbGeom, orbMat);
      orb.position.set(Math.cos(angle) * spec.radius, Math.sin(angle) * spec.radius, 0);
      ringAnchor.add(orb);

      const orbItem = { mesh: orb, baseColor: spec.color, spec };
      orbs.push(orbItem);
      orbObjects.push(orbItem);
      if (spec.name === 'Detection') detectionOrbs.push(orbItem);
    }

    ringObjects.push({ anchor: ringAnchor, spec, orbs, angle: 0 });
  });

  // e) Threat Deflection Particle
  const threatGeom = new THREE.SphereGeometry(0.18, 16, 16);
  const threatMat = new THREE.MeshStandardMaterial({
    color: 0xe5484d,
    emissive: 0x991b1b,
    emissiveIntensity: 0.5,
  });
  const threatParticle = new THREE.Mesh(threatGeom, threatMat);
  threatParticle.visible = false;
  scene.add(threatParticle);

  let threatAnim = null; // { start, target, progress, reflecting }

  function triggerThreat() {
    if (threatAnim) return;
    const spawnAngle = Math.random() * Math.PI * 2;
    const dist = 9.5;
    const startX = Math.cos(spawnAngle) * dist;
    const startY = Math.sin(spawnAngle) * dist;
    const startZ = (Math.random() - 0.5) * 2;

    threatParticle.position.set(startX, startY, startZ);
    threatParticle.visible = true;

    threatAnim = {
      start: new THREE.Vector3(startX, startY, startZ),
      target: new THREE.Vector3(0, 0, 0),
      progress: 0,
      reflecting: false,
      reflectDir: new THREE.Vector3(startX, startY, startZ).normalize().multiplyScalar(10),
      hitPoint: new THREE.Vector3(0, 0, 0.22),
    };
  }

  // f) Pulse Wave Animation State
  let pulseStartTime = 0;
  function triggerPulse() {
    pulseStartTime = performance.now();
  }

  // Click Trigger
  container.addEventListener('click', () => {
    triggerPulse();
  });

  // Interactive Cursor Tilt
  let targetTiltX = 0;
  let targetTiltY = 0;
  let curTiltX = 0;
  let curTiltY = 0;
  let isHovered = false;

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
    targetTiltY = nx * 0.17; // max ~10 deg
    targetTiltX = -ny * 0.17;
  });

  // Animation Loop Variables
  let isVisible = true;
  let isTabActive = true;
  let rafId = null;
  let lastTime = performance.now();
  let threatTimer = 0;

  function renderFrame(now) {
    const dt = (now - lastTime) / 1000;
    lastTime = now;

    if (!isStill && !isReducedMotion && isVisible && isTabActive) {
      const t = now * 0.001;

      // 1. Float & Yaw
      rootGroup.position.y = Math.sin(t * 1.05) * 0.18; // ~6px equivalent
      rootGroup.rotation.y = Math.sin(t * 0.52) * 0.22; // ~12.5 deg yaw

      // 2. Cursor Tilt Damping
      curTiltX += (targetTiltX - curTiltX) * 0.08;
      curTiltY += (targetTiltY - curTiltY) * 0.08;
      rootGroup.rotation.x = curTiltX;
      rootGroup.rotation.y += curTiltY;

      // 3. Scan Line Sweep (4s cycle top->bottom)
      const scanPhase = (t % 4.0) / 4.0;
      scanMesh.position.y = 1.6 - scanPhase * 3.2;

      // 4. Orbit Rings
      const speedMult = isHovered ? 1.4 : 1.0;
      ringObjects.forEach((ro) => {
        ro.angle += ro.spec.speed * speedMult;
        ro.anchor.rotation.z = ro.angle;
      });

      // 5. Pulse Animation (600ms ring by ring)
      if (pulseStartTime > 0) {
        const pElapsed = now - pulseStartTime;
        if (pElapsed < 700) {
          const arcIdx = Math.floor((pElapsed / 600) * arcMeshes.length);
          arcMeshes.forEach((mesh, idx) => {
            if (idx === arcIdx) {
              mesh.material.color.setHex(0xdce8ff);
              mesh.material.opacity = 1.0;
            } else {
              mesh.material.color.setHex(0x3d6fe0);
              mesh.material.opacity = 0.85;
            }
          });
          // Orb glow pop
          orbObjects.forEach((o) => {
            o.mesh.scale.set(1.25, 1.25, 1.25);
          });
        } else {
          pulseStartTime = 0;
          arcMeshes.forEach((m) => {
            m.material.color.setHex(0x3d6fe0);
            m.material.opacity = 0.85;
          });
          orbObjects.forEach((o) => {
            o.mesh.scale.set(1, 1, 1);
          });
        }
      }

      // 6. Threat Deflection Beat
      threatTimer += dt;
      if (threatTimer >= 8.0) {
        threatTimer = 0;
        triggerThreat();
      }

      if (threatAnim) {
        threatAnim.progress += dt * 1.4;

        if (!threatAnim.reflecting) {
          if (threatAnim.progress < 1.0) {
            threatParticle.position.lerpVectors(threatAnim.start, threatAnim.target, threatAnim.progress);
          } else {
            // Impact beat: nearest detection orb flashes, ripple ring expands
            threatAnim.reflecting = true;
            threatAnim.progress = 0;

            if (detectionOrbs.length > 0) {
              const nearestOrb = detectionOrbs[Math.floor(Math.random() * detectionOrbs.length)];
              nearestOrb.mesh.scale.set(1.6, 1.6, 1.6);
              nearestOrb.mesh.material.color.setHex(0xe5484d);
              setTimeout(() => {
                nearestOrb.mesh.scale.set(1, 1, 1);
                nearestOrb.mesh.material.color.setHex(nearestOrb.baseColor);
              }, 320);
            }

            rippleMesh.scale.set(1, 1, 1);
            rippleMat.opacity = 0.65;
          }
        } else {
          // Reflecting away and fading
          const rP = threatAnim.progress;
          threatParticle.position.lerpVectors(threatAnim.target, threatAnim.reflectDir, rP);
          threatMat.opacity = 1.0 - rP;

          // Expand and fade ripple on shield
          const ripScale = 1.0 + rP * 6.0;
          rippleMesh.scale.set(ripScale, ripScale, ripScale);
          rippleMat.opacity = Math.max(0, 0.65 - rP);

          if (rP >= 1.0) {
            threatParticle.visible = false;
            threatMat.opacity = 1.0;
            threatAnim = null;
            rippleMat.opacity = 0;
          }
        }
      }
    }

    renderer.render(scene, camera);

    if (!isStill && !isReducedMotion) {
      rafId = requestAnimationFrame(renderFrame);
    }
  }

  // Start Loop or Render Single Still Frame
  if (isStill || isReducedMotion) {
    renderFrame(performance.now());
  } else {
    rafId = requestAnimationFrame(renderFrame);
  }

  // Observers & Listeners
  const io = new IntersectionObserver(([entry]) => {
    isVisible = entry.isIntersecting;
  }, { threshold: 0.05 });
  io.observe(container);

  const onVisChange = () => {
    isTabActive = !document.hidden;
  };
  document.addEventListener('visibilitychange', onVisChange);

  const ro = new ResizeObserver((entries) => {
    for (const entry of entries) {
      const cr = entry.contentRect;
      if (cr.width > 0 && cr.height > 0) {
        camera.aspect = cr.width / cr.height;
        camera.updateProjectionMatrix();
        renderer.setSize(cr.width, cr.height);
        if (isStill || isReducedMotion) renderFrame(performance.now());
      }
    }
  });
  ro.observe(container);

  // Return Controller API
  return {
    pulse: () => triggerPulse(),
    threat: () => triggerThreat(),
    destroy: () => {
      if (rafId) cancelAnimationFrame(rafId);
      io.disconnect();
      ro.disconnect();
      document.removeEventListener('visibilitychange', onVisChange);

      // Clean disposal
      pmremGen.dispose();
      envScene.dispose();
      envTexture.dispose();
      shieldGeom.dispose();
      shieldMat.dispose();
      shadowGeom.dispose();
      shadowMat.dispose();
      shadowTexture.dispose();
      rippleGeom.dispose();
      rippleMat.dispose();
      scanGeom.dispose();
      scanMat.dispose();
      threatGeom.dispose();
      threatMat.dispose();

      renderer.dispose();
      container.innerHTML = '';
    },
  };
}
