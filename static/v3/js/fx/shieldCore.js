/**
 * IdentityShield v3 — "Shield Core" Standalone 3D Hero Element
 * Cyber Stealth Obsidian Theme: Dark Crystal Shield, Emerald Fingerprint Core, Amber/Teal/Gold Orbs
 * ZERO blue, ZERO purple.
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
    container.innerHTML = `
      <div style="position:relative; width:100%; height:100%; min-height:280px; display:flex; align-items:center; justify-content:center; overflow:hidden;">
        <div style="position:absolute; width:180px; height:180px; border-radius:50%; background:radial-gradient(circle, rgba(16,185,129,0.25) 0%, transparent 70%); filter:blur(24px);"></div>
        <div style="position:absolute; width:150px; height:150px; border-radius:50%; background:radial-gradient(circle, rgba(245,158,11,0.2) 0%, transparent 70%); filter:blur(20px); transform:translate(30px, -20px);"></div>
        <svg width="84" height="100" viewBox="0 0 24 28" fill="none" stroke="#10B981" stroke-width="2" style="position:relative; z-index:2; filter:drop-shadow(0 8px 16px rgba(16,185,129,0.4));">
          <path d="M12 2L3 6v8c0 6.5 4.5 11 9 12 4.5-1 9-5.5 9-12V6l-9-4z" fill="#121824" fill-opacity="0.9"/>
          <path d="M12 9v6m-3-3h6" stroke="#10B981" stroke-width="2" stroke-linecap="round"/>
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
  renderer.toneMappingExposure = 1.1;
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

  // Lights
  const hemiLight = new THREE.HemisphereLight(0x223344, 0x090d12, 1.0);
  scene.add(hemiLight);

  const warmKeyLight = new THREE.DirectionalLight(0xf59e0b, 1.2);
  warmKeyLight.position.set(-6, 8, 8);
  scene.add(warmKeyLight);

  const emeraldRimLight = new THREE.DirectionalLight(0x10b981, 1.5);
  emeraldRimLight.position.set(6, -2, -5);
  scene.add(emeraldRimLight);

  // Root Group
  const rootGroup = new THREE.Group();
  scene.add(rootGroup);

  // a) Contact Shadow Plane
  const shadowCanvas = document.createElement('canvas');
  shadowCanvas.width = 256;
  shadowCanvas.height = 256;
  const sCtx = shadowCanvas.getContext('2d');
  const radGrad = sCtx.createRadialGradient(128, 128, 10, 128, 128, 120);
  radGrad.addColorStop(0, 'rgba(0, 0, 0, 0.7)');
  radGrad.addColorStop(0.5, 'rgba(0, 0, 0, 0.25)');
  radGrad.addColorStop(1, 'rgba(0, 0, 0, 0)');
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

  // b) Dark Obsidian Shield (Beveled Extrusion)
  const shape = new THREE.Shape();
  shape.moveTo(-1.9, 2.3);
  shape.lineTo(1.9, 2.3);
  shape.bezierCurveTo(2.1, 2.3, 2.2, 2.1, 2.2, 1.8);
  shape.bezierCurveTo(2.2, 0.2, 1.4, -1.8, 0, -2.7);
  shape.bezierCurveTo(-1.4, -1.8, -2.2, 0.2, -2.2, 1.8);
  shape.bezierCurveTo(-2.2, 2.1, -2.1, 2.3, -1.9, 2.3);

  const extrudeSettings = {
    depth: 0.28,
    bevelEnabled: true,
    bevelSegments: 4,
    steps: 1,
    bevelSize: 0.08,
    bevelThickness: 0.08,
  };

  const shieldGeom = new THREE.ExtrudeGeometry(shape, extrudeSettings);
  shieldGeom.center();

  const shieldMat = new THREE.MeshPhysicalMaterial({
    color: 0x162233,
    roughness: 0.15,
    metalness: 0.1,
    clearcoat: 1.0,
    clearcoatRoughness: 0.1,
    transmission: 0.35,
    thickness: 0.5,
    ior: 1.45,
    attenuationColor: new THREE.Color(0x10b981),
    transparent: true,
    opacity: 0.95,
  });

  const shieldMesh = new THREE.Mesh(shieldGeom, shieldMat);
  rootGroup.add(shieldMesh);

  // Ripple Ring (Threat Deflection)
  const rippleGeom = new THREE.RingGeometry(0.1, 0.16, 32);
  const rippleMat = new THREE.MeshBasicMaterial({
    color: 0xef4444,
    transparent: true,
    opacity: 0,
    side: THREE.DoubleSide,
    depthWrite: false,
  });
  const rippleMesh = new THREE.Mesh(rippleGeom, rippleMat);
  rippleMesh.position.set(0, 0, 0.24);
  rootGroup.add(rippleMesh);

  // c) Identity Core (Electric Emerald Fingerprint Arcs)
  const fpGroup = new THREE.Group();
  fpGroup.position.set(0, 0.1, 0.2);
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
      color: 0x10b981,
      linewidth: 2,
      transparent: true,
      opacity: 0.9,
    });
    const line = new THREE.Line(geom, mat);
    fpGroup.add(line);
    arcMeshes.push(line);
  });

  // Sweeping Mint Scan Line
  const scanGeom = new THREE.PlaneGeometry(3.2, 0.06);
  const scanMat = new THREE.MeshBasicMaterial({
    color: 0x34d399,
    transparent: true,
    opacity: 0.7,
    side: THREE.DoubleSide,
    depthWrite: false,
  });
  const scanMesh = new THREE.Mesh(scanGeom, scanMat);
  scanMesh.position.set(0, 1.2, 0.22);
  rootGroup.add(scanMesh);

  // d) 15 Agent Orbs across 5 Rings (NO Blue, NO Purple)
  const ringsGroup = new THREE.Group();
  rootGroup.add(ringsGroup);

  const RING_SPECS = [
    { name: 'Data', count: 4, radius: 3.2, tiltX: 0.35, tiltY: 0.2, speed: 0.007, color: 0x10b981 },
    { name: 'Detection', count: 7, radius: 4.2, tiltX: -0.45, tiltY: -0.25, speed: -0.0055, color: 0xf59e0b },
    { name: 'Decision', count: 3, radius: 5.1, tiltX: 0.25, tiltY: -0.3, speed: 0.0045, color: 0xf97316 },
    { name: 'Learning', count: 1, radius: 5.9, tiltX: -0.3, tiltY: 0.35, speed: -0.0035, color: 0x14b8a6 },
    { name: 'Oversight', count: 0, radius: 6.6, tiltX: 0.1, tiltY: 0.1, speed: 0.002, color: 0xeab308 },
  ];

  const ringObjects = [];
  const orbObjects = [];
  const detectionOrbs = [];

  RING_SPECS.forEach((spec) => {
    const ringAnchor = new THREE.Group();
    ringAnchor.rotation.x = spec.tiltX;
    ringAnchor.rotation.y = spec.tiltY;
    ringsGroup.add(ringAnchor);

    const torusGeom = new THREE.TorusGeometry(spec.radius, 0.02, 8, 64);
    const torusMat = new THREE.MeshBasicMaterial({
      color: spec.color,
      transparent: true,
      opacity: spec.count === 0 ? 0.7 : 0.35,
    });
    const torusMesh = new THREE.Mesh(torusGeom, torusMat);
    ringAnchor.add(torusMesh);

    const orbs = [];
    const orbGeom = new THREE.SphereGeometry(0.17, 16, 12);
    for (let i = 0; i < spec.count; i++) {
      const angle = (i / spec.count) * Math.PI * 2;
      const orbMat = new THREE.MeshStandardMaterial({
        color: spec.color,
        emissive: spec.color,
        emissiveIntensity: 0.25,
        roughness: 0.35,
        metalness: 0.1,
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

  // e) Threat Deflection Particle (Ruby Crimson)
  const threatGeom = new THREE.SphereGeometry(0.19, 16, 16);
  const threatMat = new THREE.MeshStandardMaterial({
    color: 0xef4444,
    emissive: 0xdc2626,
    emissiveIntensity: 0.8,
  });
  const threatParticle = new THREE.Mesh(threatGeom, threatMat);
  threatParticle.visible = false;
  scene.add(threatParticle);

  let threatAnim = null;

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
    };
  }

  // f) Pulse Wave Animation State
  let pulseStartTime = 0;
  function triggerPulse() {
    pulseStartTime = performance.now();
  }

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
    targetTiltY = nx * 0.17;
    targetTiltX = -ny * 0.17;
  });

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
      rootGroup.position.y = Math.sin(t * 1.05) * 0.18;
      rootGroup.rotation.y = Math.sin(t * 0.52) * 0.22;

      // 2. Tilt Damping
      curTiltX += (targetTiltX - curTiltX) * 0.08;
      curTiltY += (targetTiltY - curTiltY) * 0.08;
      rootGroup.rotation.x = curTiltX;
      rootGroup.rotation.y += curTiltY;

      // 3. Scan Line Sweep (4s cycle)
      const scanPhase = (t % 4.0) / 4.0;
      scanMesh.position.y = 1.6 - scanPhase * 3.2;

      // 4. Orbit Rings
      const speedMult = isHovered ? 1.4 : 1.0;
      ringObjects.forEach((ro) => {
        ro.angle += ro.spec.speed * speedMult;
        ro.anchor.rotation.z = ro.angle;
      });

      // 5. Pulse (Emerald Wave)
      if (pulseStartTime > 0) {
        const pElapsed = now - pulseStartTime;
        if (pElapsed < 700) {
          const arcIdx = Math.floor((pElapsed / 600) * arcMeshes.length);
          arcMeshes.forEach((mesh, idx) => {
            if (idx === arcIdx) {
              mesh.material.color.setHex(0x34d399);
              mesh.material.opacity = 1.0;
            } else {
              mesh.material.color.setHex(0x10b981);
              mesh.material.opacity = 0.85;
            }
          });
          orbObjects.forEach((o) => {
            o.mesh.scale.set(1.25, 1.25, 1.25);
          });
        } else {
          pulseStartTime = 0;
          arcMeshes.forEach((m) => {
            m.material.color.setHex(0x10b981);
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
            threatAnim.reflecting = true;
            threatAnim.progress = 0;

            if (detectionOrbs.length > 0) {
              const nearestOrb = detectionOrbs[Math.floor(Math.random() * detectionOrbs.length)];
              nearestOrb.mesh.scale.set(1.6, 1.6, 1.6);
              nearestOrb.mesh.material.color.setHex(0xef4444);
              setTimeout(() => {
                nearestOrb.mesh.scale.set(1, 1, 1);
                nearestOrb.mesh.material.color.setHex(nearestOrb.baseColor);
              }, 320);
            }

            rippleMesh.scale.set(1, 1, 1);
            rippleMat.opacity = 0.8;
          }
        } else {
          const rP = threatAnim.progress;
          threatParticle.position.lerpVectors(threatAnim.target, threatAnim.reflectDir, rP);
          threatMat.opacity = 1.0 - rP;

          const ripScale = 1.0 + rP * 6.0;
          rippleMesh.scale.set(ripScale, ripScale, ripScale);
          rippleMat.opacity = Math.max(0, 0.8 - rP);

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

  if (isStill || isReducedMotion) {
    renderFrame(performance.now());
  } else {
    rafId = requestAnimationFrame(renderFrame);
  }

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

  return {
    pulse: () => triggerPulse(),
    threat: () => triggerThreat(),
    destroy: () => {
      if (rafId) cancelAnimationFrame(rafId);
      io.disconnect();
      ro.disconnect();
      document.removeEventListener('visibilitychange', onVisChange);

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
