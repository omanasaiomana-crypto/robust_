/**
 * IdentityShield v3 — 3D Particle Network Background
 * Context.md Section 18: Three.js particle network background (<=1,500 points,
 * lines between near points, slow drift, mouse parallax, pauses when document.hidden,
 * disabled on prefers-reduced-motion, WebGL fallback, pixel ratio capped at 2).
 */

export class Background3D {
  constructor(canvasId = 'bg3d-canvas') {
    this.canvasId = canvasId;
    this.canvas = null;
    this.renderer = null;
    this.scene = null;
    this.camera = null;
    this.particles = null;
    this.particlePositions = null;
    this.velocities = [];
    this.linesMesh = null;
    this.linesGeometry = null;

    this.particleCount = 650; // Well within <= 1500 limit for 60fps
    this.maxDistance = 110;
    this.mouseX = 0;
    this.mouseY = 0;
    this.targetMouseX = 0;
    this.targetMouseY = 0;

    this.isPaused = false;
    this.rafId = null;

    this._onResize = this._onResize.bind(this);
    this._onMouseMove = this._onMouseMove.bind(this);
    this._onVisibilityChange = this._onVisibilityChange.bind(this);
    this.animate = this.animate.bind(this);
  }

  init() {
    // Check prefers-reduced-motion
    if (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      this._applyCssFallback();
      return;
    }

    // Check Three.js availability
    if (typeof window.THREE === 'undefined') {
      console.warn('Three.js not found, falling back to CSS background.');
      this._applyCssFallback();
      return;
    }

    try {
      this._setupCanvas();
      this._setupThree();
      this._setupParticles();
      this._bindEvents();
      this.animate();
    } catch (err) {
      console.warn('WebGL initialization failed, falling back to CSS gradient:', err);
      this._applyCssFallback();
    }
  }

  _applyCssFallback() {
    if (this.canvas) this.canvas.remove();
    document.body.style.background =
      'radial-gradient(ellipse at 50% 15%, rgba(59, 130, 246, 0.08) 0%, rgba(5, 7, 13, 0) 70%), linear-gradient(180deg, #05070D 0%, #0B0F17 100%)';
  }

  _setupCanvas() {
    let canvas = document.getElementById(this.canvasId);
    if (!canvas) {
      canvas = document.createElement('canvas');
      canvas.id = this.canvasId;
      canvas.style.position = 'fixed';
      canvas.style.top = '0';
      canvas.style.left = '0';
      canvas.style.width = '100vw';
      canvas.style.height = '100vh';
      canvas.style.pointerEvents = 'none';
      canvas.style.zIndex = '-10';
      document.body.prepend(canvas);
    }
    this.canvas = canvas;
  }

  _setupThree() {
    const THREE = window.THREE;
    const width = window.innerWidth;
    const height = window.innerHeight;

    this.scene = new THREE.Scene();
    this.camera = new THREE.PerspectiveCamera(60, width / height, 1, 2000);
    this.camera.position.z = 600;

    this.renderer = new THREE.WebGLRenderer({
      canvas: this.canvas,
      alpha: true,
      antialias: true,
      powerPreference: 'high-performance',
    });

    this.renderer.setSize(width, height);
    // Cap pixel ratio at 2 per requirements
    this.renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    this.renderer.setClearColor(0x000000, 0);
  }

  _setupParticles() {
    const THREE = window.THREE;
    const count = this.particleCount;

    const geometry = new THREE.BufferGeometry();
    const positions = new Float32Array(count * 3);
    const colors = new Float32Array(count * 3);

    const brandColor = new THREE.Color(0x3B82F6);
    const cyanColor = new THREE.Color(0x22D3EE);

    const boxSize = 850;

    for (let i = 0; i < count; i++) {
      positions[i * 3] = (Math.random() - 0.5) * boxSize;
      positions[i * 3 + 1] = (Math.random() - 0.5) * boxSize;
      positions[i * 3 + 2] = (Math.random() - 0.5) * (boxSize / 1.5);

      this.velocities.push({
        x: (Math.random() - 0.5) * 0.45,
        y: (Math.random() - 0.5) * 0.45,
        z: (Math.random() - 0.5) * 0.3,
      });

      // 60% brand blue, 40% cyan
      const isCyan = Math.random() > 0.6;
      const c = isCyan ? cyanColor : brandColor;
      colors[i * 3] = c.r;
      colors[i * 3 + 1] = c.g;
      colors[i * 3 + 2] = c.b;
    }

    geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    geometry.setAttribute('color', new THREE.BufferAttribute(colors, 3));

    // Particle sprite material
    const particleMaterial = new THREE.PointsMaterial({
      size: 3.5,
      vertexColors: true,
      transparent: true,
      opacity: 0.65,
      blending: THREE.AdditiveBlending,
    });

    this.particles = new THREE.Points(geometry, particleMaterial);
    this.scene.add(this.particles);
    this.particlePositions = positions;

    // Buffer for dynamic connecting lines
    // Max potential pairs capped
    const maxLineSegments = count * 6;
    const linePositions = new Float32Array(maxLineSegments * 6);
    const lineColors = new Float32Array(maxLineSegments * 6);

    this.linesGeometry = new THREE.BufferGeometry();
    this.linesGeometry.setAttribute('position', new THREE.BufferAttribute(linePositions, 3));
    this.linesGeometry.setAttribute('color', new THREE.BufferAttribute(lineColors, 3));

    const lineMaterial = new THREE.LineSegments(
      this.linesGeometry,
      new THREE.LineBasicMaterial({
        vertexColors: true,
        transparent: true,
        opacity: 0.35,
        blending: THREE.AdditiveBlending,
      })
    );

    this.linesMesh = lineMaterial;
    this.scene.add(this.linesMesh);
  }

  _bindEvents() {
    window.addEventListener('resize', this._onResize);
    window.addEventListener('mousemove', this._onMouseMove, { passive: true });
    document.addEventListener('visibilitychange', this._onVisibilityChange);
    window.addEventListener('beforeunload', () => this.cleanup());
  }

  _onMouseMove(e) {
    // Normalise mouse coords between -1 and 1
    this.targetMouseX = (e.clientX / window.innerWidth) * 2 - 1;
    this.targetMouseY = -(e.clientY / window.innerHeight) * 2 + 1;
  }

  _onResize() {
    if (!this.camera || !this.renderer) return;
    const width = window.innerWidth;
    const height = window.innerHeight;
    this.camera.aspect = width / height;
    this.camera.updateProjectionMatrix();
    this.renderer.setSize(width, height);
    this.renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
  }

  _onVisibilityChange() {
    this.isPaused = document.hidden;
    if (!this.isPaused && !this.rafId) {
      this.animate();
    }
  }

  animate() {
    if (this.isPaused) {
      this.rafId = null;
      return;
    }

    this.rafId = requestAnimationFrame(this.animate);

    // Smooth mouse parallax lerp
    this.mouseX += (this.targetMouseX - this.mouseX) * 0.04;
    this.mouseY += (this.targetMouseY - this.mouseY) * 0.04;

    this.camera.position.x = this.mouseX * 70;
    this.camera.position.y = this.mouseY * 50;
    this.camera.lookAt(this.scene.position);

    // Drift particles
    const positions = this.particlePositions;
    const count = this.particleCount;
    const boxSize = 850;
    const halfBox = boxSize / 2;

    for (let i = 0; i < count; i++) {
      const idx = i * 3;
      positions[idx] += this.velocities[i].x;
      positions[idx + 1] += this.velocities[i].y;
      positions[idx + 2] += this.velocities[i].z;

      // Wrap boundaries
      if (positions[idx] < -halfBox) positions[idx] = halfBox;
      if (positions[idx] > halfBox) positions[idx] = -halfBox;
      if (positions[idx + 1] < -halfBox) positions[idx + 1] = halfBox;
      if (positions[idx + 1] > halfBox) positions[idx + 1] = -halfBox;
      if (positions[idx + 2] < -halfBox / 1.5) positions[idx + 2] = halfBox / 1.5;
      if (positions[idx + 2] > halfBox / 1.5) positions[idx + 2] = -halfBox / 1.5;
    }

    this.particles.geometry.attributes.position.needsUpdate = true;

    // Connect close points with lines
    const linePos = this.linesGeometry.attributes.position.array;
    const lineCol = this.linesGeometry.attributes.color.array;
    let lineIdx = 0;
    let colorIdx = 0;
    const maxDist = this.maxDistance;
    const maxDistSq = maxDist * maxDist;

    for (let i = 0; i < count; i++) {
      const i3 = i * 3;
      const x1 = positions[i3];
      const y1 = positions[i3 + 1];
      const z1 = positions[i3 + 2];

      // Sample a subset of neighboring pairs for silky performance
      for (let j = i + 1; j < Math.min(i + 25, count); j++) {
        const j3 = j * 3;
        const dx = x1 - positions[j3];
        const dy = y1 - positions[j3 + 1];
        const dz = z1 - positions[j3 + 2];
        const distSq = dx * dx + dy * dy + dz * dz;

        if (distSq < maxDistSq) {
          const alpha = 1.0 - Math.sqrt(distSq) / maxDist;

          linePos[lineIdx++] = x1;
          linePos[lineIdx++] = y1;
          linePos[lineIdx++] = z1;

          linePos[lineIdx++] = positions[j3];
          linePos[lineIdx++] = positions[j3 + 1];
          linePos[lineIdx++] = positions[j3 + 2];

          // Subtle cyan-blue line color with distance falloff
          lineCol[colorIdx++] = 0.15 * alpha;
          lineCol[colorIdx++] = 0.55 * alpha;
          lineCol[colorIdx++] = 0.95 * alpha;

          lineCol[colorIdx++] = 0.15 * alpha;
          lineCol[colorIdx++] = 0.55 * alpha;
          lineCol[colorIdx++] = 0.95 * alpha;
        }
      }
    }

    this.linesGeometry.setDrawRange(0, lineIdx / 3);
    this.linesGeometry.attributes.position.needsUpdate = true;
    this.linesGeometry.attributes.color.needsUpdate = true;

    this.renderer.render(this.scene, this.camera);
  }

  cleanup() {
    if (this.rafId) {
      cancelAnimationFrame(this.rafId);
      this.rafId = null;
    }
    window.removeEventListener('resize', this._onResize);
    window.removeEventListener('mousemove', this._onMouseMove);
    document.removeEventListener('visibilitychange', this._onVisibilityChange);

    if (this.renderer) {
      this.renderer.dispose();
      this.renderer = null;
    }
    if (this.canvas) {
      this.canvas.remove();
      this.canvas = null;
    }
  }
}

export const bg3d = new Background3D();

// Auto-initialize when Three.js is present
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => bg3d.init());
} else {
  bg3d.init();
}

export default bg3d;
