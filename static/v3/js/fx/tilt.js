/**
 * IdentityShield v3 — 3D Tilt Hover FX
 * Applies 3D perspective tilt (max 6deg) and dynamic glare reflection to [data-tilt] elements.
 * Disabled on touch and prefers-reduced-motion.
 */

export class TiltFX {
  constructor() {
    this.maxTilt = 6;
    this.perspective = 900;
    this.elements = [];
  }

  init() {
    // Disable on touch devices
    const isTouch = 'ontouchstart' in window || navigator.maxTouchPoints > 0;
    if (isTouch) return;

    // Disable on prefers-reduced-motion
    if (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      return;
    }

    this.scan();
  }

  scan() {
    const nodes = document.querySelectorAll('[data-tilt]');
    nodes.forEach((el) => this._bindElement(el));
  }

  _bindElement(el) {
    if (el._tiltBound) return;
    el._tiltBound = true;

    // Ensure perspective container styling
    el.style.perspective = `${this.perspective}px`;
    el.style.transformStyle = 'preserve-3d';
    el.style.transition = 'transform 0.15s cubic-bezier(0.2, 0, 0.2, 1)';

    // Inject glare layer if not present
    let glare = el.querySelector('.tilt-glare');
    if (!glare) {
      glare = document.createElement('div');
      glare.className = 'tilt-glare';
      el.appendChild(glare);
    }

    const onMouseMove = (e) => {
      const rect = el.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;

      const xPct = (x / rect.width) * 2 - 1; // -1 to 1
      const yPct = (y / rect.height) * 2 - 1; // -1 to 1

      // Calculate rotation angles (max 6 degrees)
      const rotateX = -yPct * this.maxTilt;
      const rotateY = xPct * this.maxTilt;

      el.style.transform = `perspective(${this.perspective}px) rotateX(${rotateX.toFixed(2)}deg) rotateY(${rotateY.toFixed(2)}deg) translateY(-2px)`;

      // Dynamic glare highlight reflection
      const glareX = (x / rect.width) * 100;
      const glareY = (y / rect.height) * 100;
      glare.style.opacity = '1';
      glare.style.background = `radial-gradient(circle at ${glareX}% ${glareY}%, rgba(255, 255, 255, 0.14) 0%, transparent 60%)`;
    };

    const onMouseLeave = () => {
      el.style.transform = `perspective(${this.perspective}px) rotateX(0deg) rotateY(0deg) translateY(0px)`;
      if (glare) {
        glare.style.opacity = '0';
      }
    };

    el.addEventListener('mousemove', onMouseMove);
    el.addEventListener('mouseleave', onMouseLeave);
  }
}

export const tilt = new TiltFX();

// Auto-initialize
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => tilt.init());
} else {
  tilt.init();
}

export default tilt;
