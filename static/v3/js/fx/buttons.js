/**
 * IdentityShield v3 — 3D Button Micro-Animations Controller (buttons.js)
 * Specification: UI_DESIGN.md Section 5
 *
 * Exports:
 *   initButtons(root)
 *   setLoading(btn, isLoading)
 *   flashSuccess(btn, duration)
 */

const isReducedMotion = () => window.matchMedia('(prefers-reduced-motion: reduce)').matches;
const isTouchDevice = () => window.matchMedia('(hover: none)').matches;

/**
 * Initialize event delegation for .btn-tilt, .btn-ripple, and keyboard keycap press.
 */
export function initButtons(root = document) {
  if (!root) return;

  // 1. 3D Tilt on .btn-tilt
  root.addEventListener('mousemove', (e) => {
    if (isReducedMotion() || isTouchDevice()) return;
    const btn = e.target.closest('.btn-tilt');
    if (!btn || btn.disabled || btn.classList.contains('is-loading')) return;

    const rect = btn.getBoundingClientRect();
    const nx = ((e.clientX - rect.left) / rect.width) * 2 - 1;
    const ny = ((e.clientY - rect.top) / rect.height) * 2 - 1;

    const rx = -ny * 6; // max 6 deg
    const ry = nx * 6;  // max 6 deg

    btn.style.setProperty('--rx', `${rx.toFixed(2)}deg`);
    btn.style.setProperty('--ry', `${ry.toFixed(2)}deg`);
    btn.style.setProperty('--mx', `${(((e.clientX - rect.left) / rect.width) * 100).toFixed(1)}%`);
    btn.style.setProperty('--my', `${(((e.clientY - rect.top) / rect.height) * 100).toFixed(1)}%`);
  });

  root.addEventListener('mouseout', (e) => {
    const btn = e.target.closest('.btn-tilt');
    if (btn && (!e.relatedTarget || !btn.contains(e.relatedTarget))) {
      btn.style.setProperty('--rx', '0deg');
      btn.style.setProperty('--ry', '0deg');
    }
  });

  // 2. Ripple Effect on .btn-ripple
  root.addEventListener('pointerdown', (e) => {
    if (isReducedMotion()) return;
    const btn = e.target.closest('.btn-ripple');
    if (!btn || btn.disabled || btn.classList.contains('is-loading')) return;

    const rect = btn.getBoundingClientRect();
    const ripple = document.createElement('span');
    ripple.className = 'ripple';

    const size = Math.max(rect.width, rect.height) * 1.8;
    ripple.style.width = `${size}px`;
    ripple.style.height = `${size}px`;
    ripple.style.left = `${e.clientX - rect.left}px`;
    ripple.style.top = `${e.clientY - rect.top}px`;

    btn.appendChild(ripple);
    setTimeout(() => ripple.remove(), 480);
  });

  // 3. Keyboard Press on Enter / Space for Keycap Feel
  root.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      const btn = e.target.closest('.btn-3d, .btn');
      if (btn && !btn.disabled && !btn.classList.contains('is-loading')) {
        btn.classList.add('is-pressed');
      }
    }
  });

  root.addEventListener('keyup', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      const btn = e.target.closest('.btn-3d, .btn');
      if (btn) {
        setTimeout(() => btn.classList.remove('is-pressed'), 120);
      }
    }
  });
}

/**
 * Toggle 3D Dish Loading Spinner on a button, preserving layout dimensions.
 */
export function setLoading(btn, isLoading = true) {
  if (!btn) return;

  if (isLoading) {
    btn.dataset.origWidth = btn.offsetWidth + 'px';
    btn.style.minWidth = btn.offsetWidth + 'px';
    btn.classList.add('is-loading');
    btn.setAttribute('aria-busy', 'true');
    btn.setAttribute('disabled', 'true');
  } else {
    btn.classList.remove('is-loading');
    btn.removeAttribute('aria-busy');
    btn.removeAttribute('disabled');
    btn.style.minWidth = '';
  }
}

/**
 * Flash mint success morph for 900ms.
 */
export function flashSuccess(btn, duration = 900) {
  if (!btn) return Promise.resolve();

  btn.classList.remove('is-loading');
  btn.removeAttribute('aria-busy');
  btn.classList.add('is-success');

  return new Promise((resolve) => {
    setTimeout(() => {
      btn.classList.remove('is-success');
      resolve();
    }, duration);
  });
}
