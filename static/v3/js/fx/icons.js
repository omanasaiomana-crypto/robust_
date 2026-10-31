/**
 * IdentityShield v3 — Project-Themed 3D Icons (icons.js)
 * Specification: UI_DESIGN.md Section 5
 *
 * Exports SVG template strings:
 *   shieldIcon(), lockIcon(), keyIcon(), fingerprintIcon(),
 *   radarIcon(), checkIcon(), bellIcon()
 */

export function shieldIcon(extraClass = '') {
  return `
    <span class="ico-3d ico-shield-spin ${extraClass}">
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        <line x1="8" y1="12" x2="16" y2="12" opacity="0.6"/>
      </svg>
    </span>
  `.trim();
}

export function lockIcon(extraClass = '') {
  return `
    <span class="ico-3d ico-lock-close ${extraClass}">
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
        <rect x="3" y="11" width="18" height="11" rx="2" ry="2" class="lock-body"/>
        <path d="M7 11V7a5 5 0 0 1 10 0v4" class="lock-shackle"/>
      </svg>
    </span>
  `.trim();
}

export function keyIcon(extraClass = '') {
  return `
    <span class="ico-3d ico-key-turn ${extraClass}">
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
        <path d="M21 2l-2 2m-1.5 1.5L13 10m-3 3l-2 2m-4 4a5 5 0 1 1 7.07-7.07l6.93-6.93H21v3l-2 2h-2v2l-2 2"/>
      </svg>
    </span>
  `.trim();
}

export function fingerprintIcon(extraClass = '') {
  return `
    <span class="ico-3d ico-fingerprint-scan ${extraClass}">
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 11c0 1.66-1.34 3-3 3s-3-1.34-3-3 1.34-3 3-3" class="fp-arc fp-arc-1"/>
        <path d="M12 7c2.76 0 5 2.24 5 5 0 2.21-1.79 4-4 4" class="fp-arc fp-arc-2"/>
        <path d="M12 3c4.97 0 9 4.03 9 9 0 3.5-2 6-4 7" class="fp-arc fp-arc-3"/>
      </svg>
    </span>
  `.trim();
}

export function radarIcon(extraClass = '') {
  return `
    <span class="ico-3d ico-radar-sweep ${extraClass}">
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="12" cy="12" r="9"/>
        <line x1="12" y1="12" x2="19" y2="7" class="radar-beam"/>
      </svg>
    </span>
  `.trim();
}

export function checkIcon(extraClass = '') {
  return `
    <span class="ico-3d ico-check-draw ${extraClass}">
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
        <polyline points="20 6 9 17 4 12" class="check-path"/>
      </svg>
    </span>
  `.trim();
}

export function bellIcon(extraClass = '') {
  return `
    <span class="ico-3d ico-bell-ring ${extraClass}">
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
        <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/>
        <path d="M13.73 21a2 2 0 0 1-3.46 0"/>
      </svg>
    </span>
  `.trim();
}
