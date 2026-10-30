# P13: UI foundation: 3D theme, shell, background (MUST)

> **Before pasting:** open a NEW Antigravity chat and paste T1 from `00_TEMPLATES.md` first. Then paste only the text block below. Run the CHECK yourself.

```text
Read context.md Section 18 fully, and Section 2 rule 8. Phase P13: UI foundation for static/v3/.
DO:
1. Vendor libraries (internet needed once): download exact, existing, stable versions of three (UMD/module build),
   3d-force-graph (UMD), globe.gl (UMD), chart.js 4.4.4 (UMD) into static/vendor/; record name, version, source URL
   and SHA-256 of each file in static/vendor/VERSIONS.md. Pages load vendor files locally (no runtime CDN dependency
   except Google Fonts and Tailwind; if Tailwind CDN is unreachable pages must still be readable because theme.css
   carries the core layout).
2. static/v3/css/theme.css: all tokens from context.md Section 18 as CSS variables; base styles (body bg gradient
   #05070D → #0B0F17, Inter font stack), .glass panel class (blur, border, shadow, top highlight), buttons
   (primary, ghost, danger), badges per band, chips for MITRE, tables (sticky header, zebra rgba), skeleton shimmer,
   focus-visible rings, scrollbar styling, reduced-motion overrides, layout grid for shell (sidebar 248px collapsible
   to 72px, topbar 60px).
3. static/v3/js/core/dom.js: escHtml (escapes & < > " ' `), el(tag, attrs, children) helper that only uses
   textContent for text, fmt helpers (time ago, number, percent, ms), bandColor(band).
   static/v3/js/core/api.js: fetch wrapper with base /api/v3, timeout 10 s, JSON errors surfaced as toasts,
   analyst token from localStorage (try/catch) sent as X-Analyst-Token on POST, ?mock=1 → load
   static/v3/mock/<route>.json instead.
   static/v3/js/core/sse.js: EventSource wrapper with auto-reconnect (backoff 1→10 s), typed listeners, mock mode
   emits fixture events on a timer.
   static/v3/js/core/shell.js: renders sidebar (Dashboard, Live, Cases, Graph 3D, Globe, Agents, Analytics,
   Performance, Input, Audit, Settings) with inline SVG icons, active state, collapse toggle (remembered in
   localStorage with try/catch); topbar with run status pill, live events/s, ingest status dot (polls
   /api/v3/health every 5 s), clock; toast container; command palette (Ctrl+K) to jump to pages and case IDs.
4. static/v3/js/fx/bg3d.js: Three.js particle network background on a fixed canvas behind content (≤ 1,500 points,
   lines between near points, slow drift, mouse parallax, color from --brand/--cyan at low opacity), pauses when
   document.hidden, disabled for prefers-reduced-motion, falls back to CSS gradient if WebGL unavailable, pixel
   ratio capped at 2, cleans up on unload.
   static/v3/js/fx/tilt.js: 3D tilt on hover for elements with data-tilt (max 6°, perspective 900px, glare
   highlight), disabled on touch and reduced motion.
5. static/v3/index.html as a placeholder page using the shell, background, 4 tilt KPI cards with skeletons.
   Every page: <title>IdentityShield · <Page></title>, meta viewport, theme.css, Tailwind CDN (pinned version),
   Google Fonts Inter + JetBrains Mono, type="module" scripts only, no inline handlers.
6. static/v3/mock/: fixtures for health, agents, cases, case detail, graph, geo, metrics (realistic E1 data).
FILES: static/vendor/*, static/v3/css/theme.css, static/v3/js/core/*.js, static/v3/js/fx/*.js,
static/v3/index.html, static/v3/mock/*.json
```

**CHECK (human, 5 min)**
- Open `http://127.0.0.1:8000/v3/index.html?mock=1` (or the path your static mount uses). Background animates, sidebar collapses, Ctrl+K opens the palette, cards tilt.
- DevTools console: zero errors. Toggle "prefers-reduced-motion" in DevTools rendering: animation stops.
- Disconnect internet and reload: page still renders (vendor files local).

---
**After the CHECK passes:** paste template T5 (in `00_TEMPLATES.md`), then commit: `git add -A && git commit -m "v3 P13: UI foundation: 3D theme, shell, background"`. Next file: `P14_ui_pages_dashboard_cases_case_detail_live.md`.
