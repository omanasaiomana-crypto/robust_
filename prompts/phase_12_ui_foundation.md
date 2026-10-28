# PHASE 12: UI foundation (≈25 min) · Person D

```text
Read context.md fully, especially Section 10 (UI design system). Follow it exactly.

GOAL: Shared UI foundation: page shells, sidebar layout, API client with mock mode, component
library. The result must look like a professional enterprise security console.

DO:
1. Every HTML page in static/ (index, alerts, alert, identities, graph, timeline, hygiene, audit)
   uses this head (adjust the title):
   <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
   <title>IdentityShield · <Page></title>
   <link rel="preconnect" href="https://fonts.googleapis.com">
   <link href="<Inter + JetBrains Mono URL from context.md Section 3>" rel="stylesheet">
   <script src="https://cdn.tailwindcss.com"></script>
   <script> tailwind.config = <exactly as context.md 10.1> </script>
   <link rel="stylesheet" href="/css/app.css">
   Body: class="bg-bg text-ink font-sans antialiased"; contains <div id="app"></div> and
   <script type="module" src="/js/<page>.js"></script>. Pages needing Chart.js or vis-network include
   those CDN scripts BEFORE the module script.
2. static/js/api.js:
   - export async function api(path, {method="GET", body}={}) → returns parsed JSON or throws an Error
     whose message is "<error>: <detail>" from ErrorResponse.
   - Mock mode when location.search contains "mock=1": GET maps paths to /mock/<name>.json using this table:
     /health→health, /summary→summary, /alerts→alerts, /alerts/{id}→alert, /alerts/{id}/events→events,
     /identities→identities, /identities/{id}/graph→graph, /sessions/{id}/timeline→timeline,
     /hygiene→hygiene, /metrics→metrics, /audit→audit, /audit/verify→audit_verify, /weights→weights.
     Mock POST returns {status:"mocked", detail:"mock mode"}.
   - export function esc(value) (HTML escape), qs(name) (URL query param), fmtTime(iso) (local short
     date-time), fmtNum(n).
3. static/js/ui.js: export functions returning HTML strings (all dynamic values passed through esc):
   card(title, bodyHtml, actionHtml?), statCard(label, value, note?), bandBadge(band),
   patternChip(code), mitreChip(id), riskRing(risk, band, size=72), riskBar(risk, band),
   table(columns, rowsHtml), button(label, {variant, id, attrs}), skeleton(lines=4),
   emptyState(message), errorState(message, retryId), plus
   toast(message, type="success"|"error") (appends to a fixed bottom-right container) and
   confirmModal(title, message) → Promise<boolean> (in-flow overlay card, Escape/Cancel = false).
   Band styles and labels exactly as context.md 10.3. Pattern names: P1 Impossible travel,
   P2 Dormant account, P3 Privilege escalation, P4 Unusual API, P5 Token abuse, ML Behavior anomaly.
4. static/js/layout.js: export function renderLayout(active, title, subtitle) that builds the sidebar
   + top bar from context.md 10.2 into #app and returns the content element. Sidebar items with inline
   SVG icons (shield logo, gauge, bell, users, broom/check, list). Top bar loads /health and shows the
   pipeline status pill and data-mode pill; "Re-run pipeline" button POSTs /pipeline/run, shows a
   toast, then reloads the page. Mobile (< 768 px): sidebar hidden behind a menu button.
   Keep the ?mock=1 query when building nav links.
5. static/css/app.css: small file only: custom scrollbar, .tabular-nums, focus-visible ring using brand,
   table sticky header helper, skeleton pulse.
6. static/mock/: create realistic mock JSON files for every name in the table above, matching
   context.md Section 5 field names exactly (use svc-report, anita.rao, meera.n, dev.kumar scenarios;
   alert.json = the svc-report revoke alert with chain, prediction, counterfactuals).
7. Each page's JS file for now only calls renderLayout(...) and shows a skeleton.

FILES: static/*.html, static/css/app.css, static/js/api.js, static/js/ui.js, static/js/layout.js,
static/js/<page>.js placeholders, static/mock/*.json

CHECK: run the server, open http://127.0.0.1:8000/index.html?mock=1 and every other page with ?mock=1.
Each shows the sidebar, top bar with status pills, correct active item, no console errors,
and works at 375 px width (DevTools device mode).
Then update context.md Section 12: Phase 12 = ☑.
```

---

**After the CHECK passes:** `git add . && git commit -m "phase 12 ok"`, then open the next file.
**If the CHECK fails:** use template T2 in `prompts/00_templates.md` with the exact error.
