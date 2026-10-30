# P15: UI pages: 3D Graph, Globe, Analytics, Performance, Settings, Input, Audit (SHOULD)

> **Before pasting:** open a NEW Antigravity chat and paste T1 from `00_TEMPLATES.md` first. Then paste only the text block below. Run the CHECK yourself.

```text
Read context.md Sections 17, 18. Phase P15.
DO:
1. Graph 3D (graph.html, pages/graph.js): 3d-force-graph with data from /identities/{id}/graph or /graph/global;
   node colors/shapes per context.md Section 18 item 3; suspicious edges red with directional particles; Okta→AWS
   edges cyan glow; node size by risk; hover tooltip (escaped); click → camera fly-to + side panel (details, linked
   case); controls: identity selector, "Only attack path" toggle, "Show campaign links" toggle, reset camera,
   screenshot button (canvas toDataURL download). Fallback to vis-network 2D if WebGL fails (reuse existing v2
   vendor file if present).
2. Globe (globe.html, pages/globe.js): globe.gl with dark texture (bundle a small night-earth image in
   static/v3/img/ or use a solid dark sphere with country polygons from a bundled GeoJSON if available), login
   points sized by count, arcs for consecutive logins per identity, impossible-travel arcs red animated dashes,
   trusted locations green; identity filter; side list of impossible-travel events linking to cases.
3. Analytics (analytics.html, pages/analytics.js): reuse v2 analytics endpoints where useful plus /metrics/kpi:
   rules vs ML vs hybrid P/R/F1 grouped bars, per-detector precision table, calibration reliability diagram and
   Brier score, attack heatmap (hour × day) and identity × pattern heatmap.
4. Performance (performance.html, pages/performance.js): latency histogram and p50/p95 tiles for hot and warm paths,
   events/s line over the run, queue depth per topic, alert reduction gauge, "Run benchmark" button
   (POST /bench/run ×1/×5/×10) with machine info and timestamp; clear note "measured on this machine".
5. Settings (settings.html, pages/settings.js): read-only view of thresholds and playbooks; analyst token input
   (stored in localStorage with try/catch); config versions list with rollback button; proposed suppressions with
   approve/reject.
6. Input (input.html, pages/input.js): upload JSON or manual entry (reuse v2 input endpoints) + v3 "Scan input only"
   (POST /api/v3/inputs/scan) + presets for E1–E9.
7. Audit (audit.html, pages/audit.js): audit entries table with filters (actor, case id), verify button with clear
   valid/broken banner.
FILES: static/v3/graph.html, globe.html, analytics.html, performance.html, settings.html, input.html, audit.html,
static/v3/js/pages/graph.js, globe.js, analytics.js, performance.js, settings.js, input.js, audit.js,
static/v3/img/* (optional), static/v3/mock/* (extend only)
```

**CHECK (human, 10 min):** every page loads with real data and with `?mock=1`; the 3D graph shows the E1 path with moving red particles; the globe shows the impossible-travel arc in red; zero console errors.

---
**After the CHECK passes:** paste template T5 (in `00_TEMPLATES.md`), then commit: `git add -A && git commit -m "v3 P15: UI pages: 3D Graph, Globe, Analytics, Performance, Settings, Input, Audit"`. Next file: `P16_attack_generator_website_ngrok_runbook.md`.
