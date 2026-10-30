# P14: UI pages: Dashboard, Cases, Case detail, Live (3D constellation), Agents (MUST)

> **Before pasting:** open a NEW Antigravity chat and paste T1 from `00_TEMPLATES.md` first. Then paste only the text block below. Run the CHECK yourself.

```text
Read context.md Sections 17, 18, 19. Phase P14. Use only core/* helpers for DOM and API.
DO (one module per page in static/v3/js/pages/):
1. Dashboard (index.html, pages/dashboard.js): KPI tilt cards (open cases by band, identities at risk ≥ 60, events/s,
   p95 latency, alert reduction %); "Top identities" table (identity risk bar, session risk, band badge, last seen);
   "Live cases" feed updated from SSE case events; mini login-globe tile linking to Globe page (globe.gl, small,
   auto-rotate, pauses when hidden); a "Run dataset" button (POST /run/dataset with analyst token) and status.
2. Cases (cases.html, pages/cases.js): filter bar (band, status, search identity), sortable table with band badge,
   risk, confidence, chain length, MITRE chips (max 3 + "+n"), status, updated; row click → case.html?id=.
3. Case detail (case.html, pages/case.js): header (identity, session, session risk gauge as an SVG arc, identity
   risk, confidence, band, status); "Attack chain" vertical timeline grouped by kill-chain stage with event id,
   action, resource, time, MITRE chips; "Why this score" (3 reasons with evidence id links that open an evidence
   drawer showing the event JSON, syntax-highlighted, escaped); "What if" horizontal bars from counterfactuals
   (score vs score_without); "Predicted next step" card with probability; "Blast radius" count + list; "Related
   identities"; "Narrative" with source tag (template/LLM); "Actions" panel listing actions with state chips and
   buttons Approve / Reject / Rollback (confirm modal, analyst name input, POST with token), label buttons
   TP / FP / Benign. Live updates from SSE for this case id.
4. Live (live.html, pages/live.js): 3D agent constellation (Three.js): 15 nodes on 5 concentric rings (layers),
   labeled sprites, idle dim, running pulse, finding amber flash, threat red burst with ring shockwave; particles
   travel between nodes when bus messages flow (derive from trace events: producer → consumer layer); orbit
   controls with gentle auto-rotate; right panel: colored terminal-style trace log (levels/state colors, agent tags,
   JSON expanders, filters by agent and state, pause/resume, auto-scroll), current step + JSON panel; controls:
   pace (Instant/Fast/Normal/Slow → 0/0.4/1/1.8 s), Start dataset scan, Replay last run; counters for events,
   signals, cases, threats; "LIVE · simulating" pulsing pill while running. Fallback: if WebGL unavailable, render
   the constellation as a 2D SVG with the same states.
5. Agents (agents.html, pages/agents.js): 15 glass cards grouped by layer with status dot, processed, errors,
   blocked, p95 ms, queue lag, last message, capability badges (from manifests), sparkline of throughput
   (Chart.js); click → drawer with recent trace lines for that agent. Polls /api/v3/agents every 2 s and listens to
   SSE trace.
All pages: skeletons while loading, empty states, error toasts, ?mock=1 works, every dynamic string escaped,
Three/Chart instances disposed on unload.
FILES: static/v3/index.html, cases.html, case.html, live.html, agents.html, static/v3/js/pages/dashboard.js,
cases.js, case.js, live.js, agents.js, static/v3/mock/* (extend only)
```

**CHECK (human, 10 min)**
- With the server running, click **Run dataset**: the Live page shows the constellation lighting up layer by layer and the trace scrolling; the Cases page lists cases; the E1 case detail shows chain, reasons, what-if bars, next step and a pending revoke. Approve it: the state changes to applied and the audit gets an entry.
- `?mock=1` works on every page; the console shows zero errors.

---
**After the CHECK passes:** paste template T5 (in `00_TEMPLATES.md`), then commit: `git add -A && git commit -m "v3 P14: UI pages: Dashboard, Cases, Case detail, Live"`. Next file: `P15_ui_pages_3d_graph_globe_analytics_performance.md`.
