# PHASE 32: Agents dashboard: show all 15 agents (≈35 min) · Person D

Spec: `kit_v2/08_FEATURE_AGENTS_SCAN_INPUT_GRAPH_SPEC.md` §3. Works in `?mock=1` before Phase 31 is live.

## Prompt

```text
Read context.md Section 10 and Sections 16.8, 21–24, then kit_v2/08_FEATURE_AGENTS_SCAN_INPUT_GRAPH_SPEC.md Section 3.

DO:
1. Create static/mock/agents.json and static/mock/scan_status.json by copying EXACTLY the blocks in
   kit_v2/reference/REF_18_mock_json_v21.md. Add to the api.js mock table (GET): /agents → agents,
   /scan/status → scan_status (match the path without the query string).
2. static/js/layout.js: add a sidebar item "Agents" (inline SVG "cpu/chip" icon) directly after Overview.
3. static/agents.html: same head/body as static/alerts.html, title "IdentityShield · Agents", module /js/agents.js.
4. static/js/agents.js: renderLayout("agents", "Agents", "15 cooperating agents · live status of every layer").
   Import escHtml from ./jsonview.js (create static/js/jsonview.js exactly from kit_v2/reference/REF_14_jsonview_js.md
   if it does not exist) and use it for EVERY dynamic value (it also escapes quotes in attributes).

   A) Orchestrator banner (full width card): agent #15 name, run state pill (Idle/Running/Complete/Failed,
      colors as context 10.3), run_id (mono), mode, "Step k / 13" + progress bar (progress from run status),
      threats count (crit), duration. Button "Open live scan" → scan.html (keep ?mock=1).

   B) Pipeline flow: 5 layer columns left→right on lg (stacked on mobile): Data (1–4), Detection (5–10),
      Decision (11–13), Learning (14), Oversight (15). Each column has a header with the layer color dot
      (data #22D3EE, detection #E879F9, decision #FBBF24, learning #34D399, oversight #60A5FA) and the layer name.
      Between columns on lg show a thin chevron "›" in text-muted to suggest flow.

   C) Agent card (one per agent, in its column): top row = number badge (font-mono "05"), name (font-medium),
      state pill on the right:
        waiting → "Waiting" muted · running → "Running" brand2 with animate-pulse dot · done → "Done" ok ·
        failed → "Failed" crit · skipped → "Skipped" warn · idle → "Idle" muted.
      Then: role (text-xs text-muted, 2 lines max), a stats row: last duration ("12 ms" or "—"),
      runs, and for detection agents a signals count chip + pattern chip (P1..P5/ML using patternChip from ui.js).
      Permissions as tiny mono chips (bg-panel2). last_error in crit text if present.
      Card border: line; running → ring-1 ring-brand2; failed → border-crit/60.
      The whole card is a button (keyboard accessible).

   D) Clicking a card opens a detail panel (in-flow card below the grid, or a right-side panel on lg)
      showing: name, role, layer, permissions, last_started / last_finished (fmtTime), last_message,
      and last_output rendered with highlightJson inside a dark <pre> (background #05070C, max-h-80 overflow-auto),
      plus "Recent events" = GET /scan/trace?after=0&limit=2000 filtered client-side to this agent (last 10),
      each as a one-line row with state and message. Close button.

   E) Polling: GET /agents every 1500 ms while run.state === "running", otherwise every 10 s; stop polling when the
      tab is hidden (document.hidden) and resume on visibilitychange. Never stack timers.
   Skeletons while loading; errorState on failure; works at 375 px.
FILES: static/mock/agents.json, static/mock/scan_status.json, static/js/api.js, static/js/layout.js,
static/agents.html, static/js/agents.js, static/js/jsonview.js (copy only if missing)
```

## CHECK (human)

1. `agents.html?mock=1`: 15 cards in 5 columns, all **Done**; detection cards show signal counts; clicking *Privilege Escalation Agent* shows its JSON (`chains` …); no console errors; works at 375 px.
2. Live: open the page, then in another tab press **Re-run pipeline** (or start a scan in Phase 33). The cards switch to **Running** and then **Done**, and the banner shows the progress.

---

**After the CHECK passes:** `git commit -m "phase 32 ok"`, then update context.md Section 24.
