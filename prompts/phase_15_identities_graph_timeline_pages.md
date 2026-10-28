# PHASE 15: Identities, Graph, Timeline pages (≈30 min) · Person D

```text
Read context.md fully, especially Section 10.4.

GOAL: Visual investigation pages.

DO:
1. static/js/identities.js: table from /identities: identity (with initials avatar circle), risk bar,
   band badge (from risk), privilege level (1-5 dots), blast radius, alerts; search box;
   row click → graph.html?identity=.
2. static/js/graph.js:
   - Read ?identity=; load /identities/{id}/graph.
   - vis-network inside a card, height 600 px, background transparent.
     Node colors by kind: user #22D3EE, session #8B5CF6, role #F59E0B, key #F97316, policy #EF4444,
     resource #10B981, ip #64748B. Font color #E6EBF2, size 12. Suspicious edges red (#EF4444) width 3,
     others #334155 width 1, arrows "to", smooth curves.
     physics barnesHut with stabilization, then disable physics after stabilization so it stops moving.
   - Right panel: legend (colored dots + kind names), blast radius stat, "Paths to admin" list
     (each path as chips joined by →), and a "Fit view" button (network.fit()).
   - Clicking a node shows its label and kind in a small details box.
   - Guard: if typeof vis === "undefined", show errorState("Graph library failed to load").
3. static/js/timeline.js:
   - Read ?session=; load /sessions/{id}/timeline.
   - Controls: Play/Pause button, range slider (0..n), step counter "Step 3 of 9", speed select (1x, 2x).
   - Vertical list of events; events beyond the slider position are dimmed (opacity-30);
     the current event is highlighted with a brand ring. Each event shows time, source badge,
     action (mono), IP/location, and signal chips (pattern + short reason) when present.
   - Auto-scroll the current event into view. Stop at the end.

FILES: static/js/identities.js, static/js/graph.js, static/js/timeline.js (and their HTML files only
if a script tag must be added).

CHECK: all three pages with ?mock=1 and live data; graph renders and stops moving; timeline plays
smoothly; no console errors.
Then update context.md Section 12: Phase 15 = ☑.
```

---

**After the CHECK passes:** `git add . && git commit -m "phase 15 ok"`, then open the next file.
**If the CHECK fails:** use template T2 in `prompts/00_templates.md` with the exact error.
