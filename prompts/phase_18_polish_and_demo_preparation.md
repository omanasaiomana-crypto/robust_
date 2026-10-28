# PHASE 18: Polish and demo preparation (≈30 min) · Person D (+ team)

```text
Read context.md fully.

GOAL: Final professional polish without risking stability.

DO (frontend only, no backend changes):
1. Consistency pass: same spacing (p-5 cards, gap-6 grids), same heading sizes, same button styles
   on all pages; every page has skeleton, empty and error states.
2. Add a subtle "Demo scenario" card on the Overview page (only when data_mode is "sample"):
   "Sample data with 5 injected attacks" and links to the svc-report alert, its graph and timeline.
3. Accessibility: buttons have aria-labels where icon-only; visible focus rings; color is never the
   only signal (band badges include text).
4. Page titles and favicon: inline SVG shield favicon via data URI in each HTML head.
5. README.md: what it is, how to run (run.bat / run.sh), pages, tech stack, how to switch to official
   data and supplied simulator, team names placeholder.
6. Do not change any API calls or backend files.

FILES: static/**, README.md

CHECK: click through every page live; pytest -q and smoke_test.py still pass.
Then update context.md Section 12: Phase 18 = ☑ and commit "v1.0-demo".
```

---

**After the CHECK passes:** `git add . && git commit -m "phase 18 ok"`, then open the next file.
**If the CHECK fails:** use template T2 in `prompts/00_templates.md` with the exact error.
