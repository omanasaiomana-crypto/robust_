# PHASE 13: Overview and Alerts pages (≈30 min) · Person D

```text
Read context.md fully, especially Sections 9 and 10.4. Use ui.js components only (no new styles
unless necessary, and then only Tailwind classes).

GOAL: Professional Overview dashboard and Alerts queue.

DO:
1. static/js/overview.js:
   - Load /summary, /metrics, /alerts?min_risk=70&limit=5 in parallel (Promise.allSettled);
     show skeletons first; each section independently shows errorState on failure.
   - 4 stat cards: Total alerts, Critical (revoke band) in crit color, Identities at risk (risk >= 40),
     Detection F1 vs baseline (e.g. "0.91" with note "Baseline 0.42"; show "—" if null).
   - "Alerts by attack pattern" horizontal bar chart (Chart.js): dark theme (grid color #1F2A3C,
     tick color #8A97AD), bars in brand color, labels with pattern names.
   - "Risk distribution" doughnut by band with band colors from context 10.1, cutout 70%,
     legend at bottom.
   - "Top risky identities" table: identity (link to graph.html?identity=), risk bar + number,
     alerts, blast radius.
   - "Latest critical alerts" list: riskRing small, identity, patterns chips, time, link to alert.
   - Destroy existing Chart instances before re-creating them.
2. static/js/alerts.js:
   - Filter bar: search box (identity contains), band select, pattern select, min-risk range slider
     with live value; filters update the URL query (history.replaceState) and re-fetch /alerts.
   - Table columns: Risk (number + riskBar), Band, Identity, Session (mono, truncated with title),
     Patterns, MITRE, Recommended, Status, Last seen. Sorted by risk desc. Rows clickable and keyboard
     accessible (tabindex=0, Enter) → alert.html?id=<id> (keep ?mock=1 if present).
   - Count summary above table: "37 alerts · 6 critical".
   - Empty state "No alerts match these filters" with a "Clear filters" button.

FILES: static/js/overview.js, static/js/alerts.js (and index.html/alerts.html only if a script tag
must be added).

CHECK: index.html?mock=1 and alerts.html?mock=1 look complete and polished; filters work;
then same pages without ?mock=1 against the live server show real data with no console errors.
Then update context.md Section 12: Phase 13 = ☑.
```

---

**After the CHECK passes:** `git add . && git commit -m "phase 13 ok"`, then open the next file.
**If the CHECK fails:** use template T2 in `prompts/00_templates.md` with the exact error.
