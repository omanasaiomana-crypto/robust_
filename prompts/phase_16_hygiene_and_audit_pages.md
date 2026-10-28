# PHASE 16: Hygiene and Audit pages (≈20 min) · Person D

```text
Read context.md fully, especially Section 10.4.

GOAL: Prevention and trust pages.

DO:
1. static/js/hygiene.js: load /hygiene.
   - Card "Dormant privileged accounts": table identity, privilege dots, days idle, last activity,
     risk badge; empty state "No dormant privileged accounts".
   - Card "Paths to admin": each row = identity + path as chips joined by arrows; link to graph.
   - Small explanatory note under each card title (one sentence, text-muted).
2. static/js/audit.js: load /audit/verify and /audit.
   - Banner: valid → ok-colored card with check icon "Audit chain intact · <n> entries verified";
     invalid → crit card "Audit chain broken at entry #<seq>".
   - Table: seq, time, agent (chip), action, detail (truncate with title), hash (first 12 chars, mono).
   - "Verify again" button re-runs verify and shows a toast.

FILES: static/js/hygiene.js, static/js/audit.js

CHECK: both pages with ?mock=1 and live data, no console errors.
Then update context.md Section 12: Phase 16 = ☑.
```

---

**After the CHECK passes:** `git add . && git commit -m "phase 16 ok"`, then open the next file.
**If the CHECK fails:** use template T2 in `prompts/00_templates.md` with the exact error.
