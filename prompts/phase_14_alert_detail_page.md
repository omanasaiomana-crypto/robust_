# PHASE 14: Alert detail page (≈30 min) · Person D

```text
Read context.md fully, especially Section 10.4 (Alert detail layout).

GOAL: The investigation page judges will look at most. It must be clear, beautiful and fast.

DO: static/js/alert.js
- Read id from ?id=. Missing id → emptyState with link back to alerts.
- Load /alerts/{id} and /alerts/{id}/events.
- Header card: riskRing (size 96), band badge, identity (large), session (mono), first seen → last seen,
  confidence as "Confidence 90%", blast radius, MITRE chips. Right side buttons:
  "Apply recommended" (primary; label shows the action, e.g. "Restrict access"),
  "Approve revoke" (danger; only when band is revoke; uses confirmModal first),
  "Dismiss" (secondary). After POST /action: toast with result.detail and refresh.
  Disable buttons when action_status is "applied".
- Left column:
  - "Why this was flagged": numbered reasons list.
  - "Score without each signal": small table (Signal removed | Risk | Change), change shown as
    "−42" in ok color; sorted by biggest change.
  - "Attack chain": vertical stepper; each step shows state name, action (mono), time;
    connector line between steps; last step highlighted.
  - "Predicted next step": callout with brand2 left border: "Next likely: Impact (71%)" and a one-line
    explanation of the state.
- Right column:
  - "Evidence": table of events (time, source badge CloudTrail/Okta, action mono, IP, location),
    event IDs in mono; highlight rows whose event_id is in evidence_event_ids.
  - "Analyst feedback": two buttons "True positive" / "False positive"; POST /feedback; toast
    "Feedback saved. Risk updated to 88."; show current feedback state.
  - Quick links: "Open identity graph" → graph.html?identity=, "Replay timeline" → timeline.html?session=.
- Two-column grid on large screens, single column on mobile.

FILES: static/js/alert.js (and alert.html only if a script tag must be added).

CHECK: alert.html?mock=1 looks complete; then live: open the svc-report alert, approve revoke
(confirm modal appears, status becomes applied, toast shown), submit feedback (risk updates).
Then update context.md Section 12: Phase 14 = ☑.
```

---

**After the CHECK passes:** `git add . && git commit -m "phase 14 ok"`, then open the next file.
**If the CHECK fails:** use template T2 in `prompts/00_templates.md` with the exact error.
