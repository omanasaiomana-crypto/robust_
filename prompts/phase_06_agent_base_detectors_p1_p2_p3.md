# PHASE 6: Agent base + detectors P1, P2, P3 (≈25 min) · Person B

```text
Read context.md fully. Then read docs/TECH_PRD.md Sections 11.1, 11.2, 11.3.

GOAL: The first three detection agents.

DO:
1. app/agents/base.py: copy EXACTLY the Agent class in TECH_PRD 11.1.
2. app/agents/impossible_travel.py: class ImpossibleTravelAgent(Agent), name "impossible_travel",
   pattern P1, logic and severity per TECH_PRD 11.2, MITRE ["T1078"].
   Use only auth events with outcome success and non-null lat/lon. Ignore pairs where hours < 0.
3. app/agents/dormant.py: class DormantAccountAgent(Agent), name "dormant", P2, MITRE ["T1078.004"].
4. app/agents/priv_escalation.py: class PrivEscalationAgent(Agent), name "priv_escalation", P3,
   MITRE ["T1098","T1548"]. Use STATE_OF_ACTION and ESCALATION_ORDER from TECH_PRD 11.3 (define them
   in this file). A chain = ordered escalation states for one identity within
   config.ESCALATION_WINDOW_HOURS; emit when >= 2 distinct escalation states (Recon alone does not count).
   Store chains in self.last_chains: dict[str, list[ChainStep]] keyed by session_id.
Every Signal must have: a clear human-readable reason sentence with numbers
(e.g. "Login from Frankfurt, 7,400 km from Bengaluru, 30 min after previous login (14,800 km/h)."),
evidence_event_ids (non-empty), timestamp of the latest evidence event.

FILES: the 4 agent files above.

CHECK: scratch script that runs the Phase 5 steps then each agent, printing signal counts per agent
and one example reason each.
Expected: P1 fires for anita.rao, P2 for svc-report, P3 for svc-report with a chain of ≥ 3 steps.
Then update context.md Section 12: Phase 6 = ☑.
```

---

**After the CHECK passes:** `git add . && git commit -m "phase 6 ok"`, then open the next file.
**If the CHECK fails:** use template T2 in `prompts/00_templates.md` with the exact error.
