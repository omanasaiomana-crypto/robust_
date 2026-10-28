# PHASE 7: Detectors P4, P5 (≈20 min) · Person B

```text
Read context.md fully. Then read docs/TECH_PRD.md Section 11.2.

GOAL: The remaining two rule agents.

DO:
1. app/agents/api_anomaly.py: class ApiAnomalyAgent(Agent), name "api_anomaly", P4,
   MITRE ["T1526","T1562"]. Identity rarity = 1 − count(identity, action)/count(identity).
   Peer rarity: if app.ml.peers is not available yet, treat peer rarity as 1.0 (wrap import in
   try/except ImportError). Flag new region for identity (region never seen in that identity's
   earlier events) and actions in config.SENSITIVE_ACTIONS. Only consider identities with >= 5 events
   for rarity (otherwise only sensitive-action and new-region rules apply).
   Severity: 0.5 base, +0.3 sensitive, +0.2 new region, capped at 1.0.
2. app/agents/token_abuse.py: class TokenAbuseAgent(Agent), name "token_abuse", P5,
   MITRE ["T1550","T1539"]. Rules: same token_id from a different IP than its first use;
   user_agent change within a session; token or session used after an Okta "user.session.end"
   event for that identity's session; same token from 2 different IPs within 5 minutes.
   Severity 0.6, or 0.9 for after-logout and concurrent use.

FILES: app/agents/api_anomaly.py, app/agents/token_abuse.py

CHECK: scratch script running both agents on sample data.
Expected: P4 fires for dev.kumar StopLogging; P5 fires for meera.n; normal users produce
at most a handful of P4/P5 signals.
Then update context.md Section 12: Phase 7 = ☑.
```

---

**After the CHECK passes:** `git add . && git commit -m "phase 7 ok"`, then open the next file.
**If the CHECK fails:** use template T2 in `prompts/00_templates.md` with the exact error.
