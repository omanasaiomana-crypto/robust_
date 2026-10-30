# P06: Agents 5–6: Access Anomaly, Session + Token Integrity (MUST)

> **Before pasting:** open a NEW Antigravity chat and paste T1 from `00_TEMPLATES.md` first. Then paste only the text block below. Run the CHECK yourself.

```text
Read context.md Sections 7, 12, 13 and PRD §12 (Agents 5, 6), §13.1. Phase P6.
DO:
1. app/v3/agents/a05_access.py (Agent 5, hot): per-identity login history (last 30 successful logins: lat/lon, asn,
   device, hour). Detections D-ACC-01..04 exactly as PRD §13.1. Strength scaling:
   D-ACC-01 strength = min(1, 0.7 * (speed / MAX_SPEED_KMH)); D-ACC-02 0.4 (0.5 if both device and ASN new);
   D-ACC-03 0.25 scaled by distance outside percentile window; D-ACC-04 0.5 only for privilege_level ≥ 4.
   Cold start (< MIN_HISTORY_LOGINS): use peer-group history if available, confidence × 0.6.
   Trusted IPs never produce D-ACC-02/04.
2. app/v3/agents/a06_session.py (Agent 6, hot): per-session fingerprint (first ip, asn, ua family, device);
   D-SES-01 token replay when the same session (or credentials derived from it) appears from a new ASN without a new
   authentication event (strength 0.8; IP change within same ASN = 0.3); D-SES-02 MFA fatigue (≥ MFA_FATIGUE_DENIES
   denied pushes within MFA_WINDOW_MINUTES followed by an accept → 0.85; evidence = all deny events + accept);
   D-SES-03 UA family + device change mid-session, strength capped 0.2 (UA is weak, context.md rule);
   D-SES-04 privileged (≥4) session with no MFA event → 0.5.
3. Detection logic as pure functions (inputs: lists of dicts / small dataclasses; outputs: list of candidate signals)
   and the Agent classes only manage state and convert to Signal messages with evidence ids, MITRE, stage.
4. Tests tests/v3/test_agents_detect_5_6.py: each detection positive and negative case including edge thresholds
   (4 denies + accept = no signal; 5 = signal), trusted IP suppression, cold-start confidence, UA-only change never
   > 0.2, evidence ids exist in input.
FILES: app/v3/agents/a05_access.py, app/v3/agents/a06_session.py, tests/v3/test_agents_detect_5_6.py
```

**CHECK**
```bash
pytest -q tests/v3
ruff check app/v3 tests/v3
```

---
**After the CHECK passes:** paste template T5 (in `00_TEMPLATES.md`), then commit: `git add -A && git commit -m "v3 P06: Agents 5–6: Access Anomaly, Session + Token Integrity"`. Next file: `P07_agents_7_9_credentials_privilege_escalation_d.md`.
