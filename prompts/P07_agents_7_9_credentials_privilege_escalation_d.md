# P07: Agents 7–9: Credentials, Privilege Escalation, Defense Evasion (MUST)

> **Before pasting:** open a NEW Antigravity chat and paste T1 from `00_TEMPLATES.md` first. Then paste only the text block below. Run the CHECK yourself.

```text
Read context.md Sections 7, 12, 13 and PRD §12 (Agents 7, 8, 9), §13.2–13.4. Phase P7.
DO:
1. app/v3/agents/a07_credentials.py (Agent 7, warm): D-CRD-01..05 per PRD §13.2. D-CRD-04: for role sessions whose
   session issuer is an EC2 instance role (userIdentity type AssumedRole with issuer role used by ec2.amazonaws.com
   or session name pattern i-xxxxxxxx), flag use from a non-AWS IP (not in hosting ASN list for AWS 16509/14618)
   or with a vpc_endpoint_id not in the identity's expected set learned from its first 20 events (or from
   app/v3/data/expected_vpce.yaml if present).
2. app/v3/data/privesc_paths.yaml: paths PE-01..PE-08 from PRD §13.4 as ordered step predicates (action names,
   optional parameter conditions like policy_arn contains AdministratorAccess or wildcard action, target user ≠
   caller), severity, MITRE list, max gap hours.
3. app/v3/agents/a08_privesc.py (Agent 8, warm): loads the YAML; keeps partial matches per identity for up to
   PRIVESC_MAX_STEP_GAP_HOURS between consecutive steps (persist in agent_state_v3 so restarts keep them);
   emits D-PE-0N with strength = (steps matched / path length) × severity once at least 2 steps match, upgraded
   when more steps match (same signal_id updated, not duplicated); evidence = every matched step's event id; stage
   per step. PE-08 full chain combines discovery burst (List*/Get*/Describe* across ≥ 5 services in 30 min) +
   any PE-01..07 + secrets/data access.
4. app/v3/agents/a09_evasion.py (Agent 9, hot): D-DEF-01..07 per PRD §13.3; boost strength +0.1 (cap 1) if the same
   identity has any signal from agents 5–7 in the last 24 h (read from a shared recent-signal index kept in the
   store); PutEventSelectors only counts if management events are being excluded (inspect request parameters).
5. Tests tests/v3/test_agents_detect_7_9.py: each detection positive/negative; PE-02 two-step match; slow chain
   with steps 2 days apart still matches (gap < 168 h) and a 9-day gap does not; signal upgraded not duplicated;
   D-CRD-04 with foreign VPC endpoint; D-DEF-01 StopLogging; PutEventSelectors negative case; mass delete threshold.
FILES: app/v3/agents/a07_credentials.py, app/v3/agents/a08_privesc.py, app/v3/agents/a09_evasion.py,
app/v3/data/privesc_paths.yaml, app/v3/data/expected_vpce.yaml (optional, empty), tests/v3/test_agents_detect_7_9.py
```

**CHECK**
```bash
pytest -q tests/v3
ruff check app/v3 tests/v3
```

---
**After the CHECK passes:** paste template T5 (in `00_TEMPLATES.md`), then commit: `git add -A && git commit -m "v3 P07: Agents 7–9: Credentials, Privilege Escalation, Defense Evasion"`. Next file: `P08_agents_10_11_behavioral_ml_campaign.md`.
