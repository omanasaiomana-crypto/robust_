# P04: Agents 1–2: Collector, Normalizer + Identity Resolver (MUST)

> **Before pasting:** open a NEW Antigravity chat and paste T1 from `00_TEMPLATES.md` first. Then paste only the text block below. Run the CHECK yourself.

```text
Read context.md Sections 5, 7, 8, 13 and PRD §8, §12 (Agents 1, 2). Phase P4.
DO:
1. app/v3/agents/a01_collector.py (Agent 1, hot): subscribes raw.okta, raw.cloudtrail; dedupe by source event id
   (exact set of last 100k ids + time-based expiry 24 h); watermark reordering: buffer events up to
   WATERMARK_SECONDS by event time and release in time order on each message or tick (in drain mode, flush all on
   tick); late events flagged late=True; publish minimal Event to `events` (event_id, time, source, action, raw_ref,
   raw dict in attrs["_raw"] for the normalizer). Malformed → deadletter with reason.
2. app/v3/agents/a02_normalizer.py (Agent 2, hot): subscribes events; maps Okta and CloudTrail fields to the Event
   model per PRD §8.1/8.2 (attrs: access_key_id, vpc_endpoint_id, external_session_id, policy_arn, role_arn,
   target_user, mfa_result, okta_session_id, session_issuer_arn, source_identity, error_code); uses catalog.py for
   event_class/action_type/read_only; identity resolution rules IR-1..IR-6 (PRD §8.3): maintain alias map,
   key lineage (CreateAccessKey response key → owner + creator), assumed-role credentials → parent identity,
   SAML role session name/email → Okta identity; resolution_confidence 1.0 for direct, 0.9 for SAML link,
   0.8 for key lineage, 0.5 unresolved. Removes attrs["_raw"] before publishing `events.normalized`.
   Persists identities_v3 and identity_aliases_v3 through the store in batches.
3. Pure helper functions in the same files (parse_okta(raw) -> dict, parse_cloudtrail(raw) -> dict,
   resolve_identity(fields, state) -> (identity_id, confidence)) so they are unit-testable.
4. Register both agents with the Supervisor (add a function register_all(supervisor, bus) in
   app/v3/agents/__init__.py that imports and registers every agent module that exists; missing ones are skipped).
5. Fixtures tests/v3/fixtures/okta_sample.json and cloudtrail_sample.json (10–20 realistic events including a SAML
   federated session for alice@example.com → AssumeRoleWithSAML → CreateAccessKey → calls with the new key).
6. Tests tests/v3/test_agents_data_1_2.py: dedupe, watermark order, late flag, field mapping for both sources,
   uncatalogued flag, identity resolution across Okta → SAML role → new key (all resolve to alice with expected
   confidences), malformed → deadletter.
FILES: app/v3/agents/a01_collector.py, app/v3/agents/a02_normalizer.py, app/v3/agents/__init__.py,
tests/v3/fixtures/*.json, tests/v3/test_agents_data_1_2.py
```

**CHECK**
```bash
pytest -q tests/v3
ruff check app/v3 tests/v3
```

---
**After the CHECK passes:** paste template T5 (in `00_TEMPLATES.md`), then commit: `git add -A && git commit -m "v3 P04: Agents 1–2: Collector, Normalizer + Identity Resolver"`. Next file: `P05_agents_3_4_context_threat_intel_correlation_g.md`.
