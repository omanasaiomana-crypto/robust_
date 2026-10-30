# P01: Contracts and config (MUST)

> **Before pasting:** open a NEW Antigravity chat and paste T1 from `00_TEMPLATES.md` first. Then paste only the text block below. Run the CHECK yourself.

```text
Read context.md Sections 2, 7, 8, 9, 12, 13. Phase P1: contracts and configuration.
DO:
1. Create app/v3/models.py exactly as context.md Section 8: all enums as str Enums, all models Pydantic v2 with
   ConfigDict(frozen=True, extra="forbid"). Add validators: strength/confidence/resolution_confidence in [0,1];
   score in [0,100]; Signal.evidence_event_ids min length 1; privilege_level and resource_sensitivity in 1..5;
   IngestEnvelope.events length 1..500. Add helper band_for(score) -> Band using config thresholds.
   Message.payload is a discriminated union over the payload models with a "kind" literal field on each payload
   model (add kind: Literal[...] to each payload model).
2. Create app/v3/config.py with every default in context.md Section 12 as typed module constants, plus
   load_env() that reads .env variables (INGEST_KEYS parsed into dict key_id->secret, ANALYST_TOKEN, ENRICH_PROVIDERS
   list, LLM settings, email settings) without printing them. Provide get_settings() returning a frozen dataclass.
   Secrets are never included in repr (custom __repr__ masks them).
3. Create app/v3/catalog.py: a table mapping (source, action) to (event_class, action_type, stage_hint, mitre list,
   read_only default). Cover at least: Okta user.session.start, user.authentication.sso, user.authentication.auth_via_mfa,
   user.authentication.verify, user.mfa.okta_verify.deny_push, system.push.send_factor_verify_push,
   user.account.lock, user.session.end, policy.evaluate_sign_on; CloudTrail ConsoleLogin, AssumeRole,
   AssumeRoleWithSAML, GetSessionToken, CreateAccessKey, DeleteAccessKey, UpdateAccessKey, CreateUser,
   CreateLoginProfile, UpdateLoginProfile, AttachUserPolicy, AttachRolePolicy, PutUserPolicy, PutRolePolicy,
   CreatePolicyVersion, SetDefaultPolicyVersion, AddUserToGroup, UpdateAssumeRolePolicy, PassRole (as part of
   CreateFunction), CreateFunction, UpdateFunctionCode, Invoke, ListUsers, ListRoles, ListBuckets, ListPolicies,
   GetAccountAuthorizationDetails, DescribeInstances, GetSecretValue, ListSecrets, GetObject, PutObject,
   DeleteObject, PutBucketPolicy, PutBucketAcl, DeletePublicAccessBlock, StopLogging, DeleteTrail, UpdateTrail,
   PutEventSelectors, DeleteDetector, UpdateDetector, DisassociateMembers, DeleteFlowLogs, ScheduleKeyDeletion,
   DisableKey, Decrypt. Unknown actions: lookup returns a default with uncatalogued=True.
   Use MITRE IDs from PRD §13.
4. Tests tests/v3/test_models.py and tests/v3/test_catalog.py: valid/invalid construction for every model,
   frozen behavior, band_for edges (39.99, 40, 69.99, 70, 89.99, 90), catalog lookups and unknown default,
   settings repr never contains a secret value.
FILES: app/v3/models.py, app/v3/config.py, app/v3/catalog.py, tests/v3/test_models.py, tests/v3/test_catalog.py
```

**CHECK**
```bash
pytest -q tests/v3
ruff check app/v3 tests/v3
```

---
**After the CHECK passes:** paste template T5 (in `00_TEMPLATES.md`), then commit: `git add -A && git commit -m "v3 P01: Contracts and config"`. Next file: `P02_event_bus_agent_base_supervisor.md`.
