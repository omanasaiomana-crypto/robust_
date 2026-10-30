# P11: Agents 14–15: Response and Feedback (MUST)

> **Before pasting:** open a NEW Antigravity chat and paste T1 from `00_TEMPLATES.md` first. Then paste only the text block below. Run the CHECK yourself.

```text
Read context.md Sections 2 (rules 1, 3), 10, 12, 16 and PRD §16, §17. Phase P11.
DO:
1. app/v3/playbooks/default.yaml with PB-01..PB-05 exactly as PRD §16.2 (fields from PRD §16.1).
2. app/v3/agents/a14_response.py (Agent 14): subscribes cases and approvals; loads and validates playbooks at start
   (invalid playbook → startup error with clear message); matches highest-priority playbook per case
   (defense-evasion PB-04 first, then by band); friction budget per identity (FRICTION_UNITS per
   FRICTION_WINDOW_HOURS; when exhausted, no step-up: action kind "monitor" with reason "friction budget exhausted,
   escalated to analyst"); creates Action records following the state machine in context.md Section 16 and PRD
   §16.4; executes non-approval actions immediately through the simulator adapter (reuse the v2 simulator module
   found in P0; idempotent by action_id; retry once on failure); revoke/quarantine → pending_approval with expiry
   APPROVAL_TIMEOUT_MINUTES (expiry checked on tick); approvals topic messages approve/reject/rollback with analyst
   name; restrict TTL expiry → rolled_back automatically; every transition → actions_v3 row, audit entry, `actions`
   message; case status updates (contained / awaiting_approval); notifier: reuse app/notify.py to send one email per
   case at band ≥ EMAIL_MIN_BAND (respect its rate limit and dedupe), escaping all values.
   Dry-run mode (config DRY_RUN, default False) records actions as "applied (dry run)" without calling the simulator.
3. app/v3/agents/a15_feedback.py (Agent 15): subscribes labels; FP → lower contributing detection weights by
   LEARNING_RATE (floors respected) and create a proposed suppression (identity + detection + asn) stored in
   config_versions_v3 as "proposed" (not active until approved via API); TP → raise weights (cap 1.0) and append the
   case chain to the next-step model training set; benign_true_positive → time-boxed suppression (24 h) active
   immediately; every change creates a new config version, audit entry and `config.updates` message; rollback to a
   version supported.
4. Tests tests/v3/test_response_feedback.py: band → playbook mapping; PB-04 overrides band; friction budget
   exhaustion; revoke pending → approve → applied; reject; expiry; rollback; restrict TTL; simulator called exactly
   once per action (idempotency); capability: Agent 13 attempting a simulator call is blocked; email sent once per
   case; FP lowers weight but not below floor; config rollback restores weights.
FILES: app/v3/playbooks/default.yaml, app/v3/agents/a14_response.py, app/v3/agents/a15_feedback.py,
app/v3/config.py (add DRY_RUN only), tests/v3/test_response_feedback.py
```

**CHECK**
```bash
pytest -q tests/v3
ruff check app/v3 tests/v3
```

---
**After the CHECK passes:** paste template T5 (in `00_TEMPLATES.md`), then commit: `git add -A && git commit -m "v3 P11: Agents 14–15: Response and Feedback"`. Next file: `P12_api_v3_sse_dataset_run_main_py_wiring.md`.
