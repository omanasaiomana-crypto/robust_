# PHASE 31: 15-agent trace, threat audit entries, terminal scan (≈40 min) · Person A

**Why:**
1. The PRD promises **15 agents**, but nothing shows them working.
2. A scan should **show each step as it happens**, with full JSON.
3. **Every detected threat must get its own audit-log entry.**

This phase instruments the pipeline and adds the backend and a terminal scan. Phases 32–33 add the pages.

Spec: `kit_v2/08_FEATURE_AGENTS_SCAN_INPUT_GRAPH_SPEC.md` §1–§2. Needs Phase 26 done; it created `app/trace.py`, the v2.1 config block and the v2.1 runner.

## Part A: make sure the reference code is in place (≈5 min)

```text
Read context.md (Sections 2, 7, 15–20 and 21–24 if present) and kit_v2/08_FEATURE_AGENTS_SCAN_INPUT_GRAPH_SPEC.md
Sections 1 and 2.

DO:
1. If context.md has no Section 21, append everything below the horizontal line in
   kit_v2/05b_CONTEXT_V21_ADDENDUM.md to the END of context.md (do not change earlier sections).
2. Run: python tools/check_ref.py app/config.py kit_v2/reference/REF_08_config_v21_block.md --contains
   If DIFFERENT/MISSING → append the REF_08 block to the END of app/config.py.
3. Same for app/trace.py (REF_09) and app/runner.py (REF_04): if missing or DIFFERENT, replace the file with the
   reference code block exactly. (An older v2 runner is expected to be DIFFERENT; replace it.)
4. Create app/scan.py exactly from kit_v2/reference/REF_10_scan_cli.md.
5. Create tests/test_v21_trace.py exactly from kit_v2/reference/REF_12_tests_v21_trace.md.
6. Do NOT change anything else yet.
FILES: context.md, app/config.py (append only), app/trace.py, app/runner.py, app/scan.py, tests/test_v21_trace.py
```

CHECK: `pytest -q tests/test_v21_trace.py tests/test_runner.py` → all pass.

## Part B: instrument the pipeline (≈20 min)

```text
Read context.md Section 7 and kit_v2/08_FEATURE_AGENTS_SCAN_INPUT_GRAPH_SPEC.md Section 2.3 (the step table).

In app/pipeline.py, wrap each existing step in a trace step WITHOUT changing what the step computes:

    from app import trace
    with trace.step("<agent_id>", "<what it is doing>") as s:
        ...existing code of the step...
        s.output({...small JSON summary...}, "<one-line result message>")

Rules:
- Use exactly the agent ids and the output keys from the spec table (Section 2.3).
- Put the `with trace.step(...)` INSIDE each existing try block, so a failing step is recorded as "failed" by
  trace and then handled by your existing except exactly as before (trace.step re-raises).
- Detector loop: for each detector agent object, use its `name` attribute as the agent id
  (impossible_travel, dormant, priv_escalation, api_anomaly, token_abuse, baseline_ml).
  Output {"signals": len(sigs), "examples": [first 3 signals as {"identity_id", "session_id", "severity",
  "reason", "evidence_count"}]}.
- If ML training is skipped for too little data: trace.skip("baseline_ml", "Not enough sessions to train (n=<n>)").
- Outputs must be SMALL summaries (counts, a few examples, never whole DataFrames). Convert numpy numbers
  with int()/float().
- Do NOT call trace.begin_run/end_run or log_threats in the pipeline; the runner already does that.
- Do NOT change run_pipeline's signature here (Phase 34 adds input_mode).
Also, in app/api/alerts.py: wrap the body of POST /alerts/{id}/action in
`with trace.step("response", f"Analyst action {action} on {alert_id}") as s:` with s.output(result summary), and the
body of POST /alerts/{id}/feedback in `with trace.step("feedback", f"Analyst marked {alert_id} as {label}") as s:`
with s.output({"weights": new_weights}). Keep existing behavior and status codes.
FILES: app/pipeline.py, app/api/alerts.py
```

CHECK:
```bash
pytest -q
python -m app.scan --sample --json --delay 0.05
```
Expected: a full-color scan in the terminal: all 13 steps `>>` started then `OK`, red ` THREAT ` lines for the injected attacks, the JSON payload under each step, and `SCAN COMPLETE` at the end. Run it a second time: no duplicate THREAT lines, because threats are deduplicated in the audit log.

## Part C: API (≈10 min)

```text
Create app/api/scan.py with APIRouter(tags=["scan"]) and plain-def routes (clean_json on every response):
- GET /agents → {"agents": trace.agents_status(), "run": trace.run_status()}
- GET /scan/status → trace.run_status()
- GET /scan/trace?after=0&limit=500&run_id=<optional> → if run_id is empty use trace.run_status()["run_id"];
  return {"run_id": run_id, "state": <run_status state if run_id is the current run, else "done">,
          "last_seq": trace.run_status()["last_seq"], "events": trace.events(after, limit, run_id)}
  Clamp after >= 0 and limit 1..2000.
Include the router in app/main.py's include loop (before the static mount).
Also: in app/api/health.py POST /pipeline/run, accept an optional "input_mode" in the body
("only" | "merge"; anything else → 422 validation_error) and pass it to runner.start(request.app, use_sample, input_mode).
Add to tests/test_v2_api.py: GET /api/agents returns 15 agents with ids matching trace.AGENTS; after startup
GET /api/scan/trace?after=0 returns events whose first item has state "started" and agent_id "orchestrator" (or an
empty list if the ring buffer was reset); GET /api/audit contains at least one entry with action "threat_detected"
when running on sample data.
FILES: app/api/scan.py, app/main.py, app/api/health.py, tests/test_v2_api.py
```

## CHECK (human)

```bash
pytest -q
python smoke_test.py
```

Open:
- `/api/agents`: 15 agents, all `done` after startup
- `/api/scan/trace?after=0`: the full step list with JSON
- `/audit.html`: one **`threat_detected`** entry per threat, each with the JSON details, and the chain is still valid

---

**After the CHECK passes:** `git commit -m "phase 31 ok"`, then update context.md Section 24.
