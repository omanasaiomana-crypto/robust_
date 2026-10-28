# PHASE 10: Pipeline and evaluation (≈30 min) · Person A (+ C for evaluation)

```text
Read context.md fully (especially Section 7). Then read docs/TECH_PRD.md Section 14.

GOAL: One function that runs everything in order and never crashes the server.

DO:
1. app/pipeline.py:
   - @dataclass PipelineResult(events, graph, alerts, metrics, status, detail, data_mode,
     signals, step_errors: list[str], timings_ms: dict[str, float]).
   - run_pipeline(use_sample: bool | None = None) -> PipelineResult following context.md Section 7.
   - Data selection: if use_sample is True → generate sample (if missing) and use SAMPLE_DIR.
     If None → use data/raw if it contains files, else sample when USE_SAMPLE_IF_NO_DATA.
   - Each numbered step is in its own try/except; errors go to step_errors and logging.exception.
     If loading/normalizing fails, return status "failed" with empty alerts.
     If a later step fails, continue with what exists and set status "degraded".
   - Group signals by session_id; for each session with at least one rule signal or ML score >= 0.6,
     create one Alert (ids AL-0001… after sorting by risk desc). Fill chain and prediction from
     PrivEscalationAgent.last_chains and ChainModel. Fill blast_radius from graph.
   - Call store.reset_run_tables(), store.save_alerts(), audit.append for pipeline start/end and for
     each alert with risk >= 70. Then auto_apply each alert via get_simulator() and save again.
   - Also expose get_identity_rows(result) -> list[dict] for the /identities endpoint
     (identity_id, risk = max alert risk, alerts count, privilege_level, blast_radius).
2. app/evaluation.py:
   - compute_metrics(events_df, alerts, signals, skipped) -> Metrics
   - Event-level: an event is "predicted malicious" if its event_id is in any alert's
     evidence_event_ids; truth = label not in (None, "", "benign").
   - Session-level precision: alerts whose session contains at least one malicious event / all alerts.
   - Baseline: simple detector that flags failed logins and any event from an IP seen with ≥ 3 failures;
     compute its event F1 as baseline_event_f1. If official baseline output exists in data/labels,
     use it instead.
   - If no labels exist, precision/recall/F1 stay None.
   - median_latency_ms = pipeline detection time divided by number of events, × 1000.

FILES: app/pipeline.py, app/evaluation.py

CHECK:
python -c "from app import store; store.init_db(); from app.pipeline import run_pipeline; r=run_pipeline(use_sample=True); print(r.status, r.data_mode, len(r.alerts), r.step_errors); print([(a.alert_id,a.identity_id,a.risk,a.band,a.patterns) for a in r.alerts[:5]]); print(r.metrics)"
Expected: status ok, 5+ alerts; the top alerts include svc-report (revoke band), anita.rao, meera.n,
dev.kumar; metrics show F1 higher than baseline_event_f1.
Then update context.md Section 12: Phase 10 = ☑.
```

---

**After the CHECK passes:** `git add . && git commit -m "phase 10 ok"`, then open the next file.
**If the CHECK fails:** use template T2 in `prompts/00_templates.md` with the exact error.
