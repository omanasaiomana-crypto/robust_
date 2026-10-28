# PHASE 21: Official data, baseline comparison, export, latency (≈60 min) · Persons A + B

**Why:** judges score on the official hidden dataset (event P/R/F1, session alert precision, latency under the published load profile). This is the highest-impact phase in v2. Send the parts **one at a time**.

## Before you start (human)

1. Put the official files in place:
   - CloudTrail → `data/raw/cloudtrail/`
   - Okta → `data/raw/okta/`
   - identity/privilege metadata → `data/metadata/`
   - labeled samples and the **official baseline detector output** → `data/labels/`
   - any organizer docs (schema, load profile, submission format) → `docs/official/`
2. Commit nothing from `data/raw` if the organizers say the data is confidential (add it to `.gitignore`).

---

## Part A: data recon (report only, ≈10 min)

```text
Read context.md Sections 5, 7 and 15–16. Then read every file in docs/official/ (if any).

Write scratch_recon.py (do not commit) that, WITHOUT using app/ingest, prints for each file in
data/raw/cloudtrail, data/raw/okta, data/metadata and data/labels:
- file name, size, detected format (Records JSON / JSON array / JSONL / gz / CSV)
- record count
- the union of top-level keys and the nested keys we map in docs/TECH_PRD.md Sections 9.3 and 9.4
  (e.g. userIdentity.*, client.geographicalContext.*, authenticationContext.externalSessionId)
- for labels: column names, distinct label values with counts, and how events/sessions are identified
- for the baseline output: columns and what it predicts (event-level? session-level? score or 0/1?)
Run it and give me a table:  Our mapped field | Present in official data? | Actual key path | Notes
Also list: label values vs our scenario names, and whether the labels key on event_id, session or identity.
Do NOT change any project file.
```

Review the table with your team and decide on mapping fixes.

## Part B: minimal mapping fixes (≈15 min)

```text
Read context.md Sections 2 and 16.
Using the recon table, fix ONLY the field mappings in app/ingest/normalize.py and app/ingest/loaders.py
(and app/ingest/enrich.py if metadata fields differ) so the official data normalizes correctly:
- add the actual key paths as FALLBACKS with dig() (keep the existing paths first, so the sample data still works)
- map official label values to the Event.label field unchanged (do not rename them)
- if labels live in a separate file keyed by event_id, attach them in normalize_all via load_labels()
Do not change models.py. Do not change any detector.
Add one test to tests/test_normalize.py: a minimal record copied from the official data shape
(redact real IPs/emails) normalizes to a valid Event.
FILES: app/ingest/normalize.py, app/ingest/loaders.py, app/ingest/enrich.py (only if needed),
tests/test_normalize.py
```

CHECK:
```bash
pytest -q
python -c "from app import store; store.init_db(); from app.pipeline import run_pipeline; r=run_pipeline(use_sample=False); print(r.status, r.data_mode, len(r.events), r.metrics.skipped_records, len(r.alerts), r.step_errors)"
```
Expected: `ok official <thousands> <under 1% of records> <alerts> []`.

## Part C: official baseline + evaluation fixes (≈15 min)

```text
Read context.md Sections 7, 15–17 and kit_v2/01_AUDIT_REVIEW.md Section 4.

In app/evaluation.py:
1. If an official baseline output exists in data/labels/ (identify it from the recon), compute
   baseline metrics from IT (event-level F1, and session-level precision if possible) instead of the
   toy failed-login baseline. Keep the toy baseline only as a fallback when no official file exists.
   Record which baseline was used in the log and in a new module-level variable BASELINE_SOURCE
   ("official" or "fallback").
2. Keep the metric definitions in context.md exactly: event-level from evidence_event_ids;
   session precision scored separately.
Do NOT tune any threshold in this step.

Then write scratch_sweep.py (do not commit) that runs the pipeline on the official LABELED data for
SESSION_LINK_WINDOW_HOURS in [0.25, 1, 4, 12] and prints event P/R/F1, session precision and alert
count for each (monkeypatch app.config values in-process; do not edit config.py for the sweep).
FILES: app/evaluation.py
```

**Decision (human):** pick the session window with the best session precision without losing event F1, and set that value in `app/config.py`. Tune other thresholds the same way **only on labeled samples**, never on hidden data. Write the final metrics table into `docs/official/RESULTS.md` (ours vs official baseline). These numbers go on your slides.

## Part D: predictions export (≈10 min)

```text
Read context.md Sections 2, 5 and 16.
1. Append to the END of app/config.py:  EXPORT_MIN_RISK = BAND_STEP_UP  and  OUTPUT_DIR = DATA_DIR / "output"
2. Create app/export.py with main() using argparse:  python -m app.export [--out DIR] [--sample]
   It runs run_pipeline() (official data unless --sample), then writes to OUTPUT_DIR (or --out):
   - event_predictions.csv: event_id, session_id, identity_id, predicted (1 if the event_id is in the
     evidence_event_ids of an alert with risk >= EXPORT_MIN_RISK, else 0), risk (max risk of such alerts,
     else 0), patterns (pipe-joined), alert_id. One row for EVERY event, not only flagged ones.
   - session_predictions.csv: session_id, identity_id, predicted, risk, band, patterns, alert_id.
     One row per session that appears in the events.
   - alerts.jsonl: one Alert per line via model_dump_json().
   - summary.json: counts, data_mode, metrics (clean_json), baseline source, generated_at.
   Use csv module, encoding utf-8, newline="". Never raise on one bad row; log and skip it.
   If docs/official/ specifies a submission format, ALSO write that exact format (file name and
   columns as specified) and say which file it is.
3. Add tests/test_export.py: run export on sample data into a tmp_path; assert both CSVs exist, the event
   CSV row count equals the number of events, and every predicted value is 0 or 1.
FILES: app/config.py (append only), app/export.py, tests/test_export.py
```

CHECK: `pytest -q tests/test_export.py` and `python -m app.export` → files in `data/output/`.

## Part E: latency replay under load (≈10 min)

```text
Read context.md Sections 7 and 15–16, and any load profile in docs/official/.
Create app/replay.py:  python -m app.replay [--batch 500] [--sample]
- Load and normalize the data once (reuse pipeline/ingest functions; do not duplicate logic).
- Sort events by timestamp. Process them in consecutive batches of --batch events (or the batch size /
  rate from the official load profile if one exists). For batch k, run the detection + scoring steps on
  all events up to the end of batch k (prefix), measure the wall time of that step, and set the latency of
  every event in batch k = that wall time (time until its alert would be available).
- Report: events, batches, throughput (events/s), latency p50, p95 and max in ms, written to
  OUTPUT_DIR / "latency.json" and logged.
- If the full prefix approach takes more than 3 minutes, use --max-batches to stop early and say so in the
  output ("sampled": true).
Then update app/evaluation.py: if OUTPUT_DIR/latency.json exists, set Metrics.median_latency_ms from its p50;
otherwise keep the current value and log that it is an estimate.
Refactor ONLY if needed: if run_pipeline cannot run detection on a given DataFrame, add a small function
detect_and_score(events_df) in app/pipeline.py that run_pipeline also uses (behavior unchanged).
FILES: app/replay.py, app/evaluation.py, app/pipeline.py (only the optional small refactor)
```

CHECK:
```bash
python -m app.replay --batch 500
pytest -q
python smoke_test.py
```

---

**After all parts pass:** `git commit -m "phase 21 ok"`, and put `docs/official/RESULTS.md` on a slide. Update context.md Section 20.
