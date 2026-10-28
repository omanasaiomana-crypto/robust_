# BUILD_PROMPTS_V2.md · all v2 + v2.1 prompts in one file

Same content as `prompts/`. Send ONE phase (or one part) per message; run its CHECK before moving on.

**Run order:** 20 → 21 → 22 → 23 → 24 → 25 → 26 → 27 → 31 → 32 → 33 → 34 → 35 → 36 → (28, 29 optional) → **30 last**.

---

## Prompt templates v2 (use any time)

### T1: Session start (every new Antigravity chat)

```text
Read context.md fully, including Sections 15–20 (v2) and 21–24 (v2.1, if present). Then read kit_v2/02_DEVELOPMENT_PLAN.md.
Summarize in 6 bullets: what IdentityShield does, the v1 golden rules, the v2 golden rules
(Section 16), the files you must never rewrite, the current progress (Sections 12 and 20),
and the next phase to do (run order is in kit_v2/02_DEVELOPMENT_PLAN.md). Do not write code yet.
```

### T2: Fix a failed CHECK

```text
Read context.md Sections 2 and 16.
The CHECK for Phase <N> failed with this exact output:
<paste the full traceback or console error>
Fix ONLY the root cause, ONLY in these files: <file list>.
Never edit files copied from kit_v2/reference/ (if the error is inside one of them, stop and tell me).
Do not refactor, rename, add dependencies, or touch other files.
Explain the root cause in one sentence, then show the change.
```

### T3: Resume after an interruption

```text
Read context.md Sections 12 and 20 and list the files that exist for the current v2 phase.
Tell me which phase is in progress, what is done, and what is missing. Do not write code until I confirm.
```

### T4: Scope guard

```text
Stop. Revert every change to files not named in the current prompt.
Follow context.md Section 2 rule 10 and Section 16.5.
```

### T5: Reference integrity check (run whenever unsure)

Run these yourself in the terminal. Each must print `MATCH`:

```bash
python tools/check_ref.py app/analytics.py kit_v2/reference/REF_02_analytics.md
python tools/check_ref.py app/notify.py kit_v2/reference/REF_03_notify.md
python tools/check_ref.py app/runner.py kit_v2/reference/REF_04_runner.md
python tools/check_ref.py app/config.py kit_v2/reference/REF_01_config_v2_block.md --contains
python tools/check_ref.py app/config.py kit_v2/reference/REF_08_config_v21_block.md --contains
python tools/check_ref.py app/trace.py kit_v2/reference/REF_09_trace.md
python tools/check_ref.py app/scan.py kit_v2/reference/REF_10_scan_cli.md
python tools/check_ref.py app/inputs.py kit_v2/reference/REF_11_inputs.md
python tools/check_ref.py static/js/jsonview.js kit_v2/reference/REF_14_jsonview_js.md
python tools/check_ref.py static/js/graphfx.js kit_v2/reference/REF_15_graphfx_js.md
python tools/check_ref.py static/js/scan.js kit_v2/reference/REF_16_scan_page_js.md
python tools/check_ref.py static/js/graph.js kit_v2/reference/REF_17_graph_page_js.md
```
(Only check files whose phase you have finished.)

If one prints `DIFFERENT`, send:

```text
<file> no longer matches kit_v2/reference/<REF file>. Restore it to exactly the code block in that
reference file. Change nothing else.
```

### T6: Slow agent / stuck more than 5 minutes

```text
Stop. Do only step <k> of the current phase prompt, then wait for me.
```

(Then send the remaining steps one at a time.)


---

## PHASE 20: Audit verification and consistency fixes (≈30 min) · Person A

**Why:** the audit has six internal inconsistencies (see `01_AUDIT_REVIEW.md` §3). This phase checks the real code, fixes hardcoded values, installs the v2 context and config, and corrects the report.

## Before you start (human, 2 min)

1. Copy the whole `kit_v2/` folder into the project root (next to `context.md`).
2. `git pull`, then `git checkout -b v2` (work on a branch so v1 stays safe).
3. Run the baseline: `pytest -q` and `python smoke_test.py`. Write down the test count; it must not go down later.

## Prompt (part A: investigate only, no code changes)

```text
Read context.md fully, then kit_v2/01_AUDIT_REVIEW.md Section 3.

Investigate and REPORT ONLY (do not change any file yet). For each item give file, line and actual value:
1. Impossible travel threshold: does app/agents/impossible_travel.py use config.IMPOSSIBLE_TRAVEL_KMH,
   or a hardcoded number (800/900)?
2. Okta↔AWS session link window in app/correlate/sessions.py: what is the actual value (15 min? 12 h?)
   and is it hardcoded?
3. Is app/ml/calibrate.py (Calibrator) used in the final risk in app/decision/scoring.py or
   app/pipeline.py? If yes, what labels does it train on?
4. How is Metrics.median_latency_ms computed in app/evaluation.py?
5. List every other hardcoded numeric threshold in app/agents/, app/correlate/, app/decision/ and
   app/pipeline.py that should come from app/config.py (ignore 0, 1, 100 and list indexes).
6. Which existing tests would break if the session link window changed?
Format: a table with columns Item | File:line | Actual | Hardcoded? | Proposed fix.
```

Read the report. If anything looks surprising, ask the agent before continuing.

## Prompt (part B: apply fixes)

```text
Read context.md Sections 2, 6 and 13, and kit_v2/05_CONTEXT_V2_ADDENDUM.md.

DO:
1. Append EVERYTHING below the horizontal line in kit_v2/05_CONTEXT_V2_ADDENDUM.md to the END of
   context.md (new Sections 15–20). Do not change Sections 1–14.
2. Append the code block from kit_v2/reference/REF_01_config_v2_block.md to the END of app/config.py,
   exactly. Do not modify existing lines.
3. Insert these constants DIRECTLY ABOVE the "# v2 additions" comment block (so the v2 block stays the
   last thing in the file):
   SESSION_LINK_WINDOW_HOURS = <current actual value in hours, so behavior does not change yet>
   plus one constant per hardcoded threshold you found in part A item 5 (keep current values).
4. Replace each hardcoded value found in part A (items 1, 2, 5) with the matching config constant.
   Behavior must not change: same values, only their source changes.
5. Create tools/check_ref.py exactly from kit_v2/reference/REF_00_check_ref_tool.md.
6. Add these lines to .gitignore if missing: .env, data/outbox/, data/output/
7. In AUDIT_REPORT.md add a section "Corrections (v2 review)" at the end, listing the corrected facts:
   real travel threshold, real session window, endpoint count (count the routes in app/api),
   "normalized" instead of "calibrated" anomaly scores, whether the calibrator is used, and how latency
   is currently computed. Do not rewrite the rest of the report.
8. Update context.md Section 20: Phase 20 = ☑.

FILES: context.md, app/config.py, app/agents/*.py and app/correlate/sessions.py and app/decision/*.py and
app/pipeline.py (constant replacement ONLY), tools/check_ref.py, .gitignore, AUDIT_REPORT.md
```

## CHECK (human)

```bash
pytest -q                      # same number of tests as before, all pass
python smoke_test.py           # SMOKE TEST PASSED
python tools/check_ref.py app/config.py kit_v2/reference/REF_01_config_v2_block.md --contains
python -c "import app.config as c; print(c.EMAIL_MODE, c.EMAIL_MIN_RISK, c.SESSION_LINK_WINDOW_HOURS, c.IMPOSSIBLE_TRAVEL_KMH)"
```

Expected: tests unchanged and green; `MATCH`; then a line like `outbox 70 <window> 900.0`.

---

**After the CHECK passes:** `git add . && git commit -m "phase 20 ok"`.
**Decision for Phase 21:** keep the current session window for now; Phase 21 tests other values on the official data.


---

## PHASE 21: Official data, baseline comparison, export, latency (≈60 min) · Persons A + B

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


---

## PHASE 22: Analytics backend (≈25 min) · Person C

**Why:** powers the new "rules vs ML" comparison and both heatmaps. The core module is pre-tested; this phase copies it and exposes three endpoints.

Spec: `kit_v2/03_FEATURE_ANALYTICS_SPEC.md` §2–§3.

## Prompt

```text
Read context.md (Sections 2, 9, 15–19), then kit_v2/03_FEATURE_ANALYTICS_SPEC.md Sections 2 and 3.

DO:
1. Create app/analytics.py by copying EXACTLY the code block in kit_v2/reference/REF_02_analytics.md.
   Do not change a single line. It imports config constants that already exist after Phase 20.
2. Create tests/test_v2_features.py by copying EXACTLY kit_v2/reference/REF_05_tests_v2_features.md.
   (It also contains notifier tests; if app/notify.py does not exist yet, ALSO create app/notify.py by
   copying EXACTLY kit_v2/reference/REF_03_notify.md so the test module imports. Do not wire the notifier
   anywhere; Phase 24 does that.)
3. Create app/api/analytics.py with an APIRouter(tags=["analytics"]) and these plain-def routes:
   - GET /analytics/detectors → analytics.detector_comparison(res.events, res.signals, res.alerts)
   - GET /analytics/heatmap/time?days=HEATMAP_DAYS (int, clamp 1..60)
       → analytics.attack_time_heatmap(res.events, res.alerts, days=days)
   - GET /analytics/heatmap/identities?top=10 (int, clamp 1..30)
       → analytics.identity_pattern_heatmap(res.signals, res.alerts, top=top)
   Use the same _result(request) pattern as the other routers (503 pipeline_not_ready when the result is
   None). If res.signals does not exist on the PipelineResult, use getattr(res, "signals", []).
   Return clean_json(...) for every response. No response_model (these are dict responses).
4. In app/main.py add the router to the existing include loop (BEFORE the static mount). Change nothing else.
5. Create tests/test_v2_api.py with tests using `with TestClient(app) as client:`:
   - the 3 endpoints return 200 (or 503 if the pipeline is not ready) and have the expected top-level keys:
     detectors → labeled, rows, matrix, agreement, winner; time → days, hours, cells, max, total, tz;
     identities → identities, patterns, cells, max
   - /api/analytics/heatmap/time?days=999 still returns 200 with len(days) <= 60
   - with sample data (labels present), detectors["labeled"] is True and the first three row ids are
     ["rules", "ml", "hybrid"]

FILES: app/analytics.py, app/notify.py (copy only, if missing), app/api/analytics.py, app/main.py (one line),
tests/test_v2_features.py, tests/test_v2_api.py
```

## CHECK (human)

```bash
python tools/check_ref.py app/analytics.py kit_v2/reference/REF_02_analytics.md
python tools/check_ref.py tests/test_v2_features.py kit_v2/reference/REF_05_tests_v2_features.md
pytest -q
python smoke_test.py
```

Then start the server and open:
- `http://127.0.0.1:8000/api/analytics/detectors`: on sample data, `winner.text` names a winner
- `http://127.0.0.1:8000/api/analytics/heatmap/time`: `total` > 0
- `http://127.0.0.1:8000/api/analytics/heatmap/identities`: `svc-report` is near the top

---

**After the CHECK passes:** `git commit -m "phase 22 ok"`, then update context.md Section 20.


---

## PHASE 23: Analytics page UI (≈45 min) · Person D

**Why:** the visual answer to "which is better, rules or ML?" and "when are we attacked?". It can be built entirely in mock mode before Phase 22 is live.

Spec: `kit_v2/03_FEATURE_ANALYTICS_SPEC.md` §4. Send the parts one at a time.

## Part A: shell, mocks and sidebar (≈10 min)

```text
Read context.md Section 10 (UI design system) and Sections 16.8–16.9, then
kit_v2/03_FEATURE_ANALYTICS_SPEC.md Section 4.

DO:
1. Create static/mock/analytics_detectors.json, analytics_heatmap_time.json and
   analytics_heatmap_identities.json by copying EXACTLY the JSON blocks in kit_v2/reference/REF_07_mock_json.md.
2. In static/js/api.js, extend the existing mock path table (GET only):
   /analytics/detectors → analytics_detectors, /analytics/heatmap/time → analytics_heatmap_time,
   /analytics/heatmap/identities → analytics_heatmap_identities.
   Query strings must be ignored when matching. Change nothing else in api.js.
3. In static/js/layout.js add a sidebar item "Analytics" (inline SVG bar-chart icon, same style as the
   others) between Identities and Hygiene, linking to analytics.html (keep ?mock=1 like the other links).
4. Create static/analytics.html using EXACTLY the same head and body structure as static/alerts.html
   (same Tailwind config, fonts, app.css), title "IdentityShield · Analytics", with the Chart.js CDN script
   BEFORE the module script /js/analytics.js.
5. Create static/js/analytics.js that only calls renderLayout("analytics", "Detection analytics",
   "Rules vs ML performance and attack activity") and shows skeletons for now.
FILES: static/mock/analytics_*.json, static/js/api.js, static/js/layout.js, static/analytics.html,
static/js/analytics.js
```

CHECK: `analytics.html?mock=1` shows the sidebar with **Analytics** active and the skeletons, with no console errors.

## Part B: comparison section (≈15 min)

```text
Read context.md Section 10 and kit_v2/03_FEATURE_ANALYTICS_SPEC.md Sections 2 and 4.1 (blocks 1–3, 8).
Implement in static/js/analytics.js (use ui.js components and esc() for every value):

Load /analytics/detectors, /analytics/heatmap/time and /analytics/heatmap/identities in parallel with
Promise.allSettled. Each block renders its own skeleton → content / emptyState / errorState independently.

Block 1 · Winner banner: full-width standard card (full border, rounded-xl) containing, on the left, a
4px-wide brand2 accent bar as its own div (flex row; do not use border-left). Check icon +
winner.text (font-medium) + muted line "Session-level comparison · {malicious_sessions} attack sessions".
If labeled is false: neutral card with the note text and an info icon.

Block 2 · Three cards in a responsive grid (1 col mobile, 3 cols lg) for rows with kind "summary"
(rules, ml, hybrid). Each card: label (text-sm text-muted), big F1 (text-4xl font-semibold tabular-nums,
"—" if null), a 4-item mini grid: Precision, Recall, Flagged, False alarms (fp); a thin recall bar
(h-1.5 rounded-full, brand2 fill). The winner card: ring-1 ring-brand2 and a small "Best" pill
(bg-brand2/15 text-brand2). Unlabeled: show only Flagged.

Block 3 · Chart.js grouped bar chart "Precision, recall and F1": labels Rules / ML / Hybrid;
datasets Precision #3B82F6, Recall #22D3EE, F1 #10B981; y min 0 max 1, ticks formatted as 0.0;
grid color #1F2A3C, tick color #8A97AD, legend bottom with #8A97AD labels, borderRadius 4,
maxBarThickness 28; maintainAspectRatio false inside a 260px-high container. Destroy any previous chart
instance before creating. Hide the card when labeled is false. Guard: if typeof Chart === "undefined",
show errorState("Chart library failed to load").

Block 8 · At the bottom: <details> "How we measure" with the definitions table from the spec Section 2,
small muted text.
FILES: static/js/analytics.js
```

CHECK: in mock mode, the banner reads "Hybrid (final alerts) performs best (F1 0.86 …)", three cards show with Hybrid marked **Best**, and the chart renders.

## Part C: heatmaps and agreement (≈20 min)

```text
Read kit_v2/03_FEATURE_ANALYTICS_SPEC.md Sections 4.1 (blocks 4–7) and 4.2 exactly.
Implement in static/js/analytics.js. Write ONE reusable function:

  heatGrid({rowLabels, colLabels, values, max, color, cellText, cellTitle, rowLabelWidth, cellHeight,
            colLabelEvery})

that returns an HTML string using a CSS grid: style="display:grid;grid-template-columns:
<rowLabelWidth> repeat(N, minmax(<min>px, 1fr));gap:2px". The first row is the column labels
(text-[11px] text-muted, centered); each next row is a row label (text-xs, truncate, title=full text)
followed by N cells. Cell style: rounded-[3px], height cellHeight, flex center, text-[11px]
tabular-nums. Zero or empty value → class bg-panel2 and no text (time heatmap) or "0/x" (matrix).
Otherwise background rgba(<color>, a) with a = 0.15 + 0.80 * value / max; text color #0B0F17 if a > 0.55,
else #E6EBF2. Every cell has a title tooltip from cellTitle. All text goes through esc().
Wrap each grid in a div with overflow-x-auto so it scrolls on mobile, never the page.

Block 4 · Card "Which detector catches which attack" (lg:col-span-2): rows = matrix rows (summary rows,
then a 1px divider row using the line color, then detectors); columns = scenarios humanized
(privilege_escalation → "Privilege escalation") + "False alarms". Recall cells: color 34,211,238,
max 1, text "caught/total", title "<row> · <scenario>: caught of total sessions (pct%)".
False alarms column: color 239,68,68, max = max false_alarms (at least 1), text = the count.
Under the grid: a legend "0% → 100% of attack sessions caught" with a small gradient bar.
If labeled is false: emptyState("Labels needed to compare detectors per attack type").

Block 5 · Card "Agreement: rules vs ML" (next to block 4 on lg): a 100%-wide stacked bar of 4 div segments
(rules_only #3B82F6, both #22D3EE, ml_only #A78BFA, missed_by_both #EF4444 at 70% opacity), widths
proportional to counts (skip zero segments), with a legend listing count per segment. Below, one sentence
generated from the numbers, e.g. "ML caught 1 attack session that rules missed; rules caught 3 that ML
missed; 1 attack was missed by both." Use *_true counts when labeled, raw counts otherwise
(and then say "sessions flagged" instead of "attack sessions").

Block 6 · Card "When are we attacked" (full width): subtitle "Events cited as evidence in alerts ·
last {days.length} days · {tz}", total on the right (text-2xl). Rows = days formatted "Tue 27 Oct"
(parse YYYY-MM-DD as a local date, NOT UTC); columns = hours "00".."23", colLabelEvery = 3 when
window.innerWidth < 640 else 1; cellHeight 18px; color 34,211,238; max = data.max; text = count when > 0;
title "Tue 27 Oct, 09:00–10:00: 3 attack events". Below: legend gradient "0 → {max}".
Empty → emptyState("No attack activity in this period").

Block 7 · Card "Identities × detectors" (full width): rows = identities with a small risk number after
the name; columns = pattern codes with title = pattern_names; color 249,115,22 (high orange); max = data.max.
Clicking a row label navigates to graph.html?identity=<id> (keep ?mock=1). Empty → emptyState("No alerts yet").

Layout: blocks 1–3 at top; then a grid lg:grid-cols-3 gap-6 with block 4 (col-span-2) and block 5;
then blocks 6 and 7 stacked; then block 8.
FILES: static/js/analytics.js
```

CHECK (human):
- `analytics.html?mock=1`: all blocks render; the heatmap cells show numbers; hover tooltips work; no horizontal page scroll at 375 px (DevTools); no console errors.
- Without `?mock=1` (backend from Phase 22 running): real data renders.

## Part D: Overview tie-in (≈5 min)

```text
In static/js/overview.js add a compact card "Rules vs ML" after the stat cards: load /analytics/detectors
(inside the existing Promise.allSettled), show winner.text and the three F1 values as small stat items,
plus a link "Open analytics →" to analytics.html (keep ?mock=1). Hide the card when labeled is false or
the request fails. Change nothing else on the page.
FILES: static/js/overview.js
```

---

**After the CHECKs pass:** `git commit -m "phase 23 ok"`, then update context.md Section 20.


---

## PHASE 24: Email notifier backend (≈30 min) · Person A

**Why:** the admin gets a short email summary when suspicious activity is detected. The notifier is pre-tested; this phase copies it, wires it and exposes 4 endpoints.

Spec: `kit_v2/04_FEATURE_EMAIL_ALERTS_SPEC.md`.

## Prompt

```text
Read context.md (Sections 2, 9, 15–19), then kit_v2/04_FEATURE_EMAIL_ALERTS_SPEC.md fully.

DO:
1. If app/notify.py does not exist, create it by copying EXACTLY kit_v2/reference/REF_03_notify.md.
   If it exists (copied in Phase 22), do not touch it.
2. Create .env.example at the project root with EXACTLY the dotenv block in the spec Section 5.
   Do NOT create .env (the team does that by hand). Ensure .gitignore contains .env and data/outbox/.
3. Create app/api/notifications.py with APIRouter(tags=["notifications"]) and plain-def routes:
   - GET  /notifications?limit=50 (clamp 1..500) → notify.list_notifications(limit)
   - GET  /notifications/status → notify.status()
   - POST /notifications/test → rec = notify.send_test(); return rec, or
         {"status": "off", "detail": "EMAIL_MODE=off"} if rec is None
   - POST /alerts/{alert_id}/notify → find the alert in app.state.result.alerts (503 if no result,
         404 not_found if missing) → rec = notify.notify_alert(alert); same None handling as above
   Every response passes through clean_json(). Never return SMTP_PASSWORD or SMTP_USER.
4. Wire the notifier in app/main.py WITHOUT changing other behavior:
   - in lifespan: call notify.init_tables() right after store.init_db()
   - after the startup pipeline succeeds (app.state.result is set and status != "failed"):
       notify.notify_new_alerts(app.state.result.alerts, total_open=len(app.state.result.alerts))
   - include the notifications router in the existing include loop (BEFORE the static mount)
5. In the existing POST /pipeline/run handler (app/api/health.py), after a successful re-run, call the
   same notify.notify_new_alerts(...) line. (Phase 26 later moves both calls into app/runner.py.)
6. Add to tests/test_v2_api.py:
   - GET /api/notifications/status → 200 and has keys mode, recipients, min_risk; the JSON text contains
     no "password" (case-insensitive)
   - POST /api/notifications/test → 200 and status in {"outbox","sent","failed","rate_limited","off"}
   - POST /api/alerts/DOES-NOT-EXIST/notify → 404 with error "not_found" (or 503 if the pipeline is not ready)
   - after startup with sample data, GET /api/notifications eventually contains a "digest" record
     (the digest runs in a background thread: poll up to 3 seconds with time.sleep(0.1))

FILES: app/notify.py (copy only if missing), .env.example, .gitignore, app/api/notifications.py,
app/main.py, app/api/health.py, tests/test_v2_api.py
```

## CHECK (human)

```bash
python tools/check_ref.py app/notify.py kit_v2/reference/REF_03_notify.md
pytest -q
python smoke_test.py
```

Then run the server and check:
1. `data/outbox/` contains one `.eml` and one `.txt` file. Open the `.txt`: it should be a readable summary of the top alerts.
2. Restart the server. **No new digest** should appear (dedupe works).
3. `curl -X POST http://127.0.0.1:8000/api/notifications/test` returns status `outbox`.

**Optional real email:** copy `.env.example` to `.env`, set `EMAIL_MODE=smtp` plus the Gmail settings (spec §5.1), restart, and run the test endpoint again. A status of `sent` means the email went out; `failed` with a timeout means the network blocks SMTP, and the outbox still has the copy.

---

**After the CHECK passes:** `git commit -m "phase 24 ok"` (make sure `.env` is NOT committed: `git status` must not list it). Update context.md Section 20.


---

## PHASE 25: Notifications page + "Email admin" button (≈35 min) · Person D

Spec: `kit_v2/04_FEATURE_EMAIL_ALERTS_SPEC.md` §7. Can be built in mock mode before Phase 24 is live.

## Part A: page, mocks, sidebar (≈20 min)

```text
Read context.md Section 10 and Sections 16.7–16.8, then kit_v2/04_FEATURE_EMAIL_ALERTS_SPEC.md Section 7.

DO:
1. Create static/mock/notifications.json and static/mock/notifications_status.json by copying EXACTLY the
   blocks in kit_v2/reference/REF_07_mock_json.md.
2. static/js/api.js: extend the mock table (GET): /notifications → notifications,
   /notifications/status → notifications_status. Order matters: match /notifications/status before
   /notifications. Change nothing else.
3. static/js/layout.js: add a sidebar item "Notifications" (inline SVG envelope icon) after Audit.
4. static/notifications.html: same head/body structure as static/audit.html, title
   "IdentityShield · Notifications", module script /js/notifications.js.
5. static/js/notifications.js: renderLayout("notifications", "Notifications",
   "Email alerts sent to the security admin"), then:

   Status card (load /notifications/status):
   - left: mode pill (outbox → "Outbox (demo)" brand2 tint; smtp → "SMTP" ok tint; off → "Off" muted),
     then a definition list: Recipients (comma list, or warn-colored "No recipients configured"),
     SMTP server (smtp_host or "—"), Threshold "Risk ≥ {min_risk}", Sent this hour "{sent_last_hour} / {max_per_hour}".
   - right: primary button "Send test email" (envelope icon). On click: disable, POST /notifications/test,
     toast by status: sent → success "Test email sent"; outbox → success "Saved to outbox (demo mode)";
     off → error "Email is turned off (EMAIL_MODE=off)"; failed/rate_limited → error with the detail text.
     Re-enable, then reload status and history.
   - footer note (text-xs text-muted): "Configure in .env (see .env.example). Outbox mode works offline."

   History card (load /notifications?limit=50): table with columns Time (fmtTime), Kind chip
   (Digest/Manual/Test), Status badge (sent ok, outbox brand2, failed crit, rate_limited warn; label text
   always shown), Subject (truncate max-w-md with title), Recipients, Alerts (links alert.html?id=, keep
   ?mock=1). Rows are buttons (keyboard accessible): clicking toggles a detail row directly under it showing
   detail (text-muted text-xs) and body_text inside <pre class="whitespace-pre-wrap font-mono text-xs
   bg-panel2 border border-line rounded-lg p-4 max-h-80 overflow-auto"> inserted via esc().
   NEVER render email HTML. Only one detail row is open at a time.
   Empty: emptyState("No emails yet. A digest is sent when an alert reaches the risk threshold.")
   Skeleton and errorState as usual.
FILES: static/mock/notifications*.json, static/js/api.js, static/js/layout.js, static/notifications.html,
static/js/notifications.js
```

CHECK: `notifications.html?mock=1` shows the status card, two history rows (the digest with an `outbox` badge, the test with `failed`); clicking a row opens the preview; works at 375 px; no console errors.

## Part B: "Email admin" on the alert page (≈10 min)

```text
In static/js/alert.js, add a secondary button "Email admin" (envelope icon, aria-label "Email the admin
about this alert") next to the existing action buttons in the header card. On click: disable it, show
"Sending…", POST /alerts/{id}/notify, then toast:
- status sent → "Email sent to {recipients}"
- status outbox → "Email saved to outbox (demo mode)"
- status off → "Email is turned off"
- failed / rate_limited → error toast with detail
Re-enable afterwards. Do not change any other behavior on the page.
FILES: static/js/alert.js
```

CHECK: on the live server, open the top alert → **Email admin** → toast → the Notifications page shows a new `Manual` record whose preview contains that alert.

---

**After the CHECKs pass:** `git commit -m "phase 25 ok"`, then update context.md Section 20.


---

## PHASE 26: Background pipeline runs (≈25 min) · Person A

**Why:** audit gap 2.2. `POST /pipeline/run` currently blocks the request. After this phase it returns `202` immediately, the UI shows "Running…", only one run can happen at a time, a failed run keeps the previous good results, and the email digest is sent after each run.

## Prompt

```text
Read context.md (Sections 2, 7, 9, 15–19) and kit_v2/02_DEVELOPMENT_PLAN.md Section 6.

DO:
1. Append the code block of kit_v2/reference/REF_08_config_v21_block.md to the END of app/config.py (exactly),
   then create app/trace.py by copying EXACTLY kit_v2/reference/REF_09_trace.md (the runner imports it),
   then create app/runner.py by copying EXACTLY kit_v2/reference/REF_04_runner.md.
2. Create tests/test_runner.py by copying EXACTLY kit_v2/reference/REF_06_tests_runner.md.
3. app/main.py lifespan: replace the direct run_pipeline call (and the notify call added in Phase 24)
   with runner.run_now(app). Keep store.init_db() and notify.init_tables() before it. Keep the defaults
   app.state.result = None and app.state.startup_error = "" BEFORE run_now.
4. app/api/health.py:
   - POST /pipeline/run: read the optional body {"use_sample": bool}; started, st = runner.start(request.app,
     use_sample); if not started → raise HTTPException(409, "A pipeline run is already in progress");
     else return JSONResponse(status_code=202, content=clean_json(st)). Remove the old synchronous run and
     the Phase-24 notify call there (the runner now does both).
   - NEW GET /pipeline/status → clean_json(runner.status())
   - GET /health: if runner.is_running() report pipeline "running" (status stays "ok" if a previous
     result exists). Keep every other field the same.
5. app/api/alerts.py: at the start of POST /alerts/{id}/action and POST /alerts/{id}/feedback, if
   runner.is_running() → raise HTTPException(409, "Pipeline is re-running; try again in a few seconds").
6. static/js/layout.js "Re-run pipeline" button: POST /pipeline/run; on 202 switch the status pill to
   "Running…" with a small spinner and disable the button; poll GET /pipeline/status every 1000 ms until state
   is "done" or "failed" (stop after 120 s with an error toast); then toast "Pipeline finished · {alerts}
   alerts · {duration_ms/1000}s" (or the error detail) and reload the page. On 409 show an info toast
   "A run is already in progress" and start polling. In mock mode just show the toast and do not poll.
7. Add static/mock/pipeline_status.json from kit_v2/reference/REF_07_mock_json.md and map
   /pipeline/status → pipeline_status in the api.js mock table.
8. tests/test_v2_api.py: add tests: POST /api/pipeline/run returns 202 or 409; GET /api/pipeline/status
   returns a "state" key; then poll status until not "running" (max 30 s) and assert GET /api/alerts is 200.

FILES: app/config.py (append), app/trace.py, app/runner.py, tests/test_runner.py, app/main.py, app/api/health.py, app/api/alerts.py,
static/js/layout.js, static/js/api.js, static/mock/pipeline_status.json, tests/test_v2_api.py
```

## CHECK (human)

```bash
python tools/check_ref.py app/runner.py kit_v2/reference/REF_04_runner.md
python tools/check_ref.py app/trace.py kit_v2/reference/REF_09_trace.md
pytest -q
python smoke_test.py
```

Live check:
1. Click **Re-run pipeline**: the pill shows "Running…", other pages stay usable, and a toast appears when the run finishes.
2. Click it twice quickly: the second click says "already in progress".
3. **Failure safety** (a failed run keeps the old results) is covered by `tests/test_runner.py::test_failed_run_keeps_previous_result`, so you don't need to break your data by hand.

---

**After the CHECK passes:** `git commit -m "phase 26 ok"`, then update context.md Section 20.


---

## PHASE 27: Offline assets: vendor the CDN files (≈15 min) · Person D

**Why:** audit gap 2.4. Venue Wi-Fi fails often. After this phase the console works with the network off.

## Step 1: download the files (human, while online)

From the project root:

**Windows PowerShell** (use `curl.exe`, not the `curl` alias):
```powershell
mkdir static\vendor
curl.exe -L -o static/vendor/tailwind.js https://cdn.tailwindcss.com
curl.exe -L -o static/vendor/chart.umd.min.js https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js
curl.exe -L -o static/vendor/vis-network.min.js https://unpkg.com/vis-network@9.1.9/standalone/umd/vis-network.min.js
```

**macOS / Linux:**
```bash
mkdir -p static/vendor
curl -L -o static/vendor/tailwind.js https://cdn.tailwindcss.com
curl -L -o static/vendor/chart.umd.min.js https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js
curl -L -o static/vendor/vis-network.min.js https://unpkg.com/vis-network@9.1.9/standalone/umd/vis-network.min.js
```

Check the sizes: each file should be well over 50 KB. A tiny file means you saved an error page; download it again.

Fonts are optional: if Google Fonts are unreachable, the pages fall back to the system font and still look clean.

## Step 2: prompt

```text
Read context.md Section 10 and 16.8.
All three vendor files now exist in static/vendor/ (tailwind.js, chart.umd.min.js, vis-network.min.js).
DO:
1. In EVERY static/*.html file, replace:
   https://cdn.tailwindcss.com → /vendor/tailwind.js
   the Chart.js CDN URL → /vendor/chart.umd.min.js
   the vis-network CDN URL → /vendor/vis-network.min.js
   Keep the script order and the inline tailwind.config script exactly as they are (the config must still
   come right AFTER the tailwind script). Keep the Google Fonts <link> tags (they fail harmlessly offline).
2. Add tests/test_vendor.py: for each of the 3 files, assert it exists and is larger than 50_000 bytes;
   with TestClient(app) GET /vendor/tailwind.js returns 200; and no static/*.html still contains
   "cdn.tailwindcss.com", "cdn.jsdelivr.net" or "unpkg.com".
3. Do NOT add static/vendor to .gitignore (the files must be committed so every laptop has them).
FILES: static/*.html, tests/test_vendor.py
```

## CHECK (human)

```bash
pytest -q
```

Then turn **Wi-Fi off**, restart the server, and click through every page. Styling, charts, the graph and the heatmaps must all work. Turn Wi-Fi back on.

---

**After the CHECK passes:** `git commit -m "phase 27 ok"`, then update context.md Section 20.


---

## PHASE 28 (optional): Analyst token for write actions (≈25 min) · Person A

**Why:** audit gap 2.5. Today anyone on the network can approve a revoke. This adds a simple, opt-in viewer/analyst split: reading stays open, and **write actions need an analyst token**. It is off by default, so the demo is unaffected unless you turn it on.

Skip this phase if you are short on time; mention it as "implemented as opt-in" only if you actually built it.

## Prompt

```text
Read context.md Sections 2, 9 and 16.7.

DO:
1. Append to the END of app/config.py:
   ANALYST_TOKEN = os.environ.get("ANALYST_TOKEN", "")      # empty = auth disabled
2. Create app/security.py:
   - def require_analyst(request: Request) -> None: if config.ANALYST_TOKEN is empty, return. Otherwise
     read the header "X-Analyst-Token"; compare with hmac.compare_digest (both encoded as utf-8);
     on mismatch or missing raise HTTPException(status_code=401, detail="Analyst token required").
   - def auth_status() -> dict: {"enabled": bool(config.ANALYST_TOKEN)}  (never return the token)
3. Add `dependencies=[Depends(require_analyst)]` to these routes only:
   POST /alerts/{id}/action, POST /alerts/{id}/feedback, POST /alerts/{id}/notify,
   POST /notifications/test, POST /pipeline/run.
4. Add GET /auth/status (in app/api/health.py) → auth_status().
5. In app/main.py's StarletteHTTPException handler, map 401 to error code "unauthorized" (add one entry
   to the existing dict; change nothing else).
6. static/js/api.js: for non-GET requests, add header X-Analyst-Token from sessionStorage key
   "is_analyst_token" when present (wrap sessionStorage access in try/catch). If a response is 401,
   open the existing confirmModal-style in-flow dialog with a password input "Analyst token", store the
   value in sessionStorage, and retry the request ONCE. Cancel → throw the original error.
7. static/js/layout.js: if GET /auth/status says enabled, show a small pill "Analyst mode" (brand tint) when
   a token is stored, else "Viewer" (muted). Clicking "Viewer" opens the token dialog.
8. Add to .env.example (commented out):  # ANALYST_TOKEN=change-me-long-random-string
9. tests/test_v2_api.py: with monkeypatch setting config.ANALYST_TOKEN="t0k": POST /api/notifications/test
   without the header → 401 with error "unauthorized"; with header "t0k" → 200; GET /api/alerts without the
   header → 200 (reads stay open). With the token empty, the POST works without the header.
FILES: app/config.py (append), app/security.py, app/api/alerts.py, app/api/notifications.py,
app/api/health.py, app/main.py (one dict entry), static/js/api.js, static/js/layout.js, .env.example,
tests/test_v2_api.py
```

## CHECK (human)

```bash
pytest -q
```

Then put `ANALYST_TOKEN=demo-analyst-2026` in `.env` and restart. **Approve revoke** asks for the token; enter it and the action succeeds. Remove the line again if you prefer an unauthenticated demo.

---

**After the CHECK passes:** `git commit -m "phase 28 ok"`, then update context.md Section 20.


---

## PHASE 29: Supplied simulator adapter (≈20 min) · Person A

**Why:** audit gap 2.1, handled the **safe** way. The audit suggests boto3 and Okta API calls. **Do not build those.** The hackathon rules say all enforcement must use the supplied simulator, and no live cloud accounts, identity providers or production tenants may be modified. This phase connects `SuppliedSimulator` to the **organizers' simulator only**.

**Do this phase only once the organizers' simulator interface is available.** Put their docs, sample code and any client module in `docs/official/simulator/`.

## Prompt

```text
Read context.md Sections 2 (rule 13), 15–16 (16.1, 16.2), and every file in docs/official/simulator/.

First REPORT (no code): what the simulator interface is (Python module/function names, or HTTP endpoints
with method, URL, request and response format, auth), and how our three actions map to it:
step_up(identity_id, session_id), restrict(identity_id, scope), revoke(identity_id, session_id).
Wait for my confirmation.
```

After you confirm:

```text
Implement app/simulator/supplied.py SuppliedSimulator(SimulatorAdapter) against EXACTLY that interface:
- If it is a Python module provided by the organizers: import it lazily inside the methods, with a clear
  error if it is missing.
- If it is HTTP: use urllib.request only (no requests library), JSON bodies, timeout=10 s, a base URL from a
  new config constant SIMULATOR_URL appended to the END of app/config.py
  (os.environ.get("SIMULATOR_URL", "")), and any auth header from an env var named in the organizer docs
  (never hardcode secrets).
- Each method returns a short status string like the mock ("simulated:<action>:<result>").
- On any error raise RuntimeError with a short message; app/decision/respond.py already turns errors into
  an ActionResult. If it does not, catch the error there and return status "failed" with the message
  (smallest possible change).
- Never call any AWS or Okta API. Never import boto3 or requests.
- SIMULATOR_MODE stays "mock" by default. To allow an override with env SIMULATOR_MODE=supplied, append
  this line to the END of app/config.py (do not edit the original constant; `os` is imported in the v2 block):
  SIMULATOR_MODE = os.environ.get("SIMULATOR_MODE", SIMULATOR_MODE).strip().lower()
Add tests/test_supplied_simulator.py that monkeypatches the transport (the urllib.request.urlopen call or the
organizer module) and checks: the correct request for each action, and that an error becomes a "failed"
ActionResult instead of an exception escaping.
FILES: app/simulator/supplied.py, app/config.py (append), app/decision/respond.py (only if needed),
tests/test_supplied_simulator.py
```

## CHECK (human)

```bash
pytest -q
```

Then set `SIMULATOR_MODE=supplied` (plus `SIMULATOR_URL` if HTTP) in `.env`, restart, and apply **step-up** on a medium alert. Confirm in the organizers' simulator that it received the action, and that the audit log shows it.

---

**After the CHECK passes:** `git commit -m "phase 29 ok"`, then update context.md Section 20.


---

## PHASE 30: Final regression, docs and demo (≈40 min) · All

**Run this phase LAST**, after phases 31–36 (and 28/29 if you did them).

## Part A: full regression (prompt)

```text
Read context.md Sections 12–24.
DO (report first, then fix only real bugs):
1. Run pytest -q and python smoke_test.py and report results.
2. Extend smoke_test.py checks (add entries, keep the existing ones): /api/analytics/detectors,
   /api/analytics/heatmap/time, /api/notifications/status, /api/pipeline/status, /api/agents, /api/scan/status,
   /api/scan/trace, /api/inputs, /api/identities/svc-report/attack (sample data), /api/graph/global,
   /analytics.html, /notifications.html, /agents.html, /scan.html, /input.html, /graph.html.
3. Mock parity: for every static/mock/*.json that maps to a GET endpoint, fetch the live endpoint with
   TestClient and compare top-level keys (and the keys of the first list item, if a list). Report every
   difference. Fix differences in the MOCK files only, unless the live API violates
   kit_v2/03, kit_v2/04 or kit_v2/08 specs (then report first).
4. Reference integrity: run tools/check_ref.py for every pair listed in prompts/00_templates_v2.md T5 plus
   tests/test_v2_features.py (REF_05), tests/test_runner.py (REF_06), tests/test_v21_trace.py (REF_12),
   tests/test_v21_inputs.py (REF_13). All must MATCH.
4b. Audit: GET /api/audit/verify must be valid, and GET /api/audit must contain one "threat_detected" entry per threat
   from the last run (compare with GET /api/scan/status "threats" on a fresh database).
5. Record any real bug in context.md Section 14 and fix it minimally.
FILES: smoke_test.py, static/mock/*.json, context.md, plus minimal bug fixes (list them)
```

## Part B: docs (prompt)

```text
DO:
1. README.md: add sections "Detection analytics", "Email alerts" (modes, .env setup, Gmail App Password
   note, outbox demo), "Background re-runs", "Offline mode", "Analyst token (optional)",
   "Exporting predictions" (python -m app.export), "Latency replay" (python -m app.replay),
   "The 15 agents" (table from kit_v2/08 spec §2.1), "Live scan and terminal scan" (python -m app.scan --json),
   "Threat audit entries", "Entering your own data" and "Attack Path Explorer".
   Keep the existing content.
2. AUDIT_REPORT.md: add a section "v2 changes" summarizing phases 20–29 and 31–36 with what was done and verified,
   and update the "What doesn't work" items that are now fixed (mark them "Resolved in v2" with the phase).
   Keep "real cloud enforcement" listed as intentionally out of scope (hackathon safety rule).
3. Copy the final metrics table from docs/official/RESULTS.md into README.md under "Results".
FILES: README.md, AUDIT_REPORT.md
```

## Part C: demo prep (human)

Follow `kit_v2/06_DEMO_SCRIPT_V2.md`. Rehearse twice with the timer. Before the demo, delete `data/input/` content (or keep a prepared input story) and run one fresh scan so the Live scan replay and the audit log are clean.

## Final CHECK (human)

```bash
pytest -q
python smoke_test.py
python -m app.export
git status            # .env must NOT appear
```

Then: `git commit -m "v2.0-demo"`, `git tag v2.0-demo`, and merge the `v2` branch into main.


---

## PHASE 31: 15-agent trace, threat audit entries, terminal scan (≈40 min) · Person A

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


---

## PHASE 32: Agents dashboard: show all 15 agents (≈35 min) · Person D

Spec: `kit_v2/08_FEATURE_AGENTS_SCAN_INPUT_GRAPH_SPEC.md` §3. Works in `?mock=1` before Phase 31 is live.

## Prompt

```text
Read context.md Section 10 and Sections 16.8, 21–24, then kit_v2/08_FEATURE_AGENTS_SCAN_INPUT_GRAPH_SPEC.md Section 3.

DO:
1. Create static/mock/agents.json and static/mock/scan_status.json by copying EXACTLY the blocks in
   kit_v2/reference/REF_18_mock_json_v21.md. Add to the api.js mock table (GET): /agents → agents,
   /scan/status → scan_status (match the path without the query string).
2. static/js/layout.js: add a sidebar item "Agents" (inline SVG "cpu/chip" icon) directly after Overview.
3. static/agents.html: same head/body as static/alerts.html, title "IdentityShield · Agents", module /js/agents.js.
4. static/js/agents.js: renderLayout("agents", "Agents", "15 cooperating agents · live status of every layer").
   Import escHtml from ./jsonview.js (create static/js/jsonview.js exactly from kit_v2/reference/REF_14_jsonview_js.md
   if it does not exist) and use it for EVERY dynamic value (it also escapes quotes in attributes).

   A) Orchestrator banner (full width card): agent #15 name, run state pill (Idle/Running/Complete/Failed,
      colors as context 10.3), run_id (mono), mode, "Step k / 13" + progress bar (progress from run status),
      threats count (crit), duration. Button "Open live scan" → scan.html (keep ?mock=1).

   B) Pipeline flow: 5 layer columns left→right on lg (stacked on mobile): Data (1–4), Detection (5–10),
      Decision (11–13), Learning (14), Oversight (15). Each column has a header with the layer color dot
      (data #22D3EE, detection #E879F9, decision #FBBF24, learning #34D399, oversight #60A5FA) and the layer name.
      Between columns on lg show a thin chevron "›" in text-muted to suggest flow.

   C) Agent card (one per agent, in its column): top row = number badge (font-mono "05"), name (font-medium),
      state pill on the right:
        waiting → "Waiting" muted · running → "Running" brand2 with animate-pulse dot · done → "Done" ok ·
        failed → "Failed" crit · skipped → "Skipped" warn · idle → "Idle" muted.
      Then: role (text-xs text-muted, 2 lines max), a stats row: last duration ("12 ms" or "—"),
      runs, and for detection agents a signals count chip + pattern chip (P1..P5/ML using patternChip from ui.js).
      Permissions as tiny mono chips (bg-panel2). last_error in crit text if present.
      Card border: line; running → ring-1 ring-brand2; failed → border-crit/60.
      The whole card is a button (keyboard accessible).

   D) Clicking a card opens a detail panel (in-flow card below the grid, or a right-side panel on lg)
      showing: name, role, layer, permissions, last_started / last_finished (fmtTime), last_message,
      and last_output rendered with highlightJson inside a dark <pre> (background #05070C, max-h-80 overflow-auto),
      plus "Recent events" = GET /scan/trace?after=0&limit=2000 filtered client-side to this agent (last 10),
      each as a one-line row with state and message. Close button.

   E) Polling: GET /agents every 1500 ms while run.state === "running", otherwise every 10 s; stop polling when the
      tab is hidden (document.hidden) and resume on visibilitychange. Never stack timers.
   Skeletons while loading; errorState on failure; works at 375 px.
FILES: static/mock/agents.json, static/mock/scan_status.json, static/js/api.js, static/js/layout.js,
static/agents.html, static/js/agents.js, static/js/jsonview.js (copy only if missing)
```

## CHECK (human)

1. `agents.html?mock=1`: 15 cards in 5 columns, all **Done**; detection cards show signal counts; clicking *Privilege Escalation Agent* shows its JSON (`chains` …); no console errors; works at 375 px.
2. Live: open the page, then in another tab press **Re-run pipeline** (or start a scan in Phase 33). The cards switch to **Running** and then **Done**, and the banner shows the progress.

---

**After the CHECK passes:** `git commit -m "phase 32 ok"`, then update context.md Section 24.


---

## PHASE 33: Live scan page (full-color console + full JSON) (≈20 min) · Person D

**Why:** when the system checks for malicious activity, the judges see every agent step in a colored console, the **current step** and its **full JSON**, the threats as they are found, and a note that each threat was written to the audit log.

The page code is **pre-built and tested** (headless Chromium, mock and live modes: 32/32 events, 4 threats, 0 browser errors). This phase copies it and wires it in.

Spec: `kit_v2/08_FEATURE_AGENTS_SCAN_INPUT_GRAPH_SPEC.md` §4.

## Prompt

```text
Read context.md Section 10, 16.5, 16.8 and kit_v2/08_FEATURE_AGENTS_SCAN_INPUT_GRAPH_SPEC.md Section 4.

DO:
1. Create static/js/jsonview.js exactly from kit_v2/reference/REF_14_jsonview_js.md (skip if it already MATCHES).
2. Create static/js/scan.js exactly from kit_v2/reference/REF_16_scan_page_js.md.
3. Create static/mock/scan_trace.json exactly from kit_v2/reference/REF_18_mock_json_v21.md (and scan_status.json /
   agents.json if missing). Add to the api.js mock table (GET): /scan/trace → scan_trace. Query strings must be
   ignored when matching.
4. static/scan.html: same head/body as static/alerts.html, title "IdentityShield · Live scan",
   module script /js/scan.js.
5. static/js/layout.js: add a sidebar item "Live scan" (inline SVG radar/pulse icon) directly after Overview.
   The renderLayout id is "scan".
6. Compatibility check (report, then fix only in api.js/ui.js/layout.js if needed, minimal change):
   scan.js imports { api } from ./api.js, { toast } from ./ui.js, { renderLayout } from ./layout.js.
   - api(path, { method: "POST", body: {...} }) must JSON-encode body and throw Error("<error>: <detail>")
     on non-2xx (Phase 12 contract). In mock mode a POST must resolve to {status:"mocked"}.
   - toast(message, type) must accept "success" and "error".
   - renderLayout(active, title, subtitle) must return the content element.
   If one of these differs, adapt api.js/ui.js/layout.js (NOT scan.js) and tell me what changed.
7. On the Overview page add a primary button "Run live scan" in the header area linking to scan.html?autostart=1
   (keep ?mock=1 → scan.html?mock=1&autostart=replay).
FILES: static/js/jsonview.js, static/js/scan.js, static/mock/scan_trace.json (+ scan_status.json, agents.json if missing),
static/js/api.js, static/scan.html, static/js/layout.js, static/js/overview.js, (ui.js only if step 6 requires)
```

## CHECK (human)

```bash
python tools/check_ref.py static/js/scan.js kit_v2/reference/REF_16_scan_page_js.md
python tools/check_ref.py static/js/jsonview.js kit_v2/reference/REF_14_jsonview_js.md
```

1. `scan.html?mock=1` → **Replay last scan**: lines stream in color; header shows "Step k / 13 · <agent>"; the JSON panel follows the current step; 4 threats appear on the right; the green banner reads "Scan complete · 4 threat(s), each written to the audit log".
2. Live, without `?mock=1`: pick **Dataset**, press **Start scan** at 1×. The real run takes about 2 s; the page replays it at a watchable pace and the banner shows the actual time.
3. Toggle **Inline JSON**, set the filter to **Threats**, use **Download JSON**, click a line to inspect it.
4. Open **Audit**: the new `threat_detected` entries are there (one per threat).

---

**After the CHECK passes:** `git commit -m "phase 33 ok"`, then update context.md Section 24.


---

## PHASE 34: Input-only data entry: backend (≈30 min) · Person B

**Why:** users (and judges) must be able to **enter their own data**, by pasting or uploading CloudTrail/Okta logs or adding single events with a form, and scan **only that input**. Until now the system could only read files from folders.

Spec: `kit_v2/08_FEATURE_AGENTS_SCAN_INPUT_GRAPH_SPEC.md` §5.

## Prompt

```text
Read context.md (Sections 2, 7, 16, 21–24) and kit_v2/08_FEATURE_AGENTS_SCAN_INPUT_GRAPH_SPEC.md Section 5.

DO:
1. Create app/inputs.py exactly from kit_v2/reference/REF_11_inputs.md.
2. Create tests/test_v21_inputs.py exactly from kit_v2/reference/REF_13_tests_v21_inputs.md.
3. app/pipeline.py: add an optional parameter → run_pipeline(use_sample: bool | None = None,
   input_mode: str | None = None). Behavior:
   - input_mode None → unchanged.
   - input_mode "only" → load CloudTrail from config.INPUT_DIR / "cloudtrail" and Okta from config.INPUT_DIR / "okta"
     with the SAME loader functions; data_mode = "input". If both are empty → return status "failed" with detail
     "No input data. Add data on the Input page first." (the runner keeps the previous results).
   - input_mode "merge" → the normal dataset selection PLUS the input records (concatenate the record lists before
     normalizing); data_mode = "<normal mode>+input".
   Metadata still comes from data/metadata. Everything after loading is unchanged.
   Make sure the loaders accept the input file names (they are "cloudtrail_*.jsonl" / "okta_*.jsonl", JSON Lines).
   If a loader filters by file name or format and would skip them, fix ONLY that filter.
4. Create app/api/inputs.py with APIRouter(tags=["inputs"]), plain-def routes, clean_json on responses:
   - GET    /inputs → inputs.list_inputs()
   - POST   /inputs/upload   body {"content": str, "source": "auto"|"cloudtrail"|"okta" (default auto),
                              "filename": str|null} → inputs.save_input(...)
   - POST   /inputs/manual   body {"kind": "okta_login"|"okta_logout"|"cloudtrail_api", "fields": {...}}
                              → inputs.add_manual(kind, fields)
   - DELETE /inputs → {"removed": inputs.clear_inputs()}
   Map inputs.InputError → HTTP 422 with error "validation_error" and the message as detail (the message is safe to
   show). Use small Pydantic request models defined in app/api/inputs.py (NOT in app/models.py, which is frozen).
   If Phase 28 (analyst token) exists, protect POST /inputs/upload, POST /inputs/manual and DELETE /inputs with
   Depends(require_analyst).
   Include the router in app/main.py (before the static mount).
5. Add to tests/test_v2_api.py (use monkeypatch to point config.INPUT_DIR at tmp_path):
   POST /api/inputs/upload with a Records JSON of 2 CloudTrail events → 200 and accepted.cloudtrail == 2;
   POST /api/inputs/manual with an invalid ip → 422 with error "validation_error";
   POST /api/pipeline/run {"input_mode": "only"} → 202 (or 409 if a run is in progress);
   DELETE /api/inputs → 200.
6. .gitignore: add data/input/
FILES: app/inputs.py, tests/test_v21_inputs.py, app/pipeline.py, app/ingest/loaders.py (filter fix only if needed),
app/api/inputs.py, app/main.py, tests/test_v2_api.py, .gitignore
```

## CHECK (human)

```bash
python tools/check_ref.py app/inputs.py kit_v2/reference/REF_11_inputs.md
pytest -q
python smoke_test.py
```

End-to-end in the terminal:

```bash
python -c "from app import inputs; print(inputs.add_manual('okta_login', {'user':'anita.rao','ip':'49.207.12.8','time':'2026-10-28T03:40:00Z','city':'Bengaluru','country':'India','lat':12.97,'lon':77.59}))"
python -c "from app import inputs; print(inputs.add_manual('okta_login', {'user':'anita.rao','ip':'91.64.18.2','time':'2026-10-28T04:10:00Z','city':'Frankfurt','country':'Germany','lat':50.11,'lon':8.68,'label':'impossible_travel'}))"
python -m app.scan --input-only
```

Expected: the scan runs on **only these 2 events** and the Impossible Travel Agent flags `anita.rao`. Some detectors, such as Dormant Account and ML, need history; on such a small input they report 0 signals or are skipped, which is correct. Clean up with `DELETE /api/inputs` or delete `data/input/`.

---

**After the CHECK passes:** `git commit -m "phase 34 ok"`, then update context.md Section 24.


---

## PHASE 35: Input page UI (≈40 min) · Person D

Spec: `kit_v2/08_FEATURE_AGENTS_SCAN_INPUT_GRAPH_SPEC.md` §5.4. Works in `?mock=1` first.

## Prompt

```text
Read context.md Section 10 and 16.8, then kit_v2/08_FEATURE_AGENTS_SCAN_INPUT_GRAPH_SPEC.md Section 5.

DO:
1. static/mock/inputs.json exactly from kit_v2/reference/REF_18_mock_json_v21.md; api.js mock table (GET): /inputs → inputs.
2. static/js/layout.js: sidebar item "Input data" (inline SVG upload/tray icon) after Live scan.
3. static/input.html: same head/body as alerts.html, title "IdentityShield · Input data", module /js/input.js.
4. static/js/input.js: renderLayout("input", "Input data", "Add your own logs or single events, then scan only them").
   Use escHtml from ./jsonview.js for every dynamic value.

   Layout (lg: 2 columns, left 2/3, right 1/3; single column on mobile):

   LEFT · Card "Add logs" with two tabs (buttons, not hidden-until-JS content: render both panels, show one):
   a) "Paste or upload":
      - source select: Auto-detect / AWS CloudTrail / Okta System Log
      - a drop zone (dashed border-line, rounded-xl, p-8, centered icon + "Drop .json / .jsonl files here or
        click to choose") backed by <input type="file" accept=".json,.jsonl,.txt" multiple>. Files are read in the
        browser with file.text() and each file is POSTed separately to /inputs/upload as
        {content, source, filename}. Reject files larger than limits.max_bytes (from GET /inputs) client-side
        with an error toast before sending.
      - a textarea (font-mono text-xs, h-56, bg #05070C, placeholder showing a 1-line CloudTrail example) +
        button "Add pasted records".
      - result box after each upload: "Accepted: 120 CloudTrail · 0 Okta · Rejected: 1" + the first errors as a list
        (crit text). Never echo the uploaded content back.
   b) "Single event" form:
      - kind select: "Okta login" (okta_login) / "Okta logout" (okta_logout) / "AWS API call" (cloudtrail_api).
        Fields shown depend on kind:
        Okta: user*, ip*, time (datetime-local; convert to ISO UTC "Z"), outcome (SUCCESS/FAILURE), city, country,
              lat, lon, session_id, label (optional, e.g. impossible_travel)
        AWS:  user*, ip*, time, event_name* (datalist of common names: ConsoleLogin, CreateAccessKey,
              AttachUserPolicy, PutUserPolicy, AssumeRole, GetSecretValue, StopLogging, DeleteTrail, ListBuckets),
              event_source (default iam.amazonaws.com), region (default ap-south-1), access_key_id, resource, label
      - "Presets" row of small secondary buttons that fill the form (do not submit):
        "Login · Bengaluru" (anita.rao, 49.207.12.8, Bengaluru, India, 12.97, 77.59),
        "Login · Frankfurt +30 min" (anita.rao, 91.64.18.2, Frankfurt, Germany, 50.11, 8.68, time = previous preset + 30 min,
          label impossible_travel),
        "Attach AdministratorAccess" (svc-report, 185.220.101.4, AttachUserPolicy,
          resource arn:aws:iam::aws:policy/AdministratorAccess, label privilege_escalation),
        "Stop CloudTrail logging" (dev.kumar, 177.71.200.9, StopLogging, region sa-east-1, event_source
          cloudtrail.amazonaws.com, label unusual_api).
      - Submit → POST /inputs/manual {kind, fields}. On 422 show the server message under the form (crit) and
        keep the values. On success toast "Event added" and show the stored record with highlightJson in a dark <pre>.

   RIGHT · Card "Your input data": totals (CloudTrail / Okta / total records), file list (name mono truncated,
      source chip, records, size in KB, modified fmtTime), "Clear all" (danger, confirmModal first, DELETE /inputs).
      Below: Card "Scan it":
        primary button "Scan input only" → navigate to scan.html?autostart=1&mode=only (keep ?mock=1).
          Do NOT POST from this page: the Live scan page starts the run itself and attaches to the new run id.
        secondary button "Scan dataset + input" → scan.html?autostart=1&mode=merge (keep ?mock=1).
        Both disabled when total_records is 0, with a hint "Add data first".
        Note (text-xs text-muted): "Input-only scans look at nothing else. Detectors that need history (dormant
        accounts, ML baseline) may report nothing on very small inputs; use Dataset + input for those."

   After every successful add/clear, reload GET /inputs.
   States: skeleton, empty ("No input yet. Paste logs, drop files or add a single event."), errorState.
5. static/js/scan.js must NOT be modified. It already supports ?autostart=1&mode=only|merge|dataset.
FILES: static/mock/inputs.json, static/js/api.js, static/js/layout.js, static/input.html, static/js/input.js
```

## CHECK (human)

1. `input.html?mock=1`: both tabs render, presets fill the form, the file list shows 3 files; no console errors; works at 375 px.
2. Live:
   - Click the preset **Login · Bengaluru**, then **Add**.
   - Click the preset **Login · Frankfurt +30 min**, then **Add**.
   - Click **Scan input only**. The live scan shows *Impossible Travel Agent* flagging `anita.rao`, a THREAT line, and a new audit entry.
3. Paste `{"foo": 1}` → a clear error ("No valid CloudTrail or Okta records found…"). Paste an invalid IP in the form → the field error from the server.
4. **Clear all** → totals go back to 0.

---

**After the CHECK passes:** `git commit -m "phase 35 ok"`, then update context.md Section 24.


---

## PHASE 36: Identity Graph upgrade: Attack Path Explorer (≈40 min) · Persons A + D

**Why:** this is the "wow" screen for judges. The attack path glows red, with particles flowing along it and numbered steps. **Play attack** walks the camera through the escalation one step at a time. Focus mode dims everything else, and the blast-radius halo shows what the attacker could reach next.

The page code is **pre-built** (REF_17) and was logic-tested in headless Chromium against a vis-network stand-in (path, playback, focus, blast radius, layouts, inspector, global view, PNG export: 0 browser errors). The real vis-network rendering is checked by you in this phase's CHECK.

Spec: `kit_v2/08_FEATURE_AGENTS_SCAN_INPUT_GRAPH_SPEC.md` §6.

## Part A: backend, 2 endpoints (≈15 min) · Person A

```text
Read context.md Sections 9, 16 and kit_v2/08_FEATURE_AGENTS_SCAN_INPUT_GRAPH_SPEC.md Section 6.2.

In app/api/identities.py add (plain def, clean_json, 503 if no pipeline result, reuse app/correlate/graph.py functions):
1. GET /identities/{identity_id}/attack →
   {"identity_id", "identity": <the row from get_identity_rows(result) for this id, or null>,
    "graph": identity_subgraph(result.graph, identity_id, suspicious_ids).model_dump(mode="json"),
    "alert": <this identity's highest-risk Alert as model_dump(mode="json"), or null>,
    "blast_radius": blast_radius(result.graph, identity_id)}
   suspicious_ids = the evidence_event_ids of that alert (so path edges are marked suspicious).
   404 not_found if the identity has no events and no alerts.
   The graph must contain the edges whose event_id is in the alert's evidence_event_ids (so the attack path can be drawn).
   If identity_subgraph's 150-node cap could drop them, keep evidence edges first when trimming (smallest change in
   identity_subgraph, behavior otherwise unchanged).
2. GET /graph/global?top=8 (clamp 1..15) → merge identity_subgraph(...) of the top-N identities by max alert risk:
   {"identities": [ids], "nodes": [...unique by id...], "edges": [...unique by (source,target,label,event_id)...],
    "truncated": bool}. Cap at 300 nodes (truncated=true if capped). Edges whose event_id is in ANY of those identities'
   top alert evidence get suspicious=true.
3. tests/test_v2_api.py: on sample data, GET /api/identities/svc-report/attack → 200, alert.alert_id present, at least one
   graph edge has an event_id contained in alert.evidence_event_ids; GET /api/identities/nobody-xyz/attack → 404;
   GET /api/graph/global → 200 with "nodes" and "edges", and len(nodes) <= 300.
FILES: app/api/identities.py, app/correlate/graph.py (only the trimming order, if needed), tests/test_v2_api.py
```

## Part B: frontend (≈15 min) · Person D

```text
Read context.md Section 10, 16.5, 16.8 and kit_v2/08_FEATURE_AGENTS_SCAN_INPUT_GRAPH_SPEC.md Section 6.

DO:
1. Create static/js/graphfx.js exactly from kit_v2/reference/REF_15_graphfx_js.md.
2. REPLACE static/js/graph.js with exactly the code in kit_v2/reference/REF_17_graph_page_js.md.
   (jsonview.js must exist from Phase 33.)
3. static/graph.html: keep the head; make sure the vis-network script (CDN or /vendor/vis-network.min.js from Phase 27)
   comes BEFORE <script type="module" src="/js/graph.js">. Title "IdentityShield · Attack path explorer".
4. Mocks: create static/mock/graph_attack.json, graph_global.json (and events_AL-0001.json) exactly from
   kit_v2/reference/REF_18_mock_json_v21.md. api.js mock table (GET, ignore query strings):
   /identities/{id}/attack → graph_attack, /graph/global → graph_global. If the existing static/mock/identities.json lacks
   "risk" or "identity_id", replace it with the REF_18 version. Map /alerts/{id}/events → events only if no mapping exists.
5. graph.js calls renderLayout("graph", …). If layout.js has no sidebar item with id "graph", make the Identities item
   active for "graph" too (change layout.js, not graph.js).
6. Identities page and alert page links to graph.html?identity=… keep working. On the alert detail page, change the
   "Open identity graph" link to graph.html?identity=<id>&play=1 so it opens and plays the attack.
FILES: static/js/graphfx.js, static/js/graph.js, static/graph.html, static/mock/graph_attack.json,
static/mock/graph_global.json, static/mock/events_AL-0001.json, static/mock/identities.json (only if needed),
static/js/api.js, static/js/layout.js (only if needed), static/js/alert.js (link only)
```

## CHECK (human, in a real browser)

```bash
python tools/check_ref.py static/js/graph.js kit_v2/reference/REF_17_graph_page_js.md
python tools/check_ref.py static/js/graphfx.js kit_v2/reference/REF_15_graphfx_js.md
```

Open `graph.html?mock=1`, then the live page for `svc-report`:
1. The red path is visible, with **moving particles** and **numbered badges 1…6**. The stats read "Path steps 5 · Time to impact 11 min".
2. **▶ Play attack**: the camera moves step by step and the caption reads "STEP 2/5 · CreateAccessKey · CredCreate".
3. **Focus attack path** dims everything else. **Blast radius** shows an orange dashed halo and glowing resources.
4. **Left → right** gives a clean hierarchical layout; **Force** returns to the organic layout.
5. Click a node: the inspector lists its connections; clicking an event id shows the evidence JSON.
6. **All risky identities** shows several identities with their suspicious edges in red. **Export PNG** downloads an image. **Fullscreen** works.
7. No console errors.

If something looks off visually (for example particles not exactly on curved edges), tell the agent which item failed. Only `graph.js` styling constants may be adjusted; keep `graphfx.js` unchanged.

---

**After the CHECK passes:** `git commit -m "phase 36 ok"`, then update context.md Section 24.

