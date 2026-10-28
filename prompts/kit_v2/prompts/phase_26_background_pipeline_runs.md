# PHASE 26: Background pipeline runs (≈25 min) · Person A

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
