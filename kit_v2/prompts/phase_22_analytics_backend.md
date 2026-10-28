# PHASE 22: Analytics backend (≈25 min) · Person C

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
