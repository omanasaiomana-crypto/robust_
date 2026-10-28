# PHASE 11: API and main app (≈30 min) · Person A

```text
Read context.md fully (Sections 2 and 9). Then read docs/TECH_PRD.md Sections 16.1–16.5.

GOAL: All REST endpoints with consistent JSON errors, and the app serving the website.

DO:
1. app/main.py: copy EXACTLY TECH_PRD 16.4, then add:
   - app.state.result = None and app.state.startup_error = "" defaults.
   - Static mount must remain the LAST line.
2. Routers (plain def handlers, response_model on every route, pattern from TECH_PRD 16.5):
   - app/api/health.py: GET /health, POST /pipeline/run (body optional {"use_sample": bool}),
     GET /summary (by_band counts, by_pattern counts, top_identities top 5, totals).
     /health must work even when result is None (pipeline "not_run" or "failed" with startup_error).
   - app/api/alerts.py: GET /alerts, GET /alerts/{id}, GET /alerts/{id}/events,
     POST /alerts/{id}/action (uses respond.apply_action; ValueError/PermissionError → 409),
     POST /alerts/{id}/feedback (apply_feedback, update alert.feedback, rescore its risk with new
     weights, save, return Alert).
   - app/api/identities.py: GET /identities, GET /identities/{id}/graph,
     GET /sessions/{id}/timeline (events of the session in order, each with the signals whose
     evidence includes that event), GET /hygiene (dormant_admins: privilege >= 4 and idle >= DORMANT_DAYS
     before last activity; escalation_paths from graph.escalation_paths for top 10 risky identities).
   - app/api/metrics.py: GET /metrics, GET /weights.
   - app/api/audit.py: GET /audit, GET /audit/verify.
   Mutations update both app.state.result.alerts (in memory) and SQLite.
   Every response that is not a Pydantic model goes through clean_json().
3. smoke_test.py already exists (pre-built). Do not change it.

FILES: app/main.py, app/api/*.py

CHECK:
python smoke_test.py   → SMOKE TEST PASSED
Then run the server and open http://127.0.0.1:8000/docs ; try GET /api/alerts and
GET /api/alerts/DOES-NOT-EXIST (must return JSON with error "not_found").
Then update context.md Section 12: Phase 11 = ☑.
```

---

**After the CHECK passes:** `git add . && git commit -m "phase 11 ok"`, then open the next file.
**If the CHECK fails:** use template T2 in `prompts/00_templates.md` with the exact error.
