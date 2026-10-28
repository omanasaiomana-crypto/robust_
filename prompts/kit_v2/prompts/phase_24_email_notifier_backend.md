# PHASE 24: Email notifier backend (≈30 min) · Person A

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
