# PHASE 28 (optional): Analyst token for write actions (≈25 min) · Person A

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
