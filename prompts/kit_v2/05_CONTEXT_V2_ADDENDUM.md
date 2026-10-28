# 05 · context.md addendum (v2)

**How to use:** Phase 20 appends everything below the line to the END of your existing `context.md` (sections 15–20). It does not replace anything; your v1 progress log stays.

---

## 15. v2 scope

v1 (phases 0–19) is complete. v2 adds:
1. Official-data evaluation, baseline comparison, predictions export, latency replay (P21).
2. Detection analytics: rules vs ML vs hybrid, detection heatmap, attack-time heatmap (P22–P23).
3. Admin email alerts (P24–P25).
4. Hardening: background runs (P26), offline assets (P27), optional analyst token (P28), supplied-simulator adapter (P29).

Specs live in `kit_v2/`:
- `01_AUDIT_REVIEW.md`: why each change exists
- `03_FEATURE_ANALYTICS_SPEC.md`: analytics contract and UI
- `04_FEATURE_EMAIL_ALERTS_SPEC.md`: email contract and UI
- `reference/REF_*.md`: **pre-tested code; copy exactly**

## 16. v2 golden rules (in addition to Section 2)

16.1 **No new dependencies.** Allowed standard-library modules for v2: `smtplib`, `ssl`, `email`, `html`, `threading`, `urllib.request`, `hmac`, `csv`, `argparse`, `uuid`, `re`, `os`. Never add boto3, requests, celery, redis or chart plugins.
16.2 **No real cloud or IdP enforcement.** Enforcement goes only through `app/simulator/`; `SuppliedSimulator` talks only to the organizers' simulator.
16.3 `app/models.py` stays frozen. New endpoints return dicts through `clean_json()`.
16.4 `app/config.py` is **append-only**: v2 settings live in the "v2 additions" block at the end. Never edit existing constants except to move a hardcoded value into a new constant (Phase 20).
16.5 Code from `kit_v2/reference/` is pre-tested. Copy it verbatim. If it seems to conflict with the project, **stop and report**; do not "adapt" it silently.
16.6 Notifications must never raise into callers and never block a request or pipeline.
16.7 Secrets (SMTP password, analyst token) are read only from environment or `.env`. Never log, return or display them.
16.8 New UI pages follow Section 10 exactly (sidebar layout, `ui.js` components, `esc()` for every value, skeleton, empty and error states, `?mock=1` support).
16.9 Heatmaps are HTML/CSS grids, not canvas plugins. Every cell prints its number (color is never the only signal).

## 17. v2 config names (appended block)

`DISPLAY_UTC_OFFSET_MINUTES=330`, `HEATMAP_DAYS=14`, `ANALYTICS_HYBRID_MIN_RISK=BAND_STEP_UP`,
`EMAIL_MODE` (off|outbox|smtp, default outbox), `SMTP_HOST`, `SMTP_PORT=587`, `SMTP_USER`, `SMTP_PASSWORD`,
`SMTP_STARTTLS=True`, `SMTP_SSL=False`, `SMTP_TIMEOUT_SECONDS=10`, `ALERT_EMAIL_FROM`, `ALERT_EMAIL_TO` (list),
`EMAIL_MIN_RISK=70`, `EMAIL_MAX_PER_HOUR=10`, `CONSOLE_BASE_URL`, `OUTBOX_DIR`.
Phase 20 may add: `SESSION_LINK_WINDOW_HOURS`, plus any constant moved out of hardcoded logic.
Phase 21 adds: `EXPORT_MIN_RISK`, `OUTPUT_DIR`. Phase 28 adds: `ANALYST_TOKEN`.

## 18. v2 files

```text
app/analytics.py            (P22, from REF_02)
app/api/analytics.py        (P22)
app/notify.py               (P24, from REF_03)
app/api/notifications.py    (P24)
app/runner.py               (P26, from REF_04)
app/export.py               (P21)
app/replay.py               (P21)
app/security.py             (P28, optional)
static/analytics.html, static/js/analytics.js            (P23)
static/notifications.html, static/js/notifications.js    (P25)
static/vendor/              (P27)
static/mock/analytics_*.json, notifications*.json, pipeline_status.json
tests/test_v2_features.py   (from REF_05)
tests/test_runner.py        (from REF_06)
tests/test_v2_api.py        (P22/P24/P26)
.env.example                (P24)
data/outbox/                (runtime, git-ignored)
data/output/                (runtime, git-ignored)
```

## 19. v2 API (added to Section 9)

| Method | Path | Returns |
|---|---|---|
| GET | /api/analytics/detectors | rules/ml/hybrid metrics, matrix, agreement, winner |
| GET | /api/analytics/heatmap/time?days | {days, hours, cells, max, total, tz} |
| GET | /api/analytics/heatmap/identities?top | {identities, risk, patterns, pattern_names, cells, max} |
| GET | /api/notifications?limit | list of notification records |
| GET | /api/notifications/status | email status (no secrets) |
| POST | /api/notifications/test | notification record |
| POST | /api/alerts/{id}/notify | notification record |
| GET | /api/pipeline/status | {state, run_id, started_at, finished_at, duration_ms, detail, alerts} |
| POST | /api/pipeline/run | 202 + status (409 if already running) — changed in P26 |

While `state == "running"`: POST action, feedback and pipeline/run return 409 with a clear message.

## 20. v2 progress log (agent updates after each phase)

| Phase | Name | Status | Notes |
|---|---|---|---|
| 20 | Audit verification and consistency fixes | ☐ | |
| 21 | Official data run, baseline, export, latency | ☐ | |
| 22 | Analytics backend | ☐ | |
| 23 | Analytics UI | ☐ | |
| 24 | Email notifier backend | ☐ | |
| 25 | Notifications UI | ☐ | |
| 26 | Background pipeline runs | ☐ | |
| 27 | Offline assets | ☐ | |
| 28 | Analyst token (optional) | ☐ | |
| 29 | Supplied simulator adapter | ☐ | |
| 30 | Regression, docs, demo | ☐ | |

v2 decisions log (append):

| # | Decision | Reason |
|---|---|---|
| v2-1 | Real AWS/Okta enforcement adapters are NOT built | Hackathon safety rule: enforcement only via the supplied simulator |
| v2-2 | Background runs use a stdlib thread, not Celery | No new services or dependencies |
| v2-3 | Analytics compares detectors at session level | Alerts are per session; fair to rules and ML |
| v2-4 | Email default mode is outbox | Demo works without internet or SMTP |
