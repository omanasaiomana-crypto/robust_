# context.md: IdentityShield project context

> **AI agent: read this whole file before every task.** It is the single source of truth for this project.
> If any instruction in a prompt conflicts with this file, follow this file and say so.
> After finishing a phase, update **Section 12 (Progress log)** and **Section 13 (Decisions log)** only.

---

## 1. What we are building

**IdentityShield** is a website that detects malicious use of *legitimate* identities by analyzing AWS CloudTrail and Okta System Log data.

It:
1. Loads CloudTrail + Okta logs (or generates sample data if none exist).
2. Normalizes them into one event format and links Okta sessions to AWS activity.
3. Runs 6 detection agents (5 attack patterns + 1 ML anomaly agent).
4. Scores risk per session (0 to 100), explains why, cites evidence event IDs.
5. Recommends a response (monitor, step-up MFA, restrict, revoke) and applies it **only** through a simulator adapter.
6. Shows everything in a professional security-console website.

Hackathon: Track 2, Zero Trust for Everyone (Intelligent Identity Protection). Build time: 8 hours.

**Attack patterns:**
| Code | Pattern |
|---|---|
| P1 | Impossible travel |
| P2 | Dormant-account reactivation |
| P3 | Privilege-escalation chain |
| P4 | Unusual API calls |
| P5 | Token / session abuse |
| ML | Isolation Forest behavior anomaly |

---

## 2. Golden rules (never break these)

1. Python **3.11**, **FastAPI 0.115**, **Pydantic v2** (`model_dump`, `model_validate`, `field_validator`). Never Pydantic v1 syntax.
2. Use **only** libraries in `requirements.txt`. Never add dependencies. Never use npm, React, Vue, Node or a build step.
3. `app/models.py` is the **frozen contract**. Never rename, remove or retype a field. Import models from it; never redefine them elsewhere.
4. Use **synchronous** `def` everywhere (route handlers too). Only the FastAPI `lifespan` is `async`.
5. Read external data with `dig()` and `parse_ts()` from `app/utils.py`. Missing data → default value, never `KeyError`.
6. A bad record is **skipped and counted**, never raised. A failing agent returns `[]`, never crashes the pipeline.
7. Absolute imports only: `from app.models import Alert`.
8. Files: `pathlib.Path`, `open(..., encoding="utf-8")`.
9. Logging only (`logging.getLogger(__name__)`), no `print` (except `smoke_test.py`).
10. **Only modify the files named in the current prompt.** If another file needs a change, stop and say which and why.
11. All config values come from `app/config.py`. No magic numbers in logic files.
12. Every API response is a Pydantic model or passes through `clean_json()`. No NumPy types, NaN or naive datetimes in responses.
13. No cloud SDKs (no boto3, no Okta SDK). Enforcement goes **only** through `app/simulator/`.
14. Frontend: insert every API value with `esc()`; never put raw data into `innerHTML`.
15. After each phase, the check command must pass before moving on.

---

## 3. Tech stack (pinned)

**requirements.txt**
```text
fastapi==0.115.0
uvicorn==0.30.6
pydantic==2.9.2
pandas==2.2.3
numpy==1.26.4
scikit-learn==1.5.2
networkx==3.3
jinja2==3.1.4
pytest==8.3.3
httpx==0.27.2
```

**Frontend (CDN only, no build):**
- Tailwind CSS: `https://cdn.tailwindcss.com` (configured inline, see Section 10)
- Inter font: Google Fonts `https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap`
- Chart.js 4: `https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js`
- vis-network: `https://unpkg.com/vis-network@9.1.9/standalone/umd/vis-network.min.js`

**Run:** `python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload` from project root.

---

## 4. Folder structure (exact)

```text
identityshield/
├── START_HERE.md
├── context.md                 ← this file
├── BUILD_PROMPTS.md           ← all prompts in one file
├── prompts/                   ← one file per phase (same prompts)
├── docs/                      ← PRD.md and TECH_PRD.md (reference specs)
├── requirements.txt
├── run.bat / run.sh
├── smoke_test.py
├── data/
│   ├── raw/cloudtrail/   raw/okta/   metadata/   labels/   sample/
├── app/
│   ├── __init__.py  main.py  config.py  models.py  utils.py  store.py  audit.py
│   ├── sample_data.py  pipeline.py  evaluation.py
│   ├── ingest/      __init__.py loaders.py normalize.py enrich.py
│   ├── correlate/   __init__.py sessions.py graph.py
│   ├── agents/      __init__.py base.py impossible_travel.py dormant.py priv_escalation.py
│   │                api_anomaly.py token_abuse.py baseline_ml.py
│   ├── ml/          __init__.py features.py anomaly.py peers.py chain_model.py calibrate.py
│   ├── decision/    __init__.py scoring.py explain.py respond.py feedback.py
│   ├── simulator/   __init__.py base.py mock.py supplied.py
│   └── api/         __init__.py health.py alerts.py identities.py metrics.py audit.py
├── static/
│   ├── index.html alerts.html alert.html identities.html graph.html timeline.html
│   │   hygiene.html audit.html
│   ├── css/app.css
│   ├── mock/        (JSON files used with ?mock=1)
│   └── js/  api.js ui.js layout.js overview.js alerts.js alert.js identities.js
│            graph.js timeline.js hygiene.js audit.js
└── tests/  __init__.py test_foundation.py test_utils.py test_normalize.py test_detectors.py
            test_scoring.py test_api.py
```

---

## 5. Data contracts (summary of app/models.py)

Full code: `docs/TECH_PRD.md` Section 8. Once `app/models.py` exists, **it** is the truth.

| Model | Key fields |
|---|---|
| `Event` | event_id, source (cloudtrail/okta), timestamp (aware UTC), identity_id, session_id, action, category (auth/session/api), outcome, src_ip, country, city, lat, lon, asn, user_agent, device_id, token_id, region, resource, resource_sensitivity (1-5), privilege_level (1-5), label |
| `Signal` | pattern, severity (0-1), identity_id, session_id, agent, reason, evidence_event_ids, mitre, timestamp |
| `ChainStep` | event_id, action, state, timestamp |
| `Prediction` | next_state, probability |
| `Counterfactual` | without, risk |
| `Alert` | alert_id, level, identity_id, session_id, risk, confidence, blast_radius, band, patterns, mitre, reasons, evidence_event_ids, chain, prediction, counterfactuals, recommended_action, action_status, feedback, first_seen, last_seen |
| `ActionRequest` | action (step_up/restrict/revoke/dismiss), approved_by |
| `ActionResult` | alert_id, action, status, detail |
| `FeedbackRequest` | label (tp/fp) |
| `Metrics` | event_precision, event_recall, event_f1, session_precision, baseline_event_f1, median_latency_ms, total_events, total_alerts, skipped_records |
| `Health` | status, pipeline, detail, data_mode, events, alerts |
| `GraphNode` / `GraphEdge` / `IdentityGraph` | id,label,kind,risk / source,target,label,event_id,suspicious / identity_id,nodes,edges,escalation_paths |
| `AuditEntry` | seq, timestamp, agent, action, detail, prev_hash, hash |
| `ErrorResponse` | error, detail, request_id |

Alert IDs: `AL-0001`, `AL-0002`, … ordered by risk descending.
Bands: `monitor` (<40), `step_up` (40-69), `restrict` (70-89), `revoke` (≥90).

---

## 6. Key config names (app/config.py)

Paths: `ROOT, DATA_DIR, RAW_CLOUDTRAIL, RAW_OKTA, METADATA_DIR, LABELS_DIR, SAMPLE_DIR, DB_PATH, STATIC_DIR`
Modes: `USE_SAMPLE_IF_NO_DATA=True`, `SIMULATOR_MODE="mock"`
Detection: `IMPOSSIBLE_TRAVEL_KMH=900`, `DORMANT_DAYS=30`, `ESCALATION_WINDOW_HOURS=6`, `API_RARITY_THRESHOLD=0.98`, `PEER_RARITY_THRESHOLD=0.95`
Scoring: `PRIVILEGE_MULTIPLIER`, `SENSITIVITY_MULTIPLIER`, `SIGNAL_WEIGHTS={"P1":25,"P2":20,"P3":35,"P4":15,"P5":30,"ML":20}`, `COMBO_BONUS_PER_PATTERN=0.25`, `RISK_HALF_LIFE_HOURS=6`
Response: `BAND_STEP_UP=40, BAND_RESTRICT=70, BAND_REVOKE=90, FRICTION_BUDGET_PER_DAY=2, REQUIRE_APPROVAL_FOR_REVOKE=True`
Feedback: `FEEDBACK_LEARNING_RATE=0.1, WEIGHT_MIN=5, WEIGHT_MAX=60`
`SENSITIVE_ACTIONS` set. `PATTERN_NAMES` (P1..ML → display name). `MITRE_BY_PATTERN` (P1..ML → list of technique IDs).

**Pre-built helper functions (use these, never re-implement):**
- `app/utils.py`: `dig`, `parse_ts`, `safe_div`, `haversine_km`, `clean_json`, `to_band`
- `app/store.py`: `init_db`, `execute`, `save_alerts`, `update_alert`, `load_alert`, `load_alerts`, `get_weights`, `set_weight`, `friction_used`, `friction_increment`, `reset_run_tables`
- `app/audit.py`: `append`, `verify`, `count`, `list_entries`

---

## 7. Pipeline order (app/pipeline.py → `run_pipeline()` returns `PipelineResult`)

1. Load official data from `data/raw/`; if empty and allowed, generate + load `data/sample/`.
2. Normalize + enrich → events DataFrame (columns = Event fields, sorted by timestamp).
3. Assign sessions (Okta `externalSessionId`; CloudTrail linked by identity + IP + time; else identity+token with 1 h gap).
4. Build NetworkX identity graph.
5. Train ML (skip silently if < 20 sessions).
6. Run 6 agents → `list[Signal]`.
7. Group signals by session → score → explain → recommend.
8. One alert per session. Apply auto-actions via simulator (revoke needs approval).
9. Save alerts to SQLite, append audit entries.
10. Compute metrics if labels exist.

Each step is wrapped in try/except. Failure → `status="failed"` or `"degraded"` with `detail`; the server still starts. Result lives in `app.state.result`.

---

## 8. Scoring (app/decision/scoring.py)

```text
base       = Σ SIGNAL_WEIGHTS[p] × max_severity[p]   (+ SIGNAL_WEIGHTS["ML"] × ml_score)
context    = PRIVILEGE_MULTIPLIER[privilege] × SENSITIVITY_MULTIPLIER[max_sensitivity]
combo      = 1 + COMBO_BONUS_PER_PATTERN × (distinct_patterns − 1)
chain      = 1 + prediction.probability   (if chain exists) else 1
risk       = min(100, base × context × combo × chain)
confidence = min(1, n_events / 10) × (distinct_patterns / max(1, n_signals))
decay      = risk × 0.5 ** (hours_since_last_signal / RISK_HALF_LIFE_HOURS)   (not for feedback == "tp")
counterfactual = risk recomputed with each pattern removed
```

MITRE: P1 T1078 · P2 T1078.004 · P3 T1098, T1548 · P4 T1526, T1562 · P5 T1550, T1539

---

## 9. API (all under /api, all JSON, errors = ErrorResponse)

| Method | Path | Returns |
|---|---|---|
| GET | /api/health | Health |
| POST | /api/pipeline/run | Health |
| GET | /api/summary | {by_band, by_pattern, top_identities, totals} |
| GET | /api/alerts?min_risk&band&pattern&identity&limit&offset | list[Alert] |
| GET | /api/alerts/{id} | Alert |
| GET | /api/alerts/{id}/events | list[Event] |
| POST | /api/alerts/{id}/action | ActionResult |
| POST | /api/alerts/{id}/feedback | Alert |
| GET | /api/identities?min_risk | list[{identity_id, risk, alerts, privilege_level, blast_radius}] |
| GET | /api/identities/{id}/graph | IdentityGraph |
| GET | /api/sessions/{id}/timeline | list[{event, signals}] |
| GET | /api/hygiene | {dormant_admins, escalation_paths} |
| GET | /api/metrics | Metrics |
| GET | /api/audit?limit | list[AuditEntry] |
| GET | /api/audit/verify | {valid, broken_at} |
| GET | /api/weights | {pattern: weight} |

Status codes: 404 not_found · 409 conflict · 422 validation_error · 503 pipeline_not_ready · 500 internal_error.
Routers are included **before** the static mount in `main.py`.

---

## 10. UI design system (professional security console)

**Goal:** looks like a real enterprise SOC product (think modern cloud-security dashboards): calm, dark, dense but readable, no gimmicks.

### 10.1 Tailwind config (put in every page `<head>` right after the Tailwind CDN script)

```html
<script>
tailwind.config = {
  theme: {
    extend: {
      fontFamily: { sans: ['Inter', 'system-ui', 'sans-serif'], mono: ['JetBrains Mono', 'monospace'] },
      colors: {
        bg:      '#0B0F17',
        panel:   '#111827',
        panel2:  '#161E2E',
        line:    '#1F2A3C',
        muted:   '#8A97AD',
        ink:     '#E6EBF2',
        brand:   '#3B82F6',
        brand2:  '#22D3EE',
        ok:      '#10B981',
        warn:    '#F59E0B',
        high:    '#F97316',
        crit:    '#EF4444',
      }
    }
  }
}
</script>
```

### 10.2 Layout

- **Left sidebar** (240 px, `bg-panel`, border-right `line`): logo mark (shield SVG + "IdentityShield"), nav items with inline SVG icons: Overview, Alerts, Identities, Hygiene, Audit. Active item: `bg-panel2`, left 2px `brand` bar, `text-ink`. Collapses to a top bar with a menu button under 768 px.
- **Top bar** (64 px, border-bottom `line`): page title + subtitle on the left; on the right a pipeline status pill (green "Pipeline OK", amber "Degraded", red "Failed"), data-mode pill ("Official data" / "Sample data"), and a "Re-run pipeline" button.
- **Content:** `max-w-7xl`, padding 24 px, 24 px gaps.
- Background `bg-bg`, text `text-ink`, secondary text `text-muted`.

### 10.3 Components (implemented once in `static/js/ui.js`, reused everywhere)

| Component | Spec |
|---|---|
| Card | `bg-panel border border-line rounded-xl p-5`; header row with title (`text-sm font-semibold`) and optional action |
| Stat card | label (`text-xs uppercase tracking-wide text-muted`), value (`text-3xl font-semibold tabular-nums`), small delta/note |
| Band badge | pill `text-xs font-medium px-2 py-0.5 rounded-full` with 15% tinted background: monitor slate, step_up warn, restrict high, revoke crit; labels "Monitor", "Step-up", "Restrict", "Revoke" |
| Pattern chip | mono `text-[11px]` chip, `bg-panel2 border border-line`, e.g. "P3 Escalation" |
| MITRE chip | mono chip with brand2 text, e.g. "T1098" |
| Risk ring | SVG circular gauge 0-100, stroke color by band, number centered |
| Risk bar | thin 4 px bar in tables, width = risk% |
| Table | `text-sm`, sticky header `bg-panel2 text-muted text-xs uppercase`, row hover `bg-panel2`, row borders `line`, numbers `tabular-nums` |
| Button | primary `bg-brand hover:bg-blue-500 text-white rounded-lg px-3.5 py-2 text-sm font-medium`; secondary `border border-line hover:bg-panel2`; danger `bg-crit/90 hover:bg-crit` |
| Toast | bottom-right stack, auto-hide 4 s, success/error variants |
| Skeleton | pulsing `bg-panel2` blocks while loading |
| Empty state | icon + one line + optional action |
| Error state | inline card with error text from ErrorResponse + "Retry" button |
| Modal (confirm) | in-flow centered card used for "Approve revoke?" confirmation |

### 10.4 Page layouts

| Page | Layout |
|---|---|
| Overview (`index.html`) | Row of 4 stat cards (Total alerts · Critical (revoke) · Identities at risk · F1 vs baseline) → 2-column: "Alerts by attack pattern" bar chart (Chart.js) + "Risk distribution" doughnut by band → "Top risky identities" table (identity, risk bar, alerts, blast radius) → "Latest critical alerts" list |
| Alerts | Filter bar (search identity, band select, pattern select, min-risk slider) → table: Risk (ring small or number+bar), Band, Identity, Session, Patterns, MITRE, Recommended, Status, Last seen; click row → alert.html?id= |
| Alert detail | Header card: risk ring, band badge, identity, session, first/last seen, action buttons → 2-column: left "Why this was flagged" (reasons list, counterfactual table "Score without each signal"), "Attack chain" vertical stepper with states and timestamps, "Predicted next step" callout (brand2 border); right "Evidence events" table (mono event IDs), "Recommended response" card with Apply / Approve revoke / Dismiss, "Analyst feedback" (True positive / False positive) → links to Graph and Timeline |
| Identities | Table of identities with risk, privilege, blast radius, alerts; click → graph.html?identity= |
| Graph | Full-width card with vis-network canvas (600 px tall) + right panel: legend by node kind, escalation paths list, blast radius |
| Timeline | Session header → horizontal slider + play button → vertical event list where events up to the slider are revealed; signals shown as chips on the event that triggered them |
| Hygiene | Two cards: "Dormant privileged accounts" table, "Paths to admin" table |
| Audit | Verification banner (valid = green check "Chain intact", invalid = red with seq) → audit table (seq, time, agent, action, detail, short hash in mono) |

### 10.5 UX rules

- Every page: skeleton while loading, empty state if no data, error state on failure.
- Numbers right-aligned, `tabular-nums`; times shown in local time, short format.
- Never show raw JSON to users.
- Colors carry meaning only through band/severity; everything else neutral.
- Responsive down to 375 px (tables scroll horizontally inside their card).
- `?mock=1` in the URL makes `api.js` read `static/mock/*.json` instead of the API.

---

## 11. Commands

| Purpose | Command |
|---|---|
| Install | `python -m venv .venv` → activate → `pip install -r requirements.txt` |
| Run | `python -m uvicorn app.main:app --reload` |
| Smoke test | `python smoke_test.py` (must print `SMOKE TEST PASSED`) |
| Unit tests | `pytest -q` |
| Commit | `git add . && git commit -m "phase N ok"` |

---

## 12. Progress log (agent updates after each phase)

| Phase | Name | Status | Notes |
|---|---|---|---|
| 0 | Scaffold | ☑ | pre-built, verified |
| 1 | Contracts, config, utils | ☑ | pre-built, verified |
| 2 | Store and audit | ☑ | pre-built, verified |
| 3 | Sample data | ☑ | generated 2,306 CT / 661 Okta records with S1-S5 |
| 4 | Loaders and normalize | ☑ | normalized 2,967 events, 0 skipped, 20 identities |
| 5 | Enrich, sessions, graph | ☑ | enriched, 661 sessions assigned, 1,173 graph nodes |
| 6 | Rule detectors P1-P3 | ☑ | P1 (anita.rao), P2 (svc-report), P3 (svc-report 4-step chain) |
| 7 | Rule detectors P4-P5 | ☑ | P4 (dev.kumar StopLogging), P5 (meera.n token abuse) |
| 8 | ML module | ☑ | features (661,14), AnomalyModel IF, ChainModel Markov, PeerModel KM, Calibrator |
| 9 | Decision + simulator | ☑ | scoring, explain, respond, feedback, simulator, test_scoring 5/5 |
| 10 | Pipeline + evaluation | ☑ | status ok, 16 alerts, top: svc-report (revoke), meera.n, dev.kumar, anita.rao; F1 0.537 > baseline 0.0 |
| 11 | API + main | ☑ | smoke_test passed, all 13 REST endpoints verified |
| 12 | UI foundation | ☑ | 8 HTML shells, Tailwind dark theme, api.js with mock mode, ui.js components, layout.js, 13 mock fixtures |
| 13 | Overview + Alerts pages | ☑ | Overview dashboard with Chart.js charts, KPIs, top identities; Alerts queue with interactive filter bar and keyboard accessible table |
| 14 | Alert detail page | ☑ | Header with risk ring (size 96), action buttons, confirm modal for revoke, why flagged, counterfactual table, attack chain stepper, predicted next step, evidence table, feedback loop |
| 15 | Identities, Graph, Timeline | ☑ | Interactive identities table, vis-network graph with escalation paths, and step-by-step session attack activity replay timeline |
| 16 | Hygiene, Audit | ☑ | Posture hygiene with dormant privileged accounts and paths to admin; tamper-evident audit ledger with chain verification |
| 17 | Live wiring + tests | ☑ | 33 pytest tests passing across utils, normalize, detectors S1-S5, API actions/feedback; mock vs live API verified |
| 18 | Polish + demo prep | ☑ | Inline SVG shield favicon, subtle demo scenario card on overview, accessibility labels, professional README.md |

Status values: ☐ not started · ◐ in progress · ☑ done (check passed).

---

## 13. Decisions log (append only)

| # | Decision | Reason |
|---|---|---|
| 1 | Single FastAPI process serves API + static site | No CORS, one command |
| 2 | No frontend build; Tailwind/Chart.js/vis via CDN | Avoid npm errors, faster generation |
| 3 | SQLite via stdlib, no ORM | No migrations |
| 4 | Synchronous pipeline at startup + re-run endpoint | Simpler, no race conditions |
| 5 | Sidebar layout replaces the top nav described in TECH_PRD | More professional console look |
| 6 | Phases 0–2 (contracts, config, utils, store, audit) ship pre-built and tested | Removes the highest-risk backend errors before AI generation starts |
| 7 | Where TECH_PRD and pre-built code differ, the pre-built code wins | Code was tested; docs are reference |

---

## 14. Known issues (agent appends if found)

| # | Issue | Status |
|---|---|---|
| 1 | ActionRequest schema defaulted approved_by='analyst', which bypassed 409 guard on unapproved revoke requests | Fixed: checked req.model_fields_set in alerts.py |

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
| 20 | Audit verification and consistency fixes | ☑ | checked thresholds, added constants, added check_ref tool, updated AUDIT_REPORT |
| 21 | Official data run, baseline, export, latency | ☑ | data recon, fallback mappings, export CLI, baseline logging, latency replay (p50=1640ms, 259.6 ev/s) |
| 22 | Analytics backend | ☑ | app/analytics.py from REF_02, app/notify.py from REF_03, tests from REF_05, app/api/analytics.py, 46 tests passing |
| 23 | Analytics UI | ☑ | static/analytics.html, analytics.js (winner, 3 cards, chart, detection matrix, agreement, heatmaps, definitions), overview card, mock fixtures |
| 24 | Email notifier backend | ☑ | app/notify.py from REF_03, .env.example, app/api/notifications.py, outbox & digest wiring, 50 tests passing |
| 25 | Notifications UI | ☑ | static/notifications.html, static/js/notifications.js (status card, expandable history), alert.js 'Email admin' button |
| 26 | Background pipeline runs | ☑ | app/runner.py from REF_04, app/trace.py from REF_09, REF_08 in config.py, async 202 runner, 54 tests passing |
| 27 | Offline assets | ☑ | vendored assets in static/vendor, replaced CDN links in all HTML files, tests/test_vendor.py passing |
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

---

## 21. v2.1 scope

Adds: the 15-agent trace and Agents page (P31–P32), the Live scan page with full-color console and full JSON (P33), one audit entry per detected threat (P31), input-only data entry (P34–P35), and the Attack Path Explorer graph (P36).
Spec: `kit_v2/08_FEATURE_AGENTS_SCAN_INPUT_GRAPH_SPEC.md`. Pre-tested code: `kit_v2/reference/REF_08` to `REF_18`.

## 22. v2.1 golden rules (in addition to Sections 2 and 16)

22.1 Agent ids are fixed (spec §2.1): ingestion, normalization, enrichment, correlation, impossible_travel, dormant,
     priv_escalation, api_anomaly, token_abuse, baseline_ml, risk_scoring, explanation, response, feedback, orchestrator.
22.2 Pipeline steps are traced with `with trace.step(agent_id, message) as s: ... s.output({...}, message)` INSIDE the
     existing try blocks. Trace outputs are small summaries, never DataFrames. Only the runner calls begin_run / end_run /
     log_threats.
22.3 Threats are audited ONLY through `trace.log_threats()` (one entry per threat, deduplicated). Never write threat audit
     entries anywhere else, and never delete audit rows (that breaks the hash chain by design).
22.4 Browser pages built in v2.1 escape every dynamic value with `escHtml` from `static/js/jsonview.js` (it also escapes
     quotes for attributes). Never render log content as HTML.
22.5 Pre-built browser files (`jsonview.js`, `graphfx.js`, `scan.js`, `graph.js`) are copied exactly. If something
     around them differs (api.js / ui.js / layout.js contracts), adapt THOSE files, not the reference files.
22.6 Input data is parsed as JSON only, size- and count-limited, and written only under `data/input/` (git-ignored).
22.7 `app/models.py` stays frozen; request models for new endpoints live in their router files.

## 23. v2.1 files and API

```text
app/trace.py (REF_09) · app/scan.py (REF_10) · app/inputs.py (REF_11) · app/runner.py (REF_04, v2.1)
app/api/scan.py · app/api/inputs.py · app/api/identities.py (+ /attack, /graph/global)
static/agents.html + js/agents.js · static/scan.html + js/scan.js (REF_16) · static/input.html + js/input.js
static/js/jsonview.js (REF_14) · static/js/graphfx.js (REF_15) · static/js/graph.js (REF_17, replaced)
static/mock/agents.json, scan_status.json, scan_trace.json, inputs.json, graph_attack.json, graph_global.json
tests/test_v21_trace.py (REF_12) · tests/test_v21_inputs.py (REF_13)
data/input/ (runtime, git-ignored)
```

| Method | Path | Returns |
|---|---|---|
| GET | /api/agents | {agents, run} |
| GET | /api/scan/status | run status |
| GET | /api/scan/trace?after&limit&run_id | {run_id, state, last_seq, events} |
| GET | /api/inputs | {files, totals, total_records, limits} |
| POST | /api/inputs/upload | {accepted, rejected, errors, files} |
| POST | /api/inputs/manual | {source, file, record} |
| DELETE | /api/inputs | {removed} |
| GET | /api/identities/{id}/attack | {identity_id, identity, graph, alert, blast_radius} |
| GET | /api/graph/global?top | {identities, nodes, edges, truncated} |
| POST | /api/pipeline/run | body may include input_mode "only" or "merge" |

Sidebar order after v2.1: Overview · Live scan · Agents · Input data · Alerts · Identities · Analytics · Hygiene · Audit · Notifications.

## 24. v2.1 progress log

| Phase | Name | Status | Notes |
|---|---|---|---|
| 31 | Agent trace, threat audit, terminal scan | ☑ | trace instrumentation (13 scan agents), threat audit entries, scan CLI, scan API, 66 tests passing |
| 32 | Agents dashboard | ☐ | |
| 33 | Live scan page | ☐ | |
| 34 | Data input backend | ☐ | |
| 35 | Input page UI | ☐ | |
| 36 | Attack Path Explorer | ☐ | |


