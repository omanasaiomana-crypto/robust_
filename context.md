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
| 16 | Hygiene, Audit | ☐ | |
| 17 | Live wiring + tests | ☐ | |
| 18 | Polish + demo prep | ☐ | |

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
| | | |
