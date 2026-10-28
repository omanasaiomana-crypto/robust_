# BUILD_PROMPTS.md: IdentityShield build kit (all phases in one file)

Same content as the `prompts/` folder. Send ONE phase at a time; run its CHECK before moving on.

---

## Prompt templates (use any time)


### T1: Session start (send once whenever you open a new Antigravity chat)

```text
Read context.md fully. It is the single source of truth for this project.
Summarize in 5 bullet points: what we are building, the golden rules, the tech stack,
the current progress from Section 12, and the next phase to do.
Do not write any code yet.
```

### T2: Fix an error (use whenever a CHECK fails)

```text
Read context.md Section 2 (golden rules).
The CHECK for Phase <N> failed with this exact output:
<paste full traceback or console error>
Fix ONLY the cause of this error, ONLY in these files: <file list>.
Do not refactor, rename, add dependencies, or touch other files.
Explain the root cause in one sentence, then show the change.
```

### T3: Resume after interruption

```text
Read context.md. Look at Section 12 (progress log) and the files that exist in the project.
Tell me which phase is in progress, which files of that phase exist, and what is missing.
Do not write code until I confirm.
```

### T4: Scope guard (send if the agent goes off-track)

```text
Stop. Revert any change to files not named in the current prompt.
Follow context.md Section 2 rule 10: only modify the files named in the prompt.
```

---

## PHASES 0–2: Verify the pre-built foundation (≈10 min) · Person A

The kit already contains the scaffold (Phase 0), contracts, config and utilities (Phase 1), and the
database and audit log (Phase 2). They were written by hand and tested, so **do not let the agent
regenerate them**. You only install and verify.

## Step 1: Install (human, in a terminal at the project root)

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS / Linux:
source .venv/bin/activate
pip install -r requirements.txt
```

Use Python 3.11. If one pinned version fails to install, remove only that pin and retry.

## Step 2: Send this prompt to Antigravity

```text
Read context.md fully. Phases 0, 1 and 2 are PRE-BUILT and tested. Do NOT rewrite, reformat or
"improve" these files: app/config.py, app/models.py, app/utils.py, app/store.py, app/audit.py,
smoke_test.py, tests/test_foundation.py, requirements.txt, run.bat, run.sh, .gitignore.

Task:
1. List any folder or file from context.md Section 4 that is missing. Create ONLY missing empty
   placeholders (empty .py files, empty .html/.js files). Do not write logic.
2. Read app/models.py, app/config.py, app/utils.py, app/store.py and app/audit.py so you know the
   exact names you must use in later phases. Summarize their public functions in a short list.
3. Update context.md Section 12: Phases 0, 1, 2 = ☑ with note "pre-built, verified".
Do not modify any other file.
```

## Step 3: CHECK (human)

```bash
python -m pytest -q tests/test_foundation.py
python -c "from app.models import Alert, Event, Signal, Health; from app.utils import parse_ts, to_band, haversine_km; print(parse_ts('2026-10-28T09:00:00Z'), to_band(95), round(haversine_km(12.97,77.59,50.11,8.68)))"
python -c "from app import store, audit; store.init_db(); audit.append('test','init','ok'); print(audit.verify()); print(store.get_weights())"
```

Expected:
- `5 passed`
- `2026-10-28 09:00:00+00:00 revoke 7406`
- `(True, None)` and the weights dict

---

**After the CHECK passes:** `git add . && git commit -m "foundation ok"` and push, so the whole team
pulls the same contracts before starting their phases.


---

## PHASE 3: Sample data generator (≈15 min) · Person B

```text
Read context.md fully. Then read docs/TECH_PRD.md Sections 9.3, 9.4 and 20.4.

GOAL: Generate realistic CloudTrail and Okta sample logs with all 5 attack scenarios, so the
whole system works without official data.

DO: write app/sample_data.py with:
  def generate(out_dir: Path, days: int = 60) -> dict  (returns counts per scenario)

Requirements:
- random.seed(42); timestamps are ISO strings ending in "Z"; base date = 60 days before 2026-10-28.
- Write out_dir/cloudtrail.json as {"Records": [...]} using real CloudTrail field names:
  eventID, eventTime, eventName, eventSource, awsRegion, sourceIPAddress, userAgent,
  userIdentity {type, userName, arn, accessKeyId}, requestParameters, resources, errorCode (rare).
- Write out_dir/okta.json as a JSON array using real Okta field names:
  uuid, published, eventType, actor {id, alternateId}, outcome {result},
  client {ipAddress, userAgent {rawUserAgent}, geographicalContext {country, city,
  geolocation {lat, lon}}}, authenticationContext {externalSessionId}, securityContext {asNumber}.
- Write out_dir/metadata.json: list of identities with identity_id, email, privilege_level, groups.
- Every record has a top-level "label": "benign" or the scenario name.
- Normal behavior: 20 users (Indian first names, e.g. anita.rao, dev.kumar, meera.n, plus
  svc-report service account), weekday logins 09:00–18:00 IST from Bengaluru/Mysuru/Chennai/Hyderabad
  with correct lat/lon, routine actions (s3:GetObject, ec2:DescribeInstances, ListBuckets).
- Okta email local part must equal the AWS userName (e.g. dev.kumar@corp.example / dev.kumar).
- Scenarios exactly as in TECH_PRD 20.4:
  S1 impossible_travel (anita.rao: Bengaluru then Frankfurt 30 min later),
  S2 dormant_reactivation (svc-report silent 47 days, then active),
  S3 privilege_escalation (svc-report: CreateAccessKey → AttachUserPolicy AdministratorAccess
     → AssumeRole AdminRole → GetSecretValue within 15 minutes),
  S4 unusual_api (dev.kumar: StopLogging in a never-used region),
  S5 token_abuse (meera.n: same accessKeyId from India and Brazil within 3 minutes, and use after
     an Okta user.session.end).
- Place all attack scenarios in the last 2 days of the window.
- Add if __name__ == "__main__": generate(SAMPLE_DIR) and log counts.

FILES: app/sample_data.py only.

CHECK:
python -m app.sample_data
python -c "import json; d=json.load(open('data/sample/cloudtrail.json',encoding='utf-8')); print(len(d['Records']))"
Expected: a few thousand records and the 3 files in data/sample/.
Then update context.md Section 12: Phase 3 = ☑.
```

---

**After the CHECK passes:** `git add . && git commit -m "phase 3 ok"`, then open the next file.
**If the CHECK fails:** use template T2 in `prompts/00_templates.md` with the exact error.


---

## PHASE 4: Loaders and normalization (≈20 min) · Person B

```text
Read context.md fully. Then read docs/TECH_PRD.md Sections 9.1–9.5 and 9.7.

GOAL: Load any supported file format and convert CloudTrail + Okta into the Event table.

DO:
1. app/ingest/loaders.py:
   - load_cloudtrail(folder: Path) -> tuple[list[dict], int]
   - load_okta(folder: Path) -> tuple[list[dict], int]
   - load_metadata(folder: Path) -> dict[str, dict]   (identity_id -> attributes)
   - load_labels(folder: Path) -> dict[str, str]     (event_id -> label)
   Support: {"Records": [...]}, JSON array, JSON Lines, .gz versions, CSV. Detect format by
   extension and first non-space character. Files sorted by name. A corrupt file or line is skipped
   and counted, never raised. A missing folder returns ([], 0).
   For the sample folder, cloudtrail.json and okta.json are in the same folder: load_cloudtrail
   reads files whose name contains "cloudtrail" or that have a "Records" key; load_okta reads files
   whose name contains "okta".
2. app/ingest/normalize.py:
   - canonical_identity(value: str | None) -> str  (lowercase; email → local part; arn → last segment
     after "/"; None → "unknown")
   - normalize_cloudtrail(rec: dict, idx: int) -> Event | None
   - normalize_okta(rec: dict, idx: int) -> Event | None
   - normalize_all(ct: list[dict], okta: list[dict]) -> tuple[pd.DataFrame, int]
   Follow the mapping tables in TECH_PRD 9.3 and 9.4 exactly, using dig() and parse_ts().
   Records with no timestamp are skipped and counted. Keep the top-level "label" field if present.
   DataFrame columns = Event model fields in model order; sorted by timestamp; index reset.
   Build rows with event.model_dump() and create the DataFrame once at the end (not row by row).

FILES: app/ingest/loaders.py, app/ingest/normalize.py

CHECK:
python -c "from app.config import SAMPLE_DIR; from app.ingest.loaders import load_cloudtrail, load_okta; from app.ingest.normalize import normalize_all; ct,a=load_cloudtrail(SAMPLE_DIR); ok,b=load_okta(SAMPLE_DIR); df,s=normalize_all(ct,ok); print(df.shape, s, df['source'].value_counts().to_dict(), df['identity_id'].nunique())"
Expected: thousands of rows, both sources present, about 20 identities, skipped close to 0.
Then update context.md Section 12: Phase 4 = ☑.
```

---

**After the CHECK passes:** `git add . && git commit -m "phase 4 ok"`, then open the next file.
**If the CHECK fails:** use template T2 in `prompts/00_templates.md` with the exact error.


---

## PHASE 5: Enrichment, sessions, identity graph (≈25 min) · Person B

```text
Read context.md fully. Then read docs/TECH_PRD.md Sections 9.6, 10.1, 10.2, 10.3.

GOAL: Add context to events, link Okta sessions to AWS activity, and build the identity graph.

DO:
1. app/ingest/enrich.py: enrich(df: pd.DataFrame, metadata: dict) -> pd.DataFrame
   - privilege_level from metadata, else inferred (admin → 5, power/ops → 3, else 1).
   - resource_sensitivity rules from TECH_PRD 9.6.
   - For CloudTrail rows missing lat/lon/country: copy from the most recent Okta login of the same
     identity with the same src_ip (use pandas merge_asof by timestamp, grouped by identity_id).
     Both frames must be sorted by timestamp before merge_asof. If it fails, leave values None.
   - Never drop rows.
2. app/correlate/sessions.py: assign_sessions(df) -> pd.DataFrame following TECH_PRD 10.1
   (okta:<externalSessionId>; CloudTrail linked to an Okta session of the same identity started
   within 12 h with matching IP; else aws:<identity>:<n> using 1-hour inactivity gaps per
   identity+token). Every row ends with a non-empty session_id.
3. app/correlate/graph.py with the 4 functions in TECH_PRD 10.3, returning models from app.models.
   Node and edge naming exactly as TECH_PRD 10.2. Use nx.MultiDiGraph. Path searches use cutoff=6.
   identity_subgraph keeps at most 150 nodes (most recent first) so the browser stays fast.
   blast_radius counts reachable resource nodes with sensitivity >= 4.

FILES: app/ingest/enrich.py, app/correlate/sessions.py, app/correlate/graph.py

CHECK: write and run a short script scratch_phase5.py (do not commit it) that loads sample data,
normalizes, enriches, assigns sessions, builds the graph and prints:
number of sessions, graph node and edge counts, blast_radius('svc-report'),
and len(identity_subgraph(g,'svc-report',set()).nodes).
Expected: no errors; svc-report blast radius > 0 after escalation.
Then update context.md Section 12: Phase 5 = ☑.
```

---

**After the CHECK passes:** `git add . && git commit -m "phase 5 ok"`, then open the next file.
**If the CHECK fails:** use template T2 in `prompts/00_templates.md` with the exact error.


---

## PHASE 6: Agent base + detectors P1, P2, P3 (≈25 min) · Person B

```text
Read context.md fully. Then read docs/TECH_PRD.md Sections 11.1, 11.2, 11.3.

GOAL: The first three detection agents.

DO:
1. app/agents/base.py: copy EXACTLY the Agent class in TECH_PRD 11.1.
2. app/agents/impossible_travel.py: class ImpossibleTravelAgent(Agent), name "impossible_travel",
   pattern P1, logic and severity per TECH_PRD 11.2, MITRE ["T1078"].
   Use only auth events with outcome success and non-null lat/lon. Ignore pairs where hours < 0.
3. app/agents/dormant.py: class DormantAccountAgent(Agent), name "dormant", P2, MITRE ["T1078.004"].
4. app/agents/priv_escalation.py: class PrivEscalationAgent(Agent), name "priv_escalation", P3,
   MITRE ["T1098","T1548"]. Use STATE_OF_ACTION and ESCALATION_ORDER from TECH_PRD 11.3 (define them
   in this file). A chain = ordered escalation states for one identity within
   config.ESCALATION_WINDOW_HOURS; emit when >= 2 distinct escalation states (Recon alone does not count).
   Store chains in self.last_chains: dict[str, list[ChainStep]] keyed by session_id.
Every Signal must have: a clear human-readable reason sentence with numbers
(e.g. "Login from Frankfurt, 7,400 km from Bengaluru, 30 min after previous login (14,800 km/h)."),
evidence_event_ids (non-empty), timestamp of the latest evidence event.

FILES: the 4 agent files above.

CHECK: scratch script that runs the Phase 5 steps then each agent, printing signal counts per agent
and one example reason each.
Expected: P1 fires for anita.rao, P2 for svc-report, P3 for svc-report with a chain of ≥ 3 steps.
Then update context.md Section 12: Phase 6 = ☑.
```

---

**After the CHECK passes:** `git add . && git commit -m "phase 6 ok"`, then open the next file.
**If the CHECK fails:** use template T2 in `prompts/00_templates.md` with the exact error.


---

## PHASE 7: Detectors P4, P5 (≈20 min) · Person B

```text
Read context.md fully. Then read docs/TECH_PRD.md Section 11.2.

GOAL: The remaining two rule agents.

DO:
1. app/agents/api_anomaly.py: class ApiAnomalyAgent(Agent), name "api_anomaly", P4,
   MITRE ["T1526","T1562"]. Identity rarity = 1 − count(identity, action)/count(identity).
   Peer rarity: if app.ml.peers is not available yet, treat peer rarity as 1.0 (wrap import in
   try/except ImportError). Flag new region for identity (region never seen in that identity's
   earlier events) and actions in config.SENSITIVE_ACTIONS. Only consider identities with >= 5 events
   for rarity (otherwise only sensitive-action and new-region rules apply).
   Severity: 0.5 base, +0.3 sensitive, +0.2 new region, capped at 1.0.
2. app/agents/token_abuse.py: class TokenAbuseAgent(Agent), name "token_abuse", P5,
   MITRE ["T1550","T1539"]. Rules: same token_id from a different IP than its first use;
   user_agent change within a session; token or session used after an Okta "user.session.end"
   event for that identity's session; same token from 2 different IPs within 5 minutes.
   Severity 0.6, or 0.9 for after-logout and concurrent use.

FILES: app/agents/api_anomaly.py, app/agents/token_abuse.py

CHECK: scratch script running both agents on sample data.
Expected: P4 fires for dev.kumar StopLogging; P5 fires for meera.n; normal users produce
at most a handful of P4/P5 signals.
Then update context.md Section 12: Phase 7 = ☑.
```

---

**After the CHECK passes:** `git add . && git commit -m "phase 7 ok"`, then open the next file.
**If the CHECK fails:** use template T2 in `prompts/00_templates.md` with the exact error.


---

## PHASE 8: ML module (≈30 min) · Person C

```text
Read context.md fully. Then read docs/TECH_PRD.md Section 12.

GOAL: Feature engineering, anomaly model, peer groups, Markov chain predictor, calibrator,
and the ML agent. Every model must degrade gracefully on small data.

DO:
1. app/ml/features.py: session_features(df) -> pd.DataFrame indexed by session_id with the columns
   in TECH_PRD 12.2 (peer_rarity_mean = 0 if peers unavailable). fillna(0), all float.
   Also return identity per session in a column "identity_id" kept OUT of the numeric feature set
   (provide numeric_columns() helper).
2. app/ml/anomaly.py: AnomalyModel exactly as TECH_PRD 12.3.
3. app/ml/peers.py: PeerModel with fit(df) -> bool and peer_rarity(identity_id, action) -> float.
   KMeans(n_clusters=min(5, n_identities), n_init=10, random_state=42); skip (return False) if
   fewer than 3 identities; peer_rarity returns 1.0 when not fitted.
4. app/ml/chain_model.py: ChainModel with fit(chains: list[list[str]]) -> None and
   predict(state: str) -> Prediction | None. Add-one smoothing; fallback prior from TECH_PRD 12.5
   when fewer than 5 chains. Predict never returns "Start".
5. app/ml/calibrate.py: Calibrator with fit(X, y) -> bool (needs both classes and >= 20 rows)
   and predict_proba(X) -> np.ndarray | None. LogisticRegression(class_weight="balanced", max_iter=1000).
6. app/agents/baseline_ml.py: BaselineMLAgent(Agent), name "baseline_ml", pattern "ML".
   detect(): build features, fit AnomalyModel on sessions (use sessions labeled "benign" if a label
   column has values, else all), score all sessions, emit a Signal for sessions with score >= 0.6
   with reason "Session behavior is unusual compared with normal activity (anomaly score 0.82)."
   and evidence = up to 5 event_ids of that session. Expose self.scores: dict[session_id, float].

FILES: the 6 files above.

CHECK: scratch script printing: feature table shape, top 5 anomaly scores with session ids,
ChainModel().predict("PermGrant"), and number of ML signals.
Expected: no exceptions; attack sessions appear among top anomaly scores.
Then update context.md Section 12: Phase 8 = ☑.
```

---

**After the CHECK passes:** `git add . && git commit -m "phase 8 ok"`, then open the next file.
**If the CHECK fails:** use template T2 in `prompts/00_templates.md` with the exact error.


---

## PHASE 9: Decision layer and simulator (≈30 min) · Person C

```text
Read context.md fully (especially Sections 6 and 8). Then read docs/TECH_PRD.md Section 13.

GOAL: Score, explain, recommend, apply via simulator, learn from feedback.

DO:
1. app/simulator/base.py: SimulatorAdapter with step_up, restrict, revoke (raise NotImplementedError).
2. app/simulator/mock.py: MockSimulator(SimulatorAdapter) storing calls in self.calls and returning
   "simulated:<action>:ok".
3. app/simulator/supplied.py: SuppliedSimulator(SimulatorAdapter) whose methods raise
   NotImplementedError("Configure the supplied simulator in app/simulator/supplied.py").
   Add get_simulator() in app/simulator/__init__.py returning MockSimulator unless
   config.SIMULATOR_MODE == "supplied".
4. app/decision/scoring.py:
   - score_session(signals: list[Signal], session_events: pd.DataFrame, weights: dict,
     prediction: Prediction | None, ml_score: float) -> tuple[float, float]  (risk, confidence)
     implementing context.md Section 8 exactly; risk rounded to 1 decimal.
   - counterfactuals(...) -> list[Counterfactual]
   - decayed(risk, hours, confirmed: bool) -> float
5. app/decision/explain.py: build_reasons(signals) -> list[str] (unique, ordered by severity desc),
   mitre_tags(signals) -> list[str] (unique, sorted), evidence_ids(signals, events) -> list[str]
   (unique, ordered by event timestamp).
6. app/decision/respond.py:
   - recommend(risk) -> str using to_band; maps band to action name (monitor, step_up, restrict, revoke).
   - apply_action(alert: Alert, action: str, approved_by: str | None, sim) -> ActionResult
     Safety guard: allowed actions only {"step_up","restrict","revoke","dismiss","monitor"};
     revoke requires approved_by when config.REQUIRE_APPROVAL_FOR_REVOKE; step_up consumes friction
     budget via store.friction_* and returns status "notified" when budget is exhausted;
     every call appends an audit entry with agent "response".
   - auto_apply(alert, sim) -> Alert: applies monitor/step_up/restrict automatically; leaves revoke "pending".
7. app/decision/feedback.py: apply_feedback(alert: Alert, label: str) -> dict[str, float]
   implementing TECH_PRD 13.5 with clipping, saving via store.set_weight, appending an audit entry.

FILES: the 9 files above.

ALSO write tests/test_scoring.py checking: bands at 39.9/40/69.9/70/89.9/90; more distinct patterns
→ higher risk; decayed halves at the half-life; revoke without approval is refused; feedback "tp"
raises the weight of the alert's patterns.

CHECK: pytest -q tests/test_scoring.py  → all pass.
Then update context.md Section 12: Phase 9 = ☑.
```

---

**After the CHECK passes:** `git add . && git commit -m "phase 9 ok"`, then open the next file.
**If the CHECK fails:** use template T2 in `prompts/00_templates.md` with the exact error.


---

## PHASE 10: Pipeline and evaluation (≈30 min) · Person A (+ C for evaluation)

```text
Read context.md fully (especially Section 7). Then read docs/TECH_PRD.md Section 14.

GOAL: One function that runs everything in order and never crashes the server.

DO:
1. app/pipeline.py:
   - @dataclass PipelineResult(events, graph, alerts, metrics, status, detail, data_mode,
     signals, step_errors: list[str], timings_ms: dict[str, float]).
   - run_pipeline(use_sample: bool | None = None) -> PipelineResult following context.md Section 7.
   - Data selection: if use_sample is True → generate sample (if missing) and use SAMPLE_DIR.
     If None → use data/raw if it contains files, else sample when USE_SAMPLE_IF_NO_DATA.
   - Each numbered step is in its own try/except; errors go to step_errors and logging.exception.
     If loading/normalizing fails, return status "failed" with empty alerts.
     If a later step fails, continue with what exists and set status "degraded".
   - Group signals by session_id; for each session with at least one rule signal or ML score >= 0.6,
     create one Alert (ids AL-0001… after sorting by risk desc). Fill chain and prediction from
     PrivEscalationAgent.last_chains and ChainModel. Fill blast_radius from graph.
   - Call store.reset_run_tables(), store.save_alerts(), audit.append for pipeline start/end and for
     each alert with risk >= 70. Then auto_apply each alert via get_simulator() and save again.
   - Also expose get_identity_rows(result) -> list[dict] for the /identities endpoint
     (identity_id, risk = max alert risk, alerts count, privilege_level, blast_radius).
2. app/evaluation.py:
   - compute_metrics(events_df, alerts, signals, skipped) -> Metrics
   - Event-level: an event is "predicted malicious" if its event_id is in any alert's
     evidence_event_ids; truth = label not in (None, "", "benign").
   - Session-level precision: alerts whose session contains at least one malicious event / all alerts.
   - Baseline: simple detector that flags failed logins and any event from an IP seen with ≥ 3 failures;
     compute its event F1 as baseline_event_f1. If official baseline output exists in data/labels,
     use it instead.
   - If no labels exist, precision/recall/F1 stay None.
   - median_latency_ms = pipeline detection time divided by number of events, × 1000.

FILES: app/pipeline.py, app/evaluation.py

CHECK:
python -c "from app import store; store.init_db(); from app.pipeline import run_pipeline; r=run_pipeline(use_sample=True); print(r.status, r.data_mode, len(r.alerts), r.step_errors); print([(a.alert_id,a.identity_id,a.risk,a.band,a.patterns) for a in r.alerts[:5]]); print(r.metrics)"
Expected: status ok, 5+ alerts; the top alerts include svc-report (revoke band), anita.rao, meera.n,
dev.kumar; metrics show F1 higher than baseline_event_f1.
Then update context.md Section 12: Phase 10 = ☑.
```

---

**After the CHECK passes:** `git add . && git commit -m "phase 10 ok"`, then open the next file.
**If the CHECK fails:** use template T2 in `prompts/00_templates.md` with the exact error.


---

## PHASE 11: API and main app (≈30 min) · Person A

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


---

## PHASE 12: UI foundation (≈25 min) · Person D

```text
Read context.md fully, especially Section 10 (UI design system). Follow it exactly.

GOAL: Shared UI foundation: page shells, sidebar layout, API client with mock mode, component
library. The result must look like a professional enterprise security console.

DO:
1. Every HTML page in static/ (index, alerts, alert, identities, graph, timeline, hygiene, audit)
   uses this head (adjust the title):
   <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
   <title>IdentityShield · <Page></title>
   <link rel="preconnect" href="https://fonts.googleapis.com">
   <link href="<Inter + JetBrains Mono URL from context.md Section 3>" rel="stylesheet">
   <script src="https://cdn.tailwindcss.com"></script>
   <script> tailwind.config = <exactly as context.md 10.1> </script>
   <link rel="stylesheet" href="/css/app.css">
   Body: class="bg-bg text-ink font-sans antialiased"; contains <div id="app"></div> and
   <script type="module" src="/js/<page>.js"></script>. Pages needing Chart.js or vis-network include
   those CDN scripts BEFORE the module script.
2. static/js/api.js:
   - export async function api(path, {method="GET", body}={}) → returns parsed JSON or throws an Error
     whose message is "<error>: <detail>" from ErrorResponse.
   - Mock mode when location.search contains "mock=1": GET maps paths to /mock/<name>.json using this table:
     /health→health, /summary→summary, /alerts→alerts, /alerts/{id}→alert, /alerts/{id}/events→events,
     /identities→identities, /identities/{id}/graph→graph, /sessions/{id}/timeline→timeline,
     /hygiene→hygiene, /metrics→metrics, /audit→audit, /audit/verify→audit_verify, /weights→weights.
     Mock POST returns {status:"mocked", detail:"mock mode"}.
   - export function esc(value) (HTML escape), qs(name) (URL query param), fmtTime(iso) (local short
     date-time), fmtNum(n).
3. static/js/ui.js: export functions returning HTML strings (all dynamic values passed through esc):
   card(title, bodyHtml, actionHtml?), statCard(label, value, note?), bandBadge(band),
   patternChip(code), mitreChip(id), riskRing(risk, band, size=72), riskBar(risk, band),
   table(columns, rowsHtml), button(label, {variant, id, attrs}), skeleton(lines=4),
   emptyState(message), errorState(message, retryId), plus
   toast(message, type="success"|"error") (appends to a fixed bottom-right container) and
   confirmModal(title, message) → Promise<boolean> (in-flow overlay card, Escape/Cancel = false).
   Band styles and labels exactly as context.md 10.3. Pattern names: P1 Impossible travel,
   P2 Dormant account, P3 Privilege escalation, P4 Unusual API, P5 Token abuse, ML Behavior anomaly.
4. static/js/layout.js: export function renderLayout(active, title, subtitle) that builds the sidebar
   + top bar from context.md 10.2 into #app and returns the content element. Sidebar items with inline
   SVG icons (shield logo, gauge, bell, users, broom/check, list). Top bar loads /health and shows the
   pipeline status pill and data-mode pill; "Re-run pipeline" button POSTs /pipeline/run, shows a
   toast, then reloads the page. Mobile (< 768 px): sidebar hidden behind a menu button.
   Keep the ?mock=1 query when building nav links.
5. static/css/app.css: small file only: custom scrollbar, .tabular-nums, focus-visible ring using brand,
   table sticky header helper, skeleton pulse.
6. static/mock/: create realistic mock JSON files for every name in the table above, matching
   context.md Section 5 field names exactly (use svc-report, anita.rao, meera.n, dev.kumar scenarios;
   alert.json = the svc-report revoke alert with chain, prediction, counterfactuals).
7. Each page's JS file for now only calls renderLayout(...) and shows a skeleton.

FILES: static/*.html, static/css/app.css, static/js/api.js, static/js/ui.js, static/js/layout.js,
static/js/<page>.js placeholders, static/mock/*.json

CHECK: run the server, open http://127.0.0.1:8000/index.html?mock=1 and every other page with ?mock=1.
Each shows the sidebar, top bar with status pills, correct active item, no console errors,
and works at 375 px width (DevTools device mode).
Then update context.md Section 12: Phase 12 = ☑.
```

---

**After the CHECK passes:** `git add . && git commit -m "phase 12 ok"`, then open the next file.
**If the CHECK fails:** use template T2 in `prompts/00_templates.md` with the exact error.


---

## PHASE 13: Overview and Alerts pages (≈30 min) · Person D

```text
Read context.md fully, especially Sections 9 and 10.4. Use ui.js components only (no new styles
unless necessary, and then only Tailwind classes).

GOAL: Professional Overview dashboard and Alerts queue.

DO:
1. static/js/overview.js:
   - Load /summary, /metrics, /alerts?min_risk=70&limit=5 in parallel (Promise.allSettled);
     show skeletons first; each section independently shows errorState on failure.
   - 4 stat cards: Total alerts, Critical (revoke band) in crit color, Identities at risk (risk >= 40),
     Detection F1 vs baseline (e.g. "0.91" with note "Baseline 0.42"; show "—" if null).
   - "Alerts by attack pattern" horizontal bar chart (Chart.js): dark theme (grid color #1F2A3C,
     tick color #8A97AD), bars in brand color, labels with pattern names.
   - "Risk distribution" doughnut by band with band colors from context 10.1, cutout 70%,
     legend at bottom.
   - "Top risky identities" table: identity (link to graph.html?identity=), risk bar + number,
     alerts, blast radius.
   - "Latest critical alerts" list: riskRing small, identity, patterns chips, time, link to alert.
   - Destroy existing Chart instances before re-creating them.
2. static/js/alerts.js:
   - Filter bar: search box (identity contains), band select, pattern select, min-risk range slider
     with live value; filters update the URL query (history.replaceState) and re-fetch /alerts.
   - Table columns: Risk (number + riskBar), Band, Identity, Session (mono, truncated with title),
     Patterns, MITRE, Recommended, Status, Last seen. Sorted by risk desc. Rows clickable and keyboard
     accessible (tabindex=0, Enter) → alert.html?id=<id> (keep ?mock=1 if present).
   - Count summary above table: "37 alerts · 6 critical".
   - Empty state "No alerts match these filters" with a "Clear filters" button.

FILES: static/js/overview.js, static/js/alerts.js (and index.html/alerts.html only if a script tag
must be added).

CHECK: index.html?mock=1 and alerts.html?mock=1 look complete and polished; filters work;
then same pages without ?mock=1 against the live server show real data with no console errors.
Then update context.md Section 12: Phase 13 = ☑.
```

---

**After the CHECK passes:** `git add . && git commit -m "phase 13 ok"`, then open the next file.
**If the CHECK fails:** use template T2 in `prompts/00_templates.md` with the exact error.


---

## PHASE 14: Alert detail page (≈30 min) · Person D

```text
Read context.md fully, especially Section 10.4 (Alert detail layout).

GOAL: The investigation page judges will look at most. It must be clear, beautiful and fast.

DO: static/js/alert.js
- Read id from ?id=. Missing id → emptyState with link back to alerts.
- Load /alerts/{id} and /alerts/{id}/events.
- Header card: riskRing (size 96), band badge, identity (large), session (mono), first seen → last seen,
  confidence as "Confidence 90%", blast radius, MITRE chips. Right side buttons:
  "Apply recommended" (primary; label shows the action, e.g. "Restrict access"),
  "Approve revoke" (danger; only when band is revoke; uses confirmModal first),
  "Dismiss" (secondary). After POST /action: toast with result.detail and refresh.
  Disable buttons when action_status is "applied".
- Left column:
  - "Why this was flagged": numbered reasons list.
  - "Score without each signal": small table (Signal removed | Risk | Change), change shown as
    "−42" in ok color; sorted by biggest change.
  - "Attack chain": vertical stepper; each step shows state name, action (mono), time;
    connector line between steps; last step highlighted.
  - "Predicted next step": callout with brand2 left border: "Next likely: Impact (71%)" and a one-line
    explanation of the state.
- Right column:
  - "Evidence": table of events (time, source badge CloudTrail/Okta, action mono, IP, location),
    event IDs in mono; highlight rows whose event_id is in evidence_event_ids.
  - "Analyst feedback": two buttons "True positive" / "False positive"; POST /feedback; toast
    "Feedback saved. Risk updated to 88."; show current feedback state.
  - Quick links: "Open identity graph" → graph.html?identity=, "Replay timeline" → timeline.html?session=.
- Two-column grid on large screens, single column on mobile.

FILES: static/js/alert.js (and alert.html only if a script tag must be added).

CHECK: alert.html?mock=1 looks complete; then live: open the svc-report alert, approve revoke
(confirm modal appears, status becomes applied, toast shown), submit feedback (risk updates).
Then update context.md Section 12: Phase 14 = ☑.
```

---

**After the CHECK passes:** `git add . && git commit -m "phase 14 ok"`, then open the next file.
**If the CHECK fails:** use template T2 in `prompts/00_templates.md` with the exact error.


---

## PHASE 15: Identities, Graph, Timeline pages (≈30 min) · Person D

```text
Read context.md fully, especially Section 10.4.

GOAL: Visual investigation pages.

DO:
1. static/js/identities.js: table from /identities: identity (with initials avatar circle), risk bar,
   band badge (from risk), privilege level (1-5 dots), blast radius, alerts; search box;
   row click → graph.html?identity=.
2. static/js/graph.js:
   - Read ?identity=; load /identities/{id}/graph.
   - vis-network inside a card, height 600 px, background transparent.
     Node colors by kind: user #22D3EE, session #8B5CF6, role #F59E0B, key #F97316, policy #EF4444,
     resource #10B981, ip #64748B. Font color #E6EBF2, size 12. Suspicious edges red (#EF4444) width 3,
     others #334155 width 1, arrows "to", smooth curves.
     physics barnesHut with stabilization, then disable physics after stabilization so it stops moving.
   - Right panel: legend (colored dots + kind names), blast radius stat, "Paths to admin" list
     (each path as chips joined by →), and a "Fit view" button (network.fit()).
   - Clicking a node shows its label and kind in a small details box.
   - Guard: if typeof vis === "undefined", show errorState("Graph library failed to load").
3. static/js/timeline.js:
   - Read ?session=; load /sessions/{id}/timeline.
   - Controls: Play/Pause button, range slider (0..n), step counter "Step 3 of 9", speed select (1x, 2x).
   - Vertical list of events; events beyond the slider position are dimmed (opacity-30);
     the current event is highlighted with a brand ring. Each event shows time, source badge,
     action (mono), IP/location, and signal chips (pattern + short reason) when present.
   - Auto-scroll the current event into view. Stop at the end.

FILES: static/js/identities.js, static/js/graph.js, static/js/timeline.js (and their HTML files only
if a script tag must be added).

CHECK: all three pages with ?mock=1 and live data; graph renders and stops moving; timeline plays
smoothly; no console errors.
Then update context.md Section 12: Phase 15 = ☑.
```

---

**After the CHECK passes:** `git add . && git commit -m "phase 15 ok"`, then open the next file.
**If the CHECK fails:** use template T2 in `prompts/00_templates.md` with the exact error.


---

## PHASE 16: Hygiene and Audit pages (≈20 min) · Person D

```text
Read context.md fully, especially Section 10.4.

GOAL: Prevention and trust pages.

DO:
1. static/js/hygiene.js: load /hygiene.
   - Card "Dormant privileged accounts": table identity, privilege dots, days idle, last activity,
     risk badge; empty state "No dormant privileged accounts".
   - Card "Paths to admin": each row = identity + path as chips joined by arrows; link to graph.
   - Small explanatory note under each card title (one sentence, text-muted).
2. static/js/audit.js: load /audit/verify and /audit.
   - Banner: valid → ok-colored card with check icon "Audit chain intact · <n> entries verified";
     invalid → crit card "Audit chain broken at entry #<seq>".
   - Table: seq, time, agent (chip), action, detail (truncate with title), hash (first 12 chars, mono).
   - "Verify again" button re-runs verify and shows a toast.

FILES: static/js/hygiene.js, static/js/audit.js

CHECK: both pages with ?mock=1 and live data, no console errors.
Then update context.md Section 12: Phase 16 = ☑.
```

---

**After the CHECK passes:** `git add . && git commit -m "phase 16 ok"`, then open the next file.
**If the CHECK fails:** use template T2 in `prompts/00_templates.md` with the exact error.


---

## PHASE 17: Live wiring and tests (≈30 min) · Person A + D

```text
Read context.md fully.

GOAL: Make sure the live website and backend agree everywhere, and add tests.

DO:
1. Compare every static/mock/*.json file with the real API response of the same endpoint
   (run the server and fetch them). List any field name or shape differences. Fix differences in the
   FRONTEND JS only (the backend contract in app/models.py is frozen) unless the backend violates
   context.md Section 9; in that case report it before changing backend files.
2. Write tests per docs/TECH_PRD.md Section 20.1:
   tests/test_utils.py, tests/test_normalize.py, tests/test_detectors.py (run on generated sample
   data; each scenario's pattern fires for the right identity), tests/test_api.py (copy TECH_PRD 20.2,
   plus: action on unknown alert → 404, revoke without approved_by → 409 if approval required,
   feedback returns an Alert).
3. Do not change application code to make a test pass unless it is a real bug; if so, report the bug
   in context.md Section 14 and fix it minimally.

FILES: tests/*.py, static/js/*.js (only if mismatches found), context.md Sections 12 and 14.

CHECK: pytest -q passes; python smoke_test.py passes; every page works without ?mock=1.
Then update context.md Section 12: Phase 17 = ☑.
```

---

**After the CHECK passes:** `git add . && git commit -m "phase 17 ok"`, then open the next file.
**If the CHECK fails:** use template T2 in `prompts/00_templates.md` with the exact error.


---

## PHASE 18: Polish and demo preparation (≈30 min) · Person D (+ team)

```text
Read context.md fully.

GOAL: Final professional polish without risking stability.

DO (frontend only, no backend changes):
1. Consistency pass: same spacing (p-5 cards, gap-6 grids), same heading sizes, same button styles
   on all pages; every page has skeleton, empty and error states.
2. Add a subtle "Demo scenario" card on the Overview page (only when data_mode is "sample"):
   "Sample data with 5 injected attacks" and links to the svc-report alert, its graph and timeline.
3. Accessibility: buttons have aria-labels where icon-only; visible focus rings; color is never the
   only signal (band badges include text).
4. Page titles and favicon: inline SVG shield favicon via data URI in each HTML head.
5. README.md: what it is, how to run (run.bat / run.sh), pages, tech stack, how to switch to official
   data and supplied simulator, team names placeholder.
6. Do not change any API calls or backend files.

FILES: static/**, README.md

CHECK: click through every page live; pytest -q and smoke_test.py still pass.
Then update context.md Section 12: Phase 18 = ☑ and commit "v1.0-demo".
```

---

**After the CHECK passes:** `git add . && git commit -m "phase 18 ok"`, then open the next file.
**If the CHECK fails:** use template T2 in `prompts/00_templates.md` with the exact error.


---

## Final demo checklist


1. Stop the dev server; start without `--reload`: `python -m uvicorn app.main:app --port 8000`.
2. `python smoke_test.py` → SMOKE TEST PASSED.
3. Pre-open tabs: Overview → Alerts → svc-report alert → Graph → Timeline → Audit.
4. Demo flow (3 minutes):
   - Overview: "5 attack types detected, F1 vs baseline."
   - Alert: "Every login succeeded, but we connected Okta and AWS into one story."
   - Counterfactual table: "This is why the score is 94."
   - Chain + prediction: "We warned before the admin role was used."
   - Approve revoke: "Only through the simulator, with analyst approval and an audit trail."
   - Graph + timeline: "Here is the attacker's full path."
   - Audit: "Our own system is tamper-evident."
5. Keep a screen recording as backup in case of Wi-Fi or CDN problems.
