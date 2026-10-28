# 08 · Feature spec v2.1: agents dashboard, live scan, threat audit, data input, attack path explorer

## 1. What was asked and what we build

| Ask | Built as | Phases |
|---|---|---|
| "We have 15 agents, but the dashboard doesn't display them" | **Agents** page: 15 live agent cards in 5 layers with state, timing, outputs and JSON | 31, 32 |
| "When the system checks for malicious activity, simulate full-color output and full JSON, showing the current state and the step being performed" | **Live scan** page (colored console, step header, full JSON of the current step) and **terminal scan** `python -m app.scan --json` | 31, 33 |
| "If a threat is detected, log the event to the audit log as a separate entry" | One `threat_detected` audit entry **per threat**, hash-chained and deduplicated | 31 |
| "A method for input-only data entry" | **Input data** page: paste/upload logs or add single events by form, then scan **only that input** | 34, 35 |
| "Make the Identity Graph more attractive; judges should be impressed" | **Attack Path Explorer**: animated attack path, step-by-step playback, focus, blast radius, layouts, inspector, global view, PNG export | 36 |

**Honest framing for judges:** the Live scan replays the real trace of a real run at a watchable speed. The run itself takes about 2 s, and the banner shows the actual scan time. Nothing on screen is invented.

---

## 2. Agent trace and threat audit (backend)

### 2.1 The 15 agents (`app/trace.py` → `AGENTS`)

| # | id | Name | Layer | Pattern |
|---|---|---|---|---|
| 1 | ingestion | Log Ingestion Agent | data | |
| 2 | normalization | Normalization Agent | data | |
| 3 | enrichment | Enrichment Agent | data | |
| 4 | correlation | Session Correlation Agent | data | |
| 5 | impossible_travel | Impossible Travel Agent | detection | P1 |
| 6 | dormant | Dormant Account Agent | detection | P2 |
| 7 | priv_escalation | Privilege Escalation Agent | detection | P3 |
| 8 | api_anomaly | API Anomaly Agent | detection | P4 |
| 9 | token_abuse | Token Abuse Agent | detection | P5 |
| 10 | baseline_ml | Behavior Baseline Agent (ML) | detection | ML |
| 11 | risk_scoring | Risk Scoring Agent | decision | |
| 12 | explanation | Explanation Agent | decision | |
| 13 | response | Response Agent | decision | |
| 14 | feedback | Feedback Learning Agent | learning | |
| 15 | orchestrator | Orchestrator & Supervisor Agent | oversight | |

Agents 1–13 run in every scan (13 steps). Agent 14 runs when an analyst gives feedback, and agent 15 wraps every run and logs threats.

### 2.2 Trace event (one per step change)

```json
{"seq": 27, "run_id": "scan-20261028-041011-a3f9", "ts": "2026-10-28T04:10:11.153+00:00",
 "agent_id": "priv_escalation", "agent_num": 7, "agent_name": "Privilege Escalation Agent", "layer": "detection",
 "state": "done", "level": "ok", "message": "1 chain · 4 steps in 11 min", "duration_ms": 3.1,
 "data": {"signals": 1, "chains": [{"session_id": "okta:102svcR7", "steps": ["CredCreate", "PermGrant", "RoleAssume", "Impact"], "minutes": 11}]}}
```

States: `started`, `progress`, `done`, `failed`, `skipped`, `threat`, `info`. Payloads are JSON-safe (NaN → null, numpy → Python) and capped at `TRACE_MAX_DATA_CHARS`; larger payloads become `{"truncated": true, "preview": …}`. The ring buffer keeps `TRACE_MAX_EVENTS` events in memory.

### 2.3 Pipeline instrumentation (Phase 31 Part B)

| Pipeline step | Agent id | Started message | Output keys (small summary) | Done message example |
|---|---|---|---|---|
| Load files | `ingestion` | Loading CloudTrail and Okta files | `files` {cloudtrail:[names], okta:[names]}, `records` {cloudtrail, okta}, `skipped` | Loaded 2,967 records from 2 files |
| Normalize | `normalization` | Mapping both formats to the unified event schema | `events`, `skipped`, `sources` {cloudtrail, okta}, `identities`, `sample_event` (first event, model_dump mode json) | 2,967 events normalized for 21 identities |
| Enrich | `enrichment` | Adding geo, privilege level and resource sensitivity | `geo_filled`, `privileged_identities`, `sensitive_events` | Enriched 2,967 events · 61 touch sensitive resources |
| Sessions + graph | `correlation` | Linking Okta sessions to AWS activity | `sessions`, `okta_linked`, `aws_only`, `graph` {nodes, edges} | 412 sessions · graph 964 nodes / 3,311 edges |
| Each rule detector | agent `name` | (detector-specific) | `signals`, `examples` (≤3: identity_id, session_id, severity, reason, evidence_count) | 1 signal · anita.rao 14,812 km/h |
| ML train + score | `baseline_ml` | Isolation Forest over N session feature vectors | `signals`, `trained_on`, `features`, `top_scores` (≤3) | 2 sessions above anomaly threshold 0.60 |
| Score | `risk_scoring` | Combining signals × privilege × sensitivity | `sessions_scored`, `alerts`, `bands` {revoke, restrict, step_up, monitor}, `top` {alert_id, risk} | 4 alerts · top risk 94 (svc-report) |
| Explain | `explanation` | Writing reasons, counterfactuals and MITRE tags | `alerts_explained`, `mitre` (list), `counterfactuals` (top alert only) | 4 alerts explained with evidence |
| Auto actions | `response` | Choosing actions (simulator only) | `applied` [{alert_id, action, result}], `pending_approval` [{alert_id, action}] | 3 actions applied · 1 revoke awaiting analyst approval |

The full realistic example of a complete run is `static/mock/scan_trace.json` (REF_18).

### 2.4 Threat audit entry (one per threat)

The runner calls `trace.log_threats(result.alerts)` after every run. **Each alert at or above `THREAT_AUDIT_MIN_RISK` (40) gets its own audit entry:**

| Field | Value |
|---|---|
| agent | `threat_detection` |
| action | `threat_detected` |
| detail | JSON: `fingerprint, alert_id, identity_id, session_id, risk, band, patterns, mitre, detectors, evidence_count, evidence_sample, recommended_action, reason, run_id` |

- **Separate entry per threat**, in addition to the existing pipeline/action/email entries.
- **Deduplicated** by fingerprint `identity|session|band`: a re-scan does not duplicate entries, but an **escalation** (for example restrict → revoke) is logged again.
- Hash-chained like every audit entry, so `/api/audit/verify` still proves integrity.
- Each threat also appears as a red `THREAT` line in the Live scan and the terminal scan.

### 2.5 Terminal scan

```bash
python -m app.scan --json --delay 0.15       # colored, full JSON, demo pacing
python -m app.scan --input-only              # only user-entered data
python -m app.scan --jsonl > scan.jsonl      # machine-readable
```

It enables ANSI colors and UTF-8 on Windows. It never sends email; threats are still audited.

### 2.6 API

| Method | Path | Returns |
|---|---|---|
| GET | `/api/agents` | `{agents: [15 × registry + live stats], run: run_status}` |
| GET | `/api/scan/status` | `{run_id, mode, state, current, completed, failed, threats, progress, total_steps, last_seq, duration_ms, summary}` |
| GET | `/api/scan/trace?after=&limit=&run_id=` | `{run_id, state, last_seq, events: [...]}` |
| POST | `/api/pipeline/run` | body may include `input_mode: "only" \| "merge"` |

---

## 3. Agents page (`agents.html`)

Orchestrator banner (run state, progress, threats) → **5 layer columns** (Data → Detection → Decision → Learning → Oversight) with 15 cards (number, name, role, state pill, last duration, runs, signals and pattern chip for detectors, permission chips) → click a card for details (last output JSON, recent events). Polls every 1.5 s while a run is active and every 10 s otherwise; pauses when the tab is hidden. Full prompt: Phase 32.

## 4. Live scan page (`scan.html`): pre-built (REF_16)

| Area | Content |
|---|---|
| Status header | State pill, run id, **"Step k / 13 · <agent>"**, current message, progress bar, Elapsed, Events, **Threats** |
| Controls | Data source (Dataset / Input only / Dataset + input), **Start scan**, **Replay last scan**, speed 0.5× to Instant, Inline JSON, filter (All / Threats / Errors), Download JSON |
| Agent strip | 15 chips grouped by layer, colored by live state, threat counters |
| Console | Terminal-style, color by layer and state, red THREAT badges, click to inspect, follow/pause auto-scroll |
| JSON panel | Full JSON of the current (or clicked) step, syntax-colored, Copy |
| Threats | One card per threat with risk, band and patterns, plus the note "audit entry written"; each links to its alert |
| Finish banner | "Scan complete · N threat(s), each written to the audit log" + **actual scan time** + visual speed |

URL options: `?autostart=1&mode=only|merge|dataset`, `?autostart=replay`, `?mock=1`.

## 5. Input-only data entry

### 5.1 Ways to enter data

1. **Paste** JSON into a text box.
2. **Upload** `.json` / `.jsonl` files (drag and drop; read in the browser and sent as text, so no multipart dependency is needed).
3. **Single-event form** for Okta login, Okta logout or AWS API call, with presets that build an attack story in a few clicks.

### 5.2 Accepted formats and rules (`app/inputs.py`, REF_11)

- `{"Records": [...]}`, a JSON array, a single object, or JSON Lines (bad lines are counted and reported, not fatal).
- Auto-detect: CloudTrail (`eventName` / `eventSource` / `userIdentity`) or Okta (`eventType` / `published` / `actor` + `outcome`).
- Validation: CloudTrail needs `eventTime` + `eventName`; Okta needs `published` + `eventType`. Invalid records are rejected with a reason.
- Limits: `INPUT_MAX_BYTES` (5 MB) and `INPUT_MAX_RECORDS` (50,000) per request.
- **Security:** JSON parsing only (nothing is executed); filenames are sanitized, so path traversal is impossible; control characters are stripped from form fields; the IP, region, event name and access key format are validated; the content is never echoed back.
- Storage: `data/input/cloudtrail/cloudtrail_<stamp>_<name>.jsonl` and `data/input/okta/okta_<stamp>_<name>.jsonl`, which the existing loaders read. Git-ignored.
- An optional `label` on a manual event (for example `impossible_travel`) lets the Analytics page measure detection on your own test input.

### 5.3 API

| Method | Path | Body | Result |
|---|---|---|---|
| GET | `/api/inputs` | none | files, totals, limits |
| POST | `/api/inputs/upload` | `{content, source, filename}` | accepted/rejected counts, first errors, files |
| POST | `/api/inputs/manual` | `{kind, fields}` | stored record |
| DELETE | `/api/inputs` | none | `{removed}` |
| POST | `/api/pipeline/run` | `{input_mode: "only" \| "merge"}` | 202 |

Errors are `422 validation_error` with a message that is safe to show.

### 5.4 Page (`input.html`)

Two tabs ("Paste or upload" and "Single event", with presets) → "Your input data" (totals, files, Clear all) → "Scan it" (**Scan input only** / **Scan dataset + input**, which open the Live scan page with `autostart`). Full prompt: Phase 35.

### 5.5 Caveat to state honestly

"Input only" means nothing else is analyzed. Detectors that need history, such as dormant accounts (30+ days of silence) and the ML baseline (at least 20 sessions), may report nothing on a tiny input. Use **Dataset + input** for those.

---

## 6. Attack Path Explorer (`graph.html`): pre-built (REF_17 + REF_15)

### 6.1 Features

| Feature | What the judge sees |
|---|---|
| Animated attack path | Red straight edges with **glowing particles flowing** along the attack, and **numbered badges** on each node in order |
| ▶ Play attack | The camera flies **step by step** (login → key → policy → role → secret), with a caption "STEP 2/5 · CreateAccessKey · CredCreate · 09:42" and the stepper lighting up |
| Focus attack path | Everything not on the path fades out |
| Blast radius | A pulsing dashed halo around the identity, reachable resources glow orange, and the count matches the Identities page |
| Layouts | Force (organic) or Left → right (hierarchical kill chain) |
| Stats | Nodes, edges, path steps, **time to impact** (for example 11 min), blast radius, risk |
| Inspector | Node details, connections in and out, and clickable event ids that show the **evidence JSON** |
| All risky identities | A combined graph of the top identities, with suspicious edges in red |
| Export / fullscreen | PNG download; fullscreen stage for the projector |
| Shapes and colors | User (cyan dot), session (violet hexagon), role (amber diamond), key (orange triangle), policy (red square), resource (green star), IP (slate dot), with a dark radial-gradient stage and outlined labels |

### 6.2 Endpoints (Phase 36 Part A)

| Method | Path | Returns |
|---|---|---|
| GET | `/api/identities/{id}/attack` | `{identity_id, identity, graph: IdentityGraph, alert: top Alert or null, blast_radius}` |
| GET | `/api/graph/global?top=8` | `{identities, nodes, edges, truncated}` (≤300 nodes) |

The path is computed in the browser from `graph.edges` and the alert's `evidence_event_ids` (time-ordered) plus `chain` (`graphfx.computeAttackPath`). Context edges such as `from_ip` are excluded from the steps.

### 6.3 Performance

Physics stops after stabilization. The animation redraw loop runs only while a path or halo is visible and pauses when the tab is hidden. Graphs are capped (150 nodes per identity, 300 global).
