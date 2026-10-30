# context.md: IdentityShield v3 (single source of truth for the IDE agent)

> **Antigravity: read this whole file at the start of every new chat.** If anything in a prompt conflicts with this file, this file wins. If something is missing, ask the human instead of guessing. Update Section 20 (Progress log) at the end of every phase.

---

## 1. What we are building (30-second version)

IdentityShield v3 is an **identity threat detection and response (ITDR)** platform for the hackathon **Track 2: Zero Trust for Everyone**. Team: **Robust Gang**.

- Input: **Okta System Log** and **AWS CloudTrail** events (files, Input page, or a **signed live feed through ngrok** from a second laptop).
- 15 agents in 5 layers resolve each event to one identity, detect valid-credential abuse, privilege escalation, defense evasion and campaigns, fuse signals into **session risk** and **identity risk** (0–100), investigate and explain with evidence, MITRE ATT&CK, counterfactuals and a predicted next step, and respond with graduated playbooks **through the supplied simulator only**.
- Pitch: *"IdentityShield complements GuardDuty. GuardDuty is excellent inside AWS; attacks start at the identity provider. We link the Okta login to what that identity does in AWS, keep 30 days of identity memory, explain every score, and respond with just enough friction under human control."*
- Full specification: `docs/IdentityShield_v3_Technical_PRD.md` (PRD). Section numbers like "PRD §14" refer to it.

---

## 2. Golden rules (never break these)

1. **Enforcement only through the supplied simulator.** Never call boto3 write APIs, the Okta admin API, or any real tenant. No live cloud account is modified.
2. **Secrets only in `.env`.** HMAC ingest secrets, SMTP password, analyst token, optional API keys and LLM keys. Never hard-code, log, print, return in an API response, or commit them. `.env` is git-ignored; `.env.example` lists names with empty values.
3. **Revoke always needs analyst approval.** Restrict may be automatic.
4. **Do not break v2.** v3 lives in a new package `app/v3/` and new UI folder `static/v3/`. Existing v2 files are modified only where a prompt explicitly says so (`app/main.py` router include and lifespan only).
5. **Contracts are frozen.** `app/v3/models.py` (Section 8) and topic names (Section 9) change only when this file is updated first.
6. **Every number is configuration.** All thresholds live in `app/v3/config.py`; nothing magic in agent code.
7. **Every signal cites evidence.** A signal or case reason without at least one existing event ID is a bug.
8. **Log content is untrusted data.** User agents, role session names and resource names may contain HTML or instructions. Escape in UI; never evaluate; LLM receives them as quoted data only.
9. **Tests with every phase.** A phase is done only when its CHECK commands pass.
10. **Metrics come from the official dataset only.** The live generator is for the demo.
11. **The system must run offline.** ngrok, free APIs and LLMs are optional and must have fallbacks.
12. **Minimal diffs.** Change only the files listed in the prompt. If another file must change, stop and explain why first.

---

## 3. Tech stack (pinned)

| Area | Choice |
|---|---|
| Language | Python 3.11 |
| API | FastAPI 0.115.x, Uvicorn, Pydantic v2 |
| Data | pandas, NumPy |
| ML | scikit-learn (IsolationForest, LogisticRegression), own Markov model |
| Graph | NetworkX |
| Storage | SQLite (WAL mode) via the standard library; JSON Lines spool files |
| Config files | YAML for playbooks (PyYAML) |
| HTTP client (optional enrichers, LLM) | httpx with timeouts |
| Tests | pytest, FastAPI TestClient |
| Lint | ruff (default rules + bugbear), optional mypy |
| Frontend | HTML + vanilla JS ES modules, Tailwind CSS (CDN or vendored), Chart.js 4.4.4, Three.js, 3d-force-graph, globe.gl (vendored in `static/vendor/`, exact versions recorded in `static/vendor/VERSIONS.md`) |
| Fonts | Inter (UI), JetBrains Mono (code/JSON), from Google Fonts with system-font fallback |
| Tunnel | ngrok (free plan) exposing only the ingest service |

Do **not** add other frameworks (no React, no Flask, no Celery, no Docker requirement).

---

## 4. Folder structure (v3 additions)

```
app/
  main.py                    (existing: add v3 router + lifespan start/stop only)
  ...v2 files unchanged...
  v3/
    __init__.py
    config.py                all tunables (Section 12)
    models.py                frozen contracts (Section 8)
    catalog.py               eventName/eventType -> class, action_type, stage, MITRE
    bus.py                   topic bus (sync drain mode + async live mode)
    supervisor.py            registry, capability manifests, health, pacing, scheduling
    store.py                 SQLite access for v3 tables (Section 11)
    audit.py                 adapter to existing hash-chained audit (or v3 table if absent)
    trace.py                 adapter: v3 trace events -> existing app/trace.py
    agents/
      base.py                Agent base: process(msg, state) -> list[Message]
      a01_collector.py
      a02_normalizer.py
      a03_context.py
      a04_correlation.py
      a05_access.py
      a06_session.py
      a07_credentials.py
      a08_privesc.py
      a09_evasion.py
      a10_ml.py
      a11_campaign.py
      a12_fusion.py
      a13_investigation.py
      a14_response.py
      a15_feedback.py
    enrich/
      offline.py             bundled lists (Tor, hosting ASNs, trusted IPs, geo table)
      providers.py           optional free-API enrichers with cache + timeout
    llm/
      narrator.py            optional guarded narrative (template fallback)
    playbooks/
      default.yaml
    data/
      tor_exits.txt, hosting_asns.txt, trusted_ips.txt, geo_seed.csv, privesc_paths.yaml
    ingest/
      service.py             separate FastAPI app on port 8001
      security.py            HMAC verify, nonce cache, rate limiter
    api.py                   router mounted at /api/v3
    sse.py                   Server-Sent Events broadcaster
    pipeline_v3.py           dataset mode: replay files through the bus, drain, return results
    bench.py                 benchmark runner (python -m app.v3.bench)
    evaluate.py              KPI evaluation on official labels (python -m app.v3.evaluate)
static/
  v3/
    index.html cases.html case.html live.html agents.html graph.html globe.html
    analytics.html performance.html settings.html input.html audit.html
    css/theme.css
    js/core/api.js js/core/sse.js js/core/dom.js (escHtml, fmt) js/core/shell.js
    js/fx/bg3d.js js/fx/tilt.js
    js/pages/*.js            one module per page
  vendor/                    three, 3d-force-graph, globe.gl, chart.js (+ VERSIONS.md)
generator/
  index.html                 attack generator / log forwarder (laptop 2)
  js/generator.js js/scenarios.js js/sign.js
  css/generator.css
tests/
  v3/ test_*.py              one file per phase area
data/
  spool/                     ingest spool (git-ignored)
```

---

## 5. Architecture summary

Layers and agents (PRD §6, §12):

| # | Agent | Layer | Consumes → Publishes | Path |
|---|---|---|---|---|
| 1 | Collector | Data | raw.okta, raw.cloudtrail → events | hot |
| 2 | Normalizer & Identity Resolver | Data | events → events.normalized | hot |
| 3 | Context & Threat Intel | Data | events.normalized → events.enriched | hot |
| 4 | Correlation & Graph | Data | events.enriched → sessions, graph.updates | hot/warm |
| 5 | Access Anomaly | Detection | events.enriched, sessions → signals | hot |
| 6 | Session & Token Integrity | Detection | events.enriched, sessions → signals | hot |
| 7 | Credential Lifecycle | Detection | events.enriched, graph.updates → signals | warm |
| 8 | Privilege Escalation | Detection | graph.updates, sessions → signals | warm |
| 9 | Defense Evasion & Impact | Detection | events.enriched → signals | hot |
| 10 | Behavioral ML | Detection | sessions (closed/updated) → signals | warm |
| 11 | Campaign | Detection | events.enriched, signals → signals | warm |
| 12 | Risk Fusion | Decision | signals, config.updates → risk | warm |
| 13 | Investigation & Explanation | Decision | risk → cases | warm |
| 14 | Response | Decision | cases, approvals → actions | warm |
| 15 | Feedback & Tuning | Learning | labels → config.updates | nightly/on label |

Platform (not agents): Supervisor, Bus, Ingest service, API + SSE, Store, Audit, Notifier.

**Agent model (important for a strong backend):** every agent is a class with `process(message, state) -> list[Message]` that is **pure given its state** (no direct I/O except through injected store/clock). The bus calls agents. This gives:
- **Drain mode** (dataset and tests): publish all raw events, then run the bus synchronously until every queue is empty. Deterministic and fast.
- **Live mode** (demo): the same agents run as asyncio tasks inside the FastAPI lifespan, consuming queues continuously.
- Same code, same results, two schedulers.

---

## 6. Processing paths

| Path | Trigger | Agents | Budget (target) |
|---|---|---|---|
| Hot | Every event | 1, 2, 3, 4 (session update), 5, 6, 9 | p95 ≤ 1 s receive → signal |
| Warm | Session close (idle 15 min), session risk ≥ 40, or tick every 30 s | 7, 8, 10, 11, 12, 13, 14 | p95 ≤ 10 s → case + action |
| Nightly | Schedule or "Retrain" | 10, 15, 3 | minutes |

In drain mode, the "tick" is triggered after all events are processed so warm agents see complete sessions.

---

## 7. Coding standards (backend must be strong)

1. Type hints on every function; Pydantic models for every message payload.
2. No bare `except:`. Catch specific exceptions; agent errors go to the `deadletter` topic with reason; never crash the bus.
3. Structured logging via `logging` with logger per module; JSON formatter; a redaction filter that masks values of keys named like secret, token, password, key, authorization.
4. Pure functions for detection logic (input lists/dicts → outputs) so they are unit-tested without the bus.
5. Time is injected (a `Clock` object) so tests control time; never call `datetime.now()` inside detection logic.
6. Determinism: fixed random seed (`config.SEED = 42`) for ML; sorted iteration where order matters.
7. Bounded everything: queue sizes, graph nodes, investigation pivots, request sizes, LLM timeouts.
8. SQLite: one connection per thread, WAL mode, parameterized queries only, indexes on time and identity_id, batched inserts.
9. API handlers are thin: validate → call a service function → return a model. All handlers return JSON; errors use `HTTPException` with clear `detail`.
10. Every new module has tests in `tests/v3/`. Target ≥ 80 % line coverage for `app/v3/` (excluding optional providers/LLM).
11. `ruff check app/v3 tests/v3` must pass with zero errors.
12. No network calls in tests (providers and LLM mocked or disabled).

---

## 8. Frozen data contracts (`app/v3/models.py`)

All models are Pydantic v2 `BaseModel` with `model_config = ConfigDict(frozen=True, extra="forbid")` unless marked mutable state.

**Enums (str enums):**
- `Source`: okta, cloudtrail, manual, generator
- `EventClass`: authentication, account_change, api_activity, entity_management, data_access
- `ActionType`: read, write, permission_change, credential_change, destructive, defense_evasion
- `Stage`: initial_access, credential_access, discovery, privilege_escalation, persistence, defense_evasion, collection, exfiltration, impact
- `Band`: monitor (<40), step_up (40–69), restrict (70–89), revoke (≥90)
- `CaseStatus`: new, investigating, contained, awaiting_approval, resolved_tp, resolved_fp, resolved_benign
- `ActionKind`: monitor, step_up, restrict, revoke_sessions, disable_key, block_ip, quarantine_identity
- `ActionState`: proposed, pending_approval, approved, executing, applied, failed, rejected, expired, rolled_back
- `Verdict`: true_positive, false_positive, benign_true_positive

**Models (fields):**
- `Message`: topic, msg_id, producer (agent id or "platform"), run_id, created_at, schema_version ("3.0"), partition_key (identity_id or ""), payload (one of the models below)
- `Event`: event_id, time, source, event_class, action (eventName/eventType), identity_id, raw_principal, session_id (nullable), src_ip, user_agent, outcome (success/failure/deny/unknown), resource_arn (nullable), read_only, region (nullable), late (bool), uncatalogued (bool), resolution_confidence (0–1), raw_ref (spool or file pointer), attrs (dict of extra parsed fields: access_key_id, vpc_endpoint_id, external_session_id, policy_arn, target_user, mfa_result, etc.)
- `Context`: country, city, lat, lon, asn, as_org, is_proxy, is_tor, is_hosting, trusted_ip, privilege_level (1–5), resource_sensitivity (1–5), action_type, stage_hint (nullable), context_complete (bool)
- `EnrichedEvent`: event (Event), context (Context)
- `Session`: session_id, identity_id, start, end (nullable), event_ids (list), ips, asns, devices, providers (okta/cloudtrail present), state (open/closed), fingerprint (dict)
- `GraphDelta`: nodes (list of {id, kind, label, attrs}), edges (list of {source, target, kind, event_id, time})
- `Signal`: signal_id, detection_id (e.g. "D-SES-02"), agent_num (5–11), identity_id, session_id (nullable), strength (0–1), confidence (0–1), evidence_event_ids (≥1), mitre (list of technique IDs), stage, summary (plain text), details (dict)
- `RiskScore`: subject_id, kind (session/identity), score (0–100), confidence (0–1), band, factors (dict name→value), computed_at
- `RiskUpdate`: identity_id, session_id, session_risk (RiskScore), identity_risk (RiskScore), signal_ids
- `CaseStep`: time, event_id, action, resource (nullable), stage, mitre (list)
- `Counterfactual`: removed_factor, score_without, delta
- `NextStep`: action, probability
- `Case`: case_id, identity_id, session_id, session_risk, identity_risk, confidence, band, status, signal_ids, chain (list CaseStep), reasons (list of {text, evidence_event_ids}), counterfactuals, next_steps, blast_radius, related_identities, narrative, narrative_source (template/llm), created_at, updated_at
- `Action`: action_id, case_id, playbook_id, kind, approval_required, state, simulator_ref (nullable), reason, created_at, updated_at, expires_at (nullable), approved_by (nullable)
- `Label`: case_id, verdict, analyst, note, time
- `ConfigUpdate`: version, changes (dict), reason, created_at, created_by ("agent15" or analyst)
- `TraceEvent`: (reuse existing v2 trace schema: seq, run_id, ts, agent_id, agent_num, agent_name, layer, state, level, message, duration_ms, data)
- `IngestEnvelope`: source (okta/cloudtrail), sender_id, batch_id, events (list of dict, 1–500)
- `IngestResult`: batch_id, accepted, rejected (list of {index, reason}), received_at

---

## 9. Topics (frozen names)

`raw.okta`, `raw.cloudtrail`, `events`, `events.normalized`, `events.enriched`, `sessions`, `graph.updates`, `signals`, `risk`, `cases`, `actions`, `approvals`, `labels`, `config.updates`, `trace`, `deadletter`.

Bus rules: bounded queue per topic (default 10,000); ordering per partition key; publish validated against producer's capability manifest; when any queue > 80 % full → Supervisor sets `backpressure=true` and ingest returns 429 with `Retry-After`.

---

## 10. Capability manifests (enforced by Supervisor)

| Agent | May publish | May write store tables | Simulator | Network |
|---|---|---|---|---|
| 1 | events, deadletter | events_v3 | no | no |
| 2 | events.normalized, deadletter | identities_v3, identity_aliases_v3 | no | no |
| 3 | events.enriched, deadletter | enrich_cache_v3 | no | optional enrichers only |
| 4 | sessions, graph.updates, deadletter | sessions_v3 | no | no |
| 5–11 | signals, deadletter | signals_v3, agent_state_v3 | no | no |
| 12 | risk, deadletter | risk_v3 | no | no |
| 13 | cases, deadletter | cases_v3 | no | optional LLM only |
| 14 | actions, deadletter | actions_v3, notifications | **yes** | email only |
| 15 | config.updates, deadletter | config_versions_v3 | no | no |

Any violation: blocked, audited, counted on the agent's health card.

---

## 11. Storage (SQLite tables, prefix `_v3`)

events_v3, identities_v3, identity_aliases_v3, sessions_v3, signals_v3, risk_v3, cases_v3, actions_v3, labels_v3, config_versions_v3, agent_state_v3, enrich_cache_v3, ingest_batches_v3, metrics_v3. Audit uses the existing hash-chained audit table (new `actor` values: `agentNN`, `ingest`, `analyst`, `supervisor`). JSON columns stored as TEXT. Indexes on (identity_id, time), (session_id), (case_id), (status).

---

## 12. Key configuration (defaults, all in `app/v3/config.py`)

| Name | Default | Meaning |
|---|---|---|
| SEED | 42 | Random seed |
| QUEUE_MAX | 10000 | Per-topic queue bound |
| WATERMARK_SECONDS | 120 | Late-event reorder window |
| SESSION_IDLE_MINUTES | 15 | Session close |
| GRAPH_RETENTION_DAYS | 30 | Graph memory |
| GRAPH_MAX_NODES | 50000 | Prune above |
| MAX_SPEED_KMH | 900 | Impossible travel |
| MIN_DISTANCE_KM | 500 | Impossible travel |
| MIN_HISTORY_LOGINS | 5 | Cold start threshold |
| MFA_FATIGUE_DENIES | 5 | Denies before accept |
| MFA_WINDOW_MINUTES | 10 | MFA fatigue window |
| DORMANT_DAYS | 30 | Dormant account |
| NEW_KEY_WINDOW_MINUTES | 60 | New key used from new place |
| PRIVESC_MAX_STEP_GAP_HOURS | 168 | Slow chains (7 days) |
| SPRAY_MIN_USERS | 10 | Password spray |
| SPRAY_WINDOW_MINUTES | 10 | Password spray |
| SHARED_INFRA_MIN_IDENTITIES | 3 | Campaign |
| MASS_DELETE_COUNT / WINDOW_MIN | 50 / 5 | Impact |
| SECRET_HARVEST_COUNT / WINDOW_MIN | 5 / 10 | Impact |
| ML_CONTAMINATION | 0.02 | IsolationForest |
| PRIVILEGE_MULT | [0.8, 1.0, 1.15, 1.3, 1.5] | Levels 1–5 |
| SENSITIVITY_MULT | [0.9, 1.0, 1.1, 1.25, 1.4] | Levels 1–5 |
| ACTION_MULT | read 1.0, write 1.1, permission/credential 1.25, destructive/defense_evasion 1.4 | Worst action |
| CHAIN_STEP | 0.15, cap 1.6 | Chain factor |
| IDENTITY_HALF_LIFE_HOURS | 24 | Decay |
| BANDS | 40 / 70 / 90 | Thresholds |
| FRICTION_UNITS / WINDOW_HOURS | 2 / 8 | Friction budget |
| APPROVAL_TIMEOUT_MINUTES | 30 | Pending approval expiry |
| RESTRICT_TTL_MINUTES | 240 | Auto-expiry |
| INVESTIGATION_MAX_DEPTH / ENTITIES / SECONDS | 2 / 50 / 2.0 | Agent 13 bounds |
| NEXT_STEP_MIN_PROB | 0.3 | Show prediction |
| LEARNING_RATE | 0.05 | Agent 15 |
| WEIGHT_FLOORS | D-PE-*, D-DEF-* ≥ 0.6 | Never silenced |
| INGEST_PORT | 8001 | Ingest service |
| INGEST_MAX_BODY_BYTES | 1048576 | 1 MB |
| INGEST_MAX_EVENTS | 500 | Per batch |
| INGEST_RATE_RPS / EVENTS_PER_MIN | 20 / 2000 | Per key |
| INGEST_SKEW_SECONDS | 60 | Timestamp window |
| INGEST_NONCE_TTL_SECONDS | 300 | Replay guard |
| EMAIL_MIN_BAND | restrict | Email at ≥ 70 |
| LLM_ENABLED | false | Optional narrator |
| ENRICH_PROVIDERS | [] | Optional free APIs (Section 15) |

---

## 13. Detections (IDs are frozen; details in PRD §13)

- Access: D-ACC-01 impossible travel, D-ACC-02 new device/ASN, D-ACC-03 unusual hour, D-ACC-04 anonymizing network on privileged identity
- Session: D-SES-01 token replay (new ASN without re-auth), D-SES-02 MFA fatigue, D-SES-03 fingerprint drift (weak), D-SES-04 privileged session without MFA
- Credentials: D-CRD-01 dormant wakes, D-CRD-02 key for another user, D-CRD-03 new key from new place, D-CRD-04 instance credential from non-AWS IP or unexpected VPC endpoint, D-CRD-05 login profile change for another user
- Evasion/impact: D-DEF-01 logging stopped, D-DEF-02 GuardDuty detector disabled, D-DEF-03 flow logs deleted, D-DEF-04 data made public, D-DEF-05 KMS key destruction, D-DEF-06 mass deletion, D-DEF-07 secret harvesting
- Escalation paths: PE-01 … PE-08 (PRD §13.4); signal detection_id = "D-PE-0N"
- ML: D-ML-01 session anomaly (IsolationForest), D-ML-02 sequence rarity (Markov)
- Campaign: D-CMP-01 password spray, D-CMP-02 spray then success, D-CMP-03 shared infrastructure

User agent is **weak evidence only** (it is spoofable). No detection may reach strength > 0.3 from user agent alone.

---

## 14. Risk fusion (PRD §14)

- P = 1 − Π(1 − wᵢ·cᵢ·sᵢ) over session signals (noisy-OR).
- SessionRisk = min(100, 100·P·M_privilege·M_sensitivity·M_action·F_chain).
- IdentityRisk(t) = max(IdentityRisk₀·e^(−λΔt), latest SessionRisk), half-life 24 h.
- Identity risk ≥ 60 lowers the next session's step-up threshold by 10.
- Confidence = mean signal confidence × context completeness × identity resolution confidence.
- Counterfactuals: recompute without each signal family and each multiplier; keep top 3 drops.
- Weights wᵢ default 1.0 for rule detections and 0.8 for ML; calibrated by logistic regression on labeled sessions (Phase 17); floors apply.

---

## 15. Optional free APIs (see `FREE_APIS.md`)

- Off by default. Enabled per provider in `.env` (`ENRICH_PROVIDERS=ipinfo_lite,abuseipdb`).
- Never called on the hot path synchronously: Agent 3 uses the cache; misses are queued for a background prefetch task with a 2 s timeout and per-provider rate limit; results cached 24 h in `enrich_cache_v3`.
- Any failure → offline values, `context_complete` unchanged, warning counter increment.
- Never send anything except an IP address to a provider. Never send user names, emails or keys.

---

## 16. Response playbooks (PRD §16)

Default playbooks PB-01 … PB-05 in `app/v3/playbooks/default.yaml`. Friction budget 2 units per 8 h. Action lifecycle: proposed → (pending_approval → approved | rejected | expired) → executing → applied | failed → rolled_back. Simulator calls are idempotent by action_id. Every state change → audit entry and `actions` topic message.

**Simulator adapter:** reuse the existing v2 simulator client/module. If its interface differs, write a thin adapter in `a14_response.py`; never call anything else.

---

## 17. API (all v3 routes under `/api/v3`, ingest on port 8001)

Ingest (port 8001): `POST /ingest/v1/events` (HMAC), `GET /ingest/v1/health`.

Core `/api/v3`: `GET /health`, `GET /agents`, `GET /identities`, `GET /identities/{id}`, `GET /identities/{id}/graph`, `GET /graph/global`, `GET /geo/logins`, `GET /cases`, `GET /cases/{id}`, `POST /cases/{id}/label`, `GET /actions`, `POST /actions/{id}/approve`, `POST /actions/{id}/reject`, `POST /actions/{id}/rollback`, `GET /playbooks`, `GET /stream` (SSE), `POST /run/dataset`, `GET /run/status`, `GET /metrics/kpi`, `GET /metrics/perf`, `POST /bench/run`, `GET /config`, `GET /config/versions`, `POST /config/rollback/{version}`, `POST /inputs/scan`.

Mutating endpoints require header `X-Analyst-Token` when `ANALYST_TOKEN` is set in `.env`. Port 8000 binds to 127.0.0.1 in demo mode.

**HMAC ingest headers:** `X-IS-Key-Id`, `X-IS-Timestamp` (Unix seconds), `X-IS-Nonce` (16+ random bytes hex), `X-IS-Signature` = hex HMAC-SHA256(secret, timestamp + "\n" + nonce + "\n" + sha256_hex(raw_body)). Keys from `.env`: `INGEST_KEYS=keyid1:secret1,keyid2:secret2`. Errors: 401 auth, 413 size, 422 schema, 429 rate/backpressure.

---

## 18. UI design system: professional 3D (dark "command center")

**Feel:** a security operations command center in deep space: dark, calm, glass panels, neon data, purposeful 3D. 3D is used where it carries meaning (graphs, globe, agent constellation), never as decoration that slows the page.

**Tokens (CSS variables in `static/v3/css/theme.css`):**

| Token | Value |
|---|---|
| --bg | #05070D |
| --bg-2 | #0B0F17 |
| --panel | rgba(17, 24, 39, 0.62) with backdrop-filter blur(14px) saturate(140%) |
| --panel-border | rgba(148, 163, 184, 0.14) |
| --text | #E5E7EB |
| --muted | #94A3B8 |
| --brand | #3B82F6 |
| --cyan | #22D3EE |
| --violet | #8B5CF6 |
| --ok | #10B981 |
| --warn | #F59E0B |
| --crit | #EF4444 |
| band colors | monitor #64748B, step_up #F59E0B, restrict #F97316, revoke #EF4444 |
| radius | 14px panels, 10px controls |
| shadow | 0 10px 30px rgba(0,0,0,.45), inner 1px top highlight rgba(255,255,255,.06) |
| fonts | Inter 400/500/600/700; JetBrains Mono for IDs, JSON, numbers |

**3D components:**
1. **Background (`bg3d.js`):** Three.js particle network (≤ 1,500 points, slow drift, faint connecting lines), mouse parallax. Pauses when tab hidden; disabled when `prefers-reduced-motion`; falls back to a CSS radial gradient if WebGL is unavailable.
2. **Agent constellation (Live page):** 15 agent nodes in 3D arranged in 5 rings by layer; idle = dim, running = pulsing glow, finding = amber flash, threat = red burst; bus messages animate as particles flying between nodes; click a node → agent drawer.
3. **3D attack graph (Graph page):** 3d-force-graph; node colors by kind (identity blue, session cyan, IP slate, key violet, role amber, resource green, sensitive resource red ring); suspicious edges red with directional moving particles along the attack path; Okta→AWS edges highlighted; camera fly-to on click; side panel with node details; 2D fallback with vis-network if WebGL fails.
4. **Login globe (Globe page and dashboard tile):** globe.gl with login points; arcs between consecutive logins of an identity; impossible-travel arcs red and animated; trusted locations green.
5. **Tilt cards:** KPI cards tilt slightly in 3D on hover (CSS perspective, max 6°), disabled on touch and reduced motion.

**Layout:** left sidebar (icons + labels, collapsible), top bar (run status pill, live event rate, ngrok/ingest status dot, clock), content grid of glass panels. Responsive down to 1280 px for the demo projector; mobile is not a goal but must not break.

**Rules:** every dynamic string inserted with `escHtml` or `textContent`; no inline event handlers; charts and 3D scenes are destroyed on page change to avoid memory leaks; 60 fps target, scenes cap pixel ratio at 2; each page shows a skeleton loader and an empty state; `?mock=1` loads fixtures from `static/v3/mock/` so the UI works without the backend.

---

## 19. Demo facts to keep consistent

- Hero scenario E1: identity `svc-report` (or the dataset's equivalent): new-country Okta login → SAML role → CreateAccessKey → AttachUserPolicy (admin) → AssumeRole → GetSecretValue. Expected: session risk ≥ 90, restrict applied, revoke pending approval, counterfactual "without escalation chain" around 44, next step GetSecretValue or secret harvesting.
- Evasion pack E2–E9 and tamper tests T1–T5: PRD §25.3.
- Never present targets as measured numbers.

---

## 20. Progress log (update at the end of every phase)

| Phase | Status | Date | Notes (bugs found, decisions) |
|---|---|---|---|
| P0 Baseline | done | 2026-10-30 | Baseline pytest (64 passed) and smoke test verified; safety net, empty v3 packages, .env.example, and test fixtures initialized. |
| P1 Contracts + config | done | 2026-10-30 | Frozen Pydantic models (models.py), Section 12 config constants + secret-masking Settings (config.py), and event catalog (catalog.py) implemented with 78 unit tests passing and clean ruff check. |
| P2 Bus + Supervisor | done | 2026-10-30 | Base agent & context (agents/base.py), topic event bus with drain/live modes (bus.py), 15-slot supervisor with capabilities and health (supervisor.py), SQLite WAL store (store.py), trace adapter (trace.py), and audit adapter (audit.py) verified with 93 passing unit tests and clean ruff check. |
| P3 Ingest service | done | 2026-10-30 | FastAPI on port 8001 with HMAC-SHA256 signature verification, NonceCache, per-key token bucket rate limiting (20 rps / 2000 epm), 1MB body limit, minimal event validation, daily spooling, backpressure handling, and audit integration verified with 10 unit tests passing and clean ruff check. |
| P4 Agents 1–2 | done | 2026-10-30 | Agent 1 Collector (dedupe, watermark buffering, late flag, deadletter) and Agent 2 Normalizer & Identity Resolver (Okta/CloudTrail field mapping, catalog classification, IR-1..IR-6 identity resolution, _raw removal, identities/aliases persistence) verified with 11 unit tests passing and clean ruff check. |
| P5 Agents 3–4 | done | 2026-10-30 | Agent 3 Context & Threat Intel (offline geo/ASN/Tor/hosting lists, sensitivity/privilege rules, optional background providers with cache) and Agent 4 Correlation & Graph (cross-provider session stitching, 15-min idle timeout, NetworkX MultiDiGraph, blast radius) verified with 10 unit tests passing and clean ruff check. |
| P6 Agents 5–6 | done | 2026-10-30 | Agent 5 Access Anomaly (D-ACC-01..04: impossible travel, new device/ASN, unusual hour, anonymizing network on privileged identity, cold-start damping, trusted IP suppression) and Agent 6 Session & Token Integrity (D-SES-01..04: token replay, MFA fatigue, UA/device drift capped at 0.2, privileged session without MFA) verified with 14 unit tests passing (202 full suite) and clean ruff check. |
| P7 Agents 7–9 | done | 2026-10-30 | Agent 7 Credentials (D-CRD-01..05: dormant wake, key for another user, new key from new place, EC2 instance credential misuse with non-AWS IP / unexpected VPCE, login profile change), Agent 8 Privilege Escalation (PE-01..08 YAML path library, 168h gap window, partial match persistence, stable signal upgrade, PE-08 full chain), Agent 9 Defense Evasion & Impact (D-DEF-01..07, PutEventSelectors management filter, mass deletion, secret harvesting, +0.1 anomaly boost) verified with 21 unit tests (223 full suite) and clean ruff check. |
| P8 Agents 10–11 | done | 2026-10-30 | Agent 10 Behavioral ML (11 features per PRD §12, peer-group IsolationForest contamination 0.02 + Laplace-smoothed Markov transition matrices, D-ML-01 percentile >= 0.98 strength 0.4..0.8, D-ML-02 NLL percentile >= 0.99 strength 0.3..0.7, no-model skip) and Agent 11 Campaign (sliding windows, D-CMP-01 password spray on 10 users, D-CMP-02 stuffing success, D-CMP-03 shared infra on 3 identities, shared campaign_id) verified with 11 unit tests (234 full suite) and clean ruff check. |
| P9 Agent 12 | done | 2026-10-30 | Agent 12 Risk Fusion (pure mathematical noisy-OR model, privilege/sensitivity/action multipliers, chain factor capped at 1.6, exponential decay half-life 24h, identity max rule, top-3 counterfactual drops showing 'without escalation chain' around 44, weight floors D-PE/D-DEF >= 0.6, pre-emptive scrutiny flag lowering step-up by 10 points when identity risk >= 60, publish threshold delta >= 1.0 or band change) verified with 10 unit tests passing (244 full suite) and clean ruff check. |
| P10 Agent 13 | done | 2026-10-30 | Agent 13 Investigation & Explanation (bounded investigation loop <=2.0s/50 entities/depth 2, chronological CaseStep chain, top 3 plain-English reasons with event citations from explain_templates.py, fusion counterfactuals, Markov next-step predictor for escalation/data access, graph IP/key pivoting uncovering related identities, optional guarded LLM narrator with citation validation and prompt-injection boundaries, re-investigation threshold delta >= 10, cases_v3 persistence) verified with 8 unit tests passing (252 full suite) and clean ruff check. |
| P11 Agents 14–15 | done | 2026-10-30 | Agent 14 Response (policy playbooks PB-01..05, PB-04 defense evasion override, friction budget 2/8h with monitor fallback, revoke approval required with 30m timeout, restrict 240m TTL auto-rollback, simulator idempotency and retry, case status updates, email alert deduplication and HTML escaping) and Agent 15 Feedback (FP weights lowered with floors D-PE/DEF >= 0.6 and proposed suppression in config_versions_v3, TP weights raised and chain appended to Markov training set, benign TP 24h active suppression, versioning, config rollback) verified with 13 unit tests passing (265 full suite) and clean ruff check. |
| P12 API + SSE + dataset run | not started | | |
| P13 UI foundation (3D) | not started | | |
| P14 UI core pages | not started | | |
| P15 UI 3D graph, globe, analytics, performance | not started | | |
| P16 Generator + ngrok | not started | | |
| P17 Evaluation + benchmark + calibration | not started | | |
| P18 Hardening + docs + demo | not started | | |

### Known issues / decisions
- Integration points:
  - `app/main.py`: Creates FastAPI application `app` with async lifespan (`store.init_db()`, `run_pipeline()`), registers routers (`health`, `alerts`, `identities`, `metrics`, `audit`, `v21` under `/api`), exception handlers (`http_error`, `validation_error`, `unhandled_error`), and mounts `static/` at `/`.
  - Simulator (`app/simulator/`): Provides `get_simulator() -> SimulatorAdapter` (supporting `MockSimulator` and `SuppliedSimulator`) with enforcement methods `step_up(identity_id, session_id=None)`, `restrict(identity_id, scope="default")`, and `revoke(identity_id, session_id=None)`. Also invoked via `app/decision/respond.py`.
  - Trace (`app/trace.py`): Live agent event telemetry via `emit(agent_id, state, message, data, level, duration_ms)` (thread-safe, non-raising, size-capped), `step(agent_id, message, data)` (context manager tracking execution time/state), `progress(agent_id, message, data)` (intermediate pipeline progress), `finding(agent_id, message, data)` (live threat/score findings), and terminal rendering via `render_ansi()`.
  - Audit (`app/audit.py`): Immutable tamper-evident logging via `append(agent, action, detail)` with SHA-256 chaining against previous hash, and `verify() -> tuple[bool, int | None]` to check audit integrity.
  - Notify (`app/notify.py`): Alert dissemination via `notify_new_alerts(alerts, total_open, async_)` (deduplicated by fingerprint), `notify_alert(alert)` (manual send), and `deliver(msg, text, kind, alert_ids, fps)` supporting off/outbox/smtp modes with rate limiting.
  - Inputs (`app/inputs.py`): Ingestion and sample data entry via `save_input(content, source, filename)` (validates and writes JSONL to `data/input/<source>/`), `detect_source(rec)`, `add_manual(kind, fields)`, `list_inputs()`, `clear_inputs()`, `list_samples()`, and `load_sample(sample_id)`.
  - Datasets: Official log datasets reside at `data/sample/cloudtrail.json` and `data/sample/okta.json` with metadata in `data/sample/metadata.json`; raw ingress folders at `data/raw/cloudtrail/` and `data/raw/okta/`; sample scenarios at `data/samples/sample_attack_scenario.json`, `data/samples/sample_cloudtrail.json`, `data/samples/sample_okta.json`; analyst benchmark labels stored in `data/labels/` with schema containing `threats: [{identity_id, session_id, patterns, mitre, is_threat, notes}]`.

