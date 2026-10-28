# 05b · context.md addendum (v2.1)

**How to use:** Phase 31 appends everything below the line to the END of `context.md` (Sections 21–24), after the v2 addendum (Sections 15–20). Nothing earlier is changed.

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
| 31 | Agent trace, threat audit, terminal scan | ☐ | |
| 32 | Agents dashboard | ☐ | |
| 33 | Live scan page | ☐ | |
| 34 | Data input backend | ☐ | |
| 35 | Input page UI | ☐ | |
| 36 | Attack Path Explorer | ☐ | |
