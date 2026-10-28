# IdentityShield · 4-hour prompt pack (phase by phase)

**Needs:** `install_v21.py` from **IdentityShield_FastTrack_4h.zip**, copied into the project root. The installer writes all the pre-tested code; these prompts only **wire it in**. So every prompt is short, and Antigravity edits only 1–3 files per phase.

**Rules for every phase:**
- Open a **new Antigravity chat** for each phase (slow agents get slower with long chats).
- Send the prompt **exactly as written**, run the **CHECK**, then `git commit`.
- If a CHECK fails, send **FIX** (bottom of this file). If it fails twice, `git checkout .` and resend the phase.
- Never let Antigravity rewrite the installed files (the list is in FIX).

## Timeline (4 h)

| Time | Phase | Who | Minutes |
|---|---|---|---|
| 0:00 | P0 Safety point | Human | 5 |
| 0:05 | P1 Install + verify | A | 10 |
| 0:15 | P2 Trace the pipeline steps | A | 30 |
| 0:15 | P4 Sidebar | D (parallel) | 10 |
| 0:25 | P5 Buttons and links | D (parallel) | 15 |
| 0:45 | P3 Input-only scans | A | 15 |
| 1:00 | P6 Full verification | A | 20 |
| 1:20 | P7 Fix list from P6 | A + D | 30 |
| 1:50 | P8 Official data (skip if none) | B | 30 |
| 2:20 | P9 README + jury facts | C | 15 |
| 2:35 | P10 Freeze + demo data | All | 15 |
| 2:50 | Rehearsal × 2, backup video, jury Q&A | All | 70 |
| 4:00 | Done | | |

Persons B and C: until P8/P9, practise the demo and `JURY_QA_PREP.md` in mock mode (`scan.html?mock=1`, `explorer.html?mock=1&play=1`).

---

## P0 · Safety point (human, 5 min)

```bash
git add . && git commit -m "before v2.1"
```

Copy `install_v21.py` into the project root (next to `app/` and `static/`). Activate the venv.

---

## P1 · Install + verify (Person A, 10 min)

```text
Run these commands in the project root, in order, and report each output. Do NOT edit any file in this phase.
1. python install_v21.py
2. python -m pytest -q
3. python smoke_test.py
If step 1 prints [TODO] lines, that is expected for: "traced steps", "input_mode", "sidebar links".
Any OTHER [TODO] line, a failing test or a smoke-test failure: show me the full output and stop.
```

**CHECK:** the installer shows `[OK]` for files, config, pages, `main.py`, compile and the `app.api.v21` import; pytest passes; the smoke test passes.
`git add . && git commit -m "P1 installed"`

---

## P2 · Trace the 13 pipeline steps (Person A, 30 min)

```text
Read ONLY app/pipeline.py and, in app/trace.py, the AGENTS list and the step() and skip() functions.
Modify ONLY app/pipeline.py. Behavior must stay exactly the same.

Add `from app import trace` and wrap each existing pipeline step INSIDE its existing try block:

    with trace.step("<agent_id>", "<started message>") as s:
        ...existing code, unchanged...
        s.output({<small summary>}, "<one-line result>")

Use these ids in this order (summaries = counts and up to 3 examples, never DataFrames; cast numpy values with int()/float()):
 1 "ingestion"     "Loading CloudTrail and Okta files"      -> {"records": {"cloudtrail": n, "okta": n}, "skipped": n}
 2 "normalization" "Mapping both formats to one schema"     -> {"events": n, "skipped": n, "identities": n}
 3 "enrichment"    "Adding geo, privilege and sensitivity"  -> {"events": n, "privileged_identities": n}
 4 "correlation"   "Linking Okta sessions to AWS activity"  -> {"sessions": n, "graph": {"nodes": n, "edges": n}}
 5-9 each rule detector, id = the detector object's `name` (impossible_travel, dormant, priv_escalation, api_anomaly,
     token_abuse) -> {"signals": len(sigs), "examples": [first 3 as {"identity_id","session_id","severity","reason"}]}
 10 "baseline_ml"  "Isolation Forest over session features" -> {"signals": n}
     (if ML is skipped for too little data: trace.skip("baseline_ml", "Not enough sessions to train"))
 11 "risk_scoring" "Combining signals x privilege x sensitivity" -> {"alerts": n, "top_risk": x}
 12 "explanation"  "Writing reasons, counterfactuals and MITRE tags" -> {"alerts_explained": n}
 13 "response"     "Choosing actions (simulator only)" -> {"applied": n, "pending_approval": n}
If two ids happen in one block, wrap the block with the first and add a second `with trace.step(...)` for the other
right after, so all 13 ids appear. trace.step re-raises errors, so the existing except blocks keep working.
Do NOT call trace.begin_run, trace.end_run or trace.log_threats. Show me the diff summary when done.
```

**CHECK:**
```bash
python -m pytest -q
python -m app.scan --sample --json --delay 0.03
```
You should see 13 colored steps (`>>` then `OK`), red **THREAT** lines, and **SCAN COMPLETE**.
`git commit -am "P2 pipeline traced"`

---

## P3 · Input-only scans (Person A, 15 min)

```text
Modify ONLY app/pipeline.py (and app/ingest/loaders.py only for step 3).
1. Change the signature to: def run_pipeline(use_sample: bool | None = None, input_mode: str | None = None)
2. input_mode None -> unchanged.
   input_mode "only" -> load CloudTrail from config.INPUT_DIR / "cloudtrail" and Okta from config.INPUT_DIR / "okta" with the
   SAME loader functions; data_mode = "input"; if both are empty return the failed result with detail
   "No input data. Add data on the Input page first."
   input_mode "merge" -> normal dataset selection PLUS the input records (concatenate the record lists before
   normalizing); data_mode = "<normal mode>+input".
3. Input files are JSON Lines named cloudtrail_*.jsonl and okta_*.jsonl. If a loader skips them because of a
   file-name or format filter, fix ONLY that filter.
Keep the P2 trace.step wrappers. Show me the diff summary.
```

**CHECK:**
```bash
python -m pytest -q
python -c "from app import inputs; inputs.add_manual('okta_login', {'user':'anita.rao','ip':'49.207.12.8','time':'2026-10-28T03:40:00Z','city':'Bengaluru','country':'India','lat':12.97,'lon':77.59}); inputs.add_manual('okta_login', {'user':'anita.rao','ip':'91.64.18.2','time':'2026-10-28T04:10:00Z','city':'Frankfurt','country':'Germany','lat':50.11,'lon':8.68,'label':'impossible_travel'})"
python -m app.scan --input-only
python -c "from app import inputs; print(inputs.clear_inputs())"
python install_v21.py --check
```
The input-only scan flags **anita.rao** with impossible travel. `--check` shows the traced steps and `input_mode` as `[OK]`.
`git commit -am "P3 input mode"`

---

## P4 · Sidebar (Person D, 10 min, in parallel with P2)

```text
Modify ONLY static/js/layout.js.
Add sidebar items in the same style as the existing ones (inline SVG icon + label, keep ?mock=1 on links like the
existing items). Final order:
Overview, Live scan (scan.html, id "scan"), Agents (agents.html, id "agents"), Input data (input.html, id "input"),
Alerts, Identities, Attack paths (explorer.html, id "explorer"), Analytics (analytics.html, id "analytics"),
Hygiene, Audit, Notifications (notifications.html, id "notifications").
If an item already exists, keep one copy. renderLayout(<id>, …) must highlight the item with that id.
```

**CHECK:** open `index.html?mock=1`; every sidebar item opens its page; the active item is highlighted; no console errors.
`git commit -am "P4 sidebar"`

---

## P5 · Buttons and links (Person D, 15 min)

```text
Modify ONLY static/js/overview.js, static/js/alert.js and static/js/identities.js.
1. overview.js: add a primary button "Run live scan" in the page header linking to scan.html?autostart=1
   (when ?mock=1 is in the URL: scan.html?mock=1&autostart=replay).
2. alert.js: (a) change the "Open identity graph" link to explorer.html?identity=<identity_id>&play=1 (keep ?mock=1);
   (b) add a secondary button "Email admin" that calls the existing api() helper with path `/alerts/<id>/notify`
   and method POST (the helper adds /api), then a toast: status "outbox" -> "Email saved to outbox (demo mode)",
   "sent" -> "Email sent", "mocked" -> "Mock mode: nothing sent", otherwise the detail text as an error toast.
3. identities.js: rows link to explorer.html?identity=<id> instead of graph.html.
Change nothing else.
```

**CHECK:** the Overview button opens the Live scan; on an alert, **Email admin** shows a toast and the graph link opens the explorer with playback; identity rows open the explorer.
`git commit -am "P5 links"`

---

## P6 · Full verification (Person A, 20 min)

Start the server (`python -m uvicorn app.main:app --port 8000`), then:

```text
Do NOT edit files. Write and run scratch_verify.py (do not commit it) that uses fastapi.testclient.TestClient(app.main.app)
inside `with TestClient(app) as c:` and prints status code + top-level keys for:
GET /api/agents, POST /api/scan/start (body {}), then poll GET /api/scan/status every 0.5 s until state != "running"
(max 60 s), GET /api/scan/trace?after=0 (print number of events and the distinct agent_id values),
GET /api/audit (count entries with action "threat_detected"), GET /api/audit/verify,
GET /api/identities/svc-report/attack (print number of nodes/edges and alert id),
GET /api/graph/global, GET /api/analytics/detectors (print winner), GET /api/analytics/heatmap/time (print total),
GET /api/inputs, GET /api/notifications/status, POST /api/notifications/test,
GET /scan.html, /agents.html, /input.html, /explorer.html, /analytics.html, /notifications.html.
Report a table: endpoint | status | key facts. Mark anything that is not 2xx.
```

**Expected:** all 2xx (or 202); 14+ distinct agent ids in the trace; at least one `threat_detected` entry; audit `valid: true`; the explorer for svc-report has edges and an alert id.

Then **click through in the browser** (10 min):

| Page | Must see |
|---|---|
| Live scan | Start scan at 1×: steps stream, "Step k/13", JSON panel, THREAT cards, banner with the actual time |
| Agents | 15 cards, all Done; click one to see its JSON |
| Attack paths | svc-report: red path with particles, numbered badges, ▶ Play attack, Focus, Blast radius |
| Input data | Presets Bengaluru + Frankfurt → Add → Scan input only → THREAT anita.rao |
| Analytics | Winner, 3 cards, chart, heatmaps |
| Notifications | Send test email → outbox row with a preview |
| Audit | `threat_detected` entries; chain intact |

Write every problem into a list for P7.

---

## P7 · Fix list (Persons A + D, 30 min)

Send **one FIX prompt per problem** (template below), the most visible problem first. Common cases:

| Symptom | Likely cause | What to do |
|---|---|---|
| Explorer area empty | Wrong vis-network script path in `explorer.html` | Set it to `/vendor/vis-network.min.js` if that file exists, otherwise `https://unpkg.com/vis-network@9.1.9/standalone/umd/vis-network.min.js` |
| Agents page all Idle | No scan run yet since server start | Run one Live scan |
| Live scan shows only orchestrator lines | P2 not done or wrappers missing | Redo P2 |
| Explorer: "Path steps —" | Evidence edges were cut by the 150-node cap | FIX: "in identity_subgraph keep edges whose event_id is in suspicious_ids first when trimming" |
| Input scan: "No input data" | Nothing added, or loader filter | Add presets first; otherwise redo P3 step 3 |

`git commit -am "P7 fixes"` after each fix that passes.

---

## P8 · Official data (Person B, 30 min, skip if you have no dataset)

Put the files in `data/raw/cloudtrail/`, `data/raw/okta/` and `data/labels/`, restart the server, then:

```text
Do NOT edit files yet. Run: python -c "from app import store; store.init_db(); from app.pipeline import run_pipeline; r=run_pipeline(use_sample=False); print(r.status, r.data_mode, len(r.events), r.metrics)"
Report: status, number of events, skipped_records, and the metrics. If skipped_records is more than 1% of the input,
open 2 records from data/raw (redact emails/IPs), list which of our mapped fields are missing or at a different
key path, and wait for my OK before changing anything.
```

If needed, follow up with: *"Add those key paths as FALLBACKS with dig() in app/ingest/normalize.py only. Keep the existing paths first."*
Write the final metrics into `JURY_QA_PREP.md` §8. `git commit -am "P8 official data"`

---

## P9 · README + jury facts (Person C, 15 min)

```text
Modify ONLY README.md. Add short sections (keep existing content):
"The 15 agents" (5 layers: data 1-4, detection 5-10, decision 11-13, learning 14, oversight 15),
"Live scan" (scan.html, and terminal: python -m app.scan --json --delay 0.05),
"Threat audit entries" (one threat_detected audit entry per threat, deduplicated, hash-chained),
"Entering your own data" (input.html: paste/upload/form, Scan input only),
"Attack Path Explorer" (explorer.html: playback, focus, blast radius),
"Analytics" and "Email alerts" (.env.example; outbox mode works offline).
```

`git commit -am "P9 docs"`

---

## P10 · Freeze + demo data (all, 15 min)

```bash
python -c "from app import inputs; print(inputs.clear_inputs())"
git add . && git commit -m "demo freeze" && git tag demo-final
python -m uvicorn app.main:app --port 8000
```

1. Open the **Live scan** page and run **Start scan** once, so the audit log and the replay are fresh.
2. Pre-open tabs: Live scan, Agents, Attack paths (svc-report), Input data, the svc-report alert, Analytics, Audit.
3. Record a 3-minute backup video.
4. **No code changes after this point.**

**Demo order (6 min):** Live scan → Agents → Attack paths (Play attack) → Input data (2 presets → Scan input only) → Alert (Approve revoke, Email admin) → Analytics → Audit (Verify).

---

## FIX · use for any failed CHECK

```text
This command failed: <command>
Exact output:
<paste the full error>
Fix ONLY the cause, ONLY in: <file list>.
Never modify these installed files: app/trace.py, app/runner.py, app/notify.py, app/analytics.py, app/inputs.py,
app/scan.py, app/v21_service.py, app/api/v21.py, app/models.py, static/js/v21kit.js, jsonview.js, graphfx.js,
scan.js, explorer.js, agents.js, input.js, analytics.js, notifications.js.
If the error is inside one of those, stop and tell me.
Explain the root cause in one sentence, then show the change.
```

**If something is badly broken and time is short:** `git checkout <last good commit> -- <file>`. Demo in mock mode as a last resort: `scan.html?mock=1&autostart=replay` and `explorer.html?mock=1&play=1` work without the backend.
