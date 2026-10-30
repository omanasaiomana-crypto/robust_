# P12: API v3, SSE, dataset run, main.py wiring (MUST)

> **Before pasting:** open a NEW Antigravity chat and paste T1 from `00_TEMPLATES.md` first. Then paste only the text block below. Run the CHECK yourself.

```text
Read context.md Sections 2, 5, 6, 17 and PRD §19. Phase P12.
DO:
1. app/v3/pipeline_v3.py: run_dataset(paths=None, input_only=False, pace=0) builds a fresh bus + supervisor with
   register_all, replays the official dataset (paths from P0 integration notes) or the Input page data through
   raw.okta/raw.cloudtrail, drains, triggers final tick, returns a summary (events, signals, cases, actions,
   duration, per-agent counts). Paced mode delegates to live mode with the Supervisor pace.
2. app/v3/sse.py: broadcaster with per-client asyncio queues (max 1,000, drop oldest), heartbeat comment every 15 s,
   event types: trace, risk, case, action, metrics; GET /api/v3/stream returns text/event-stream.
3. app/v3/api.py (APIRouter prefix /api/v3) implementing every endpoint in context.md Section 17 with thin handlers
   calling service functions; pagination (limit ≤ 500, offset); 404s with clear detail; analyst token dependency on
   mutating routes; GET /geo/logins returns login points and consecutive-login arcs per identity (flag impossible
   travel arcs) for the globe; GET /identities/{id}/graph and /graph/global return {nodes, edges} with kind,
   suspicious flags, okta_to_aws flags for the 3D graph (cap 1,500 nodes); GET /metrics/perf returns latency
   percentiles, events/s, queue depths, alert reduction; GET /metrics/kpi returns the latest evaluation file content
   or {"status":"not_run"}.
4. app/main.py: include the v3 router BEFORE the static mount; in the app lifespan (or startup/shutdown events,
   whichever the file already uses) start the v3 live runtime: create store tables, supervisor, bus (live mode),
   register agents, start SSE broadcaster, and start the ingest service on INGEST_PORT in a background thread
   sharing the same bus; stop everything cleanly on shutdown. Guard with config V3_ENABLED (default True).
   Do not change any v2 route.
5. Tests tests/v3/test_api.py: every GET returns 200 with expected keys on a dataset run of the fixtures; mutating
   routes 401 without token when ANALYST_TOKEN set; approve flow through API changes action state; SSE endpoint
   streams a heartbeat and a trace event (use a short timeout); /api/v3/run/dataset produces at least one case
   on the E1 fixture; v2 smoke still passes.
FILES: app/v3/pipeline_v3.py, app/v3/sse.py, app/v3/api.py, app/main.py (router include + lifespan only),
app/v3/config.py (add V3_ENABLED only), tests/v3/test_api.py, tests/v3/fixtures/e1_attack.json
```

**CHECK**
```bash
pytest -q
ruff check app/v3 tests/v3
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
# second terminal:
curl -s localhost:8000/api/v3/health
curl -s -X POST localhost:8000/api/v3/run/dataset
curl -s localhost:8000/api/v3/cases | head -c 600
curl -s localhost:8001/ingest/v1/health
```

---
**After the CHECK passes:** paste template T5 (in `00_TEMPLATES.md`), then commit: `git add -A && git commit -m "v3 P12: API v3, SSE, dataset run, main.py wiring"`. Next file: `P13_ui_foundation_3d_theme_shell_background.md`.
