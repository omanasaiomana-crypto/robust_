# PHASE 30: Final regression, docs and demo (≈40 min) · All

**Run this phase LAST**, after phases 31–36 (and 28/29 if you did them).

## Part A: full regression (prompt)

```text
Read context.md Sections 12–24.
DO (report first, then fix only real bugs):
1. Run pytest -q and python smoke_test.py and report results.
2. Extend smoke_test.py checks (add entries, keep the existing ones): /api/analytics/detectors,
   /api/analytics/heatmap/time, /api/notifications/status, /api/pipeline/status, /api/agents, /api/scan/status,
   /api/scan/trace, /api/inputs, /api/identities/svc-report/attack (sample data), /api/graph/global,
   /analytics.html, /notifications.html, /agents.html, /scan.html, /input.html, /graph.html.
3. Mock parity: for every static/mock/*.json that maps to a GET endpoint, fetch the live endpoint with
   TestClient and compare top-level keys (and the keys of the first list item, if a list). Report every
   difference. Fix differences in the MOCK files only, unless the live API violates
   kit_v2/03, kit_v2/04 or kit_v2/08 specs (then report first).
4. Reference integrity: run tools/check_ref.py for every pair listed in prompts/00_templates_v2.md T5 plus
   tests/test_v2_features.py (REF_05), tests/test_runner.py (REF_06), tests/test_v21_trace.py (REF_12),
   tests/test_v21_inputs.py (REF_13). All must MATCH.
4b. Audit: GET /api/audit/verify must be valid, and GET /api/audit must contain one "threat_detected" entry per threat
   from the last run (compare with GET /api/scan/status "threats" on a fresh database).
5. Record any real bug in context.md Section 14 and fix it minimally.
FILES: smoke_test.py, static/mock/*.json, context.md, plus minimal bug fixes (list them)
```

## Part B: docs (prompt)

```text
DO:
1. README.md: add sections "Detection analytics", "Email alerts" (modes, .env setup, Gmail App Password
   note, outbox demo), "Background re-runs", "Offline mode", "Analyst token (optional)",
   "Exporting predictions" (python -m app.export), "Latency replay" (python -m app.replay),
   "The 15 agents" (table from kit_v2/08 spec §2.1), "Live scan and terminal scan" (python -m app.scan --json),
   "Threat audit entries", "Entering your own data" and "Attack Path Explorer".
   Keep the existing content.
2. AUDIT_REPORT.md: add a section "v2 changes" summarizing phases 20–29 and 31–36 with what was done and verified,
   and update the "What doesn't work" items that are now fixed (mark them "Resolved in v2" with the phase).
   Keep "real cloud enforcement" listed as intentionally out of scope (hackathon safety rule).
3. Copy the final metrics table from docs/official/RESULTS.md into README.md under "Results".
FILES: README.md, AUDIT_REPORT.md
```

## Part C: demo prep (human)

Follow `kit_v2/06_DEMO_SCRIPT_V2.md`. Rehearse twice with the timer. Before the demo, delete `data/input/` content (or keep a prepared input story) and run one fresh scan so the Live scan replay and the audit log are clean.

## Final CHECK (human)

```bash
pytest -q
python smoke_test.py
python -m app.export
git status            # .env must NOT appear
```

Then: `git commit -m "v2.0-demo"`, `git tag v2.0-demo`, and merge the `v2` branch into main.
