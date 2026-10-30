# P18: Hardening, regression, docs, demo prep (MUST)

> **Before pasting:** open a NEW Antigravity chat and paste T1 from `00_TEMPLATES.md` first. Then paste only the text block below. Run the CHECK yourself.

```text
Read context.md fully. Phase P18: report first, then fix only real bugs.
DO:
1. Run pytest -q (all), ruff check app/v3 tests/v3, and the v2 smoke test; report.
2. Security review (report, then minimal fixes): grep the repo for hard-coded secrets, print/log of headers or
   bodies, f-string SQL, innerHTML with unescaped data in static/v3 and generator, CORS "*", port 8000 bound to
   0.0.0.0, missing analyst-token dependency on any mutating /api/v3 route, simulator call outside a14_response.py,
   network calls outside providers.py/narrator.py. List every finding with file:line and fix.
3. Add tests tests/v3/test_security.py: XSS strings in user agent and resource names appear escaped in API output
   used by UI (API returns raw but UI escapes: assert API never returns HTML-rendered fields), capability violation
   test, ingest tamper suite, secrets never in /api/v3/config output.
4. Mock parity: for each static/v3/mock/*.json compare top-level keys with the live endpoint after a dataset run;
   fix mocks only.
5. README.md: add "IdentityShield v3" section: architecture summary with the 15 agents table, how to run (core,
   ingest, ngrok, generator), environment variables (names only), detections list, risk model summary, response
   safety, evaluation and benchmark commands with the latest numbers from data/eval/latest.json and
   data/bench/latest.json, limitations (out of scope: DNS, malware, TLS fingerprinting, inline pre-auth), roadmap.
6. DEMO_CHECKLIST.md: fresh DB step, audit verify, both network modes, pace Normal, generator secret masked,
   backup recording, owner per question area, the 5-minute script from PRD §30.1.
7. Update context.md Section 20 for all phases and list remaining known issues.
FILES: tests/v3/test_security.py, static/v3/mock/*.json, README.md, DEMO_CHECKLIST.md, context.md, plus minimal
bug-fix files (list them)
```

**FINAL CHECK**
```bash
pytest -q
ruff check app/v3 tests/v3
python -m app.v3.evaluate
git status        # .env must NOT be listed
```

---
**After the CHECK passes:** paste template T5 (in `00_TEMPLATES.md`), then commit: `git add -A && git commit -m "v3 P18: Hardening, regression, docs, demo prep"`. Next file: `DEMO_CHECKLIST.md` (final rehearsal).
