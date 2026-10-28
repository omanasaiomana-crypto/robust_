# PHASES 0–2: Verify the pre-built foundation (≈10 min) · Person A

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
