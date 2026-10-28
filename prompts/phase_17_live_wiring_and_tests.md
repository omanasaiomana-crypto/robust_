# PHASE 17: Live wiring and tests (≈30 min) · Person A + D

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
