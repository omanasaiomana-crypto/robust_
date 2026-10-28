# PHASE 20: Audit verification and consistency fixes (≈30 min) · Person A

**Why:** the audit has six internal inconsistencies (see `01_AUDIT_REVIEW.md` §3). This phase checks the real code, fixes hardcoded values, installs the v2 context and config, and corrects the report.

## Before you start (human, 2 min)

1. Copy the whole `kit_v2/` folder into the project root (next to `context.md`).
2. `git pull`, then `git checkout -b v2` (work on a branch so v1 stays safe).
3. Run the baseline: `pytest -q` and `python smoke_test.py`. Write down the test count; it must not go down later.

## Prompt (part A: investigate only, no code changes)

```text
Read context.md fully, then kit_v2/01_AUDIT_REVIEW.md Section 3.

Investigate and REPORT ONLY (do not change any file yet). For each item give file, line and actual value:
1. Impossible travel threshold: does app/agents/impossible_travel.py use config.IMPOSSIBLE_TRAVEL_KMH,
   or a hardcoded number (800/900)?
2. Okta↔AWS session link window in app/correlate/sessions.py: what is the actual value (15 min? 12 h?)
   and is it hardcoded?
3. Is app/ml/calibrate.py (Calibrator) used in the final risk in app/decision/scoring.py or
   app/pipeline.py? If yes, what labels does it train on?
4. How is Metrics.median_latency_ms computed in app/evaluation.py?
5. List every other hardcoded numeric threshold in app/agents/, app/correlate/, app/decision/ and
   app/pipeline.py that should come from app/config.py (ignore 0, 1, 100 and list indexes).
6. Which existing tests would break if the session link window changed?
Format: a table with columns Item | File:line | Actual | Hardcoded? | Proposed fix.
```

Read the report. If anything looks surprising, ask the agent before continuing.

## Prompt (part B: apply fixes)

```text
Read context.md Sections 2, 6 and 13, and kit_v2/05_CONTEXT_V2_ADDENDUM.md.

DO:
1. Append EVERYTHING below the horizontal line in kit_v2/05_CONTEXT_V2_ADDENDUM.md to the END of
   context.md (new Sections 15–20). Do not change Sections 1–14.
2. Append the code block from kit_v2/reference/REF_01_config_v2_block.md to the END of app/config.py,
   exactly. Do not modify existing lines.
3. Insert these constants DIRECTLY ABOVE the "# v2 additions" comment block (so the v2 block stays the
   last thing in the file):
   SESSION_LINK_WINDOW_HOURS = <current actual value in hours, so behavior does not change yet>
   plus one constant per hardcoded threshold you found in part A item 5 (keep current values).
4. Replace each hardcoded value found in part A (items 1, 2, 5) with the matching config constant.
   Behavior must not change: same values, only their source changes.
5. Create tools/check_ref.py exactly from kit_v2/reference/REF_00_check_ref_tool.md.
6. Add these lines to .gitignore if missing: .env, data/outbox/, data/output/
7. In AUDIT_REPORT.md add a section "Corrections (v2 review)" at the end, listing the corrected facts:
   real travel threshold, real session window, endpoint count (count the routes in app/api),
   "normalized" instead of "calibrated" anomaly scores, whether the calibrator is used, and how latency
   is currently computed. Do not rewrite the rest of the report.
8. Update context.md Section 20: Phase 20 = ☑.

FILES: context.md, app/config.py, app/agents/*.py and app/correlate/sessions.py and app/decision/*.py and
app/pipeline.py (constant replacement ONLY), tools/check_ref.py, .gitignore, AUDIT_REPORT.md
```

## CHECK (human)

```bash
pytest -q                      # same number of tests as before, all pass
python smoke_test.py           # SMOKE TEST PASSED
python tools/check_ref.py app/config.py kit_v2/reference/REF_01_config_v2_block.md --contains
python -c "import app.config as c; print(c.EMAIL_MODE, c.EMAIL_MIN_RISK, c.SESSION_LINK_WINDOW_HOURS, c.IMPOSSIBLE_TRAVEL_KMH)"
```

Expected: tests unchanged and green; `MATCH`; then a line like `outbox 70 <window> 900.0`.

---

**After the CHECK passes:** `git add . && git commit -m "phase 20 ok"`.
**Decision for Phase 21:** keep the current session window for now; Phase 21 tests other values on the official data.
