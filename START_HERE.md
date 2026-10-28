# START HERE: IdentityShield build kit

Everything you need to build the IdentityShield website in 8 hours with Antigravity.

## What is in this kit

| Item | What it is |
|---|---|
| `context.md` | Project memory. The agent reads it before every prompt so it never loses context. |
| `prompts/` | One prompt file per phase, in order. Each has a CHECK you must pass before the next. |
| `BUILD_PROMPTS.md` | The same prompts in one file, if you prefer scrolling. |
| `docs/PRD.md` | Product and ML design (for judges, slides and the paper round). |
| `docs/TECH_PRD.md` | Technical spec the prompts refer to (sections by number). |
| `app/` (pre-built part) | Tested foundation: `models.py`, `config.py`, `utils.py`, `store.py`, `audit.py`. |
| `tests/test_foundation.py` | Tests for the foundation (5 tests, all passing). |
| `smoke_test.py`, `run.bat`, `run.sh`, `requirements.txt` | Run and verify scripts. |

## Steps

1. Unzip. Open the `identityshield` folder in Antigravity.
2. `git init && git add . && git commit -m "kit"`
3. Open `prompts/phase_00_02_verify_foundation.md` and follow it (install, verify, commit, push).
4. In every new Antigravity chat, first send **T1** from `prompts/00_templates.md`.
5. Then send phases in order, one per message: `phase_03` → `phase_18`. After each: run the CHECK,
   then `git commit`.
6. Check fails? Send **T2** with the exact error. Agent drifting? Send **T4**.
7. Finish with `prompts/phase_19_final_demo_checklist.md`.

## Team split (4 laptops, in parallel)

| Person | Files to run |
|---|---|
| A (lead) | phase_00_02 → phase_10 → phase_11 → phase_17 |
| B | phase_03 → 04 → 05 → 06 → 07 |
| C | phase_08 → 09 (+ evaluation part of 10) |
| D | phase_12 → 13 → 14 → 15 → 16 (use `?mock=1`, no backend needed) → 18 |

Person A pushes the verified foundation first (about 15 minutes); everyone pulls before starting.

## Timeline (8 hours)

| Time | Milestone |
|---|---|
| 0:15 | Foundation verified and pushed |
| 2:30 | Sample data loads and normalizes; UI shell works in mock mode |
| 4:30 | All 6 detectors and scoring work |
| 5:30 | Pipeline + API pass `python smoke_test.py` |
| 6:30 | Website connected to live API |
| 7:15 | Metrics vs baseline; code freeze |
| 8:00 | Demo rehearsed twice |

## Rules that keep the backend error-free

- Never let the agent edit files not named in the current prompt.
- Never let it rewrite the pre-built foundation files.
- Run the CHECK after every phase and commit only when it passes.
- If something breaks badly: `git checkout .` and resend the prompt.
