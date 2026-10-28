# START HERE · IdentityShield 4-hour prompt pack

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


## Phase files (run in order, one new Antigravity chat per phase)

| File | Phase |
|---|---|
| `prompts/00_P0_safety_point_human_5_min.md` | P0 · Safety point (human, 5 min) |
| `prompts/01_P1_install_verify_person_a_10_min.md` | P1 · Install + verify (Person A, 10 min) |
| `prompts/02_P2_trace_the_13_pipeline_steps_person_a_30_.md` | P2 · Trace the 13 pipeline steps (Person A, 30 min) |
| `prompts/03_P3_input_only_scans_person_a_15_min.md` | P3 · Input-only scans (Person A, 15 min) |
| `prompts/04_P4_sidebar_person_d_10_min_in_parallel_with.md` | P4 · Sidebar (Person D, 10 min, in parallel with P2) |
| `prompts/05_P5_buttons_and_links_person_d_15_min.md` | P5 · Buttons and links (Person D, 15 min) |
| `prompts/06_P6_full_verification_person_a_20_min.md` | P6 · Full verification (Person A, 20 min) |
| `prompts/07_P7_fix_list_persons_a_d_30_min.md` | P7 · Fix list (Persons A + D, 30 min) |
| `prompts/08_P8_official_data_person_b_30_min_skip_if_yo.md` | P8 · Official data (Person B, 30 min, skip if you have no dataset) |
| `prompts/09_P9_readme_jury_facts_person_c_15_min.md` | P9 · README + jury facts (Person C, 15 min) |
| `prompts/10_P10_freeze_demo_data_all_15_min.md` | P10 · Freeze + demo data (all, 15 min) |
| `prompts/99_FIX_template.md` | FIX · use for any failed CHECK |

**Before P1:** copy `install_v21.py` from this folder into your project root.
