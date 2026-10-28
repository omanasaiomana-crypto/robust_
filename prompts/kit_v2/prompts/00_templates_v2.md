# Prompt templates v2 (use any time)

### T1: Session start (every new Antigravity chat)

```text
Read context.md fully, including Sections 15–20 (v2) and 21–24 (v2.1, if present). Then read kit_v2/02_DEVELOPMENT_PLAN.md.
Summarize in 6 bullets: what IdentityShield does, the v1 golden rules, the v2 golden rules
(Section 16), the files you must never rewrite, the current progress (Sections 12 and 20),
and the next phase to do (run order is in kit_v2/02_DEVELOPMENT_PLAN.md). Do not write code yet.
```

### T2: Fix a failed CHECK

```text
Read context.md Sections 2 and 16.
The CHECK for Phase <N> failed with this exact output:
<paste the full traceback or console error>
Fix ONLY the root cause, ONLY in these files: <file list>.
Never edit files copied from kit_v2/reference/ (if the error is inside one of them, stop and tell me).
Do not refactor, rename, add dependencies, or touch other files.
Explain the root cause in one sentence, then show the change.
```

### T3: Resume after an interruption

```text
Read context.md Sections 12 and 20 and list the files that exist for the current v2 phase.
Tell me which phase is in progress, what is done, and what is missing. Do not write code until I confirm.
```

### T4: Scope guard

```text
Stop. Revert every change to files not named in the current prompt.
Follow context.md Section 2 rule 10 and Section 16.5.
```

### T5: Reference integrity check (run whenever unsure)

Run these yourself in the terminal. Each must print `MATCH`:

```bash
python tools/check_ref.py app/analytics.py kit_v2/reference/REF_02_analytics.md
python tools/check_ref.py app/notify.py kit_v2/reference/REF_03_notify.md
python tools/check_ref.py app/runner.py kit_v2/reference/REF_04_runner.md
python tools/check_ref.py app/config.py kit_v2/reference/REF_01_config_v2_block.md --contains
python tools/check_ref.py app/config.py kit_v2/reference/REF_08_config_v21_block.md --contains
python tools/check_ref.py app/trace.py kit_v2/reference/REF_09_trace.md
python tools/check_ref.py app/scan.py kit_v2/reference/REF_10_scan_cli.md
python tools/check_ref.py app/inputs.py kit_v2/reference/REF_11_inputs.md
python tools/check_ref.py static/js/jsonview.js kit_v2/reference/REF_14_jsonview_js.md
python tools/check_ref.py static/js/graphfx.js kit_v2/reference/REF_15_graphfx_js.md
python tools/check_ref.py static/js/scan.js kit_v2/reference/REF_16_scan_page_js.md
python tools/check_ref.py static/js/graph.js kit_v2/reference/REF_17_graph_page_js.md
```
(Only check files whose phase you have finished.)

If one prints `DIFFERENT`, send:

```text
<file> no longer matches kit_v2/reference/<REF file>. Restore it to exactly the code block in that
reference file. Change nothing else.
```

### T6: Slow agent / stuck more than 5 minutes

```text
Stop. Do only step <k> of the current phase prompt, then wait for me.
```

(Then send the remaining steps one at a time.)
