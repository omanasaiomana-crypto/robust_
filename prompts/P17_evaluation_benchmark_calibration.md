# P17: Evaluation, benchmark, calibration (MUST: evaluation + benchmark; SHOULD: calibration)

> **Before pasting:** open a NEW Antigravity chat and paste T1 from `00_TEMPLATES.md` first. Then paste only the text block below. Run the CHECK yourself.

```text
Read context.md Sections 2 (rule 10), 14 and PRD §22, §23. Phase P17.
DO:
1. app/v3/evaluate.py (python -m app.v3.evaluate): splits the official labeled dataset by identity or time
   (70/30, seed 42); runs the v3 pipeline in drain mode in three configurations: rules only (agents 10 disabled),
   ML only (only agent 10 signals fused), hybrid (all); computes event-level P/R/F1, session alert precision,
   chain reconstruction (ordered step recall per labeled chain), explanation quality (share of reasons with valid
   evidence ids, counterfactual present, MITRE present), alert reduction; writes data/eval/results_<timestamp>.json
   and latest.json including config hash and dataset hash; prints a table. Thresholds tuned on the 70 % split only.
2. Calibration (SHOULD): fit LogisticRegression on per-detection max strengths per session (train split), map
   coefficients to weights in [0,1] (respect floors), compute reliability diagram (10 bins) and Brier score on the
   test split; save as a new config version (actor "calibration") only when it improves Brier score.
3. app/v3/bench.py (python -m app.v3.bench --multiplier 1|5|10): replays the dataset with fresh ids at the given
   multiplier in live mode (or drain mode with timestamps), measures per-event receive→signal and session-close→case
   latencies (p50/p95/max), events/s, peak queue depth, peak memory (tracemalloc), alert reduction; writes
   data/bench/latest.json with machine info (CPU, cores, RAM, OS, Python version) and timestamp; POST /bench/run
   calls it in a background thread.
4. GET /api/v3/metrics/kpi and /metrics/perf read these files.
5. Tests tests/v3/test_eval_bench.py on fixtures: metric math on a tiny labeled set, results file shape,
   benchmark runs at multiplier 1 on fixtures in < 30 s.
FILES: app/v3/evaluate.py, app/v3/bench.py, app/v3/api.py (wire files only), tests/v3/test_eval_bench.py,
.gitignore (data/eval/, data/bench/ are git-ignored except a sample)
```

**CHECK**
```bash
pytest -q
python -m app.v3.evaluate
python -m app.v3.bench --multiplier 5
```
Record the printed numbers in `context.md` Section 20. These are the only numbers you present.

---
**After the CHECK passes:** paste template T5 (in `00_TEMPLATES.md`), then commit: `git add -A && git commit -m "v3 P17: Evaluation, benchmark, calibration"`. Next file: `P18_hardening_regression_docs_demo_prep.md`.
