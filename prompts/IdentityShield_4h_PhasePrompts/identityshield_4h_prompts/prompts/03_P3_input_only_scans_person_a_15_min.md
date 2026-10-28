# P3 · Input-only scans (Person A, 15 min)

```text
Modify ONLY app/pipeline.py (and app/ingest/loaders.py only for step 3).
1. Change the signature to: def run_pipeline(use_sample: bool | None = None, input_mode: str | None = None)
2. input_mode None -> unchanged.
   input_mode "only" -> load CloudTrail from config.INPUT_DIR / "cloudtrail" and Okta from config.INPUT_DIR / "okta" with the
   SAME loader functions; data_mode = "input"; if both are empty return the failed result with detail
   "No input data. Add data on the Input page first."
   input_mode "merge" -> normal dataset selection PLUS the input records (concatenate the record lists before
   normalizing); data_mode = "<normal mode>+input".
3. Input files are JSON Lines named cloudtrail_*.jsonl and okta_*.jsonl. If a loader skips them because of a
   file-name or format filter, fix ONLY that filter.
Keep the P2 trace.step wrappers. Show me the diff summary.
```

**CHECK:**
```bash
python -m pytest -q
python -c "from app import inputs; inputs.add_manual('okta_login', {'user':'anita.rao','ip':'49.207.12.8','time':'2026-10-28T03:40:00Z','city':'Bengaluru','country':'India','lat':12.97,'lon':77.59}); inputs.add_manual('okta_login', {'user':'anita.rao','ip':'91.64.18.2','time':'2026-10-28T04:10:00Z','city':'Frankfurt','country':'Germany','lat':50.11,'lon':8.68,'label':'impossible_travel'})"
python -m app.scan --input-only
python -c "from app import inputs; print(inputs.clear_inputs())"
python install_v21.py --check
```
The input-only scan flags **anita.rao** with impossible travel. `--check` shows the traced steps and `input_mode` as `[OK]`.
`git commit -am "P3 input mode"`


---
**If the CHECK fails:** use `prompts/99_FIX_template.md`. **Next:** the next numbered file.
