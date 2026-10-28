# P2 · Trace the 13 pipeline steps (Person A, 30 min)

```text
Read ONLY app/pipeline.py and, in app/trace.py, the AGENTS list and the step() and skip() functions.
Modify ONLY app/pipeline.py. Behavior must stay exactly the same.

Add `from app import trace` and wrap each existing pipeline step INSIDE its existing try block:

    with trace.step("<agent_id>", "<started message>") as s:
        ...existing code, unchanged...
        s.output({<small summary>}, "<one-line result>")

Use these ids in this order (summaries = counts and up to 3 examples, never DataFrames; cast numpy values with int()/float()):
 1 "ingestion"     "Loading CloudTrail and Okta files"      -> {"records": {"cloudtrail": n, "okta": n}, "skipped": n}
 2 "normalization" "Mapping both formats to one schema"     -> {"events": n, "skipped": n, "identities": n}
 3 "enrichment"    "Adding geo, privilege and sensitivity"  -> {"events": n, "privileged_identities": n}
 4 "correlation"   "Linking Okta sessions to AWS activity"  -> {"sessions": n, "graph": {"nodes": n, "edges": n}}
 5-9 each rule detector, id = the detector object's `name` (impossible_travel, dormant, priv_escalation, api_anomaly,
     token_abuse) -> {"signals": len(sigs), "examples": [first 3 as {"identity_id","session_id","severity","reason"}]}
 10 "baseline_ml"  "Isolation Forest over session features" -> {"signals": n}
     (if ML is skipped for too little data: trace.skip("baseline_ml", "Not enough sessions to train"))
 11 "risk_scoring" "Combining signals x privilege x sensitivity" -> {"alerts": n, "top_risk": x}
 12 "explanation"  "Writing reasons, counterfactuals and MITRE tags" -> {"alerts_explained": n}
 13 "response"     "Choosing actions (simulator only)" -> {"applied": n, "pending_approval": n}
If two ids happen in one block, wrap the block with the first and add a second `with trace.step(...)` for the other
right after, so all 13 ids appear. trace.step re-raises errors, so the existing except blocks keep working.
Do NOT call trace.begin_run, trace.end_run or trace.log_threats. Show me the diff summary when done.
```

**CHECK:**
```bash
python -m pytest -q
python -m app.scan --sample --json --delay 0.03
```
You should see 13 colored steps (`>>` then `OK`), red **THREAT** lines, and **SCAN COMPLETE**.
`git commit -am "P2 pipeline traced"`


---
**If the CHECK fails:** use `prompts/99_FIX_template.md`. **Next:** the next numbered file.
