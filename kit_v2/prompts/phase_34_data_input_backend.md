# PHASE 34: Input-only data entry: backend (≈30 min) · Person B

**Why:** users (and judges) must be able to **enter their own data**, by pasting or uploading CloudTrail/Okta logs or adding single events with a form, and scan **only that input**. Until now the system could only read files from folders.

Spec: `kit_v2/08_FEATURE_AGENTS_SCAN_INPUT_GRAPH_SPEC.md` §5.

## Prompt

```text
Read context.md (Sections 2, 7, 16, 21–24) and kit_v2/08_FEATURE_AGENTS_SCAN_INPUT_GRAPH_SPEC.md Section 5.

DO:
1. Create app/inputs.py exactly from kit_v2/reference/REF_11_inputs.md.
2. Create tests/test_v21_inputs.py exactly from kit_v2/reference/REF_13_tests_v21_inputs.md.
3. app/pipeline.py: add an optional parameter → run_pipeline(use_sample: bool | None = None,
   input_mode: str | None = None). Behavior:
   - input_mode None → unchanged.
   - input_mode "only" → load CloudTrail from config.INPUT_DIR / "cloudtrail" and Okta from config.INPUT_DIR / "okta"
     with the SAME loader functions; data_mode = "input". If both are empty → return status "failed" with detail
     "No input data. Add data on the Input page first." (the runner keeps the previous results).
   - input_mode "merge" → the normal dataset selection PLUS the input records (concatenate the record lists before
     normalizing); data_mode = "<normal mode>+input".
   Metadata still comes from data/metadata. Everything after loading is unchanged.
   Make sure the loaders accept the input file names (they are "cloudtrail_*.jsonl" / "okta_*.jsonl", JSON Lines).
   If a loader filters by file name or format and would skip them, fix ONLY that filter.
4. Create app/api/inputs.py with APIRouter(tags=["inputs"]), plain-def routes, clean_json on responses:
   - GET    /inputs → inputs.list_inputs()
   - POST   /inputs/upload   body {"content": str, "source": "auto"|"cloudtrail"|"okta" (default auto),
                              "filename": str|null} → inputs.save_input(...)
   - POST   /inputs/manual   body {"kind": "okta_login"|"okta_logout"|"cloudtrail_api", "fields": {...}}
                              → inputs.add_manual(kind, fields)
   - DELETE /inputs → {"removed": inputs.clear_inputs()}
   Map inputs.InputError → HTTP 422 with error "validation_error" and the message as detail (the message is safe to
   show). Use small Pydantic request models defined in app/api/inputs.py (NOT in app/models.py, which is frozen).
   If Phase 28 (analyst token) exists, protect POST /inputs/upload, POST /inputs/manual and DELETE /inputs with
   Depends(require_analyst).
   Include the router in app/main.py (before the static mount).
5. Add to tests/test_v2_api.py (use monkeypatch to point config.INPUT_DIR at tmp_path):
   POST /api/inputs/upload with a Records JSON of 2 CloudTrail events → 200 and accepted.cloudtrail == 2;
   POST /api/inputs/manual with an invalid ip → 422 with error "validation_error";
   POST /api/pipeline/run {"input_mode": "only"} → 202 (or 409 if a run is in progress);
   DELETE /api/inputs → 200.
6. .gitignore: add data/input/
FILES: app/inputs.py, tests/test_v21_inputs.py, app/pipeline.py, app/ingest/loaders.py (filter fix only if needed),
app/api/inputs.py, app/main.py, tests/test_v2_api.py, .gitignore
```

## CHECK (human)

```bash
python tools/check_ref.py app/inputs.py kit_v2/reference/REF_11_inputs.md
pytest -q
python smoke_test.py
```

End-to-end in the terminal:

```bash
python -c "from app import inputs; print(inputs.add_manual('okta_login', {'user':'anita.rao','ip':'49.207.12.8','time':'2026-10-28T03:40:00Z','city':'Bengaluru','country':'India','lat':12.97,'lon':77.59}))"
python -c "from app import inputs; print(inputs.add_manual('okta_login', {'user':'anita.rao','ip':'91.64.18.2','time':'2026-10-28T04:10:00Z','city':'Frankfurt','country':'Germany','lat':50.11,'lon':8.68,'label':'impossible_travel'}))"
python -m app.scan --input-only
```

Expected: the scan runs on **only these 2 events** and the Impossible Travel Agent flags `anita.rao`. Some detectors, such as Dormant Account and ML, need history; on such a small input they report 0 signals or are skipped, which is correct. Clean up with `DELETE /api/inputs` or delete `data/input/`.

---

**After the CHECK passes:** `git commit -m "phase 34 ok"`, then update context.md Section 24.
