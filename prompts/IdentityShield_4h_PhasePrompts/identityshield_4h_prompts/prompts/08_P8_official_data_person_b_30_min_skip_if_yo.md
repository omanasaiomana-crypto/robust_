# P8 · Official data (Person B, 30 min, skip if you have no dataset)

Put the files in `data/raw/cloudtrail/`, `data/raw/okta/` and `data/labels/`, restart the server, then:

```text
Do NOT edit files yet. Run: python -c "from app import store; store.init_db(); from app.pipeline import run_pipeline; r=run_pipeline(use_sample=False); print(r.status, r.data_mode, len(r.events), r.metrics)"
Report: status, number of events, skipped_records, and the metrics. If skipped_records is more than 1% of the input,
open 2 records from data/raw (redact emails/IPs), list which of our mapped fields are missing or at a different
key path, and wait for my OK before changing anything.
```

If needed, follow up with: *"Add those key paths as FALLBACKS with dig() in app/ingest/normalize.py only. Keep the existing paths first."*
Write the final metrics into `JURY_QA_PREP.md` §8. `git commit -am "P8 official data"`


---
**If the CHECK fails:** use `prompts/99_FIX_template.md`. **Next:** the next numbered file.
