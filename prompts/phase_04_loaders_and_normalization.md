# PHASE 4: Loaders and normalization (≈20 min) · Person B

```text
Read context.md fully. Then read docs/TECH_PRD.md Sections 9.1–9.5 and 9.7.

GOAL: Load any supported file format and convert CloudTrail + Okta into the Event table.

DO:
1. app/ingest/loaders.py:
   - load_cloudtrail(folder: Path) -> tuple[list[dict], int]
   - load_okta(folder: Path) -> tuple[list[dict], int]
   - load_metadata(folder: Path) -> dict[str, dict]   (identity_id -> attributes)
   - load_labels(folder: Path) -> dict[str, str]     (event_id -> label)
   Support: {"Records": [...]}, JSON array, JSON Lines, .gz versions, CSV. Detect format by
   extension and first non-space character. Files sorted by name. A corrupt file or line is skipped
   and counted, never raised. A missing folder returns ([], 0).
   For the sample folder, cloudtrail.json and okta.json are in the same folder: load_cloudtrail
   reads files whose name contains "cloudtrail" or that have a "Records" key; load_okta reads files
   whose name contains "okta".
2. app/ingest/normalize.py:
   - canonical_identity(value: str | None) -> str  (lowercase; email → local part; arn → last segment
     after "/"; None → "unknown")
   - normalize_cloudtrail(rec: dict, idx: int) -> Event | None
   - normalize_okta(rec: dict, idx: int) -> Event | None
   - normalize_all(ct: list[dict], okta: list[dict]) -> tuple[pd.DataFrame, int]
   Follow the mapping tables in TECH_PRD 9.3 and 9.4 exactly, using dig() and parse_ts().
   Records with no timestamp are skipped and counted. Keep the top-level "label" field if present.
   DataFrame columns = Event model fields in model order; sorted by timestamp; index reset.
   Build rows with event.model_dump() and create the DataFrame once at the end (not row by row).

FILES: app/ingest/loaders.py, app/ingest/normalize.py

CHECK:
python -c "from app.config import SAMPLE_DIR; from app.ingest.loaders import load_cloudtrail, load_okta; from app.ingest.normalize import normalize_all; ct,a=load_cloudtrail(SAMPLE_DIR); ok,b=load_okta(SAMPLE_DIR); df,s=normalize_all(ct,ok); print(df.shape, s, df['source'].value_counts().to_dict(), df['identity_id'].nunique())"
Expected: thousands of rows, both sources present, about 20 identities, skipped close to 0.
Then update context.md Section 12: Phase 4 = ☑.
```

---

**After the CHECK passes:** `git add . && git commit -m "phase 4 ok"`, then open the next file.
**If the CHECK fails:** use template T2 in `prompts/00_templates.md` with the exact error.
