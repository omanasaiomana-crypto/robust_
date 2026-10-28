# Config v2.1 block

**Target file:** `app/config.py (APPEND to the end; do not change existing lines)`

Trace buffer size, payload cap, threat-audit threshold and data-input limits.

**Status:** written and tested before shipping this kit. Copy the code block EXACTLY; other phases call these names.
Verify with: `python tools/check_ref.py app/config.py kit_v2/reference/REF_08_config_v21_block.md` --contains

```python
# ---------------------------------------------------------------------------
# v2.1 additions (append-only block: agent trace, threat audit, data input)
# ---------------------------------------------------------------------------
TRACE_MAX_EVENTS = 5000                    # in-memory ring buffer of scan trace events
TRACE_MAX_DATA_CHARS = 20000               # larger JSON payloads are truncated with a preview
THREAT_AUDIT_MIN_RISK = BAND_STEP_UP       # every alert at/above this risk gets its own audit entry
INPUT_DIR = DATA_DIR / "input"             # data/input/cloudtrail, data/input/okta
INPUT_MAX_BYTES = _env_int("INPUT_MAX_BYTES", 5_000_000)
INPUT_MAX_RECORDS = _env_int("INPUT_MAX_RECORDS", 50_000)
```
