# FIX · use for any failed CHECK

```text
This command failed: <command>
Exact output:
<paste the full error>
Fix ONLY the cause, ONLY in: <file list>.
Never modify these installed files: app/trace.py, app/runner.py, app/notify.py, app/analytics.py, app/inputs.py,
app/scan.py, app/v21_service.py, app/api/v21.py, app/models.py, static/js/v21kit.js, jsonview.js, graphfx.js,
scan.js, explorer.js, agents.js, input.js, analytics.js, notifications.js.
If the error is inside one of those, stop and tell me.
Explain the root cause in one sentence, then show the change.
```

**If something is badly broken and time is short:** `git checkout <last good commit> -- <file>`. Demo in mock mode as a last resort: `scan.html?mock=1&autostart=replay` and `explorer.html?mock=1&play=1` work without the backend.
