# Final demo checklist


1. Stop the dev server; start without `--reload`: `python -m uvicorn app.main:app --port 8000`.
2. `python smoke_test.py` → SMOKE TEST PASSED.
3. Pre-open tabs: Overview → Alerts → svc-report alert → Graph → Timeline → Audit.
4. Demo flow (3 minutes):
   - Overview: "5 attack types detected, F1 vs baseline."
   - Alert: "Every login succeeded, but we connected Okta and AWS into one story."
   - Counterfactual table: "This is why the score is 94."
   - Chain + prediction: "We warned before the admin role was used."
   - Approve revoke: "Only through the simulator, with analyst approval and an audit trail."
   - Graph + timeline: "Here is the attacker's full path."
   - Audit: "Our own system is tamper-evident."
5. Keep a screen recording as backup in case of Wi-Fi or CDN problems.