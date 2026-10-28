# PHASE 29: Supplied simulator adapter (≈20 min) · Person A

**Why:** audit gap 2.1, handled the **safe** way. The audit suggests boto3 and Okta API calls. **Do not build those.** The hackathon rules say all enforcement must use the supplied simulator, and no live cloud accounts, identity providers or production tenants may be modified. This phase connects `SuppliedSimulator` to the **organizers' simulator only**.

**Do this phase only once the organizers' simulator interface is available.** Put their docs, sample code and any client module in `docs/official/simulator/`.

## Prompt

```text
Read context.md Sections 2 (rule 13), 15–16 (16.1, 16.2), and every file in docs/official/simulator/.

First REPORT (no code): what the simulator interface is (Python module/function names, or HTTP endpoints
with method, URL, request and response format, auth), and how our three actions map to it:
step_up(identity_id, session_id), restrict(identity_id, scope), revoke(identity_id, session_id).
Wait for my confirmation.
```

After you confirm:

```text
Implement app/simulator/supplied.py SuppliedSimulator(SimulatorAdapter) against EXACTLY that interface:
- If it is a Python module provided by the organizers: import it lazily inside the methods, with a clear
  error if it is missing.
- If it is HTTP: use urllib.request only (no requests library), JSON bodies, timeout=10 s, a base URL from a
  new config constant SIMULATOR_URL appended to the END of app/config.py
  (os.environ.get("SIMULATOR_URL", "")), and any auth header from an env var named in the organizer docs
  (never hardcode secrets).
- Each method returns a short status string like the mock ("simulated:<action>:<result>").
- On any error raise RuntimeError with a short message; app/decision/respond.py already turns errors into
  an ActionResult. If it does not, catch the error there and return status "failed" with the message
  (smallest possible change).
- Never call any AWS or Okta API. Never import boto3 or requests.
- SIMULATOR_MODE stays "mock" by default. To allow an override with env SIMULATOR_MODE=supplied, append
  this line to the END of app/config.py (do not edit the original constant; `os` is imported in the v2 block):
  SIMULATOR_MODE = os.environ.get("SIMULATOR_MODE", SIMULATOR_MODE).strip().lower()
Add tests/test_supplied_simulator.py that monkeypatches the transport (the urllib.request.urlopen call or the
organizer module) and checks: the correct request for each action, and that an error becomes a "failed"
ActionResult instead of an exception escaping.
FILES: app/simulator/supplied.py, app/config.py (append), app/decision/respond.py (only if needed),
tests/test_supplied_simulator.py
```

## CHECK (human)

```bash
pytest -q
```

Then set `SIMULATOR_MODE=supplied` (plus `SIMULATOR_URL` if HTTP) in `.env`, restart, and apply **step-up** on a medium alert. Confirm in the organizers' simulator that it received the action, and that the audit log shows it.

---

**After the CHECK passes:** `git commit -m "phase 29 ok"`, then update context.md Section 20.
