# PHASE 9: Decision layer and simulator (≈30 min) · Person C

```text
Read context.md fully (especially Sections 6 and 8). Then read docs/TECH_PRD.md Section 13.

GOAL: Score, explain, recommend, apply via simulator, learn from feedback.

DO:
1. app/simulator/base.py: SimulatorAdapter with step_up, restrict, revoke (raise NotImplementedError).
2. app/simulator/mock.py: MockSimulator(SimulatorAdapter) storing calls in self.calls and returning
   "simulated:<action>:ok".
3. app/simulator/supplied.py: SuppliedSimulator(SimulatorAdapter) whose methods raise
   NotImplementedError("Configure the supplied simulator in app/simulator/supplied.py").
   Add get_simulator() in app/simulator/__init__.py returning MockSimulator unless
   config.SIMULATOR_MODE == "supplied".
4. app/decision/scoring.py:
   - score_session(signals: list[Signal], session_events: pd.DataFrame, weights: dict,
     prediction: Prediction | None, ml_score: float) -> tuple[float, float]  (risk, confidence)
     implementing context.md Section 8 exactly; risk rounded to 1 decimal.
   - counterfactuals(...) -> list[Counterfactual]
   - decayed(risk, hours, confirmed: bool) -> float
5. app/decision/explain.py: build_reasons(signals) -> list[str] (unique, ordered by severity desc),
   mitre_tags(signals) -> list[str] (unique, sorted), evidence_ids(signals, events) -> list[str]
   (unique, ordered by event timestamp).
6. app/decision/respond.py:
   - recommend(risk) -> str using to_band; maps band to action name (monitor, step_up, restrict, revoke).
   - apply_action(alert: Alert, action: str, approved_by: str | None, sim) -> ActionResult
     Safety guard: allowed actions only {"step_up","restrict","revoke","dismiss","monitor"};
     revoke requires approved_by when config.REQUIRE_APPROVAL_FOR_REVOKE; step_up consumes friction
     budget via store.friction_* and returns status "notified" when budget is exhausted;
     every call appends an audit entry with agent "response".
   - auto_apply(alert, sim) -> Alert: applies monitor/step_up/restrict automatically; leaves revoke "pending".
7. app/decision/feedback.py: apply_feedback(alert: Alert, label: str) -> dict[str, float]
   implementing TECH_PRD 13.5 with clipping, saving via store.set_weight, appending an audit entry.

FILES: the 9 files above.

ALSO write tests/test_scoring.py checking: bands at 39.9/40/69.9/70/89.9/90; more distinct patterns
→ higher risk; decayed halves at the half-life; revoke without approval is refused; feedback "tp"
raises the weight of the alert's patterns.

CHECK: pytest -q tests/test_scoring.py  → all pass.
Then update context.md Section 12: Phase 9 = ☑.
```

---

**After the CHECK passes:** `git add . && git commit -m "phase 9 ok"`, then open the next file.
**If the CHECK fails:** use template T2 in `prompts/00_templates.md` with the exact error.
