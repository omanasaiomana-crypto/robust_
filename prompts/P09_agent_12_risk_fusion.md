# P09: Agent 12: Risk Fusion (MUST)

> **Before pasting:** open a NEW Antigravity chat and paste T1 from `00_TEMPLATES.md` first. Then paste only the text block below. Run the CHECK yourself.

```text
Read context.md Sections 7, 12, 14 and PRD §14. Phase P9.
DO:
1. app/v3/fusion.py (pure functions): noisy_or(signals, weights), multipliers(context_summary), chain_factor(stages),
   session_risk(...) -> (score, factors dict), identity_risk(previous, last_update, now, session_score),
   confidence(...), counterfactuals(signals, context, weights) -> top 3 by delta (remove each detection family:
   ACC, SES, CRD, PE, DEF, ML, CMP; and each multiplier set to 1.0; and chain factor set to 1.0). All per PRD §14.
2. app/v3/agents/a12_fusion.py (Agent 12): subscribes signals and config.updates; keeps per-session signal sets and a
   per-session context summary (max privilege, max sensitivity, worst action type, stages with evidence) that it
   gets from the signal details and a lookup of the session's enriched events in the store; on every new signal
   recomputes session risk and identity risk; publishes RiskUpdate on `risk` when score changes by ≥ 1 point or band
   changes; applies weights from config (default 1.0 rules, 0.8 ML) with floors; identity risk ≥ 60 lowers next
   session's step-up threshold by 10 (store flag in state, expose in RiskUpdate factors).
3. Tests tests/v3/test_fusion.py: noisy-OR math examples (single 0.8 → 80 before multipliers; two 0.5 → 75),
   multipliers per table, chain factor cap 1.6, min 100 cap, decay half-life (score 80 → 40 after 24 h),
   identity max rule, counterfactual for E1-like signals shows "without escalation chain" as the largest drop,
   floors respected when weights updated, no publish when change < 1 point.
FILES: app/v3/fusion.py, app/v3/agents/a12_fusion.py, tests/v3/test_fusion.py
```

**CHECK**
```bash
pytest -q tests/v3
ruff check app/v3 tests/v3
```

---
**After the CHECK passes:** paste template T5 (in `00_TEMPLATES.md`), then commit: `git add -A && git commit -m "v3 P09: Agent 12: Risk Fusion"`. Next file: `P10_agent_13_investigation_explanation.md`.
