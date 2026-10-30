# P08: Agents 10–11: Behavioral ML, Campaign (SHOULD)

> **Before pasting:** open a NEW Antigravity chat and paste T1 from `00_TEMPLATES.md` first. Then paste only the text block below. Run the CHECK yourself.

```text
Read context.md Sections 7, 12, 13 and PRD §12 (Agents 10, 11), §13.5. Phase P8.
DO:
1. app/v3/agents/a10_ml.py (Agent 10, warm): features per PRD §12 Agent 10; train() fits one IsolationForest per
   peer group (fallback: global) with contamination ML_CONTAMINATION and random_state SEED, plus first-order Markov
   transition matrices over action categories per identity and per peer group with Laplace smoothing; save models
   with version and metadata to data/models/ (git-ignored) using joblib or pickle; score(session) returns
   D-ML-01 strength = percentile rank of anomaly within the peer group (only emit if ≥ 0.98 percentile → strength
   0.4..0.8 linear) and D-ML-02 strength from sequence negative log-likelihood percentile (emit ≥ 0.99 → 0.3..0.7).
   ML confidence = 0.8 (0.5 if the peer group has < 30 sessions). If no model: skip with a trace message, no signal.
   Training is triggered by POST /api/v3/run/dataset when models are missing, or by a "train" call; never during
   the hot path.
2. app/v3/agents/a11_campaign.py (Agent 11, warm): sliding windows keyed by src_ip, asn, access_key_id, ua hash;
   D-CMP-01..03 per PRD §13.5; a campaign signal is emitted once per campaign key and attached to every affected
   identity (one Signal per identity, same details.campaign_id).
3. Tests tests/v3/test_agents_ml_campaign.py: deterministic training with seed (same scores twice), no-model skip,
   feature vector shape, Markov rarity higher for an escalation sequence than a routine one, spray with 10 users
   triggers and 9 does not, spray then success triggers D-CMP-02, campaign id shared.
FILES: app/v3/agents/a10_ml.py, app/v3/agents/a11_campaign.py, tests/v3/test_agents_ml_campaign.py,
.gitignore (add data/models/)
```

**CHECK**
```bash
pytest -q tests/v3
ruff check app/v3 tests/v3
```

---
**After the CHECK passes:** paste template T5 (in `00_TEMPLATES.md`), then commit: `git add -A && git commit -m "v3 P08: Agents 10–11: Behavioral ML, Campaign"`. Next file: `P09_agent_12_risk_fusion.md`.
