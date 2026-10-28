# PHASE 8: ML module (≈30 min) · Person C

```text
Read context.md fully. Then read docs/TECH_PRD.md Section 12.

GOAL: Feature engineering, anomaly model, peer groups, Markov chain predictor, calibrator,
and the ML agent. Every model must degrade gracefully on small data.

DO:
1. app/ml/features.py: session_features(df) -> pd.DataFrame indexed by session_id with the columns
   in TECH_PRD 12.2 (peer_rarity_mean = 0 if peers unavailable). fillna(0), all float.
   Also return identity per session in a column "identity_id" kept OUT of the numeric feature set
   (provide numeric_columns() helper).
2. app/ml/anomaly.py: AnomalyModel exactly as TECH_PRD 12.3.
3. app/ml/peers.py: PeerModel with fit(df) -> bool and peer_rarity(identity_id, action) -> float.
   KMeans(n_clusters=min(5, n_identities), n_init=10, random_state=42); skip (return False) if
   fewer than 3 identities; peer_rarity returns 1.0 when not fitted.
4. app/ml/chain_model.py: ChainModel with fit(chains: list[list[str]]) -> None and
   predict(state: str) -> Prediction | None. Add-one smoothing; fallback prior from TECH_PRD 12.5
   when fewer than 5 chains. Predict never returns "Start".
5. app/ml/calibrate.py: Calibrator with fit(X, y) -> bool (needs both classes and >= 20 rows)
   and predict_proba(X) -> np.ndarray | None. LogisticRegression(class_weight="balanced", max_iter=1000).
6. app/agents/baseline_ml.py: BaselineMLAgent(Agent), name "baseline_ml", pattern "ML".
   detect(): build features, fit AnomalyModel on sessions (use sessions labeled "benign" if a label
   column has values, else all), score all sessions, emit a Signal for sessions with score >= 0.6
   with reason "Session behavior is unusual compared with normal activity (anomaly score 0.82)."
   and evidence = up to 5 event_ids of that session. Expose self.scores: dict[session_id, float].

FILES: the 6 files above.

CHECK: scratch script printing: feature table shape, top 5 anomaly scores with session ids,
ChainModel().predict("PermGrant"), and number of ML signals.
Expected: no exceptions; attack sessions appear among top anomaly scores.
Then update context.md Section 12: Phase 8 = ☑.
```

---

**After the CHECK passes:** `git add . && git commit -m "phase 8 ok"`, then open the next file.
**If the CHECK fails:** use template T2 in `prompts/00_templates.md` with the exact error.
