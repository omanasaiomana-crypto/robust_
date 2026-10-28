# 01 · Review of the Antigravity audit report

**Reviewed:** `AUDIT_REPORT.md` (IdentityShield v1.0-demo, commit `8d35ea4`, 28 Oct 2026)
**Reviewer view:** what is solid, what needs checking, what the audit missed, and which recommendations to follow or skip during the hackathon.

---

## 1. Verdict in one paragraph

The build looks solid for a demo: the full pipeline, 6 detectors, explanations, the approval-gated simulator, the hash-chained audit log and an 8-page console all work, and 33 tests pass. **But the audit was written by the same agent that built the system, and it measures success on sample data that the same team generated.** The judges score on the **official hidden dataset** (event-level precision/recall/F1, session-level alert precision, detection latency under the published load profile, explanation quality, chain reconstruction). The audit never mentions the official dataset, the official baseline detector or a predictions export. That is the most important gap, and it is more urgent than any item on the audit's own roadmap.

---

## 2. What the audit gets right (keep as is)

| Area | Assessment |
|---|---|
| Ingestion, normalization, canonical identities | Good. Multi-format loading is the right foundation for the official data. |
| 5 rule agents + Isolation Forest | Good coverage of all five required patterns. |
| Counterfactual explanations, Markov next-step prediction | Strong differentiators; keep them prominent in the demo. |
| Revoke approval gate (HTTP 409) and friction budget | Directly answers the "balance security and disruption" stretch goal. |
| Hash-chained audit log with live verify | Good "secure the defender" story. |
| Mock/live schema parity | Good; keep it when adding new endpoints. |

---

## 3. Inconsistencies inside the audit (verify before the demo)

These are small, but a judge who reads both the PRD and the code can spot them. Phase 20 checks each one.

| # | Audit says | Spec says | Why it matters | Action |
|---|---|---|---|---|
| 1 | Impossible travel flags speed above **800 km/h** | `IMPOSSIBLE_TRAVEL_KMH = 900` in config | Either the detector hardcodes a number (breaks golden rule 11) or the report is wrong | Detector must read `config.IMPOSSIBLE_TRAVEL_KMH`; fix the report |
| 2 | Okta↔AWS correlation uses a **15-minute sliding window** | Okta session started within **12 h** with matching IP | A 15-minute window splits long sessions; one attack chain becomes several small "sessions", which lowers session-level precision and breaks chain reconstruction | Make it a config constant `SESSION_LINK_WINDOW_HOURS`; test both values on the official data |
| 3 | "**13** fully verified endpoints" | 16 endpoints are listed | Documentation error only | Fix the count |
| 4 | Isolation Forest produces "**calibrated** 0–1 anomaly scores" | Scores are min-max normalized, not calibrated probabilities | Do not claim calibration to judges | Say "normalized anomaly score" |
| 5 | Logistic calibrator "calibrates raw detector outputs" | Calibrator trains on labels | If it trains on **our own sample labels**, risk scores fit our generator, not reality | Confirm whether the final risk uses it; for the hidden dataset prefer the formula-based risk unless official training labels exist |
| 6 | `median_latency_ms` reported | Computed as total time ÷ events | That is an average from a batch run, not a median detection latency under load | Replace with a real replay measurement (Phase 21) |

---

## 4. Gaps the audit missed (ranked by impact on judging)

| Rank | Gap | Impact | Fix (phase) |
|---|---|---|---|
| 1 | **No run on the official CloudTrail/Okta dataset** reported | All headline KPIs are scored on hidden data; real field names usually differ from the sample generator | Data recon + mapping fixes + official run (P21) |
| 2 | **No comparison with the official baseline detector** | "Beat the baseline" is the main success metric; our toy failed-login baseline does not count | Load official baseline output, compare (P21) |
| 3 | **No predictions export** in a scorable format | Judges may need event-level and session-level predictions files | `python -m app.export` (P21) |
| 4 | **Circular testing**: generator and detectors share assumptions | 33 green tests do not prove generalization | Evaluate on official labeled samples; tune thresholds there only (P21) |
| 5 | **No proof of what ML adds over rules** | Judges will ask "why ML?" | Detector comparison analytics + heatmap (P22–P23), the feature you asked for |
| 6 | **No admin notification** | An alert nobody sees is useless in a real SOC | Email alerts (P24–P25), the feature you asked for |
| 7 | Failed re-run replaces good results with an empty state | Demo risk if a re-run fails live | Runner keeps the previous good result (P26) |

---

## 5. The audit's recommendations: follow, adapt or skip

| Audit recommendation | Decision | Reason |
|---|---|---|
| Vendor CDN assets into `static/vendor/` | **Follow** (P27) | Cheap; protects the demo from venue Wi-Fi |
| Real cloud adapters with **boto3 `put_user_policy`** and **Okta session DELETE** | **Do NOT do this** | The hackathon safety rules say *"All access enforcement must use the supplied simulator. No live cloud accounts, identity providers, or production tenants may be modified."* Wiring real AWS/Okta calls risks disqualification and adds banned dependencies (boto3, requests). **Adapt instead:** implement `SuppliedSimulator` against the organizers' simulator only (P29). Keep real adapters as a future-scope slide. |
| Background processing with Celery/RQ | **Adapt** (P26) | Use a standard-library background thread with single-flight locking and `202 Accepted` + status polling. Same user benefit, no Redis, no new services. |
| Real-time streaming (SQS, EventBridge, Okta Event Hooks) | **Skip, future scope** | Needs live cloud accounts and infrastructure |
| OAuth2/OIDC RBAC | **Adapt, optional** (P28) | A simple opt-in analyst token for write actions shows security maturity in 25 minutes; full OIDC is future scope |
| TimescaleDB / ClickHouse | **Skip, future scope** | Not needed at hackathon scale |
| Graph neural networks | **Skip, future scope** | Training data and time do not allow it |
| SIEM/SOAR webhooks | **Partly covered** | Email alerts (P24) give the admin-notification story now; webhooks become future scope |

---

## 6. Risk register after this review

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Official data fields differ from sample assumptions | High | High | P21 data recon first, then minimal mapping fixes, then tests |
| Session window too short or too long on real data | Medium | High | Config constant; compare session precision at 1 h / 12 h |
| Thresholds overfit to sample data | Medium | High | Tune only on official labeled samples; never on hidden data |
| SMTP blocked on venue network | High | Low | `outbox` mode is default; emails still appear in the console |
| Email header injection via attacker-controlled usernames | Low | Medium | Reference notifier strips CR/LF from all header text (tested) |
| Live re-run fails during demo | Low | High | Runner keeps the previous good result (tested) |
| New features break existing pages | Medium | Medium | New endpoints and pages only; existing contracts untouched; full regression in P30 |

---

## 7. What to tell the judges (honest framing)

- "We measured on the official labeled samples and beat the provided baseline by X F1." (Only after P21 is done.)
- "Rules give precision and explanations; ML catches what rules miss. Our analytics page shows exactly where each one wins." (P22–P23)
- "When risk crosses 70, the admin gets a short email digest. Revocation still needs a human." (P24)
- "Enforcement only goes through the supplied simulator, by design." (Do not mention boto3 adapters as implemented.)
