# 00_INDEX: IdentityShield v3 phase prompts (one file per phase)

**How to use**

1. Copy the whole build kit folder into your project root (next to `app/`).
2. Start **every new Antigravity chat** with **T1** from `00_TEMPLATES.md`. Use a new chat for each phase; long chats drift.
3. Paste one phase prompt at a time. Do not paste the next phase until the CHECK passes.
4. After each phase: run the CHECK commands yourself, then `git add -A && git commit -m "v3 Pn: <name>"`.
5. If a CHECK fails, use **T2**. If the agent starts editing files outside the list, use **T3**.
6. Time estimates assume Antigravity is slow. "MUST" phases give a complete demo; "SHOULD" phases add polish.

**Run order and time plan**

| Phase | Name | Priority | Est. time |
|---|---|---|---|
| P0 | Baseline and safety net | MUST | 15 min |
| P1 | Contracts and config | MUST | 30 min |
| P2 | Event bus, agent base, Supervisor | MUST | 45 min |
| P3 | Secure ingest service (port 8001) | MUST | 40 min |
| P4 | Agents 1–2: Collector, Normalizer + Identity Resolver | MUST | 45 min |
| P5 | Agents 3–4: Context + Intel, Correlation + Graph | MUST | 50 min |
| P6 | Agents 5–6: Access, Session + Token | MUST | 40 min |
| P7 | Agents 7–9: Credentials, Privilege Escalation, Defense Evasion | MUST | 60 min |
| P8 | Agents 10–11: Behavioral ML, Campaign | SHOULD | 45 min |
| P9 | Agent 12: Risk Fusion | MUST | 35 min |
| P10 | Agent 13: Investigation + Explanation | MUST | 50 min |
| P11 | Agents 14–15: Response, Feedback | MUST | 50 min |
| P12 | API v3, SSE, dataset run, main.py wiring | MUST | 45 min |
| P13 | UI foundation: 3D theme, shell, background | MUST | 45 min |
| P14 | UI pages: Dashboard, Cases, Case detail, Live (3D constellation), Agents | MUST | 75 min |
| P15 | UI pages: 3D Graph, Globe, Analytics, Performance, Settings, Input, Audit | SHOULD | 75 min |
| P16 | Attack generator website + ngrok runbook | MUST | 50 min |
| P17 | Evaluation, benchmark, calibration | MUST | 40 min |
| P18 | Hardening, regression, docs, demo prep | MUST | 40 min |

If time is short, do P0–P7, P9–P14, P16, P18 first (skip P8, P15, P17 calibration part).

---

## Files in this folder (in order)

| File | Phase |
|---|---|
| `00_TEMPLATES.md` | Templates (use in every phase) |
| `99_EMERGENCY.md` | Emergency prompts |
| `P00_baseline_and_safety_net.md` | P00: Baseline and safety net (MUST) |
| `P01_contracts_and_config.md` | P01: Contracts and config (MUST) |
| `P02_event_bus_agent_base_supervisor.md` | P02: Event bus, agent base, Supervisor (MUST) |
| `P03_secure_ingest_service_on_port_8001.md` | P03: Secure ingest service on port 8001 (MUST) |
| `P04_agents_1_2_collector_normalizer_identity_reso.md` | P04: Agents 1–2: Collector, Normalizer + Identity Resolver (MUST) |
| `P05_agents_3_4_context_threat_intel_correlation_g.md` | P05: Agents 3–4: Context + Threat Intel, Correlation + Graph (MUST) |
| `P06_agents_5_6_access_anomaly_session_token_integ.md` | P06: Agents 5–6: Access Anomaly, Session + Token Integrity (MUST) |
| `P07_agents_7_9_credentials_privilege_escalation_d.md` | P07: Agents 7–9: Credentials, Privilege Escalation, Defense Evasion (MUST) |
| `P08_agents_10_11_behavioral_ml_campaign.md` | P08: Agents 10–11: Behavioral ML, Campaign (SHOULD) |
| `P09_agent_12_risk_fusion.md` | P09: Agent 12: Risk Fusion (MUST) |
| `P10_agent_13_investigation_explanation.md` | P10: Agent 13: Investigation + Explanation (MUST) |
| `P11_agents_14_15_response_and_feedback.md` | P11: Agents 14–15: Response and Feedback (MUST) |
| `P12_api_v3_sse_dataset_run_main_py_wiring.md` | P12: API v3, SSE, dataset run, main.py wiring (MUST) |
| `P13_ui_foundation_3d_theme_shell_background.md` | P13: UI foundation: 3D theme, shell, background (MUST) |
| `P14_ui_pages_dashboard_cases_case_detail_live.md` | P14: UI pages: Dashboard, Cases, Case detail, Live (3D constellation), Agents (MUST) |
| `P15_ui_pages_3d_graph_globe_analytics_performance.md` | P15: UI pages: 3D Graph, Globe, Analytics, Performance, Settings, Input, Audit (SHOULD) |
| `P16_attack_generator_website_ngrok_runbook.md` | P16: Attack generator website + ngrok runbook (MUST) |
| `P17_evaluation_benchmark_calibration.md` | P17: Evaluation, benchmark, calibration (MUST: evaluation + benchmark; SHOULD: calibration) |
| `P18_hardening_regression_docs_demo_prep.md` | P18: Hardening, regression, docs, demo prep (MUST) |
