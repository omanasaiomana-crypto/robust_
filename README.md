# IdentityShield v3 Build Kit (Team Robust Gang)

This kit lets you continue building the IdentityShield project in **Antigravity**, phase by phase, on top of your existing v2 code, without breaking it.

## What's inside

| File | Purpose |
|---|---|
| `context.md` | **The single source of truth for Antigravity:** golden rules, architecture, the 15 agents, frozen data contracts, topics, configuration, detections, risk model, API, the 3D UI design system and the progress log. Antigravity reads it at the start of every chat. |
| `prompts/` | **One file per phase:** `00_INDEX.md` (run order and time plan), `00_TEMPLATES.md` (T1–T5), `P00_…md` to `P18_…md` (one phase each, with file list, CHECK commands and the next file to open), `99_EMERGENCY.md` |
| `FREE_APIS.md` | Every free API and service you can use (ngrok, IP intel, LLM, email): free limits, where to get the key, the `.env` variable name and the privacy rules |
| `env.example.txt` | All environment variable names with empty values; copy to `.env` |
| `docs/IdentityShield_v3_Technical_PRD.md` | The full technical PRD with 9 UML diagrams (Mermaid); prompts refer to it as "PRD §N" |

## Setup (10 minutes)

1. Commit your current project: `git add -A && git commit -m "v2 final before v3"`.
2. Copy `context.md`, the `prompts/` folder, `FREE_APIS.md`, `env.example.txt` and the `docs/` folder into the project root.
3. Copy `env.example.txt` to `.env` and fill in only `INGEST_KEYS` (one key ID and a long random secret) and `ANALYST_TOKEN` for now. Everything else is optional.
4. Open the project in Antigravity. In a new chat, paste **T1** from `prompts/00_TEMPLATES.md`, then the text block from `prompts/P00_baseline_and_safety_net.md`.

## The workflow for every phase

1. Open a **new chat**, then paste T1 (`prompts/00_TEMPLATES.md`).
2. Open that phase's file in `prompts/` and paste its text block.
3. Run the CHECK commands yourself.
4. If the CHECK fails, use T2.
5. When it passes, use T5 to update the progress log, then commit.

## Priorities if time is short

- **MUST:** P0–P7, P9–P14, P16, P18. This gives the complete live demo: signed ngrok feed → 15 agents → case with explanation → graduated response → 3D Live and Case pages.
- **SHOULD:** P8 (ML + campaign), P15 (3D graph, globe, analytics, performance pages), P17 calibration.
- Always run **P17 evaluation + benchmark** before judging, so every number you present is measured.

## The rules that keep the backend strong

- v3 lives in `app/v3/` and `static/v3/`; v2 keeps working.
- Each agent is a pure `process(message, state)` unit. The same code runs in drain mode (tests, dataset metrics) and live mode (demo).
- Frozen contracts, typed models, bounded queues, capability manifests, dead-letter handling, audit for every decision, tests and `ruff` in every phase.
- Only the Response agent can reach the simulator, and revoke always needs analyst approval.

## Demo-day summary

Run the core app on laptop 1, then start ngrok on port 8001 (ingest only). Open the generator on laptop 2, paste the URL, key and secret, and click E1. The Live page shows the 3D agent constellation lighting up. The case appears with risk ≥ 90, the attack chain, a what-if score and the predicted next step. Restrict is applied automatically. You approve the revoke and the audit entry appears. Then run the evasion pack and the tamper tests, and finish on the measured metrics. Full script: PRD §30 and `DEMO_CHECKLIST.md`.

---

# IdentityShield v3: Autonomous ITDR Platform

> **Hackathon Track 2: Zero Trust for Everyone**  
> **Team:** Robust Gang  
> **Single Source of Truth:** `context.md` | **PRD:** `docs/IdentityShield_v3_Technical_PRD.md`

IdentityShield v3 is an **Identity Threat Detection & Response (ITDR)** platform linking identity provider authentication (Okta System Log) with downstream cloud infrastructure actions (AWS CloudTrail). It protects against valid-credential abuse, privilege escalation, defense evasion, and compromised identities.

```
                           [ Laptop 2 / Attack Generator ]
                                         │
                         HMAC-SHA256 Signed HTTP Batch
                                         ▼
                               [ ngrok Tunnel ]
                                         │
                    ┌────────────────────┴────────────────────┐
                    ▼                                         ▼
       [ Ingest Service (Port 8001) ]            [ Console API (Port 8000) ]
        - HMAC Signature Verification             - REST Endpoints (/api/v3)
        - Nonce & Replay Cache                    - Server-Sent Events (/stream)
        - Token Bucket Rate Limiter               - 3D Glass Command Center
                    │
                    ▼
         [ In-Memory Topic Bus ] ◄──► [ Supervisor & Capability Sandbox ]
                    │
   ┌────────────────┼────────────────┬────────────────┬────────────────┐
   ▼                ▼                ▼                ▼                ▼
Layer 1: Data    Layer 2: Detections Layer 3: Risk    Layer 4: Decision Layer 5: Learning
A01-A04          A05-A11             A12 (Fusion)     A13-A14 (Cases)   A15 (Feedback)
```

---

## 1. 15-Agent Architecture

| # | Agent | Layer | Consumes | Publishes | Path | Responsibility |
|---|---|---|---|---|---|---|
| **01** | Collector | Data | `raw.okta`, `raw.cloudtrail` | `events` | Hot | Ingests, parses, and normalizes timestamps/sources |
| **02** | Normalizer & Resolver | Data | `events` | `events.normalized` | Hot | Resolves raw principals into unified identities |
| **03** | Context & Intel | Data | `events.normalized` | `events.enriched` | Hot | Enriches with geo, ASN, Tor status, and tags |
| **04** | Correlation & Graph | Data | `events.enriched` | `sessions`, `graph.updates` | Hot/Warm | Tracks login sessions and graph relationships |
| **05** | Access Anomaly | Detection | `events.enriched`, `sessions` | `signals` | Hot | Detects impossible travel, new ASN, and unusual hour |
| **06** | Session Integrity | Detection | `events.enriched`, `sessions` | `signals` | Hot | Token replay, MFA fatigue, and session drift |
| **07** | Credential Lifecycle | Detection | `events.enriched`, `graph.updates` | `signals` | Warm | Dormant wakeups, foreign keys, non-AWS IP use |
| **08** | Privilege Escalation | Detection | `graph.updates`, `sessions` | `signals` | Warm | Tracks 8 IAM escalation paths (PE-01..PE-08) |
| **09** | Defense Evasion | Detection | `events.enriched` | `signals` | Hot | CloudTrail stop logging, guardduty disable, mass deletes |
| **10** | Behavioral ML | Detection | `sessions` (closed/updated) | `signals` | Warm | IsolationForest and Markov chain transition rarity |
| **11** | Campaign | Detection | `events.enriched`, `signals` | `signals` | Warm | Multi-identity password spraying & shared infra |
| **12** | Risk Fusion | Decision | `signals`, `config.updates` | `risk` | Warm | Noisy-OR fusion, context multipliers, decay |
| **13** | Investigation | Decision | `risk` | `cases` | Warm | Case synthesis, counterfactuals, next-step prediction |
| **14** | Response | Decision | `cases`, `approvals` | `actions` | Warm | Policy-as-code playbooks via simulator ONLY |
| **15** | Feedback & Tuning | Learning | `labels` | `config.updates` | Nightly | Calibrates detection weights based on analyst verdicts |

---

## 2. Detections Catalog

- **Access Anomalies (D-ACC):**
  - `D-ACC-01`: Impossible travel (>900 km/h and >500 km between consecutive logins)
  - `D-ACC-02`: New device or unseen ASN prefix
  - `D-ACC-03`: Unusual hour of access outside 30-day baseline
  - `D-ACC-04`: Anonymizing network / Tor exit used by privileged identity
- **Session & Token Abuse (D-SES):**
  - `D-SES-01`: Token replay (same session ID from different ASN without re-auth)
  - `D-SES-02`: MFA fatigue (≥5 MFA denials within 10 minutes followed by success)
  - `D-SES-03`: Fingerprint & user-agent drift
  - `D-SES-04`: Privileged session assumed without multi-factor authentication
- **Credential Lifecycle (D-CRD):**
  - `D-CRD-01`: Dormant account activity (>30 days inactive)
  - `D-CRD-02`: Access key generated for another identity
  - `D-CRD-03`: Newly created key used from an unfamiliar location (<60 mins)
  - `D-CRD-04`: Instance profile credentials used from outside AWS / unknown IP
  - `D-CRD-05`: Login profile password modification for another user
- **Defense Evasion & Impact (D-DEF):**
  - `D-DEF-01`: CloudTrail logging disabled (`StopLogging`)
  - `D-DEF-02`: GuardDuty detector deleted or updated
  - `D-DEF-03`: VPC Flow Logs deleted
  - `D-DEF-04`: S3 bucket or resource policy made publicly accessible
  - `D-DEF-05`: AWS KMS key scheduled for deletion
  - `D-DEF-06`: Mass deletion of infrastructure resources (≥50 in 5 mins)
  - `D-DEF-07`: Secret harvesting across Secrets Manager / SSM (≥5 in 10 mins)
- **Privilege Escalation (D-PE):**
  - `D-PE-01` through `D-PE-08`: IAM policy attachment, default version changes, role assumption chains, and policy creation matching PRD §13.4.
- **Behavioral ML & Campaign (D-ML / D-CMP):**
  - `D-ML-01`: IsolationForest multi-feature session anomaly detection
  - `D-ML-02`: Markov chain transition rarity (<0.01 transition probability)
  - `D-CMP-01`: Distributed password spray (≥10 identities targeted within 10 mins)
  - `D-CMP-02`: Password spray followed by immediate successful login
  - `D-CMP-03`: Shared malicious infrastructure across multiple distinct accounts

---

## 3. Mathematical Risk Model

The platform fuses multiple signals into an explainable score between 0 and 100:

1. **Noisy-OR Aggregation:**
   $$P_{\text{threat}} = 1 - \prod_{i} \left(1 - w_i \cdot c_i \cdot s_i\right)$$
   Where $w_i$ is detection weight, $c_i$ is signal confidence, and $s_i$ is signal strength.
2. **Context Multipliers:**
   $$\text{SessionRisk} = \min\left(100, 100 \cdot P_{\text{threat}} \cdot M_{\text{privilege}} \cdot M_{\text{sensitivity}} \cdot M_{\text{action}} \cdot F_{\text{chain}}\right)$$
3. **Temporal Decay:**
   $$\text{IdentityRisk}(t) = \max\left(\text{IdentityRisk}_0 \cdot e^{-\lambda \Delta t}, \text{SessionRisk}_{\text{current}}\right)$$
   (Half-life: 24 hours).
4. **Action Bands:**
   - `0 - 39`: **Monitor** (Log & track baseline)
   - `40 - 69`: **Step-up** (Trigger step-up MFA challenge)
   - `70 - 89`: **Restrict** (Deny sensitive actions, read-only boundary via simulator)
   - `90 - 100`: **Revoke** (Quarantine identity, revoke sessions — requires analyst approval)

---

## 4. Evaluated Benchmarks & KPIs (Official Dataset Replay)

All metrics measured using `python -m app.v3.evaluate` and `python -m app.v3.bench`:

| Metric | Measured Value | Standard / Target |
|---|---|---|
| **Chain Reconstruction Recall** | **100.0%** | ≥95% (Perfect attack progression mapping) |
| **Evidence Citing Ratio** | **100.0%** | 100% (Every reason links to raw event IDs) |
| **Counterfactual Analysis Rate** | **100.0%** | 100% (Every case explains what-if drops) |
| **Brier Calibration Score** | **0.0150** | 0.0228 Baseline (Lower is better; well-calibrated probabilities) |
| **Peak Throughput** | **42.5 events/sec** | Sustained end-to-end replay |
| **Total Test Events Processed** | **14,835 events** | 5x multiplier burst without queue overflow |
| **Peak Memory Usage** | **168.8 MB** | Extremely lightweight; under 256 MB bound |
| **Alert Volume Reduction** | **21.4%** | Thousands of logs clustered into high-value incidents |

---

## 5. Configuration & Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `INGEST_KEYS` | `demo-key-1:secret...` | Key-ID and HMAC secret pairs for signing batches |
| `ANALYST_TOKEN` | *(Empty)* | Required in `X-Analyst-Token` for all mutating routes |
| `INGEST_PORT` | `8001` | Dedicated ingest service listening port |
| `DRY_RUN` | `false` | When true, simulator actions log without modifying state |
| `ENRICH_PROVIDERS` | `[]` | Optional free OSINT providers (`ipinfo_lite`, `abuseipdb`) |
| `LLM_ENABLED` | `false` | Enable LLM case narratives (falls back to deterministic template) |
| `GEMINI_API_KEY` | *(Empty)* | Google Gemini API key for narrative enrichment |

---

## 6. Runbook: Starting & Testing the System

### 1. Start the Console and Ingest Server
```powershell
.venv\Scripts\uvicorn app.main:app --host 0.0.0.0 --port 8000
```
- Web UI: `http://localhost:8000/v3/index.html`
- Ingest Receiver: `http://localhost:8001/ingest/v1/health`

### 2. Expose Ingest Service with ngrok (For 2nd Laptop Demo)
```powershell
ngrok http 8001
```
Copy the forwarding HTTPS URL to the Attack Generator on Laptop 2.

### 3. Run Test Suites & Validations
```powershell
# Run full test suite
.venv\Scripts\pytest -q

# Run security & tamper tests
.venv\Scripts\pytest -q tests/v3/test_security.py

# Lint checks
.venv\Scripts\ruff check app/v3 tests/v3

# KPI evaluation runner
.venv\Scripts\python -m app.v3.evaluate

# Performance benchmark runner
.venv\Scripts\python -m app.v3.bench
```

---

## 7. Limitations & Roadmap

- **Simulated Cloud Actions:** All enforcement actions execute strictly through the simulated cloud environment to protect live infrastructure from accidental damage.
- **Provider Support:** Current release focuses on Okta System Log and AWS CloudTrail; roadmap includes Microsoft Entra ID and Google Cloud Audit Logs.
- **Decentralized Bus:** The bus currently uses in-memory Python threading; roadmap includes Redis / Kafka backends for enterprise horizontal scaling.

