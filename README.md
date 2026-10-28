# IdentityShield · Intelligent Identity Threat Detection

> **Hackathon Track 2:** Zero Trust for Everyone (Intelligent Identity Protection)  
> *Detecting compromised legitimate identities across AWS CloudTrail and Okta System Logs with multi-agent correlation, behavioral ML, and safe containment.*

---

## 1. What IdentityShield Is

Modern identity attacks rarely break encryption; attackers log in using legitimate credentials, session tokens, or assumed roles. **IdentityShield** correlates authentication signals from **Okta System Logs** with infrastructure operations from **AWS CloudTrail**, constructs cross-domain identity graphs, runs specialized detection agents, and simulates Zero Trust containment responses.

### Key Capabilities
- **Unified Event Normalization:** Ingests disparate Okta and CloudTrail formats into a standardized `Event` contract.
- **Session Correlation:** Accurately links federated Okta sessions to downstream AWS assumed-role sessions and access keys.
- **Multi-Agent Threat Detection:** 5 deterministic rule agents + 1 unsupervised machine learning agent:
  - **P1 · Impossible Travel:** Multi-city logins exceeding 800 km/h threshold (`anita.rao`).
  - **P2 · Dormant Account Reactivation:** Administrative accounts inactive for 30+ days suddenly initiating sensitive actions (`svc-report`).
  - **P3 · Privilege Escalation Chain:** Multi-step stealth chains: `CredCreate` &rarr; `PermGrant` &rarr; `RoleAssume` &rarr; `Impact` (`svc-report`).
  - **P4 · Unusual API Activity:** High-risk management calls such as `StopLogging` or security reconnaissance (`dev.kumar`).
  - **P5 · Token & Session Abuse:** Identical access keys replayed concurrently from disjoint geolocations (`meera.n`).
  - **ML · Behavioral Anomaly:** Isolation Forest scoring across 13 behavioral session features.
- **Transparent Risk Scoring & Explainability:** Evaluates risk (0–100), severity bands (`monitor`, `step_up`, `restrict`, `revoke`), and counterfactuals showing the exact risk delta if individual signals are removed.
- **Predictive Next-Step Guidance:** First-order Markov chain predictor forecasting the attacker's next likely tactic.
- **Friction-Budgeted Containment Simulator:** Automated response guard with strict analyst approval gates for critical actions (`revoke`).
- **Cryptographic Audit Ledger:** Append-only SHA-256 chained transaction log with tamper verification.

---

## 2. Technology Stack

- **Backend:** Python 3.12, FastAPI 0.115, Pydantic v2 (`model_validate`, `model_dump`), NetworkX, Scikit-learn, NumPy, Pandas, SQLite, Uvicorn.
- **Frontend:** Vanilla JavaScript (ES Modules), Tailwind CSS (Tailwind CDN, dark enterprise theme), Chart.js (KPI bar & doughnut charts), Vis-network (graph topology).
- **Zero Frontend Build Dependencies:** No Node.js, npm, Webpack, or Babel required. Served directly by FastAPI.

---

## 3. How to Run Locally

### Prerequisites
- Python 3.11 or 3.12

### Quickstart Scripts
- **Windows:**
  ```bat
  run.bat
  ```
- **macOS / Linux:**
  ```bash
  chmod +x run.sh
  ./run.sh
  ```

The server automatically starts at:  
👉 **http://127.0.0.1:8000** (Interactive API Documentation: **http://127.0.0.1:8000/docs**)

---

## 4. Verification & Testing

Run the automated verification suite:
```bash
# Smoke test (checks all core endpoints and HTML shells)
python smoke_test.py

# Full unit and integration test suite (33 tests)
pytest -q
```

---

## 5. Security Console Pages

| Page | Route | Description |
|---|---|---|
| **Threat Overview** | `/index.html` | High-level KPIs, F1 score vs baseline, attack patterns distribution bar chart, risk doughnut, demo scenario launcher, and Run live scan trigger. |
| **Live Scan** | `/scan.html` | Real-time multi-agent streaming pipeline console with 15-agent status strip, JSON inspection panel, and threat cards. |
| **Agents** | `/agents.html` | Live operational status cards, metrics, and JSON state for all 15 cooperating agents across 5 architectural layers. |
| **Input Data** | `/input.html` | Custom log upload (JSON/JSONL), single event builder, preset attacks, and instant "Scan input only" execution. |
| **Alerts Queue** | `/alerts.html` | Filterable queue with search, band selector, pattern filter, and min-risk scrubber. |
| **Alert Detail** | `/alert.html?id=` | Risk score ring, why flagged explanations, counterfactual analysis table, attack chain stepper, Markov next-step prediction, containment actions, "Email admin" button, analyst feedback loop. |
| **Identities** | `/identities.html` | Searchable directory with risk progress bars, 1–5 dots privilege rating, blast radius metric, alert counts, and Attack Path pivot. |
| **Attack Paths** | `/explorer.html?identity=` | Interactive attack progression canvas with step-by-step animated playback, Focus on attack, and blast radius inspection. |
| **Identity Graph** | `/graph.html?identity=` | Global topology network showing identity relationships, resource links, and discovered paths to Administrator. |
| **Analytics** | `/analytics.html` | Rules vs ML detector comparison matrix (Precision, Recall, F1), automated winner callout, and date × hour attack heatmaps. |
| **Session Timeline** | `/timeline.html?session=` | Interactive step-by-step attack replay engine with play/pause, scrub slider, 1x/2x speed toggle, and threat signal chips. |
| **Identity Hygiene** | `/hygiene.html` | Posture review of dormant privileged accounts and discovered routes to Administrator roles. |
| **Audit Log** | `/audit.html` | Cryptographically verified SHA-256 tamper-evident ledger with live re-verification and threat_detected audit entries. |
| **Notifications** | `/notifications.html` | Admin email notification management with live status, outbox preview, test email generator, and delivery history. |

*Note: Adding `?mock=1` to any page URL enables transparent offline mock mode using pre-built static JSON fixtures.*

---

## 6. Switching to Official Data and Supplied Simulator

### Ingesting Official Logs
1. Place raw AWS CloudTrail log files (`.json`, `.json.gz`) in `data/raw/cloudtrail/`.
2. Place raw Okta System Log files (`.json`) in `data/raw/okta/`.
3. Re-run the pipeline via the console top-bar **Re-run** button or via API:
   ```bash
   curl -X POST http://127.0.0.1:8000/api/pipeline/run -H "Content-Type: application/json" -d '{"use_sample": false}'
   ```

### Connecting Live Infrastructure (Supplied Simulator)
- Out of the box, IdentityShield runs in **mock simulation mode** via `app/simulator/mock.py` to prevent accidental modification of production assets.
- To connect real AWS or Okta tenants for live containment, implement credentials in `app/simulator/supplied.py` and set `SIMULATOR_BACKEND = "supplied"` in your environment configuration.

---

## 7. The 15 agents

IdentityShield organizes detection and Zero Trust decision-making across **15 cooperating agents** structured into 5 specialized architectural layers:

1. **Data Layer (Agents 1–4):**
   - **Agent 1 · Log Ingestion (`ingestion`):** Reads AWS CloudTrail and Okta System Log sources and replays events in chronological sequence.
   - **Agent 2 · Normalization (`normalization`):** Transforms heterogeneous vendor schemas into unified, type-safe `Event` records.
   - **Agent 3 · Enrichment (`enrichment`):** Attaches geolocation, IP intelligence, identity privilege levels (1–5), and resource sensitivity tags.
   - **Agent 4 · Session Correlation (`correlation`):** Connects federated Okta sessions to AWS assumed-role sessions and builds the identity graph.

2. **Detection Layer (Agents 5–10):**
   - **Agent 5 · Impossible Travel (`impossible_travel`, P1):** Flags logins between locations requiring travel speeds exceeding 800 km/h.
   - **Agent 6 · Dormant Account Reactivation (`dormant`, P2):** Flags inactive administrative identities suddenly active after 30+ days.
   - **Agent 7 · Privilege Escalation (`priv_escalation`, P3):** Reconstructs multi-step stealth escalation sequences (`CredCreate` &rarr; `PermGrant` &rarr; `RoleAssume` &rarr; `Impact`).
   - **Agent 8 · API Anomaly (`api_anomaly`, P4):** Flags rare, sensitive, or new-region API calls (e.g., `StopLogging`, security reconnaissance).
   - **Agent 9 · Token & Session Abuse (`token_abuse`, P5):** Flags concurrent token usage across disjoint geographical endpoints.
   - **Agent 10 · Behavior Baseline ML (`baseline_ml`, ML):** Unsupervised Isolation Forest anomaly scoring across 13 behavioral session features.

3. **Decision Layer (Agents 11–13):**
   - **Agent 11 · Risk Scoring (`risk_scoring`):** Fuses detector signals, privilege levels, and resource blast radius into a normalized 0–100 risk score and severity band (`monitor`, `step_up`, `restrict`, `revoke`).
   - **Agent 12 · Explanation (`explanation`):** Synthesizes human-readable reasons, MITRE ATT&CK technique tags, and counterfactual risk deltas.
   - **Agent 13 · Containment Response (`response`):** Enforces friction-budgeted Zero Trust actions via the safety-isolated containment simulator.

4. **Learning Layer (Agent 14):**
   - **Agent 14 · Feedback Learning (`feedback`):** Dynamically tunes detector weights and detection sensitivity based on analyst true/false positive feedback.

5. **Oversight Layer (Agent 15):**
   - **Agent 15 · Orchestrator & Supervisor (`orchestrator`):** Coordinates pipeline ordering, deduplicates events, guards safety constraints, and streams trace events.

---

## 8. Live scan

IdentityShield provides real-time visibility into the multi-agent execution pipeline:

- **Web Console (`/scan.html`):** Watch all 15 agents process events step-by-step with real-time progress indicators, adjustable playback speed (0.5×, 1×, 2×, instant), live JSON payload inspector, instant THREAT cards, and an execution summary banner.
- **Terminal CLI:** Stream the live scan directly from the command line with colored ANSI output:
  ```bash
  # Live JSON-traced scan with custom pacing
  python -m app.scan --json --delay 0.05

  # Run on sample data with replay
  python -m app.scan --sample --delay 0.03

  # Run specifically on user-provided input data
  python -m app.scan --input-only
  ```

---

## 9. Threat audit entries

Every threat flagged by IdentityShield is recorded for complete forensic accountability:
- **One Entry per Threat:** Emits a distinct `threat_detected` audit record whenever a session alert is produced, deduplicated by fingerprint (`identity_id|session_id|band`).
- **Cryptographic Hash Chain:** Each audit log entry includes a SHA-256 hash incorporating the previous entry's hash, forming an immutable ledger.
- **Tamper Verification:** The chain can be verified at any time through the UI (`/audit.html`) or via API (`GET /api/audit/verify`), immediately detecting any unauthorized deletion, reordering, or tampering.

---

## 10. Entering your own data

Test custom logs and threat scenarios without restarting the server:
- **Input Console (`/input.html`):**
  - **Paste or Upload:** Paste raw JSON or JSON Lines directly into the browser, or drag-and-drop `.json` / `.jsonl` files (up to 5 MB / 50,000 records).
  - **Single Event Form:** Create ad-hoc Okta logins or AWS operations using intuitive forms. Includes one-click presets like Bengaluru &rarr; Frankfurt impossible travel.
- **Targeted Scanning:**
  - **Scan input only (`input_mode="only"`):** Analyzes solely user-entered data to quickly verify detections without reprocessing historical datasets.
  - **Scan dataset + input (`input_mode="merge"`):** Seamlessly merges uploaded logs into the active dataset for global correlation.

---

## 11. Attack Path Explorer

The **Attack Path Explorer** (`/explorer.html?identity=<identity_id>&play=1`) transforms complex multi-hop identity compromise into an intuitive visual story:
- **Step-by-Step Playback:** Watch the exact sequence of adversary actions unfold with animated node/edge particles and numbered step badges.
- **Focus Mode:** Isolates the active attack path to filter out background infrastructure noise.
- **Blast Radius Analysis:** Computes and highlights all downstream resources, roles, and services reachable from the compromised identity.

---

## 12. Analytics and Email alerts

- **Detection Analytics (`/analytics.html`):**
  - **Rules vs ML Evaluation:** Session-level comparison matrix showing Precision, Recall, and F1 score across deterministic rule detectors (P1–P5) and the Isolation Forest ML agent.
  - **Automated Winner Determination:** Highlights the best-performing detector configuration against ground truth.
  - **Activity Heatmaps:** Interactive Date &times; Hour-of-day attack event heatmaps and top-identity detector distribution charts.
- **Email Alerts (`/notifications.html`):**
  - **Offline Outbox Mode (`EMAIL_MODE="outbox"`):** Defaults to writing full `.eml` and `.txt` notification files to `data/outbox/` with an interactive console preview—perfect for offline demonstrations and local development.
  - **Production SMTP (`EMAIL_MODE="smtp"`):** Delivers email digests for high-risk alerts (`risk >= 70`) to configured recipients (`ALERT_EMAIL_TO`).
  - **Configuration:** Copy `.env.example` to `.env` to configure SMTP host, port, credentials, rate limits (default max 10/hour), and min-risk thresholds.
  - **Manual Triggering:** Analysts can immediately dispatch notifications for any alert via the **"Email admin"** button on the Alert Detail page.

---

## 13. Team & Credits

- **Track 2:** Zero Trust for Everyone (Hackathon)
- **Team Name:** IdentityShield Engineering
- **Version:** v1.0-demo

