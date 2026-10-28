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
| **Threat Overview** | `/index.html` | High-level KPIs, F1 score vs baseline, attack patterns distribution bar chart, risk doughnut, demo scenario launcher. |
| **Alerts Queue** | `/alerts.html` | Filterable queue with search, band selector, pattern filter, and min-risk scrubber. |
| **Alert Detail** | `/alert.html?id=` | Risk score ring, why flagged explanations, counterfactual analysis table, attack chain stepper, Markov next-step prediction, containment actions, analyst feedback loop. |
| **Identities** | `/identities.html` | Searchable directory with risk progress bars, 1–5 dots privilege rating, blast radius metric, and alert counts. |
| **Identity Graph** | `/graph.html?identity=` | Interactive `vis-network` canvas showing blast radius, toxic paths to administrator, and node inspector. |
| **Session Timeline** | `/timeline.html?session=` | Interactive step-by-step attack replay engine with play/pause, scrub slider, 1x/2x speed toggle, and threat signal chips. |
| **Identity Hygiene** | `/hygiene.html` | Posture review of dormant privileged accounts and discovered routes to Administrator roles. |
| **Audit Log** | `/audit.html` | Cryptographically verified SHA-256 tamper-evident ledger with live re-verification and searchable entries. |

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

## 7. Team & Credits

- **Track 2:** Zero Trust for Everyone (Hackathon)
- **Team Name:** IdentityShield Engineering
- **Version:** v1.0-demo
