# IdentityShield v3 — Demo Day Checklist & Rehearsal Runbook

> **Track 2: Zero Trust for Everyone** | **Team: Robust Gang**  
> *"IdentityShield complements GuardDuty. GuardDuty is excellent inside AWS; attacks start at the identity provider. We link the Okta login to what that identity does in AWS, keep 30 days of identity memory, explain every score, and respond with just enough friction under human control."*

---

## 1. Pre-Flight Setup Checklist (T-30 Minutes)

- [ ] **Power & Display:**
  - Laptop 1 (Console Server) plugged in; display set to 1080p / 1280px minimum.
  - Laptop 2 (Attack Generator) connected to same network or cellular hotspot.
- [ ] **Fresh Database & Clean State:**
  ```powershell
  # Clean old demo runs if desired (preserves schema)
  .venv\Scripts\python -c "from app.v3.store import create_tables; create_tables()"
  ```
- [ ] **Cryptographic Audit Chain Intact:**
  ```powershell
  .venv\Scripts\python -c "import app.audit; valid, broken = app.audit.verify(); assert valid, f'Audit broken at {broken}'; print('Audit chain: 100% INTACT')"
  ```
- [ ] **Service Ports Verified:**
  - Port `8000`: FastAPI Web Console (`http://localhost:8000/v3/index.html`)
  - Port `8001`: Ingest Receiver (`http://localhost:8001/ingest/v1/health`)
- [ ] **Security Token Setup (`.env`):**
  - Verify `.env` exists with `INGEST_KEYS` and `ANALYST_TOKEN`.
  - Ensure `.env` is NOT tracked in git (`git status` must not show `.env`).
- [ ] **Generator Secret Masked:**
  - Verify the generator UI on Laptop 2 displays the HMAC secret masked (`●●●●●●●●`) with a reveal toggle.

---

## 2. Network Operating Modes & Contingencies

| Scenario | Mode | Ingest URL in Generator | Notes |
|---|---|---|---|
| **Primary (2 Laptops)** | ngrok Tunnel | `https://<subdomain>.ngrok-free.app` | Run `ngrok http 8001` on Laptop 1 |
| **Secondary (LAN)** | Local WiFi / Hotspot | `http://192.168.x.x:8001` | Ensure port 8001 is open on Windows firewall |
| **Air-Gap / Offline** | Single Machine Live | `http://127.0.0.1:8001` | Run generator in second tab on Laptop 1 |
| **Total Outage** | Mock Mode Fallback | `http://localhost:8000/v3/index.html?mock=1` | Complete UI with 3D visualizations from local mocks |

---

## 3. Team Ownership & Q&A Roster

| Role | Team Member | Primary Responsibility | Target Question Area |
|---|---|---|---|
| **Lead Presenter** | Presenter 1 | 5-Minute Pitch & UI Walkthrough | Value proposition, GuardDuty contrast, business friction |
| **Technical Operator** | Presenter 2 | Generator execution, approvals, rollback | HMAC anti-tamper, agent bus, architecture |
| **ML & Calibration Lead** | Presenter 3 | Explains KPIs, Brier score, weights | ML models, calibration, false positive mitigation |
| **Security & Safety Lead** | Presenter 4 | Anti-tamper, simulator boundary, secrets | Golden rules, capability manifest, MITRE mapping |

---

## 4. 5-Minute Rehearsal Script (PRD §30.1)

### Minute 0:00 – 1:00: The Problem & Architecture (Presenter 1)
- **Visual:** Open Dashboard (`/v3/index.html`) on Laptop 1.
- **Narrative:**
  > *"Every modern cloud attack starts at the identity provider—Okta, Google Workspace, Azure AD—before touching AWS or GCP. AWS GuardDuty sees an API call inside AWS, but has zero identity context. Attackers use valid credentials, rotate keys, and evade detection.  
  > IdentityShield v3 unifies IdP login events with cloud data planes across 15 autonomous agents organized in 5 pipelined layers. It operates strictly within a simulator safety sandbox without ever risking production cloud assets."*

### Minute 1:00 – 2:00: Live Ingest & Real-Time Visualization (Presenter 2)
- **Action:** Switch to Live Agent Constellation (`/v3/live.html`).
- **Laptop 2:** In the Attack Generator, trigger **Scenario E1: Full Attack Chain** (svc-report privilege escalation and defense evasion).
- **Visual:**
  - 3D agent rings light up as events enter port 8001 with verified HMAC signatures.
  - Live throughput metric updates; messages stream across topic channels.
  - Red indicator flashes at Agent 08 (Privilege Escalation) and Agent 09 (Defense Evasion).

### Minute 2:00 – 3:00: Deep Investigation & Explainability (Presenter 1)
- **Action:** Click into the newly opened case on the Cases page (`/v3/cases.html` → `/v3/case.html?id=...`).
- **Visual Elements to Point Out:**
  1. **Score & Band:** Risk 92.4 (`restrict` band, confidence 0.94).
  2. **Evidence Chain:** Exact CloudTrail & Okta event IDs cited for every reason.
  3. **Counterfactual "What-If" Analysis:** Score drops by 48.4 points without the escalation chain, and 30.3 points without defense evasion.
  4. **Markov Next-Step Prediction:** Predicts `SecretsManager:GetSecretValue` or `S3 Exfiltration` with 72% probability.

### Minute 3:00 – 4:00: Graduated Response, Human Approval & Rollback (Presenter 2)
- **Visual:** Action Workflow card in Case Detail.
- **Narrative:**
  - *"Our friction budget enforces zero disruptive downtime. Autonomous restrict policy PB-02 was applied immediately in the simulator."*
  - *"Critical actions—like revoking credentials—require analyst consent."*
- **Action:** Click **Approve Revocation** with Analyst Token. Show immediate simulator execution.
- **Action:** Click **Rollback** on a previously restricted action to demonstrate reversible defense.
- **Visual:** Open Tamper-Evident Audit (`/v3/audit.html`), run cryptographic verification: **100% Valid Chain**.

### Minute 4:00 – 5:00: Calibrated Benchmarks & Defense Hardening (Presenter 3 & 4)
- **Action:** Open Analytics (`/v3/analytics.html`) and Performance (`/v3/performance.html`).
- **Show Evaluated Results (from official dataset replay):**
  - **100% Chain Reconstruction Recall** on multi-stage attack scenarios.
  - **100% Evidence Citation Ratio** (every claim is backed by raw log event IDs).
  - **Brier Calibration Score:** 0.0150 (improved from 0.0228 baseline).
  - **Throughput:** >40 events/sec sustained under 5x replay stress.
  - **Alert Reduction:** Correlated thousands of events into actionable high-fidelity cases.
- **Closing:**
  > *"Zero trust isn't just about blocking everything; it's about verified identity, contextual evidence, and proportional response. Thank you."*

---

## 5. Emergency Contingency Card

If anything goes wrong during live judging:
1. **Network Drops:** Switch URL bar to `?mock=1` immediately. All 15 pages remain fully interactive with realistic high-fidelity offline mock fixtures.
2. **ngrok Disconnects:** Switch generator target to Laptop 1 local IP or replay via `POST /api/v3/run/dataset`.
3. **Database Lock on Windows:** Restart main server; WAL mode SQLite automatically recovers state.
