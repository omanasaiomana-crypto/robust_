# IdentityShield v3 — Ingest & ngrok Demo Runbook

> **Demonstration Architecture:**
> - **Laptop 1 (Defense Console):** Core Server (`http://127.0.0.1:8000`), Secure Ingest Service (`http://0.0.0.0:8001`), and `ngrok http 8001` tunnel.
> - **Laptop 2 (Attacker & Forwarder):** Attack Generator static web application (`generator/index.html`).
> - **Live Jury Inspector:** Second monitor running the ngrok traffic inspector at `http://127.0.0.1:4040`.

---

## 1. Quick Prerequisites

- **Python:** 3.11+ installed with virtual environment (`.venv`) activated.
- **ngrok:** Free account and CLI installed.
  - Windows: `choco install ngrok` or `winget install ngrok.ngrok` or download from [ngrok.com](https://ngrok.com).
  - macOS: `brew install ngrok/ngrok/ngrok`
  - Linux: `curl -s https://ngrok-agent.s3.amazonaws.com/ngrok.asc | sudo tee /etc/apt/trusted.gpg.d/ngrok.asc >/dev/null && echo "deb https://ngrok-agent.s3.amazonaws.com buster main" | sudo tee /etc/apt/sources.list.d/ngrok.list && sudo apt update && sudo apt install ngrok`
- **ngrok Free Tier Limits:** 
  - 20,000 requests per month.
  - Max 40 requests/minute.
  - The generator UI features a built-in monthly quota tracker and enforces a minimum 3-second interval on noise generation to stay comfortably within limits.

---

## 2. Setup Laptop 1 (Core Server & Ingest Service)

### Step 2.1: Configure ngrok Authtoken
Authenticate your local ngrok CLI with your personal free authtoken (never commit your token to version control):
```bash
ngrok config add-authtoken <YOUR_NGROK_AUTHTOKEN>
```

### Step 2.2: Verify Environment Settings
Ensure your `.env` contains the ingest keys and allowed origins. Example:
```ini
V3_ENABLED=true
INGEST_KEYS=test-key-1:test_super_secret_signing_key_32bytes_long!,dev:dev_secret_key_32bytes_long_random!
INGEST_ALLOWED_ORIGINS=null,http://localhost:5500,http://127.0.0.1:5500
```
> **Note on Origins:** Opening `generator/index.html` directly from disk (`file:///`) sends an origin header of `"null"`, which is permitted by default. If serving via a local server (e.g. port 5500), ensure that origin is in `INGEST_ALLOWED_ORIGINS`.

### Step 2.3: Start Core & Ingest Server
Launch the application:
```bash
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```
- **Port 8000:** Command Center UI (`/v3/index.html`) and API (`/api/v3/*`).
- **Port 8001:** Secure Ingest Service (`/ingest/v1/*`), automatically launched in the background by the application lifespan.

### Step 2.4: Launch ngrok Tunnel
In a second terminal on Laptop 1:
```bash
ngrok http 8001
```
*Tip: If you claimed a free static dev domain from ngrok, use it so the URL never changes:*
```bash
ngrok http --url=<your-free-dev-domain>.ngrok-free.app 8001
```

Copy the public HTTPS forwarding URL (e.g., `https://a1b2-34-56-78-90.ngrok-free.app`).

### Step 2.5: Open ngrok Live Inspector (Second Monitor)
Open your browser to:
```text
http://127.0.0.1:4040
```
Keep this window visible on the second screen to show the jury incoming signed HTTP requests, HMAC headers, and status codes in real time.

---

## 3. Setup Laptop 2 (Attack Generator & Forwarder)

### Step 3.1: Open Generator
Copy the `generator/` folder to Laptop 2 (or run in a second browser window):
- Simply double click `generator/index.html` to open it in Chrome / Edge / Firefox (works 100% offline).
- Or run a lightweight local static server: `python -m http.server 5500 --directory generator` and visit `http://localhost:5500`.

### Step 3.2: Connect to Ingest
In the **Connection** panel at the top:
1. **Target Ingest Base URL:** Paste the HTTPS ngrok URL from Step 2.4 (e.g. `https://<your-id>.ngrok-free.app`).
2. **Key ID:** `test-key-1` (or your configured key in `.env`).
3. **Secret:** `test_super_secret_signing_key_32bytes_long!` (kept in-memory only; never written to storage).
4. **Sender ID:** `laptop-2-generator`.
5. Click **Test Connection**.
   - The connection pill turns green: `Online (<latency>ms)`.

---

## 4. Demo Script for the Jury (10 Minutes)

### Phase 1: Prove System Security Controls (Tamper Suite T1–T5)
1. In the **Cryptographic Tamper Suite** section, click **Run All Tamper Tests**.
2. Point the jury to the real-time responses:
   - **T1 (No Headers):** Returns `401 Unauthorized` (Missing `X-IS-*` headers).
   - **T2 (Bad Signature):** Returns `401 Unauthorized` (HMAC verification failed).
   - **T3 (Stale Timestamp):** Returns `401 Unauthorized` (120s clock skew rejected by 60s window).
   - **T4 (Replayed Nonce):** First request succeeds `202`, second request rejected with `401` (Nonce cache replay guard).
   - **T5 (Oversized Body):** Returns `413 Payload Too Large` (Exceeds 1.0 MB limit).
3. On Laptop 1, open `http://127.0.0.1:8000/v3/audit.html` and demonstrate that every rejected attempt was cryptographically logged in the SHA-256 tamper-evident ledger.

### Phase 2: Fire Hero Attack Scenario E1
1. On Laptop 2, find the **E1: Okta Login → AWS Escalation** card.
2. Click **Inspect** to show the jury the authentic Okta System Log and AWS CloudTrail payloads.
3. Click **Send All**.
4. Show the jury the transmission log:
   - Okta batch sent $\rightarrow$ `202 Accepted`.
   - CloudTrail batch sent 150ms later $\rightarrow$ `202 Accepted`.
5. Switch to Laptop 1:
   - In ngrok inspector (`127.0.0.1:4040`), show the signed POSTs with `X-IS-Signature`.
   - In the Command Center (`127.0.0.1:8000/v3/cases.html`), a new critical case appears within 10 seconds:
     - **Session Risk:** $\ge 90$ (`CRITICAL`).
     - **Band:** `restrict` (Simulator automatically throttled identity `svc-report`).
     - **Action:** Revoke credentials pending analyst approval.
     - **Explainability:** Plain-English reasons, counterfactual "without escalation chain" drop, next-step prediction.

### Phase 3: Advanced Evasions & Background Traffic
1. **E2 Slow Escalation:** Sends attack spread over 48 hours; prove Agent 8 correlates the chain across the multi-day window.
2. **E6 MFA Fatigue:** Sends 7 denied pushes followed by 1 accept; triggers D-SES-02.
3. **E7 Blind the Monitors:** Executes `StopLogging` and `DeleteDetector`; triggers PB-04 immediate restrict.
4. **E9 Password Spray:** Targets 15 users from 1 IP; creates campaign case and flags attacker infrastructure.
5. **Background Noise:** Flip the "Simulate Corporate Background Traffic" toggle ON; watch benign events stream periodically without false alerting.

---

## 5. Fallback Network Modes (No Wi-Fi / No Internet)

If conference Wi-Fi blocks ngrok or drops:

### Fallback A: Phone Hotspot / Local LAN
1. Connect Laptop 1 and Laptop 2 to the same phone hotspot or Wi-Fi router.
2. Find Laptop 1's local IP address (`ipconfig` on Windows or `ifconfig` on macOS/Linux), e.g., `192.168.1.50`.
3. Start ingest on all interfaces: Ingest listens on `0.0.0.0:8001` by default.
4. On Laptop 2, enter Target Ingest Base URL: `http://192.168.1.50:8001`.
5. Add `http://192.168.1.50` to `INGEST_ALLOWED_ORIGINS` in `.env` if needed.

### Fallback B: Single Laptop Demo (Localhost)
1. Run both the Core Server and Generator on Laptop 1.
2. Set Target Ingest Base URL to `http://127.0.0.1:8001`.
3. No external network connectivity required.

---

## 6. Troubleshooting Matrix

| Issue | Root Cause | Solution |
|---|---|---|
| **401 Unauthorized: clock skew** | System time difference $>60\text{s}$ between laptops | Sync system clocks in Windows/macOS Settings $\rightarrow$ Date & Time $\rightarrow$ "Sync Now". |
| **401 Unauthorized: signature** | Secret mismatch | Verify that the secret entered on Laptop 2 matches the secret in `INGEST_KEYS` on Laptop 1. |
| **CORS Network Error in Browser** | Origin not permitted | Ensure `null` or your generator server origin is in `INGEST_ALLOWED_ORIGINS` in `.env`. |
| **429 Too Many Requests** | Rate limit or ngrok limit exceeded | Slow down noise slider ($\ge 5\text{s}$). Token bucket allows up to 20 rps / 2000 epm per key. |
| **ngrok Browser Warning Interstitial** | Free ngrok plan warning page | Handled automatically! The generator sends `ngrok-skip-browser-warning: true` on every request. |
| **Connection Refused (Port 8001)** | Ingest service not running | Verify core server is running (`python -m uvicorn app.main:app`). Lifespan automatically starts port 8001. |
