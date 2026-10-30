# P16: Attack generator website + ngrok runbook (MUST)

> **Before pasting:** open a NEW Antigravity chat and paste T1 from `00_TEMPLATES.md` first. Then paste only the text block below. Run the CHECK yourself.

```text
Read context.md Sections 17, 19 and PRD §25. Phase P16: generator/ (runs on laptop 2, static files).
DO:
1. generator/index.html + css/generator.css: same dark glass style (copy the needed tokens, no dependency on
   static/v3), sections: Connection (target base URL, key id, secret as password input, sender id, "Test
   connection" → GET /ingest/v1/health), Scenarios (cards N1, E1–E9 with description and expected outcome),
   Tamper tests (T1–T5), Background noise toggle with rate slider (noise is sent as batches of up to 20 events per
   request, minimum 3 s between requests, because the ngrok free plan allows 20,000 requests per month; show a
   running request counter), Log panel (request id, scenario, status,
   accepted/rejected, latency ms, server received_at), counters.
2. generator/js/sign.js: Web Crypto HMAC-SHA256 signing exactly per context.md Section 17 (timestamp seconds, random
   16-byte nonce hex, sha256 hex of the exact body string); secret kept only in memory (never written to storage,
   never logged); headers X-IS-*, Content-Type application/json, ngrok-skip-browser-warning: true.
3. generator/js/scenarios.js: builders that create realistic Okta System Log and CloudTrail events with current
   timestamps (E2 uses timestamps spread over the last 48 h), consistent identities/resources/IPs taken from the
   dataset's identities (read a small generator/data/identities.json you create from the dataset: names, usual
   city/IP/ASN, roles, buckets, secrets), unique event ids (crypto.randomUUID), SAML federation fields linking Okta
   user to the AWS role session, VPC endpoint id for E4, MFA deny/accept sequence for E6, StopLogging + GuardDuty
   DeleteDetector for E7, hosting ASN securityContext for E8, 15-user spray for E9. Each scenario returns batches
   per source.
4. generator/js/generator.js: UI logic; send batches in order (Okta then CloudTrail, 150 ms apart) with step-by-step
   mode; tamper tests deliberately: no headers, wrong signature, timestamp −120 s, reused nonce (send same request
   twice), 1.2 MB body; show expected vs actual status with ✓/✗.
5. RUNBOOK_NGROK.md in the project root: install ngrok, `ngrok config add-authtoken <token>` (token from .env is
   for docs only; never commit), start core `python -m uvicorn app.main:app --host 127.0.0.1 --port 8000`, ingest
   is started by the core app on 0.0.0.0:8001, run `ngrok http 8001` (or with the account's free dev domain so
   the URL never changes: `ngrok http --url=<your-dev-domain> 8001`); note the free plan's 20,000 requests/month, copy HTTPS URL into the generator, open inspector http://127.0.0.1:4040;
   fallbacks: hotspot LAN IP and localhost; set INGEST_ALLOWED_ORIGINS to the generator origin; troubleshooting
   table (401 skew → sync clocks; 401 signature → same secret both sides; CORS → origins; 429 → slow noise).
FILES: generator/**, RUNBOOK_NGROK.md
```

**CHECK (human, 10 min)**
- Laptop 1: server running and `ngrok http 8001`. Laptop 2: open `generator/index.html`, enter the URL, key and secret, then click **Test connection**.
- Click E1: within 10 s the case appears on laptop 1 with risk ≥ 90 and a pending revoke; the ngrok inspector shows the signed POST.
- T1–T5 all show ✓ (rejected as expected), and the audit page shows the rejects.

---
**After the CHECK passes:** paste template T5 (in `00_TEMPLATES.md`), then commit: `git add -A && git commit -m "v3 P16: Attack generator website + ngrok runbook"`. Next file: `P17_evaluation_benchmark_calibration.md`.
