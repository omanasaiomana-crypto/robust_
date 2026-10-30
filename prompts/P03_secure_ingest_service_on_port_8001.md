# P03: Secure ingest service on port 8001 (MUST)

> **Before pasting:** open a NEW Antigravity chat and paste T1 from `00_TEMPLATES.md` first. Then paste only the text block below. Run the CHECK yourself.

```text
Read context.md Sections 2, 7, 12, 17 and PRD §9. Phase P3: ingest service.
DO:
1. app/v3/ingest/security.py:
   - verify_signature(headers, raw_body, keys, now) -> key_id, implementing context.md Section 17 exactly
     (timestamp + "\n" + nonce + "\n" + sha256_hex(body)), hmac.compare_digest, skew check INGEST_SKEW_SECONDS.
   - NonceCache with TTL INGEST_NONCE_TTL_SECONDS and max size 100,000 (evict oldest).
   - TokenBucket rate limiter per key for requests/s and events/min.
   - Typed exceptions: AuthError (401), TooLarge (413), RateLimited (429 with retry_after), SchemaError (422).
2. app/v3/ingest/service.py: a separate FastAPI app (create_ingest_app(bus_handoff)) with:
   - POST /ingest/v1/events: read raw body with size limit INGEST_MAX_BODY_BYTES before parsing; verify signature;
     rate-limit; parse IngestEnvelope; validate each event minimally per source (okta needs uuid, published, eventType,
     actor; cloudtrail needs eventID, eventTime, eventName, userIdentity); drop unknown top-level keys only for the
     envelope (keep raw event dicts but truncate any string > 2048 chars); reject invalid events by index;
     append accepted events as JSON lines to data/spool/YYYYMMDD.jsonl with batch_id and received_at;
     hand accepted events to the bus as raw.okta/raw.cloudtrail messages via bus_handoff (non-blocking);
     audit entry (actor "ingest": sender_id, batch_id, accepted, rejected, sha256 of body); return IngestResult 202.
     If the Supervisor backpressure flag is set → 429 with Retry-After: 2.
   - GET /ingest/v1/health: status, accepted_total, rejected_total by reason, backpressure.
   - No other routes. No CORS for browsers except the generator origin is not needed because the generator
     uses fetch with mode "cors": add CORSMiddleware allowing only POST and the X-IS-* and content-type headers,
     origins from env INGEST_ALLOWED_ORIGINS (default "*" is NOT allowed; default "null,http://localhost:5500").
   - Logs never include header values or body contents.
3. A runner: python -m app.v3.ingest.service starts uvicorn on 0.0.0.0:INGEST_PORT, sharing the bus with the core
   app when both run in one process (document in a module docstring: in demo, core app lifespan starts the ingest
   server in a background thread on port 8001; Phase 12 wires this).
4. Tests tests/v3/test_ingest.py with TestClient: valid signed batch → 202 and spool line; missing headers → 401;
   bad signature → 401; timestamp 61 s old → 401; replayed nonce → 401; body > 1 MB → 413; 21 requests in 1 s → 429;
   invalid event at index 2 → accepted n-1, rejected [{index:2}]; backpressure → 429; audit entry written;
   response never echoes secrets.
FILES: app/v3/ingest/__init__.py, app/v3/ingest/security.py, app/v3/ingest/service.py, tests/v3/test_ingest.py,
app/v3/config.py (add INGEST_ALLOWED_ORIGINS parsing only)
```

**CHECK**
```bash
pytest -q tests/v3/test_ingest.py
ruff check app/v3 tests/v3
```

---
**After the CHECK passes:** paste template T5 (in `00_TEMPLATES.md`), then commit: `git add -A && git commit -m "v3 P03: Secure ingest service on port 8001"`. Next file: `P04_agents_1_2_collector_normalizer_identity_reso.md`.
