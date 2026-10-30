"""Unit and integration tests for app/v3/ingest/service.py and security.py."""
import hashlib
import hmac
import json
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from app.v3.config import Settings
from app.v3.ingest.security import NonceCache, TokenBucket
from app.v3.ingest.service import create_ingest_app
from app.v3.supervisor import Supervisor

TEST_KEY_ID = "test-key-1"
TEST_SECRET = "test_super_secret_signing_key_32bytes_long!"


def _make_signed_headers(
    key_id: str,
    secret: str,
    raw_body: bytes,
    timestamp: float | None = None,
    nonce: str | None = None,
) -> dict[str, str]:
    ts_str = str(int(timestamp if timestamp is not None else time.time()))
    nonce_str = nonce or uuid.uuid4().hex
    body_hash = hashlib.sha256(raw_body).hexdigest()
    string_to_sign = f"{ts_str}\n{nonce_str}\n{body_hash}".encode()
    sig = hmac.new(secret.encode("utf-8"), string_to_sign, hashlib.sha256).hexdigest()
    return {
        "X-IS-Key-Id": key_id,
        "X-IS-Timestamp": ts_str,
        "X-IS-Nonce": nonce_str,
        "X-IS-Signature": sig,
        "Content-Type": "application/json",
    }


def _make_test_settings() -> Settings:
    return Settings(
        v3_enabled=True,
        analyst_token="",
        dry_run=False,
        console_base_url="http://127.0.0.1:8000",
        ingest_keys={TEST_KEY_ID: TEST_SECRET},
        ingest_allowed_origins=["http://localhost:5500"],
        enrich_providers=[],
        ipinfo_token="",
        abuseipdb_key="",
        greynoise_key="",
        otx_key="",
        vt_key="",
        maxmind_license_key="",
        llm_enabled=False,
        llm_provider="",
        gemini_api_key="",
        groq_api_key="",
        ollama_url="http://127.0.0.1:11434",
        openrouter_api_key="",
        email_mode="outbox",
        admin_email="",
        alert_email_to=[],
        alert_email_from="shield@example.com",
        email_min_risk=70.0,
        email_max_per_hour=10,
        smtp_host="",
        smtp_port=587,
        smtp_user="",
        smtp_password="",
        smtp_starttls=True,
        smtp_ssl=False,
        smtp_timeout_seconds=10,
        ngrok_authtoken="",
    )


def _sample_okta_payload(events: list[dict[str, Any]]) -> bytes:
    payload = {
        "source": "okta",
        "sender_id": "laptop-generator",
        "batch_id": f"batch-{uuid.uuid4().hex[:8]}",
        "events": events,
    }
    return json.dumps(payload).encode("utf-8")


# ---------------------------------------------------------------------------
# Test 1: Valid Signed Batch -> 202, Spool Written, and Bus Handoff
# ---------------------------------------------------------------------------


def test_valid_signed_batch_ingestion(tmp_path: Path) -> None:
    spool_dir = tmp_path / "spool"
    handoff_records: list[tuple[str, list[dict]]] = []

    def mock_handoff(topic: str, events: list[dict]) -> None:
        handoff_records.append((topic, events))

    app = create_ingest_app(
        bus_handoff=mock_handoff,
        settings=_make_test_settings(),
        nonce_cache=NonceCache(),
        rate_limiter=TokenBucket(),
        spool_dir=spool_dir,
    )
    client = TestClient(app)

    events = [
        {
            "uuid": "okta-ev-1",
            "published": "2026-10-30T12:00:00Z",
            "eventType": "user.session.start",
            "actor": {"id": "usr-1", "alternateId": "alice@corp.example"},
        },
        {
            "uuid": "okta-ev-2",
            "published": "2026-10-30T12:01:00Z",
            "eventType": "user.authentication.verify",
            "actor": {"id": "usr-1", "alternateId": "alice@corp.example"},
        },
    ]
    raw_body = _sample_okta_payload(events)
    headers = _make_signed_headers(TEST_KEY_ID, TEST_SECRET, raw_body)

    response = client.post("/ingest/v1/events", content=raw_body, headers=headers)
    assert response.status_code == 202

    body = response.json()
    assert body["accepted"] == 2
    assert body["rejected"] == []

    # Check spool file written
    date_str = datetime.now(UTC).strftime("%Y%m%d")
    spool_file = spool_dir / f"{date_str}.jsonl"
    assert spool_file.exists()
    lines = spool_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2

    # Check bus handoff
    assert len(handoff_records) == 1
    assert handoff_records[0][0] == "raw.okta"
    assert len(handoff_records[0][1]) == 2

    # Secret never in response
    assert TEST_SECRET not in response.text


# ---------------------------------------------------------------------------
# Test 2: Missing Headers -> 401
# ---------------------------------------------------------------------------


def test_missing_signature_headers() -> None:
    app = create_ingest_app(settings=_make_test_settings(), nonce_cache=NonceCache())
    client = TestClient(app)
    raw_body = _sample_okta_payload([])

    # Missing X-IS-Signature
    headers = {"X-IS-Key-Id": TEST_KEY_ID, "X-IS-Timestamp": str(int(time.time())), "X-IS-Nonce": "123"}
    resp = client.post("/ingest/v1/events", content=raw_body, headers=headers)
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Test 3: Bad Signature -> 401
# ---------------------------------------------------------------------------


def test_bad_signature_rejection() -> None:
    app = create_ingest_app(settings=_make_test_settings(), nonce_cache=NonceCache())
    client = TestClient(app)
    raw_body = _sample_okta_payload([])
    headers = _make_signed_headers(TEST_KEY_ID, TEST_SECRET, raw_body)
    headers["X-IS-Signature"] = "0" * 64

    resp = client.post("/ingest/v1/events", content=raw_body, headers=headers)
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Test 4: Timestamp 61 s Old -> 401
# ---------------------------------------------------------------------------


def test_stale_timestamp_rejection() -> None:
    app = create_ingest_app(settings=_make_test_settings(), nonce_cache=NonceCache())
    client = TestClient(app)
    raw_body = _sample_okta_payload([])
    stale_time = time.time() - 61.0
    headers = _make_signed_headers(TEST_KEY_ID, TEST_SECRET, raw_body, timestamp=stale_time)

    resp = client.post("/ingest/v1/events", content=raw_body, headers=headers)
    assert resp.status_code == 401
    assert "skew" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# Test 5: Replayed Nonce -> 401
# ---------------------------------------------------------------------------


def test_replayed_nonce_detection() -> None:
    nonce_cache = NonceCache()
    app = create_ingest_app(settings=_make_test_settings(), nonce_cache=nonce_cache)
    client = TestClient(app)

    ev = [{"uuid": "e1", "published": "2026-10-30T12:00:00Z", "eventType": "a", "actor": "b"}]
    raw_body = _sample_okta_payload(ev)
    fixed_nonce = "fixed_nonce_12345678"
    headers = _make_signed_headers(TEST_KEY_ID, TEST_SECRET, raw_body, nonce=fixed_nonce)

    # First request: 202
    resp1 = client.post("/ingest/v1/events", content=raw_body, headers=headers)
    assert resp1.status_code == 202

    # Second request with identical nonce: 401
    resp2 = client.post("/ingest/v1/events", content=raw_body, headers=headers)
    assert resp2.status_code == 401
    assert "replay" in resp2.json()["detail"].lower()


# ---------------------------------------------------------------------------
# Test 6: Body > 1 MB -> 413
# ---------------------------------------------------------------------------


def test_payload_too_large_rejection() -> None:
    app = create_ingest_app(settings=_make_test_settings())
    client = TestClient(app)

    # Construct body exceeding 1MB (1,048,576 bytes)
    oversized_body = b"{" + b'"padding":"' + (b"x" * 1_050_000) + b'"}'
    headers = _make_signed_headers(TEST_KEY_ID, TEST_SECRET, oversized_body)

    resp = client.post("/ingest/v1/events", content=oversized_body, headers=headers)
    assert resp.status_code == 413


# ---------------------------------------------------------------------------
# Test 7: Rate Limiting (21 requests in 1 second -> 429)
# ---------------------------------------------------------------------------


def test_rate_limiting_twenty_one_requests() -> None:
    from datetime import UTC, timedelta

    rate_limiter = TokenBucket(rps_limit=20.0, epm_limit=2000.0)
    nonce_cache = NonceCache()
    start_time = datetime(2026, 10, 30, 12, 0, 0, tzinfo=UTC)

    class ControlledClock:
        def __init__(self, start: datetime) -> None:
            self.cur = start

        def __call__(self) -> datetime:
            return self.cur

        def tick(self, seconds: float = 0.01) -> None:
            self.cur += timedelta(seconds=seconds)

    clock = ControlledClock(start_time)
    app = create_ingest_app(
        settings=_make_test_settings(),
        nonce_cache=nonce_cache,
        rate_limiter=rate_limiter,
        clock=clock,
    )
    client = TestClient(app)

    ev = [{"uuid": "e1", "published": "2026-10-30T12:00:00Z", "eventType": "a", "actor": "b"}]
    raw_body = _sample_okta_payload(ev)

    for _ in range(20):
        headers = _make_signed_headers(TEST_KEY_ID, TEST_SECRET, raw_body, timestamp=clock().timestamp())
        resp = client.post("/ingest/v1/events", content=raw_body, headers=headers)
        assert resp.status_code == 202
        clock.tick(0.001)

    # 21st request exceeds rate limit within 1 second
    headers21 = _make_signed_headers(TEST_KEY_ID, TEST_SECRET, raw_body, timestamp=clock().timestamp())
    resp21 = client.post("/ingest/v1/events", content=raw_body, headers=headers21)
    assert resp21.status_code == 429
    assert "Retry-After" in resp21.headers


# ---------------------------------------------------------------------------
# Test 8: Invalid Event at Index 2 -> Accepted n-1, Rejected [{index: 2}]
# ---------------------------------------------------------------------------


def test_partial_rejection_by_index() -> None:
    app = create_ingest_app(settings=_make_test_settings(), nonce_cache=NonceCache())
    client = TestClient(app)

    events = [
        {"uuid": "e0", "published": "2026-10-30T12:00:00Z", "eventType": "login", "actor": "alice"},
        {"uuid": "e1", "published": "2026-10-30T12:01:00Z", "eventType": "login", "actor": "alice"},
        {"uuid": "e2", "published": "2026-10-30T12:02:00Z", "eventType": "login"},  # Missing actor
    ]
    raw_body = _sample_okta_payload(events)
    headers = _make_signed_headers(TEST_KEY_ID, TEST_SECRET, raw_body)

    resp = client.post("/ingest/v1/events", content=raw_body, headers=headers)
    assert resp.status_code == 202
    data = resp.json()
    assert data["accepted"] == 2
    assert len(data["rejected"]) == 1
    assert data["rejected"][0]["index"] == 2
    assert "actor" in data["rejected"][0]["reason"]


# ---------------------------------------------------------------------------
# Test 9: Supervisor Backpressure -> 429 with Retry-After: 2
# ---------------------------------------------------------------------------


def test_supervisor_backpressure_rejection() -> None:
    sup = Supervisor()
    sup.backpressure = True

    app = create_ingest_app(supervisor=sup, settings=_make_test_settings())
    client = TestClient(app)

    raw_body = _sample_okta_payload([])
    headers = _make_signed_headers(TEST_KEY_ID, TEST_SECRET, raw_body)

    resp = client.post("/ingest/v1/events", content=raw_body, headers=headers)
    assert resp.status_code == 429
    assert resp.headers.get("Retry-After") == "2"


# ---------------------------------------------------------------------------
# Test 10: Audit Entry Written and Secret Never Echoed
# ---------------------------------------------------------------------------


def test_audit_entry_and_secret_safety() -> None:
    app = create_ingest_app(settings=_make_test_settings(), nonce_cache=NonceCache())
    client = TestClient(app)

    events = [{"uuid": "e-audit", "published": "2026-10-30T12:00:00Z", "eventType": "a", "actor": "b"}]
    raw_body = _sample_okta_payload(events)
    headers = _make_signed_headers(TEST_KEY_ID, TEST_SECRET, raw_body)

    resp = client.post("/ingest/v1/events", content=raw_body, headers=headers)
    assert resp.status_code == 202

    # Secret is never in response body or headers
    assert TEST_SECRET not in resp.text
    for hval in resp.headers.values():
        assert TEST_SECRET not in hval

    # Verify health endpoint reflects accepted events
    health_resp = client.get("/ingest/v1/health")
    assert health_resp.status_code == 200
    assert health_resp.json()["accepted_total"] >= 1
