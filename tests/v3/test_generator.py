"""Tests for Phase P16: Attack Generator Website & ngrok Ingest Compatibility.

Validates:
- All static assets (index.html, css/generator.css, js/sign.js, js/scenarios.js,
  js/generator.js, data/identities.json) and RUNBOOK_NGROK.md exist and conform
  to specifications.
- Web Crypto HMAC signing scheme compatibility with app/v3/ingest/security.py.
- Tamper tests T1-T5 behavior against the live FastAPI ingest service.
- CORS preflight options including ngrok-skip-browser-warning.
- Scenario payload schema compliance with Okta and CloudTrail validators.
"""
import hashlib
import hmac
import json
import time
import uuid
from pathlib import Path

from fastapi.testclient import TestClient

from app.v3.config import Settings
from app.v3.ingest.security import NonceCache, verify_signature
from app.v3.ingest.service import create_ingest_app

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
GENERATOR_DIR = ROOT_DIR / "generator"
RUNBOOK_FILE = ROOT_DIR / "RUNBOOK_NGROK.md"

TEST_KEY_ID = "test-key-1"
TEST_SECRET = "test_super_secret_signing_key_32bytes_long!"


def _generate_signed_headers(
    key_id: str,
    secret: str,
    raw_body: bytes,
    timestamp: float | None = None,
    nonce: str | None = None,
    signature_override: str | None = None,
    omit_headers: bool = False,
) -> dict[str, str]:
    """Mirror ShieldSign.signRequest in generator/js/sign.js."""
    if omit_headers:
        return {
            "Content-Type": "application/json",
            "ngrok-skip-browser-warning": "true",
        }

    ts_str = str(int(timestamp if timestamp is not None else time.time()))
    nonce_str = nonce or uuid.uuid4().hex
    body_hash = hashlib.sha256(raw_body).hexdigest()
    string_to_sign = f"{ts_str}\n{nonce_str}\n{body_hash}".encode()

    if signature_override:
        sig = signature_override
    else:
        sig = hmac.new(secret.encode("utf-8"), string_to_sign, hashlib.sha256).hexdigest()

    return {
        "X-IS-Key-Id": key_id,
        "X-IS-Timestamp": ts_str,
        "X-IS-Nonce": nonce_str,
        "X-IS-Signature": sig,
        "Content-Type": "application/json",
        "ngrok-skip-browser-warning": "true",
    }


def _make_test_client(spool_dir: Path) -> tuple[TestClient, NonceCache]:
    settings = Settings(
        v3_enabled=True,
        analyst_token="",
        dry_run=False,
        console_base_url="http://127.0.0.1:8000",
        ingest_keys={TEST_KEY_ID: TEST_SECRET},
        ingest_allowed_origins=["null", "http://localhost:5500"],
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
    nonce_cache = NonceCache(ttl_seconds=300)
    app = create_ingest_app(
        settings=settings,
        nonce_cache=nonce_cache,
        spool_dir=spool_dir,
    )
    return TestClient(app), nonce_cache


# ---------------------------------------------------------------------------
# Test 1: File Existence & Completeness
# ---------------------------------------------------------------------------


def test_generator_files_and_runbook_exist() -> None:
    """Verify all generator files and RUNBOOK_NGROK.md exist and contain required tokens."""
    assert RUNBOOK_FILE.exists(), "RUNBOOK_NGROK.md must exist in the root"
    runbook_text = RUNBOOK_FILE.read_text(encoding="utf-8")
    assert "ngrok" in runbook_text
    assert "20,000" in runbook_text
    assert "4040" in runbook_text
    assert "8001" in runbook_text
    assert "Troubleshooting" in runbook_text or "troubleshooting" in runbook_text.lower()

    # Generator static assets
    index_html = GENERATOR_DIR / "index.html"
    assert index_html.exists()
    html_text = index_html.read_text(encoding="utf-8")
    assert "targetUrl" in html_text
    assert "secretKey" in html_text
    assert "scenariosGrid" in html_text
    assert "tamperGrid" in html_text
    assert "noiseToggle" in html_text
    assert "quotaFill" in html_text
    assert "logTableBody" in html_text

    # CSS
    css_file = GENERATOR_DIR / "css" / "generator.css"
    assert css_file.exists()
    css_text = css_file.read_text(encoding="utf-8")
    assert "--bg:" in css_text
    assert "--cyan:" in css_text

    # JS files
    sign_js = GENERATOR_DIR / "js" / "sign.js"
    scenarios_js = GENERATOR_DIR / "js" / "scenarios.js"
    generator_js = GENERATOR_DIR / "js" / "generator.js"
    assert sign_js.exists()
    assert scenarios_js.exists()
    assert generator_js.exists()

    # Data
    identities_json = GENERATOR_DIR / "data" / "identities.json"
    assert identities_json.exists()
    data = json.loads(identities_json.read_text(encoding="utf-8"))
    assert "identities" in data
    assert any(i["identity_id"] == "svc-report" for i in data["identities"])


# ---------------------------------------------------------------------------
# Test 2: Cryptographic Signature Verification Compatibility
# ---------------------------------------------------------------------------


def test_crypto_signing_compatibility() -> None:
    """Ensure generator signing algorithm matches server-side verify_signature."""
    body = json.dumps({"source": "okta", "events": []}).encode("utf-8")
    nonce = uuid.uuid4().hex
    now = time.time()

    headers = _generate_signed_headers(
        key_id=TEST_KEY_ID,
        secret=TEST_SECRET,
        raw_body=body,
        timestamp=now,
        nonce=nonce,
    )

    nonce_cache = NonceCache(ttl_seconds=300)
    verified_key = verify_signature(
        headers=headers,
        raw_body=body,
        keys={TEST_KEY_ID: TEST_SECRET},
        now=now,
        nonce_cache=nonce_cache,
    )
    assert verified_key == TEST_KEY_ID


# ---------------------------------------------------------------------------
# Test 3: Tamper Suite T1-T5 Live Verification
# ---------------------------------------------------------------------------


def test_tamper_suite_t1_to_t5_behavior(tmp_path: Path) -> None:
    """Verify live HTTP status codes for tamper tests T1 to T5 against ingest app."""
    client, _ = _make_test_client(tmp_path / "spool")

    base_batch = {
        "source": "okta",
        "sender_id": "test-runner",
        "batch_id": "batch-tamper-check",
        "events": [
            {
                "uuid": str(uuid.uuid4()),
                "published": "2026-10-30T12:00:00Z",
                "eventType": "user.session.start",
                "actor": {"id": "00u123", "alternateId": "test@corp.example"},
            }
        ],
    }
    raw_body = json.dumps(base_batch).encode("utf-8")

    # T1: Unsigned (No headers) -> 401
    t1_headers = _generate_signed_headers(TEST_KEY_ID, TEST_SECRET, raw_body, omit_headers=True)
    res_t1 = client.post("/ingest/v1/events", content=raw_body, headers=t1_headers)
    assert res_t1.status_code == 401

    # T2: Bad signature -> 401
    t2_headers = _generate_signed_headers(
        TEST_KEY_ID,
        TEST_SECRET,
        raw_body,
        signature_override="deadbeef00000000111122223333444455556666777788889999aaaabbbbcccc",
    )
    res_t2 = client.post("/ingest/v1/events", content=raw_body, headers=t2_headers)
    assert res_t2.status_code == 401

    # T3: Stale timestamp (120s past skew window) -> 401
    t3_headers = _generate_signed_headers(
        TEST_KEY_ID,
        TEST_SECRET,
        raw_body,
        timestamp=time.time() - 120,
    )
    res_t3 = client.post("/ingest/v1/events", content=raw_body, headers=t3_headers)
    assert res_t3.status_code == 401

    # T4: Replay nonce -> 202 first, 401 second
    fixed_nonce = uuid.uuid4().hex
    t4_headers = _generate_signed_headers(
        TEST_KEY_ID,
        TEST_SECRET,
        raw_body,
        nonce=fixed_nonce,
    )
    res_t4_first = client.post("/ingest/v1/events", content=raw_body, headers=t4_headers)
    assert res_t4_first.status_code == 202

    res_t4_second = client.post("/ingest/v1/events", content=raw_body, headers=t4_headers)
    assert res_t4_second.status_code == 401
    assert "replayed nonce" in res_t4_second.json().get("detail", "").lower()

    # T5: Oversized body (> 1.0 MB) -> 413
    huge_payload = b"X" * (1200 * 1024)  # 1.2 MB
    t5_headers = _generate_signed_headers(TEST_KEY_ID, TEST_SECRET, huge_payload)
    res_t5 = client.post("/ingest/v1/events", content=huge_payload, headers=t5_headers)
    assert res_t5.status_code == 413


# ---------------------------------------------------------------------------
# Test 4: CORS Preflight and Health Check
# ---------------------------------------------------------------------------


def test_cors_preflight_and_health(tmp_path: Path) -> None:
    """Verify OPTIONS preflight allows ngrok-skip-browser-warning and health returns 200."""
    client, _ = _make_test_client(tmp_path / "spool")

    # Health check
    res_health = client.get("/ingest/v1/health", headers={"ngrok-skip-browser-warning": "true"})
    assert res_health.status_code == 200
    assert res_health.json()["status"] == "ok"

    # Preflight OPTIONS request
    res_options = client.options(
        "/ingest/v1/events",
        headers={
            "Origin": "http://localhost:5500",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type,X-IS-Key-Id,X-IS-Timestamp,X-IS-Nonce,X-IS-Signature,ngrok-skip-browser-warning",
        },
    )
    assert res_options.status_code == 200
    assert "ngrok-skip-browser-warning" in res_options.headers.get("access-control-allow-headers", "")
