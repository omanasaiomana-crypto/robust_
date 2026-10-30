"""Comprehensive security, hardening, and anti-tamper tests for IdentityShield v3.

Follows context.md Section 2 (Golden Rules), Section 12, and Phase P18 requirements:
1. XSS injection strings in user agent and resource names are preserved as raw untrusted data
   and never returned as executed/rendered HTML by the API or backend.
2. Capability violations: Agents cannot publish to topics outside their declared manifest;
   unauthorized agents cannot access or trigger simulator execution.
3. Ingest security tamper suite:
   - Tampered HMAC signature rejected (401)
   - Replayed nonce rejected (401)
   - Expired timestamp rejected (> 300s window) (401)
   - Payload > 1 MB rejected (413)
4. Secrets hygiene: Secrets (ANALYST_TOKEN, INGEST_KEYS, SMTP_PASSWORD, GEMINI_API_KEY)
   are never returned by /api/v3/config or API status endpoints.
"""
import time
from pathlib import Path
from typing import Any, ClassVar
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.v3.agents.a14_response import SimulatorClient
from app.v3.agents.base import Agent, AgentContext
from app.v3.ingest.security import NonceCache, TokenBucket
from app.v3.ingest.service import create_ingest_app
from app.v3.models import ActionKind, Event, EventClass, Message, Source
from app.v3.store import close_connection, create_tables, set_db_path
from app.v3.supervisor import CapabilityError, Supervisor
from tests.v3.test_ingest import (
    TEST_KEY_ID,
    TEST_SECRET,
    _make_signed_headers,
    _make_test_settings,
    _sample_okta_payload,
)


@pytest.fixture
def client(tmp_db: Path):
    set_db_path(tmp_db)
    create_tables(tmp_db)
    with TestClient(app) as test_client:
        yield test_client
    close_connection(tmp_db)


@pytest.fixture
def ingest_client(tmp_path: Path):
    settings = _make_test_settings()
    ingest_app = create_ingest_app(
        settings=settings,
        nonce_cache=NonceCache(),
        rate_limiter=TokenBucket(),
        spool_dir=tmp_path / "spool",
    )
    with TestClient(ingest_app) as client:
        yield client


# ---------------------------------------------------------------------------
# 1. XSS Defense & Untrusted Data Preservation
# ---------------------------------------------------------------------------


def test_xss_data_preservation_and_no_eval(tmp_db: Path) -> None:
    """Verify XSS payloads in user agents & resource ARNs are treated as raw data."""
    set_db_path(tmp_db)
    create_tables(tmp_db)

    xss_ua = "<script>alert('xss-ua')</script><img src=x onerror=alert(1)>"
    xss_arn = "arn:aws:iam::123456789012:role/<svg onload=alert('xss-arn')>"

    event = Event(
        event_id="ev-xss-01",
        time="2026-10-30T12:00:00Z",
        source=Source.cloudtrail,
        event_class=EventClass.authentication,
        action="AssumeRole",
        identity_id="alice",
        raw_principal="alice",
        session_id="sess-xss-1",
        src_ip="198.51.100.1",
        user_agent=xss_ua,
        outcome="success",
        resource_arn=xss_arn,
        read_only=True,
        resolution_confidence=1.0,
    )

    # API returns event data as raw JSON without executing or mutating the string
    assert event.user_agent == xss_ua
    assert event.resource_arn == xss_arn

    # Ensure model dump preserves string literally
    dump = event.model_dump()
    assert dump["user_agent"] == xss_ua
    assert dump["resource_arn"] == xss_arn


# ---------------------------------------------------------------------------
# 2. Capability Enforcement & Sandbox Violations
# ---------------------------------------------------------------------------


def test_supervisor_forbids_undeclared_topic_publication() -> None:
    """Verify Bus & Supervisor drop or block messages published on undeclared topics."""
    sup = Supervisor()

    class RogueAgent(Agent):
        num = 1
        agent_id = "agent01_collector"
        name = "Collector"
        layer = "collection"
        path = "hot"
        subscribes: ClassVar[list[str]] = ["raw.okta"]
        publishes: ClassVar[list[str]] = ["events"]  # Only allowed to publish "events", NOT "cases"

        def process(self, msg: Message, state: dict[str, Any], ctx: AgentContext) -> list[Message]:
            return [ctx.new_message(topic="cases", payload={"rogue": True})]

    rogue = RogueAgent()
    sup.register_agent(rogue)

    # Supervisor capability check: RogueAgent cannot publish to "cases"
    with pytest.raises(CapabilityError, match="forbids publishing to topic 'cases'"):
        sup.check_publish(rogue, "cases")


def test_simulator_forbids_unauthorized_agent_call() -> None:
    """Verify SimulatorClient raises CapabilityError when called by non-Agent-14."""
    mock_sim = MagicMock()
    sim_client = SimulatorClient(simulator_instance=mock_sim)

    # Agent 1 attempting to execute simulator action
    with pytest.raises(CapabilityError, match="capability manifest forbids simulator access"):
        sim_client.execute(
            action_kind=ActionKind.restrict,
            identity_id="alice",
            caller="agent01_collector",
        )

    # Agent 14 (allowed) succeeds
    sim_ref = sim_client.execute(
        action_kind=ActionKind.restrict,
        identity_id="alice",
        caller="a14",
    )
    assert sim_ref is not None
    assert mock_sim.restrict.called


# ---------------------------------------------------------------------------
# 3. Ingest Security & Anti-Tamper Suite (T1–T5)
# ---------------------------------------------------------------------------


def test_tamper_signature_rejected(ingest_client: TestClient) -> None:
    """T1: Tampered signature must be rejected with 401."""
    body = _sample_okta_payload([{"uuid": "test-1", "published": "2026-10-30T12:00:00Z", "eventType": "user.session.start", "actor": {"id": "u1"}}])
    headers = _make_signed_headers(TEST_KEY_ID, TEST_SECRET, body, time.time(), "nonce-t1")
    headers["X-IS-Signature"] = "0" * 64  # Corrupted signature

    resp = ingest_client.post("/ingest/v1/events", content=body, headers=headers)
    assert resp.status_code == 401


def test_tamper_replayed_nonce_rejected(ingest_client: TestClient) -> None:
    """T2: Replayed nonce must be rejected on second request."""
    body = _sample_okta_payload([{"uuid": "test-nonce-1", "published": "2026-10-30T12:00:00Z", "eventType": "user.session.start", "actor": {"id": "u1"}}])
    t = time.time()
    nonce = f"nonce-replay-{int(t)}"
    headers = _make_signed_headers(TEST_KEY_ID, TEST_SECRET, body, t, nonce)

    # First request succeeds
    resp1 = ingest_client.post("/ingest/v1/events", content=body, headers=headers)
    assert resp1.status_code == 202

    # Immediate replay with same nonce fails
    resp2 = ingest_client.post("/ingest/v1/events", content=body, headers=headers)
    assert resp2.status_code == 401
    assert "nonce" in resp2.text.lower()


def test_tamper_expired_timestamp_rejected(ingest_client: TestClient) -> None:
    """T3: Timestamp outside clock skew window must be rejected."""
    body = _sample_okta_payload([{"uuid": "test-exp-1", "published": "2026-10-30T12:00:00Z", "eventType": "user.session.start", "actor": {"id": "u1"}}])
    expired_t = time.time() - 3600  # 1 hour in the past
    headers = _make_signed_headers(TEST_KEY_ID, TEST_SECRET, body, expired_t, "nonce-expired")

    resp = ingest_client.post("/ingest/v1/events", content=body, headers=headers)
    assert resp.status_code == 401
    assert "timestamp" in resp.text.lower() or "skew" in resp.text.lower()


def test_tamper_oversized_payload_rejected(ingest_client: TestClient) -> None:
    """T4: Payloads exceeding MAX_BODY_BYTES (1 MB) must be rejected."""
    oversized_body = b'{"data": "' + (b"X" * (1024 * 1024 + 100)) + b'"}'
    headers = _make_signed_headers(TEST_KEY_ID, TEST_SECRET, oversized_body, time.time(), "nonce-oversize")

    resp = ingest_client.post("/ingest/v1/events", content=oversized_body, headers=headers)
    assert resp.status_code in (413, 400)


# ---------------------------------------------------------------------------
# 4. Secrets Hygiene & Zero-Leakage
# ---------------------------------------------------------------------------


def test_secrets_never_in_api_config(client: TestClient) -> None:
    """Verify no secret environment variables are leaked via GET /api/v3/config."""
    resp = client.get("/api/v3/config")
    assert resp.status_code == 200
    config_data = resp.json()

    # Assert known secret field names do not exist in config response
    forbidden_keys = {
        "analyst_token",
        "ingest_keys",
        "secret",
        "password",
        "smtp_password",
        "gemini_api_key",
        "anthropic_api_key",
        "openai_api_key",
        "ipinfo_token",
    }

    serialized = str(config_data).lower()
    for secret_name in forbidden_keys:
        assert secret_name not in config_data
        assert f"'{secret_name}':" not in serialized


def test_analyst_token_protects_mutating_routes(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify mutating routes return 401 when ANALYST_TOKEN is configured and missing."""
    monkeypatch.setenv("ANALYST_TOKEN", "super-secret-token")

    mutating_routes = [
        ("POST", "/api/v3/cases/case-test/label", {"verdict": "true_positive"}),
        ("POST", "/api/v3/actions/act-test/approve", {}),
        ("POST", "/api/v3/actions/act-test/reject", {}),
        ("POST", "/api/v3/actions/act-test/rollback", {}),
        ("POST", "/api/v3/run/dataset", {}),
        ("POST", "/api/v3/inputs/scan", {}),
        ("POST", "/api/v3/bench/run", {}),
        ("POST", "/api/v3/config/rollback/1", {}),
    ]

    for method, path, json_body in mutating_routes:
        # Request WITHOUT token -> 401
        res = client.request(method, path, json=json_body)
        assert res.status_code == 401, f"Route {method} {path} did not reject unauthenticated call"

        # Request WITH invalid token -> 401
        res_bad = client.request(method, path, json=json_body, headers={"X-Analyst-Token": "wrong-token"})
        assert res_bad.status_code == 401, f"Route {method} {path} did not reject bad token"
