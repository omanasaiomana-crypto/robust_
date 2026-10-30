"""Unit tests for Agent 3 (Context & Threat Intel) and Agent 4 (Correlation & Graph).

Verifies requirements from P05:
- securityContext preferred over geo_seed
- hosting ASN flag
- unknown IP -> context_complete=False
- sensitivity rules
- providers disabled by default and mocked when enabled
- cross-provider session (Okta login + SAML + AWS calls) forms ONE session
- idle close
- graph edges and blast radius on fixture
"""
import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from app.v3 import store
from app.v3.agents import register_all
from app.v3.agents.a01_collector import Collector
from app.v3.agents.a02_normalizer import Normalizer
from app.v3.agents.a03_context import ContextThreatIntel
from app.v3.agents.a04_correlation import CorrelationGraph
from app.v3.agents.base import AgentContext
from app.v3.bus import Bus
from app.v3.config import get_settings
from app.v3.enrich.offline import (
    get_privilege_level,
    get_resource_sensitivity,
    lookup_ip,
)
from app.v3.enrich.providers import ExternalEnricher
from app.v3.models import (
    EnrichedEvent,
    Event,
    EventClass,
    GraphDelta,
    RawLog,
    Session,
    Source,
)
from app.v3.supervisor import Supervisor

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


class FixedClock:
    def __init__(self, dt: datetime) -> None:
        self.dt = dt

    def now(self) -> datetime:
        return self.dt

    def __call__(self) -> datetime:
        return self.dt

    def tick(self, seconds: float) -> None:
        self.dt = datetime.fromtimestamp(self.dt.timestamp() + seconds, tz=UTC)


@pytest.fixture
def test_ctx(tmp_path: Path) -> AgentContext:
    db_file = tmp_path / "test_agents_3_4.db"
    store.create_tables(db_file)
    settings = get_settings()
    clock = FixedClock(datetime(2026, 10, 30, 12, 0, 0, tzinfo=UTC))
    return AgentContext(clock=clock, settings=settings, store=type("StoreRef", (), {"db_path": db_file})())


def test_security_context_preferred() -> None:
    # IP in geo_seed is normally San Francisco / Google AS15169
    ip = "198.51.100.10"
    attrs = {
        "securityContext": {
            "asNumber": "AS99999",
            "asOrg": "OverriddenOrg",
            "isProxy": True,
        },
        "geographicalContext": {
            "country": "Japan",
            "city": "Tokyo",
            "geolocation": {"lat": 35.6762, "lon": 139.6503},
        },
    }
    meta = lookup_ip(ip, attrs=attrs)
    assert meta["asn"] == 99999
    assert meta["as_org"] == "OverriddenOrg"
    assert meta["country"] == "Japan"
    assert meta["city"] == "Tokyo"
    assert meta["is_proxy"] is True
    assert meta["context_complete"] is True


def test_hosting_asn_flag() -> None:
    # Google ASN 15169 should be marked as hosting
    meta_google = lookup_ip("198.51.100.10")
    assert meta_google["is_hosting"] is True

    # Bharti Airtel 45609 is not in hosting_asns
    meta_airtel = lookup_ip("103.50.162.10")
    assert meta_airtel["is_hosting"] is False


def test_unknown_ip_incomplete_context() -> None:
    meta_unknown = lookup_ip("198.18.99.1")
    assert meta_unknown["context_complete"] is False
    assert meta_unknown["country"] is None
    assert meta_unknown["city"] is None


def test_sensitivity_rules() -> None:
    # SecretsManager -> 5
    assert get_resource_sensitivity("arn:aws:secretsmanager:us-east-1:123:secret:prod/db/pass") == 5
    # KMS -> 5
    assert get_resource_sensitivity("arn:aws:kms:us-east-1:123:key/abc-123") == 5
    # S3 with prod/finance in name -> 5
    assert get_resource_sensitivity("arn:aws:s3:::corporate-prod-finance-records") == 5
    # IAM -> 4
    assert get_resource_sensitivity("arn:aws:iam::123:role/DevOpsAdmin") == 4
    # Generic S3 -> 3
    assert get_resource_sensitivity("arn:aws:s3:::my-general-data-lake-bucket") == 3
    # EC2 instance -> 2
    assert get_resource_sensitivity("arn:aws:ec2:us-east-1:123:instance/i-12345") == 2
    # None or empty -> 1
    assert get_resource_sensitivity(None) == 1


def test_privilege_rules() -> None:
    assert get_privilege_level("alice@example.com", policies=["arn:aws:iam::aws:policy/AdministratorAccess"]) == 5
    assert get_privilege_level("admin-service", policies=[]) == 5
    assert get_privilege_level("auditor", policies=["SecurityAudit"]) == 4
    assert get_privilege_level("regular-user", policies=[]) == 1


def test_providers_disabled_by_default_and_mocked_when_enabled(tmp_path: Path) -> None:
    db_file = tmp_path / "enrich_test.db"
    store.create_tables(db_file)

    # 1. Disabled by default
    enricher_default = ExternalEnricher(db_path=db_file, enabled_providers=[])
    assert enricher_default.is_enabled() is False
    assert enricher_default.enqueue_prefetch("1.2.3.4") is False

    # 2. Enabled and mocked
    enricher_active = ExternalEnricher(db_path=db_file, enabled_providers=["ipinfo_lite"])
    assert enricher_active.is_enabled() is True

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "ip": "203.0.113.5",
        "city": "Seattle",
        "region": "Washington",
        "country": "US",
        "org": "AS8075 Microsoft",
    }

    mock_client = MagicMock()
    mock_client.get.return_value = mock_resp

    data = enricher_active.fetch_provider("203.0.113.5", "ipinfo_lite", client=mock_client)
    assert data is not None
    assert data["city"] == "Seattle"

    # Save to cache and retrieve
    enricher_active.save_cache("203.0.113.5", "ipinfo_lite", data)
    cached = enricher_active.get_cached("203.0.113.5")
    assert cached is not None
    assert cached["country"] == "US"
    enricher_active.stop()


def test_cross_provider_session_stitching(test_ctx: AgentContext) -> None:
    with (FIXTURES_DIR / "okta_sample.json").open("r", encoding="utf-8") as f:
        okta_records = json.load(f)
    with (FIXTURES_DIR / "cloudtrail_sample.json").open("r", encoding="utf-8") as f:
        ct_records = json.load(f)["Records"]

    collector = Collector()
    c_state = collector.init_state()
    normalizer = Normalizer()
    n_state = normalizer.init_state()
    context_agent = ContextThreatIntel()
    ctx_state = context_agent.init_state()
    corr_agent = CorrelationGraph()
    corr_state = corr_agent.init_state()

    def step_event(rec: dict, source_topic: str) -> None:
        src = Source.okta if "okta" in source_topic else Source.cloudtrail
        collector.process(test_ctx.new_message(topic=source_topic, payload=RawLog(source=src, records=[rec])), c_state, test_ctx)
        col = collector.on_tick(c_state, test_ctx)[0]
        norm = normalizer.process(col, n_state, test_ctx)[0]
        enr = context_agent.process(norm, ctx_state, test_ctx)[0]
        corr_agent.process(enr, corr_state, test_ctx)

    # 1. Okta login (sess-alice-001)
    okta_alice = next(r for r in okta_records if r.get("uuid") == "okta-alice-0001")
    step_event(okta_alice, "raw.okta")

    # 2. AssumeRoleWithSAML (alice@example.com -> ASIA_ALICE_TEMP_KEY)
    ct_saml = next(r for r in ct_records if r.get("eventName") == "AssumeRoleWithSAML")
    step_event(ct_saml, "raw.cloudtrail")

    # 3. CreateAccessKey (creates AKIA_ALICE_NEW_KEY)
    ct_key = next(r for r in ct_records if r.get("eventName") == "CreateAccessKey")
    step_event(ct_key, "raw.cloudtrail")

    # 4. DescribeInstances (using AKIA_ALICE_NEW_KEY)
    ct_desc = next(r for r in ct_records if r.get("eventName") == "DescribeInstances")
    step_event(ct_desc, "raw.cloudtrail")

    # 5. GetSecretValue (using AKIA_ALICE_NEW_KEY)
    ct_sec = next(r for r in ct_records if r.get("eventName") == "GetSecretValue")
    step_event(ct_sec, "raw.cloudtrail")

    # Verify: All joined the Okta session sess:sess-alice-001
    sessions = corr_state["sessions"]
    target_session_id = "sess:sess-alice-001"
    assert target_session_id in sessions

    s = sessions[target_session_id]
    assert s["identity_id"] == "alice@example.com"
    assert len(s["event_ids"]) == 5
    # Cross-provider: both Okta and CloudTrail are present
    assert "okta" in s["providers"]
    assert "cloudtrail" in s["providers"]


def test_session_idle_close(test_ctx: AgentContext) -> None:
    corr_agent = CorrelationGraph()
    state = corr_agent.init_state()

    # Create dummy EnrichedEvent
    ev = Event(
        event_id="ev-100",
        time="2026-10-30T10:00:00Z",
        source=Source.cloudtrail,
        event_class=EventClass.api_activity,
        action="DescribeRegions",
        identity_id="bob",
        raw_principal="bob",
        session_id=None,
        src_ip="203.0.113.1",
        user_agent="cli",
        outcome="success",
        resource_arn=None,
        read_only=True,
        region="us-east-1",
        late=False,
        uncatalogued=False,
        resolution_confidence=1.0,
        raw_ref=None,
        attrs={},
    )
    from app.v3.models import ActionType, Context

    ctx_model = Context(
        country="US",
        action_type=ActionType.read,
        context_complete=True,
    )
    enr = EnrichedEvent(event=ev, context=ctx_model)
    msg = test_ctx.new_message(topic="events.enriched", payload=enr)

    # Process opening event
    out_open = corr_agent.process(msg, state, test_ctx)
    sess_open_msgs = [m for m in out_open if isinstance(m.payload, Session)]
    assert len(sess_open_msgs) == 1
    assert sess_open_msgs[0].payload.state == "open"

    # Advance time by 20 minutes (> 15 min idle timeout)
    test_ctx.clock.tick(1200.0)

    # Tick should close the idle session
    out_tick = corr_agent.on_tick(state, test_ctx)
    sess_close_msgs = [m for m in out_tick if isinstance(m.payload, Session) and m.payload.state == "closed"]
    assert len(sess_close_msgs) == 1
    assert sess_close_msgs[0].payload.state == "closed"


def test_graph_edges_and_blast_radius(test_ctx: AgentContext) -> None:
    with (FIXTURES_DIR / "okta_sample.json").open("r", encoding="utf-8") as f:
        okta_records = json.load(f)
    with (FIXTURES_DIR / "cloudtrail_sample.json").open("r", encoding="utf-8") as f:
        ct_records = json.load(f)["Records"]

    collector = Collector()
    c_state = collector.init_state()
    normalizer = Normalizer()
    n_state = normalizer.init_state()
    context_agent = ContextThreatIntel()
    ctx_state = context_agent.init_state()
    corr_agent = CorrelationGraph()
    corr_state = corr_agent.init_state()

    all_graph_deltas = []
    # Send all records through pipeline
    for rec in okta_records:
        collector.process(test_ctx.new_message(topic="raw.okta", payload=RawLog(source=Source.okta, records=[rec])), c_state, test_ctx)
        for col in collector.on_tick(c_state, test_ctx):
            for norm in normalizer.process(col, n_state, test_ctx):
                for enr in context_agent.process(norm, ctx_state, test_ctx):
                    for out_m in corr_agent.process(enr, corr_state, test_ctx):
                        if isinstance(out_m.payload, GraphDelta):
                            all_graph_deltas.append(out_m.payload)

    for rec in ct_records:
        collector.process(test_ctx.new_message(topic="raw.cloudtrail", payload=RawLog(source=Source.cloudtrail, records=[rec])), c_state, test_ctx)
        for col in collector.on_tick(c_state, test_ctx):
            for norm in normalizer.process(col, n_state, test_ctx):
                for enr in context_agent.process(norm, ctx_state, test_ctx):
                    for out_m in corr_agent.process(enr, corr_state, test_ctx):
                        if isinstance(out_m.payload, GraphDelta):
                            all_graph_deltas.append(out_m.payload)

    # Check graph properties
    graph = corr_agent.get_graph()
    assert graph.number_of_nodes() > 5
    assert graph.number_of_edges() > 5
    assert len(all_graph_deltas) > 0

    # Verify blast radius calculation:
    # alice touched secretsmanager: prod/database/credentials (sensitivity 5)
    radius = corr_agent.blast_radius("alice@example.com")
    assert radius >= 1


def test_supervisor_registers_agents_1_to_4() -> None:
    sup = Supervisor()
    bus = Bus(supervisor=sup)
    registered = register_all(sup, bus)

    nums = [ag.num for ag in registered]
    assert 1 in nums
    assert 2 in nums
    assert 3 in nums
    assert 4 in nums
