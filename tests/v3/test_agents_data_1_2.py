"""Unit tests for Agent 1 (Collector) and Agent 2 (Normalizer & Identity Resolver).

Verifies requirements from P04:
- Deduplication by event ID (exact set + 24h rolling expiry)
- Watermark buffering and chronological ordering
- Late arrival flagging (late=True)
- Okta and CloudTrail field mapping with _raw removal
- Uncatalogued action flagging
- Identity resolution chain: Okta (1.0) -> SAML role (0.9) -> new key (0.8) -> unresolved (0.5)
- Malformed records directed to deadletter
- Supervisor and Bus registration via register_all
- Database persistence of identities_v3 and identity_aliases_v3
"""
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.v3 import store
from app.v3.agents import register_all
from app.v3.agents.a01_collector import Collector, parse_cloudtrail, parse_okta
from app.v3.agents.a02_normalizer import (
    Normalizer,
    parse_okta_fields,
    resolve_identity,
)
from app.v3.agents.base import AgentContext
from app.v3.bus import Bus
from app.v3.config import get_settings
from app.v3.models import (
    DeadletterPayload,
    Event,
    EventClass,
    RawLog,
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


@pytest.fixture
def test_ctx(tmp_path: Path) -> AgentContext:
    db_file = tmp_path / "test_agents.db"
    store.create_tables(db_file)
    settings = get_settings()
    clock = FixedClock(datetime(2026, 10, 30, 12, 0, 0, tzinfo=UTC))
    return AgentContext(clock=clock, settings=settings, store=type("StoreRef", (), {"db_path": db_file})())


def test_collector_deduplication(test_ctx: AgentContext) -> None:
    collector = Collector()
    state = collector.init_state()

    raw_event = {
        "uuid": "okta-dup-001",
        "published": "2026-10-30T10:00:00Z",
        "eventType": "user.session.start",
        "actor": {"alternateId": "alice@example.com"},
        "client": {"ipAddress": "1.2.3.4"},
    }
    msg1 = test_ctx.new_message(topic="raw.okta", payload=RawLog(source=Source.okta, records=[raw_event]))
    msg2 = test_ctx.new_message(topic="raw.okta", payload=RawLog(source=Source.okta, records=[raw_event]))

    collector.process(msg1, state, test_ctx)
    collector.process(msg2, state, test_ctx)

    # Flush watermark buffer
    flushed = collector.on_tick(state, test_ctx)
    assert len(flushed) == 1
    assert flushed[0].payload.event_id == "okta-dup-001"
    assert "okta-dup-001" in state["seen_ids"]


def test_collector_watermark_order(test_ctx: AgentContext) -> None:
    collector = Collector()
    state = collector.init_state()

    # Send 3 events out of order (times: 10:02:00, 10:00:30, 10:01:15)
    e1 = {"uuid": "e1", "published": "2026-10-30T10:02:00Z", "eventType": "user.session.start"}
    e2 = {"uuid": "e2", "published": "2026-10-30T10:00:30Z", "eventType": "user.session.start"}
    e3 = {"uuid": "e3", "published": "2026-10-30T10:01:15Z", "eventType": "user.session.start"}

    collector.process(test_ctx.new_message(topic="raw.okta", payload=RawLog(source=Source.okta, records=[e1])), state, test_ctx)
    collector.process(test_ctx.new_message(topic="raw.okta", payload=RawLog(source=Source.okta, records=[e2])), state, test_ctx)
    collector.process(test_ctx.new_message(topic="raw.okta", payload=RawLog(source=Source.okta, records=[e3])), state, test_ctx)

    # Flush on tick
    flushed = collector.on_tick(state, test_ctx)
    assert len(flushed) == 3
    # Released in strictly ascending chronological order: e2 (10:00:30), e3 (10:01:15), e1 (10:02:00)
    assert [m.payload.event_id for m in flushed] == ["e2", "e3", "e1"]
    assert all(not m.payload.late for m in flushed)


def test_collector_late_flag(test_ctx: AgentContext) -> None:
    collector = Collector()
    state = collector.init_state()

    # Watermark will be established at 10:05:00 (watermark_seconds = 120, cutoff = 10:03:00)
    e_new = {"uuid": "e-new", "published": "2026-10-30T10:05:00Z", "eventType": "user.session.start"}
    out_new = collector.process(test_ctx.new_message(topic="raw.okta", payload=RawLog(source=Source.okta, records=[e_new])), state, test_ctx)

    # Send an event with time 10:01:00 (< 10:03:00 cutoff)
    e_late = {"uuid": "e-late", "published": "2026-10-30T10:01:00Z", "eventType": "user.session.start"}
    out_late = collector.process(test_ctx.new_message(topic="raw.okta", payload=RawLog(source=Source.okta, records=[e_late])), state, test_ctx)

    flushed = collector.on_tick(state, test_ctx)
    late_events = [m.payload for m in (out_new + out_late + flushed) if m.payload.event_id == "e-late"]
    assert len(late_events) == 1
    assert late_events[0].late is True


def test_collector_malformed_deadletter(test_ctx: AgentContext) -> None:
    collector = Collector()
    state = collector.init_state()

    # Missing uuid
    bad_record = {"published": "2026-10-30T10:00:00Z", "eventType": "user.session.start"}
    out = collector.process(
        test_ctx.new_message(topic="raw.okta", payload=RawLog(source=Source.okta, records=[bad_record])),
        state,
        test_ctx,
    )

    assert len(out) == 1
    msg = out[0]
    assert msg.topic == "deadletter"
    assert isinstance(msg.payload, DeadletterPayload)
    assert "uuid" in msg.payload.error


def test_normalizer_field_mapping_okta(test_ctx: AgentContext) -> None:
    with (FIXTURES_DIR / "okta_sample.json").open("r", encoding="utf-8") as f:
        okta_records = json.load(f)

    collector = Collector()
    c_state = collector.init_state()
    raw_msg = test_ctx.new_message(topic="raw.okta", payload=RawLog(source=Source.okta, records=okta_records[:3]))
    collector.process(raw_msg, c_state, test_ctx)
    collected = collector.on_tick(c_state, test_ctx)

    normalizer = Normalizer()
    n_state = normalizer.init_state()

    for col_msg in collected:
        norm_msgs = normalizer.process(col_msg, n_state, test_ctx)
        assert len(norm_msgs) == 1
        ev: Event = norm_msgs[0].payload
        assert norm_msgs[0].topic == "events.normalized"
        assert ev.source == Source.okta
        assert ev.event_class == EventClass.authentication
        assert ev.identity_id == "alice@example.com"
        assert ev.resolution_confidence == 1.0
        assert "_raw" not in ev.attrs
        assert "okta_session_id" in ev.attrs
        assert ev.attrs["okta_session_id"] == "sess-alice-001"


def test_normalizer_field_mapping_cloudtrail(test_ctx: AgentContext) -> None:
    with (FIXTURES_DIR / "cloudtrail_sample.json").open("r", encoding="utf-8") as f:
        data = json.load(f)
        ct_records = data["Records"]

    describe_record = next(r for r in ct_records if r.get("eventName") == "DescribeInstances")

    collector = Collector()
    c_state = collector.init_state()
    collector.process(
        test_ctx.new_message(topic="raw.cloudtrail", payload=RawLog(source=Source.cloudtrail, records=[describe_record])),
        c_state,
        test_ctx,
    )
    collected = collector.on_tick(c_state, test_ctx)

    normalizer = Normalizer()
    n_state = normalizer.init_state()
    norm_msgs = normalizer.process(collected[0], n_state, test_ctx)

    assert len(norm_msgs) == 1
    ev: Event = norm_msgs[0].payload
    assert ev.action == "DescribeInstances"
    assert ev.read_only is True
    assert ev.attrs.get("access_key_id") == "AKIA_ALICE_NEW_KEY"
    assert "_raw" not in ev.attrs


def test_normalizer_uncatalogued_action(test_ctx: AgentContext) -> None:
    custom_raw = {
        "eventID": "ct-unknown-999",
        "eventTime": "2026-10-30T10:10:00Z",
        "eventName": "ExecuteProprietaryCustomAPI",
        "sourceIPAddress": "198.51.100.22",
        "userIdentity": {"type": "IAMUser", "userName": "custom-service"},
    }

    collector = Collector()
    c_state = collector.init_state()
    collector.process(
        test_ctx.new_message(topic="raw.cloudtrail", payload=RawLog(source=Source.cloudtrail, records=[custom_raw])),
        c_state,
        test_ctx,
    )
    collected = collector.on_tick(c_state, test_ctx)

    normalizer = Normalizer()
    n_state = normalizer.init_state()
    norm_msgs = normalizer.process(collected[0], n_state, test_ctx)

    ev: Event = norm_msgs[0].payload
    assert ev.uncatalogued is True
    assert ev.event_class == EventClass.api_activity


def test_identity_resolution_chain_okta_saml_new_key(test_ctx: AgentContext) -> None:
    with (FIXTURES_DIR / "okta_sample.json").open("r", encoding="utf-8") as f:
        okta_records = json.load(f)
    with (FIXTURES_DIR / "cloudtrail_sample.json").open("r", encoding="utf-8") as f:
        ct_records = json.load(f)["Records"]

    collector = Collector()
    c_state = collector.init_state()
    normalizer = Normalizer()
    n_state = normalizer.init_state()

    def process_record(rec: dict, source_topic: str) -> Event:
        src = Source.okta if "okta" in source_topic else Source.cloudtrail
        collector.process(
            test_ctx.new_message(topic=source_topic, payload=RawLog(source=src, records=[rec])),
            c_state,
            test_ctx,
        )
        col = collector.on_tick(c_state, test_ctx)[0]
        norm = normalizer.process(col, n_state, test_ctx)[0]
        return norm.payload

    # Step 1: Okta session start for alice@example.com
    okta_alice = next(r for r in okta_records if r.get("uuid") == "okta-alice-0001")
    ev_okta = process_record(okta_alice, "raw.okta")
    assert ev_okta.identity_id == "alice@example.com"
    assert ev_okta.resolution_confidence == 1.0

    # Step 2: CloudTrail AssumeRoleWithSAML with roleSessionName="alice@example.com"
    ct_saml = next(r for r in ct_records if r.get("eventName") == "AssumeRoleWithSAML")
    ev_saml = process_record(ct_saml, "raw.cloudtrail")
    assert ev_saml.identity_id == "alice@example.com"
    assert ev_saml.resolution_confidence == 0.9

    # Step 3: CloudTrail CreateAccessKey using temporary key ASIA_ALICE_TEMP_KEY
    ct_create_key = next(r for r in ct_records if r.get("eventName") == "CreateAccessKey")
    ev_create_key = process_record(ct_create_key, "raw.cloudtrail")
    assert ev_create_key.identity_id == "alice@example.com"

    # Step 4: Calls with the new key AKIA_ALICE_NEW_KEY (DescribeInstances)
    ct_describe = next(r for r in ct_records if r.get("eventName") == "DescribeInstances")
    ev_describe = process_record(ct_describe, "raw.cloudtrail")
    assert ev_describe.identity_id == "alice@example.com"
    assert ev_describe.resolution_confidence == 0.8  # Key lineage

    # Step 5: Calls with the new key (GetSecretValue)
    ct_secret = next(r for r in ct_records if r.get("eventName") == "GetSecretValue")
    ev_secret = process_record(ct_secret, "raw.cloudtrail")
    assert ev_secret.identity_id == "alice@example.com"
    assert ev_secret.resolution_confidence == 0.8

    # Step 6: Unresolved principal with unknown user
    unknown_rec = {
        "eventID": "ct-unknown-1",
        "eventTime": "2026-10-30T10:15:00Z",
        "eventName": "DescribeRegions",
        "sourceIPAddress": "192.0.2.1",
        "userIdentity": {"type": "IAMUser", "userName": "stranger_without_lineage"},
    }
    ev_unresolved = process_record(unknown_rec, "raw.cloudtrail")
    assert ev_unresolved.identity_id == "stranger_without_lineage"
    assert ev_unresolved.resolution_confidence == 0.5


def test_pure_helpers() -> None:
    okta_raw = {
        "uuid": "okta-pure-1",
        "published": "2026-10-30T10:00:00Z",
        "eventType": "user.session.start",
        "actor": {"alternateId": "pure@example.com"},
        "client": {"ipAddress": "1.1.1.1"},
    }
    parsed_ok = parse_okta(okta_raw)
    assert parsed_ok["event_id"] == "okta-pure-1"
    assert parsed_ok["raw_principal"] == "pure@example.com"

    ct_raw = {
        "eventID": "ct-pure-1",
        "eventTime": "2026-10-30T10:00:00Z",
        "eventName": "GetUser",
        "sourceIPAddress": "2.2.2.2",
        "userIdentity": {"userName": "pure_ct"},
    }
    parsed_ct = parse_cloudtrail(ct_raw)
    assert parsed_ct["event_id"] == "ct-pure-1"
    assert parsed_ct["raw_principal"] == "pure_ct"

    fields = parse_okta_fields(okta_raw)
    state = {"aliases": {}, "key_lineage": {}, "identities": {}, "pending_db_identities": [], "pending_db_aliases": []}
    ident, conf = resolve_identity(fields, state)
    assert ident == "pure@example.com"
    assert conf == 1.0


def test_register_all_supervisor_and_bus() -> None:
    sup = Supervisor()
    bus = Bus(supervisor=sup)
    registered = register_all(sup, bus)

    # Agents 1 and 2 should be registered
    nums = [ag.num for ag in registered]
    assert 1 in nums
    assert 2 in nums

    h1 = sup.get_health("a01")
    assert h1 is not None
    assert h1["status"] == "idle"

    h2 = sup.get_health("a02")
    assert h2 is not None
    assert h2["status"] == "idle"


def test_normalizer_db_persistence(test_ctx: AgentContext) -> None:
    normalizer = Normalizer()
    n_state = normalizer.init_state()

    raw_event = {
        "uuid": "okta-persist-1",
        "published": "2026-10-30T10:00:00Z",
        "eventType": "user.session.start",
        "actor": {"alternateId": "persisted.user@corp.example", "id": "00upersist"},
        "client": {"ipAddress": "10.0.0.1"},
    }

    event = Event(
        event_id="okta-persist-1",
        time="2026-10-30T10:00:00Z",
        source=Source.okta,
        event_class=EventClass.authentication,
        action="user.session.start",
        identity_id="",
        raw_principal="",
        session_id=None,
        src_ip="10.0.0.1",
        user_agent="browser",
        outcome="success",
        resource_arn=None,
        read_only=True,
        region=None,
        late=False,
        uncatalogued=False,
        resolution_confidence=0.0,
        raw_ref=None,
        attrs={"_raw": raw_event},
    )

    msg = test_ctx.new_message(topic="events", payload=event)
    normalizer.process(msg, n_state, test_ctx)
    normalizer.on_tick(n_state, test_ctx)

    db_path = getattr(test_ctx.store, "db_path", None)
    conn = store.get_connection(db_path)
    cur = conn.execute("SELECT identity_id, primary_user FROM identities_v3 WHERE identity_id=?", ("persisted.user@corp.example",))
    row = cur.fetchone()
    assert row is not None
    assert row["primary_user"] == "persisted.user@corp.example"
