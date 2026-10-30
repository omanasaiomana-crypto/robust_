"""Unit tests for Agent 5 (Access Anomaly) and Agent 6 (Session & Token Integrity).

Verifies requirements from P06:
- D-ACC-01..04 positive and negative cases
- D-SES-01..04 positive and negative cases
- Edge thresholds: 4 denies + accept = no signal; 5 denies + accept = signal
- Trusted IP suppression (D-ACC-02 and D-ACC-04 never produced)
- Cold-start confidence scaling (* 0.6)
- UA-only change strength capped at 0.2
- Evidence event IDs exist in input
- Supervisor and Bus registration for Agents 1 through 6
"""
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.v3 import store
from app.v3.agents import register_all
from app.v3.agents.a05_access import (
    AccessAnomaly,
    detect_access_anomalies,
    haversine_km,
)
from app.v3.agents.a06_session import (
    SessionTokenIntegrity,
    detect_session_anomalies,
    parse_ua_family,
)
from app.v3.agents.base import AgentContext
from app.v3.bus import Bus
from app.v3.config import get_settings
from app.v3.models import (
    ActionType,
    Context,
    EnrichedEvent,
    Event,
    EventClass,
    Session,
    Signal,
    Source,
)
from app.v3.supervisor import Supervisor


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
    db_file = tmp_path / "test_agents_5_6.db"
    store.create_tables(db_file)
    settings = get_settings()
    clock = FixedClock(datetime(2026, 10, 30, 12, 0, 0, tzinfo=UTC))
    return AgentContext(clock=clock, settings=settings, store=type("StoreRef", (), {"db_path": db_file})())


def make_enriched_event(
    event_id: str,
    identity_id: str = "alice",
    session_id: str | None = "sess-1",
    action: str = "user.session.start",
    event_class: EventClass = EventClass.authentication,
    outcome: str = "success",
    src_ip: str = "198.51.100.10",
    user_agent: str = "Mozilla/5.0 Chrome/124.0",
    lat: float | None = 37.7749,
    lon: float | None = -122.4194,
    asn: int | None = 15169,
    is_tor: bool = False,
    is_hosting: bool = False,
    is_proxy: bool = False,
    trusted_ip: bool = False,
    privilege_level: int = 1,
    time_str: str = "2026-10-30T10:00:00Z",
) -> EnrichedEvent:
    ev = Event(
        event_id=event_id,
        time=time_str,
        source=Source.okta,
        event_class=event_class,
        action=action,
        identity_id=identity_id,
        raw_principal=identity_id,
        session_id=session_id,
        src_ip=src_ip,
        user_agent=user_agent,
        outcome=outcome,
        resource_arn=None,
        read_only=True,
        region=None,
        late=False,
        uncatalogued=False,
        resolution_confidence=1.0,
        raw_ref=None,
        attrs={},
    )
    ctx = Context(
        country="United States",
        city="San Francisco",
        lat=lat,
        lon=lon,
        asn=asn,
        is_proxy=is_proxy,
        is_tor=is_tor,
        is_hosting=is_hosting,
        trusted_ip=trusted_ip,
        privilege_level=privilege_level,
        resource_sensitivity=1,
        action_type=ActionType.read,
        context_complete=True,
    )
    return EnrichedEvent(event=ev, context=ctx)


# ---------------------------------------------------------------------------
# Agent 5: Access Anomaly Tests (D-ACC-01..04)
# ---------------------------------------------------------------------------


def test_d_acc_01_impossible_travel_positive() -> None:
    # SF (37.77, -122.41) to Tokyo (35.67, 139.65) in 30 minutes (~8,200 km)
    dist = haversine_km(37.7749, -122.4194, 35.6762, 139.6503)
    assert dist > 8000.0

    history = [
        {
            "event_id": "ev-sf",
            "lat": 37.7749,
            "lon": -122.4194,
            "timestamp": 1000.0,
            "asn": 15169,
            "device": "Chrome",
            "src_ip": "1.1.1.1",
        }
    ]
    event_dict = {
        "event_id": "ev-tokyo",
        "identity_id": "alice",
        "timestamp": 2800.0,  # 1800s later (0.5 hours)
        "src_ip": "2.2.2.2",
        "user_agent": "Chrome",
    }
    context_dict = {
        "lat": 35.6762,
        "lon": 139.6503,
        "asn": 15169,
    }

    signals = detect_access_anomalies(event_dict, context_dict, history)
    d_acc_01 = [s for s in signals if s["detection_id"] == "D-ACC-01"]
    assert len(d_acc_01) == 1
    assert d_acc_01[0]["strength"] == 1.0  # capped at 1.0
    assert d_acc_01[0]["evidence_event_ids"] == ["ev-sf", "ev-tokyo"]


def test_d_acc_01_impossible_travel_negative() -> None:
    # Short distance (< 500 km)
    history = [
        {
            "event_id": "ev-sf",
            "lat": 37.7749,
            "lon": -122.4194,
            "timestamp": 1000.0,
            "asn": 15169,
            "device": "Chrome",
        }
    ]
    # Oakland (15 km away) 5 minutes later
    event_short = {
        "event_id": "ev-oak",
        "identity_id": "alice",
        "timestamp": 1300.0,
        "src_ip": "1.1.1.2",
    }
    context_short = {"lat": 37.8044, "lon": -122.2712, "asn": 15169}
    signals = detect_access_anomalies(event_short, context_short, history)
    assert not any(s["detection_id"] == "D-ACC-01" for s in signals)

    # Long distance (> 500 km) but plausible speed (< 900 km/h)
    # NY is ~4100 km away, 10 hours later = 410 km/h
    event_ny = {
        "event_id": "ev-ny",
        "identity_id": "alice",
        "timestamp": 1000.0 + 36000.0,
        "src_ip": "3.3.3.3",
    }
    context_ny = {"lat": 40.7128, "lon": -74.0060, "asn": 15169}
    signals_ny = detect_access_anomalies(event_ny, context_ny, history)
    assert not any(s["detection_id"] == "D-ACC-01" for s in signals_ny)


def test_d_acc_02_new_device_or_asn() -> None:
    history = [
        {"event_id": f"ev-{i}", "asn": 15169, "device": "Chrome"} for i in range(10)
    ]

    # Both new device and new ASN -> strength 0.5
    event_both = {"event_id": "ev-new-both", "identity_id": "alice", "user_agent": "Firefox/120.0"}
    context_both = {"asn": 8075}
    sigs_both = detect_access_anomalies(event_both, context_both, history)
    d02_both = [s for s in sigs_both if s["detection_id"] == "D-ACC-02"]
    assert len(d02_both) == 1
    assert d02_both[0]["strength"] == 0.5

    # New ASN only -> strength 0.4
    event_asn = {"event_id": "ev-new-asn", "identity_id": "alice", "user_agent": "Chrome"}
    context_asn = {"asn": 8075}
    sigs_asn = detect_access_anomalies(event_asn, context_asn, history)
    d02_asn = [s for s in sigs_asn if s["detection_id"] == "D-ACC-02"]
    assert len(d02_asn) == 1
    assert d02_asn[0]["strength"] == 0.4


def test_trusted_ip_suppression() -> None:
    # On trusted IP, neither D-ACC-02 nor D-ACC-04 may fire
    history = [{"event_id": "ev-0", "asn": 15169, "device": "Chrome"}]
    event_dict = {"event_id": "ev-trusted", "identity_id": "alice", "user_agent": "curl/7.88"}
    context_dict = {
        "asn": 99999,
        "is_tor": True,
        "is_hosting": True,
        "trusted_ip": True,  # Trusted!
        "privilege_level": 5,
    }
    signals = detect_access_anomalies(event_dict, context_dict, history)
    assert not any(s["detection_id"] in ("D-ACC-02", "D-ACC-04") for s in signals)


def test_d_acc_03_unusual_hour() -> None:
    # 10 logins during business hours (9:00 - 17:00)
    history = [{"event_id": f"ev-{i}", "hour": 10 + (i % 5)} for i in range(10)]

    # Login at 3am (hour=3)
    event_night = {"event_id": "ev-night", "identity_id": "alice", "time": "2026-10-30T03:00:00Z"}
    context_dict = {}
    sigs = detect_access_anomalies(event_night, context_dict, history)
    d03 = [s for s in sigs if s["detection_id"] == "D-ACC-03"]
    assert len(d03) == 1
    assert d03[0]["strength"] >= 0.25

    # Login at 12pm (normal)
    event_day = {"event_id": "ev-day", "identity_id": "alice", "time": "2026-10-30T12:00:00Z"}
    sigs_day = detect_access_anomalies(event_day, context_dict, history)
    assert not any(s["detection_id"] == "D-ACC-03" for s in sigs_day)


def test_d_acc_04_anonymizing_network() -> None:
    event_dict = {"event_id": "ev-tor", "identity_id": "alice"}
    # Privileged identity (privilege_level=4) on Tor
    ctx_tor = {"is_tor": True, "privilege_level": 4, "trusted_ip": False}
    sigs_tor = detect_access_anomalies(event_dict, ctx_tor, [])
    d04 = [s for s in sigs_tor if s["detection_id"] == "D-ACC-04"]
    assert len(d04) == 1
    assert d04[0]["strength"] == 0.5

    # Low privilege identity (privilege_level=2) on Tor -> no signal
    ctx_low = {"is_tor": True, "privilege_level": 2, "trusted_ip": False}
    sigs_low = detect_access_anomalies(event_dict, ctx_low, [])
    assert not any(s["detection_id"] == "D-ACC-04" for s in sigs_low)


def test_cold_start_confidence() -> None:
    # History < 5 logins
    cold_history = [{"event_id": "ev-1", "asn": 15169, "device": "Chrome"}]
    event_dict = {"event_id": "ev-cold", "identity_id": "alice", "user_agent": "NewDevice"}
    context_dict = {"asn": 8888}
    sigs = detect_access_anomalies(event_dict, context_dict, cold_history)
    d02 = next(s for s in sigs if s["detection_id"] == "D-ACC-02")
    # Cold start: confidence * 0.6 = 0.9 * 0.6 = 0.54
    assert d02["confidence"] <= 0.6


# ---------------------------------------------------------------------------
# Agent 6: Session & Token Integrity Tests (D-SES-01..04)
# ---------------------------------------------------------------------------


def test_d_ses_01_token_replay() -> None:
    fp = {
        "first_event_id": "ev-first",
        "ip": "198.51.100.10",
        "asn": 15169,
        "device": "Chrome",
        "ua_family": "Chrome",
    }
    # Event on new ASN 8075 without re-auth -> strength 0.8
    ev_asn = {
        "event_id": "ev-replay-asn",
        "identity_id": "alice",
        "session_id": "sess-1",
        "action": "GetObject",
        "src_ip": "203.0.113.5",
    }
    ctx_asn = {"asn": 8075}
    sigs_asn = detect_session_anomalies(ev_asn, ctx_asn, fp, [])
    d01_asn = [s for s in sigs_asn if s["detection_id"] == "D-SES-01"]
    assert len(d01_asn) == 1
    assert d01_asn[0]["strength"] == 0.8
    assert d01_asn[0]["evidence_event_ids"] == ["ev-first", "ev-replay-asn"]

    # Event on new IP within same ASN 15169 -> strength 0.3
    ev_ip = {
        "event_id": "ev-replay-ip",
        "identity_id": "alice",
        "session_id": "sess-1",
        "action": "GetObject",
        "src_ip": "198.51.100.88",
    }
    ctx_ip = {"asn": 15169}
    sigs_ip = detect_session_anomalies(ev_ip, ctx_ip, fp, [])
    d01_ip = [s for s in sigs_ip if s["detection_id"] == "D-SES-01"]
    assert len(d01_ip) == 1
    assert d01_ip[0]["strength"] == 0.3


def test_d_ses_02_mfa_fatigue_edge_thresholds() -> None:
    # 4 denies + 1 accept: NO signal
    mfa_history_4 = [
        {"event_id": f"deny-{i}", "timestamp": 100.0 + i * 10, "outcome": "deny"}
        for i in range(4)
    ]
    ev_accept = {
        "event_id": "accept-ev",
        "identity_id": "bob",
        "action": "user.mfa.okta_verify.deny_push",
        "outcome": "success",
        "timestamp": 200.0,
    }
    sigs_4 = detect_session_anomalies(ev_accept, {}, None, mfa_history_4, mfa_fatigue_denies=5)
    assert not any(s["detection_id"] == "D-SES-02" for s in sigs_4)

    # 5 denies + 1 accept: SIGNAL with strength 0.85
    mfa_history_5 = [
        {"event_id": f"deny-{i}", "timestamp": 100.0 + i * 10, "outcome": "deny"}
        for i in range(5)
    ]
    sigs_5 = detect_session_anomalies(ev_accept, {}, None, mfa_history_5, mfa_fatigue_denies=5)
    d02 = [s for s in sigs_5 if s["detection_id"] == "D-SES-02"]
    assert len(d02) == 1
    assert d02[0]["strength"] == 0.85
    # Evidence must contain all 5 denies + the accept event = 6 event IDs
    assert len(d02[0]["evidence_event_ids"]) == 6
    assert d02[0]["evidence_event_ids"] == ["deny-0", "deny-1", "deny-2", "deny-3", "deny-4", "accept-ev"]


def test_d_ses_03_fingerprint_drift_ua_cap() -> None:
    fp = {
        "first_event_id": "ev-0",
        "ip": "1.1.1.1",
        "asn": 15169,
        "device": "Mozilla/5.0 Chrome/124.0",
        "ua_family": "Chrome",
    }
    # Mid-session action with curl
    ev_curl = {
        "event_id": "ev-curl",
        "identity_id": "alice",
        "session_id": "sess-1",
        "action": "GetObject",
        "src_ip": "1.1.1.1",
        "user_agent": "curl/7.68.0",
    }
    sigs = detect_session_anomalies(ev_curl, {"asn": 15169}, fp, [])
    d03 = [s for s in sigs if s["detection_id"] == "D-SES-03"]
    assert len(d03) == 1
    # UA is weak evidence alone -> capped at 0.2
    assert d03[0]["strength"] <= 0.2


def test_d_ses_04_privileged_session_without_mfa() -> None:
    fp = {
        "first_event_id": "ev-0",
        "ip": "1.1.1.1",
        "asn": 15169,
        "has_mfa": False,  # No MFA!
    }
    ev_priv = {
        "event_id": "ev-priv",
        "identity_id": "alice",
        "session_id": "sess-1",
        "action": "AttachRolePolicy",
    }
    ctx_priv = {"asn": 15169, "privilege_level": 5}
    sigs = detect_session_anomalies(ev_priv, ctx_priv, fp, [])
    d04 = [s for s in sigs if s["detection_id"] == "D-SES-04"]
    assert len(d04) == 1
    assert d04[0]["strength"] == 0.5


def test_parse_ua_family() -> None:
    assert parse_ua_family("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edg/120.0.0.0") == "Edge"
    assert parse_ua_family("Mozilla/5.0 Chrome/124.0.0.0") == "Chrome"
    assert parse_ua_family("Mozilla/5.0 Firefox/125.0") == "Firefox"
    assert parse_ua_family("Mozilla/5.0 Version/17.4 Safari/605.1.15") == "Safari"
    assert parse_ua_family("curl/7.88.1") == "curl"
    assert parse_ua_family("Boto3/1.28.0 Python/3.11.0") == "python/boto3"
    assert parse_ua_family("aws-cli/2.15.0") == "aws-cli"
    assert parse_ua_family("SomethingCustom/1.0") == "other"
    assert parse_ua_family("") == "unknown"


def test_agent_integration_access_and_session(test_ctx: AgentContext) -> None:
    access_agent = AccessAnomaly()
    a_state = access_agent.init_state()
    session_agent = SessionTokenIntegrity()
    s_state = session_agent.init_state()

    # Step 1: Initialize session fingerprint
    sess_msg = test_ctx.new_message(
        topic="sessions",
        payload=Session(
            session_id="sess-integration",
            identity_id="alice",
            start="2026-10-30T10:00:00Z",
            event_ids=["ev-0"],
            ips=["198.51.100.10"],
            asns=[15169],
            devices=["Mozilla/5.0 Chrome/124.0"],
            providers=["okta"],
        ),
    )
    session_agent.process(sess_msg, s_state, test_ctx)

    # Step 2: Send second event from new ASN
    enr_event = make_enriched_event(
        event_id="ev-replay",
        identity_id="alice",
        session_id="sess-integration",
        action="GetObject",
        event_class=EventClass.data_access,
        outcome="success",
        src_ip="203.0.113.88",
        asn=8075,
        lat=40.71,
        lon=-74.00,
    )
    enr_msg = test_ctx.new_message(topic="events.enriched", payload=enr_event)

    signals_access = access_agent.process(enr_msg, a_state, test_ctx)
    assert isinstance(signals_access, list)

    signals_session = session_agent.process(enr_msg, s_state, test_ctx)
    sig_payloads = [m.payload for m in signals_session if isinstance(m.payload, Signal)]
    assert any(s.detection_id == "D-SES-01" for s in sig_payloads)


def test_supervisor_and_bus_registers_agents_1_to_6() -> None:
    sup = Supervisor()
    bus = Bus(supervisor=sup)
    registered = register_all(sup, bus)

    nums = [ag.num for ag in registered]
    assert 1 in nums
    assert 2 in nums
    assert 3 in nums
    assert 4 in nums
    assert 5 in nums
    assert 6 in nums
