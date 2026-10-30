"""Tests for Agent 10 (Behavioral ML) and Agent 11 (Campaign).

Covers:
- Feature vector shape and names (11 features per PRD §12 Agent 10)
- Deterministic training with fixed seed (identical scores twice)
- No-model skip with trace message and no signals
- Markov rarity higher for escalation sequence than routine sequence
- IsolationForest and Markov percentile scoring
- Password spray threshold (9 users no signal, 10 users triggers D-CMP-01)
- Spray followed by success triggers D-CMP-02 (Credential Stuffing Success)
- Shared attack infrastructure triggers D-CMP-03
- Shared campaign_id across all affected identities
- Supervisor and Bus registration for Agents 1 through 11
"""
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.v3 import store
from app.v3.agents import register_all
from app.v3.agents.a10_ml import (
    FEATURE_NAMES,
    BehavioralML,
    build_markov_matrix,
    compute_sequence_nll,
    extract_session_features,
    score_session_with_bundle,
    train_ml_models,
)
from app.v3.agents.a11_campaign import (
    Campaign,
    detect_campaign_anomalies,
    hash_ua,
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
    Stage,
)
from app.v3.supervisor import Supervisor


class FixedClock:
    def __init__(self, dt: datetime) -> None:
        self.dt = dt

    def __call__(self) -> datetime:
        return self.dt

    def now(self) -> datetime:
        return self.dt


def make_test_context(tmp_path: Path) -> AgentContext:
    db_file = tmp_path / "test_ml_campaign.db"
    store.create_tables(db_file)
    clock = FixedClock(datetime(2026, 10, 30, 12, 0, 0, tzinfo=UTC))
    settings = get_settings()
    return AgentContext(
        run_id="run-test-10-11",
        clock=clock,
        store=type("StoreRef", (), {"db_path": db_file})(),
        settings=settings,
    )


def make_enriched_event(
    event_id: str,
    identity_id: str,
    action: str,
    event_class: EventClass = EventClass.authentication,
    outcome: str = "failure",
    src_ip: str = "198.51.100.22",
    asn: int = 15169,
    action_type: ActionType = ActionType.read,
    user_agent: str = "Mozilla/5.0 Chrome/124.0",
    ts: float = 1000.0,
) -> EnrichedEvent:
    ev = Event(
        event_id=event_id,
        time=datetime.fromtimestamp(ts, tz=UTC).isoformat(),
        source=Source.okta,
        event_class=event_class,
        action=action,
        identity_id=identity_id,
        raw_principal=identity_id,
        session_id=None,
        src_ip=src_ip,
        user_agent=user_agent,
        outcome=outcome,
        read_only=True,
        resolution_confidence=1.0,
        attrs={},
    )
    cx = Context(
        country="US",
        city="San Francisco",
        lat=37.77,
        lon=-122.41,
        asn=asn,
        as_org="Google LLC",
        action_type=action_type,
    )
    return EnrichedEvent(event=ev, context=cx)


# ---------------------------------------------------------------------------
# Agent 10: Behavioral ML Tests
# ---------------------------------------------------------------------------


def test_feature_vector_shape() -> None:
    session_dict = {
        "session_id": "sess-test-feat",
        "identity_id": "alice",
        "start": "2026-10-30T10:00:00Z",
        "end": "2026-10-30T10:30:00Z",
        "event_ids": ["ev-1", "ev-2", "ev-3"],
        "asns": [15169],
    }
    events = [
        {"action": "s3:GetObject", "action_type": "read", "outcome": "success", "resource_sensitivity": 1},
        {"action": "s3:PutObject", "action_type": "write", "outcome": "success", "resource_sensitivity": 2},
        {"action": "iam:AttachUserPolicy", "action_type": "permission_change", "outcome": "deny", "resource_sensitivity": 4},
    ]
    baseline = {"known_apis": ["s3:GetObject", "s3:PutObject"], "mean_hour": 10.0, "known_asns": [15169]}

    feat = extract_session_features(session_dict, events, baseline)
    assert len(feat) == 11
    assert len(feat) == len(FEATURE_NAMES)
    # Check features are numeric floats
    for f in feat:
        assert isinstance(f, float)
    # Check duration is 1800.0 s
    assert feat[0] == 1800.0
    # Check event count is 3.0
    assert feat[1] == 3.0


def test_deterministic_training_with_seed() -> None:
    # Build 40 synthetic benign sessions for training
    synthetic_sessions: list[dict[str, Any]] = []
    synthetic_events: dict[str, list[dict[str, Any]]] = {}

    for i in range(40):
        s_id = f"sess-train-{i}"
        synthetic_sessions.append({
            "session_id": s_id,
            "identity_id": f"user-{i % 5}",
            "start": "2026-10-30T09:00:00Z",
            "end": "2026-10-30T09:15:00Z",
            "event_ids": [f"ev-{i}-1", f"ev-{i}-2"],
            "asns": [15169],
        })
        synthetic_events[s_id] = [
            {"action": "s3:GetObject", "action_type": "read", "outcome": "success", "resource_sensitivity": 1},
            {"action": "s3:PutObject", "action_type": "write", "outcome": "success", "resource_sensitivity": 1},
        ]

    bundle1 = train_ml_models(synthetic_sessions, synthetic_events, seed=42)
    bundle2 = train_ml_models(synthetic_sessions, synthetic_events, seed=42)

    # Test scoring reproducibility on a test session
    test_sess = {
        "session_id": "sess-eval",
        "identity_id": "eval-user",
        "start": "2026-10-30T09:00:00Z",
        "end": "2026-10-30T09:20:00Z",
        "event_ids": ["ev-e1", "ev-e2"],
        "asns": [15169],
    }
    test_evs = [
        {"action": "s3:GetObject", "action_type": "read", "outcome": "success"},
        {"action": "s3:PutObject", "action_type": "write", "outcome": "success"},
    ]

    forest1 = bundle1["peer_groups"]["global"]["isolation_forest"]
    forest2 = bundle2["peer_groups"]["global"]["isolation_forest"]

    feat = extract_session_features(test_sess, test_evs)
    score1 = forest1.score_samples([feat])[0]
    score2 = forest2.score_samples([feat])[0]

    assert score1 == score2


def test_no_model_skip(tmp_path: Path) -> None:
    nonexistent = tmp_path / "models_missing.joblib"
    agent = BehavioralML(model_path=nonexistent)
    assert agent.models is None

    traces: list[dict[str, Any]] = []

    def trace_fn(st: str, msg: str, data: Any) -> None:
        traces.append({"state": st, "message": msg, "data": data})

    clock = FixedClock(datetime(2026, 10, 30, 12, 0, 0, tzinfo=UTC))
    ctx = AgentContext(clock=clock, trace_fn=trace_fn)
    state = agent.init_state()

    sess_msg = ctx.new_message(
        topic="sessions",
        payload=Session(
            session_id="sess-unscored",
            identity_id="bob",
            start="2026-10-30T10:00:00Z",
        ),
    )

    result = agent.process(sess_msg, state, ctx)
    assert result == []
    assert len(traces) == 1
    assert "model not trained" in traces[0]["message"]


def test_markov_rarity_escalation_vs_routine() -> None:
    # Routine corpus: mostly read -> read, read -> write, write -> read
    routine_sequences = [
        ["read", "read", "read"],
        ["read", "write", "read"],
        ["read", "read", "write"],
        ["write", "read", "read"],
    ] * 20

    markov = build_markov_matrix(routine_sequences)

    routine_seq = ["read", "read", "write"]
    escalation_seq = ["read", "permission_change", "credential_change", "destructive"]

    nll_routine = compute_sequence_nll(routine_seq, markov)
    nll_escalation = compute_sequence_nll(escalation_seq, markov)

    assert nll_escalation > nll_routine
    assert nll_routine < 2.0


def test_d_ml_scoring_anomalous_session() -> None:
    # 50 benign sessions
    sessions = []
    events_map = {}
    for i in range(50):
        s_id = f"s-{i}"
        sessions.append({
            "session_id": s_id,
            "identity_id": "standard-user",
            "start": "2026-10-30T10:00:00Z",
            "end": "2026-10-30T10:10:00Z",
            "event_ids": [f"e-{i}-1", f"e-{i}-2"],
            "asns": [15169],
        })
        events_map[s_id] = [
            {"action": "s3:GetObject", "action_type": "read", "outcome": "success"},
            {"action": "s3:PutObject", "action_type": "write", "outcome": "success"},
        ]

    bundle = train_ml_models(sessions, events_map, seed=42)

    # Extreme anomalous session: 500 events, 20 distinct services, 8 hours long, all errors/sensitive
    anom_sess = {
        "session_id": "s-anom",
        "identity_id": "standard-user",
        "start": "2026-10-30T02:00:00Z",
        "end": "2026-10-30T10:00:00Z",
        "event_ids": [f"ev-{x}" for x in range(100)],
        "asns": [99999],
    }
    anom_events = [
        {"action": "iam:AttachUserPolicy", "action_type": "permission_change", "outcome": "deny", "resource_sensitivity": 5},
        {"action": "kms:ScheduleKeyDeletion", "action_type": "destructive", "outcome": "error", "resource_sensitivity": 5},
    ] * 50

    sigs = score_session_with_bundle(anom_sess, anom_events, bundle)
    assert len(sigs) >= 1
    # Check at least one ML detection was emitted
    d_ids = [s["detection_id"] for s in sigs]
    assert "D-ML-01" in d_ids or "D-ML-02" in d_ids
    for s in sigs:
        assert 0.3 <= s["strength"] <= 0.8
        assert s["confidence"] == 0.8  # >= 30 sessions in peer group


# ---------------------------------------------------------------------------
# Agent 11: Campaign Tests
# ---------------------------------------------------------------------------


def test_hash_ua() -> None:
    assert hash_ua("Mozilla/5.0") != "empty"
    assert hash_ua("") == "empty"
    assert len(hash_ua("Mozilla/5.0 Chrome/124.0")) == 12


def test_password_spray_threshold_10_vs_9() -> None:
    state: dict = {}
    src_ip = "198.51.100.55"
    base_ts = 1000.0

    # 9 distinct users fail authentication -> NO spray signal
    for i in range(9):
        ev = {
            "event_id": f"ev-fail-{i}",
            "identity_id": f"user-{i}",
            "action": "user.session.start",
            "event_class": EventClass.authentication,
            "outcome": "failure",
            "src_ip": src_ip,
            "timestamp": base_ts + i * 5,
        }
        sigs = detect_campaign_anomalies(ev, {"asn": 15169}, state, spray_min_users=10)
        assert not any(s["detection_id"] == "D-CMP-01" for s in sigs)

    # 10th distinct user fails authentication -> TRIGGERS D-CMP-01
    ev10 = {
        "event_id": "ev-fail-9",
        "identity_id": "user-9",
        "action": "user.session.start",
        "event_class": EventClass.authentication,
        "outcome": "failure",
        "src_ip": src_ip,
        "timestamp": base_ts + 45,
    }
    sigs10 = detect_campaign_anomalies(ev10, {"asn": 15169}, state, spray_min_users=10)
    cmp01_sigs = [s for s in sigs10 if s["detection_id"] == "D-CMP-01"]
    # One signal per affected identity
    assert len(cmp01_sigs) == 10
    target_users = {s["identity_id"] for s in cmp01_sigs}
    assert len(target_users) == 10

    # All signals share the exact same campaign_id
    campaign_ids = {s["details"]["campaign_id"] for s in cmp01_sigs}
    assert len(campaign_ids) == 1
    assert f"cmp-spray-ip-{src_ip}" in next(iter(campaign_ids))


def test_spray_then_success_triggers_d_cmp_02() -> None:
    state: dict = {}
    src_ip = "198.51.100.88"
    base_ts = 2000.0

    # Trigger spray across 10 users
    for i in range(10):
        ev = {
            "event_id": f"ev-sp-{i}",
            "identity_id": f"victim-{i}",
            "action": "user.session.start",
            "event_class": EventClass.authentication,
            "outcome": "failure",
            "src_ip": src_ip,
            "timestamp": base_ts + i * 5,
        }
        detect_campaign_anomalies(ev, {"asn": 15169}, state, spray_min_users=10)

    # User 9 now succeeds from the same spray source
    ev_success = {
        "event_id": "ev-stuffed",
        "identity_id": "victim-9",
        "action": "user.session.start",
        "event_class": EventClass.authentication,
        "outcome": "success",
        "src_ip": src_ip,
        "timestamp": base_ts + 120.0,
    }
    sigs = detect_campaign_anomalies(ev_success, {"asn": 15169}, state, spray_min_users=10)
    d02 = [s for s in sigs if s["detection_id"] == "D-CMP-02"]
    assert len(d02) == 1
    assert d02[0]["strength"] == 0.85
    assert d02[0]["identity_id"] == "victim-9"
    assert f"cmp-spray-ip-{src_ip}" in d02[0]["details"]["campaign_id"]


def test_d_cmp_03_shared_infrastructure() -> None:
    state: dict = {
        "identities_with_signals": {
            "compromised-1": 1000.0,
            "compromised-2": 1050.0,
            "compromised-3": 1100.0,
        }
    }
    shared_ip = "203.0.113.99"
    base_ts = 2000.0

    # Events from compromised-1, compromised-2, then compromised-3 on same IP
    ev1 = {"event_id": "e1", "identity_id": "compromised-1", "src_ip": shared_ip, "timestamp": base_ts}
    sigs1 = detect_campaign_anomalies(ev1, {}, state, shared_infra_min_identities=3)
    assert not any(s["detection_id"] == "D-CMP-03" for s in sigs1)

    ev2 = {"event_id": "e2", "identity_id": "compromised-2", "src_ip": shared_ip, "timestamp": base_ts + 10}
    sigs2 = detect_campaign_anomalies(ev2, {}, state, shared_infra_min_identities=3)
    assert not any(s["detection_id"] == "D-CMP-03" for s in sigs2)

    ev3 = {"event_id": "e3", "identity_id": "compromised-3", "src_ip": shared_ip, "timestamp": base_ts + 20}
    sigs3 = detect_campaign_anomalies(ev3, {}, state, shared_infra_min_identities=3)
    d03 = [s for s in sigs3 if s["detection_id"] == "D-CMP-03"]
    assert len(d03) == 3
    assert {s["identity_id"] for s in d03} == {"compromised-1", "compromised-2", "compromised-3"}
    campaign_ids = {s["details"]["campaign_id"] for s in d03}
    assert len(campaign_ids) == 1


# ---------------------------------------------------------------------------
# Integration and Supervisor Registration Tests (Agents 1 through 11)
# ---------------------------------------------------------------------------


def test_supervisor_and_bus_registers_agents_1_to_11() -> None:
    sup = Supervisor()
    bus = Bus(supervisor=sup)
    registered = register_all(sup, bus)

    nums = [ag.num for ag in registered]
    for n in range(1, 12):
        assert n in nums


def test_campaign_agent_signal_and_event_flow(tmp_path: Path) -> None:
    ctx = make_test_context(tmp_path)
    campaign_agent = Campaign()
    c_state = campaign_agent.init_state()

    # Step 1: Send a Signal message to campaign agent -> records identity_with_signals
    sig_msg = ctx.new_message(
        topic="signals",
        payload=Signal(
            signal_id="sig-sample",
            detection_id="D-ACC-01",
            agent_num=5,
            identity_id="alice",
            strength=0.8,
            confidence=0.9,
            evidence_event_ids=["ev-0"],
            mitre=["T1078.004"],
            stage=Stage.initial_access,
            summary="Impossible travel",
        ),
    )
    res1 = campaign_agent.process(sig_msg, c_state, ctx)
    assert res1 == []
    assert "alice" in c_state["identities_with_signals"]
