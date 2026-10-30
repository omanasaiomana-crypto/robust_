"""Unit and integration tests for Agent 14 (Response) and Agent 15 (Feedback).

Covers Phase P11 requirements:
- Band -> playbook mapping (PB-01, PB-02, PB-03)
- PB-04 defense evasion overrides band
- Friction budget exhaustion behavior (step_up -> monitor)
- Revoke pending -> approve -> applied; reject; expiry; rollback; restrict TTL expiry
- Simulator called exactly once per action (idempotency)
- Capability: Agent 13 attempting a simulator call is blocked
- Email sent once per case (deduplication)
- False positive lowers weight but respects floors (D-PE >= 0.6, D-DEF >= 0.6)
- Config rollback restores weights
"""
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, ClassVar

import pytest

from app.simulator.mock import MockSimulator
from app.v3.agents.a14_response import (
    ResponseAgent,
    SimulatorClient,
    execute_simulator_action,
    load_playbooks,
    match_playbook,
)
from app.v3.agents.a15_feedback import FeedbackAgent
from app.v3.agents.base import Agent, AgentContext
from app.v3.bus import Bus
from app.v3.models import (
    Action,
    ActionKind,
    ActionState,
    Band,
    Case,
    CaseReason,
    CaseStatus,
    CaseStep,
    Counterfactual,
    Label,
    Message,
    NextStep,
    Verdict,
)
from app.v3.store import create_tables, fetch_all, fetch_one, insert_many, set_db_path
from app.v3.supervisor import CapabilityError, Supervisor


class DummyAgent13(Agent):
    num = 13
    agent_id = "a13"
    name = "Investigation"
    layer = "decision"
    subscribes: ClassVar[list[str]] = ["risk"]
    publishes: ClassVar[list[str]] = ["cases", "deadletter"]

    def process(self, msg: Message, state: dict[str, Any], ctx: AgentContext) -> list[Message]:
        return []


def _make_sample_case(
    case_id: str = "case-001",
    identity_id: str = "alice",
    band: Band = Band.step_up,
    risk: float = 55.0,
    signal_ids: list[str] | None = None,
    reasons: list[str] | None = None,
    status: CaseStatus = CaseStatus.investigating,
) -> Case:
    sig_ids = signal_ids or ["sig-D-ACC-02-1"]
    rsns = [CaseReason(text=r, evidence_event_ids=["evt-1"]) for r in (reasons or ["Unusual activity"])]
    return Case(
        case_id=case_id,
        identity_id=identity_id,
        session_id=f"sess-{case_id}",
        session_risk=risk,
        identity_risk=risk,
        confidence=0.9,
        band=band,
        status=status,
        signal_ids=sig_ids,
        chain=[CaseStep(time="2026-10-28T12:00:00Z", event_id="evt-1", action="login", stage="initial_access", mitre=["T1078"])],
        reasons=rsns,
        counterfactuals=[Counterfactual(removed_factor="login", score_without=10.0, delta=45.0)],
        next_steps=[NextStep(action="AssumeRole", probability=0.5)],
        blast_radius=1,
        related_identities=[],
        narrative="Test case",
        narrative_source="template",
        created_at="2026-10-28T12:00:00Z",
        updated_at="2026-10-28T12:00:00Z",
    )


# ---------------------------------------------------------------------------
# 1. Band -> Playbook Mapping
# ---------------------------------------------------------------------------


def test_band_to_playbook_mapping() -> None:
    playbooks = load_playbooks()
    assert len(playbooks) >= 5

    # step_up band -> PB-01
    c_stepup = _make_case(band=Band.step_up)
    pb_stepup = match_playbook(c_stepup, playbooks)
    assert pb_stepup is not None
    assert pb_stepup["id"] == "PB-01"
    assert pb_stepup["action"] == "step_up"
    assert pb_stepup["approval_required"] is False

    # restrict band -> PB-02
    c_restrict = _make_case(band=Band.restrict, risk=75.0)
    pb_restrict = match_playbook(c_restrict, playbooks)
    assert pb_restrict is not None
    assert pb_restrict["id"] == "PB-02"
    assert pb_restrict["action"] == "restrict"
    assert pb_restrict["approval_required"] is False
    assert pb_restrict["ttl_minutes"] == 240

    # revoke band -> PB-03
    c_revoke = _make_case(band=Band.revoke, risk=95.0)
    pb_revoke = match_playbook(c_revoke, playbooks)
    assert pb_revoke is not None
    assert pb_revoke["id"] == "PB-03"
    assert pb_revoke["action"] == "revoke_sessions"
    assert pb_revoke["approval_required"] is True


def _make_case(
    band: Band = Band.step_up,
    risk: float = 50.0,
    signal_ids: list[str] | None = None,
    reasons: list[str] | None = None,
) -> Case:
    return _make_sample_case(
        case_id=f"c-{band.value}",
        identity_id="user1",
        band=band,
        risk=risk,
        signal_ids=signal_ids,
        reasons=reasons,
    )


# ---------------------------------------------------------------------------
# 2. PB-04 Defense Evasion Overrides Band
# ---------------------------------------------------------------------------


def test_pb04_overrides_band() -> None:
    playbooks = load_playbooks()

    # Case has low score (step_up band) but has D-DEF-01 signal
    case_def = _make_sample_case(
        case_id="case-def-1",
        identity_id="carol",
        band=Band.step_up,
        risk=45.0,
        signal_ids=["sig-D-DEF-01-abc"],
        reasons=["Defense evasion detected via CloudTrail StopLogging"],
    )

    matched = match_playbook(case_def, playbooks)
    assert matched is not None
    assert matched["id"] == "PB-04"
    assert matched["action"] == "restrict"
    assert matched["approval_required"] is False


# ---------------------------------------------------------------------------
# 3. Friction Budget Exhaustion
# ---------------------------------------------------------------------------


def test_friction_budget_exhaustion(tmp_db: Path, fixed_clock: Any) -> None:
    set_db_path(tmp_db)
    create_tables(tmp_db)

    mock_sim = MockSimulator()
    sim_client = SimulatorClient(simulator_instance=mock_sim)
    agent = ResponseAgent(simulator=sim_client)
    state = agent.init_state()
    ctx = AgentContext(clock=fixed_clock)

    case = _make_sample_case(case_id="case-fric-1", identity_id="user_fb", band=Band.step_up, risk=50.0)
    msg = ctx.new_message(topic="cases", payload=case)

    # 1st step_up: succeeds
    out1 = agent.process(msg, state, ctx)
    assert len(out1) == 1
    act1 = out1[0].payload
    assert isinstance(act1, Action)
    assert act1.action_kind == ActionKind.step_up
    assert act1.state == ActionState.applied

    # 2nd step_up: succeeds (budget limit is 2)
    out2 = agent.process(msg, state, ctx)
    assert len(out2) == 1
    act2 = out2[0].payload
    assert isinstance(act2, Action)
    assert act2.action_kind == ActionKind.step_up

    # 3rd step_up: budget exhausted -> downgraded to monitor
    out3 = agent.process(msg, state, ctx)
    assert len(out3) == 1
    act3 = out3[0].payload
    assert isinstance(act3, Action)
    assert act3.action_kind == ActionKind.monitor
    assert "friction budget exhausted, escalated to analyst" in act3.reason


# ---------------------------------------------------------------------------
# 4. Revoke Lifecycle: Pending -> Approve -> Applied; Reject; Expiry; Rollback
# ---------------------------------------------------------------------------


def test_revoke_lifecycle_pending_approve_applied(tmp_db: Path, fixed_clock: Any) -> None:
    set_db_path(tmp_db)
    create_tables(tmp_db)

    mock_sim = MockSimulator()
    sim_client = SimulatorClient(simulator_instance=mock_sim)
    agent = ResponseAgent(simulator=sim_client)
    state = agent.init_state()
    ctx = AgentContext(clock=fixed_clock)

    case = _make_sample_case(case_id="case-rev-1", identity_id="bob", band=Band.revoke, risk=95.0)
    # Seed case in database
    insert_many("cases_v3", [{
        "case_id": case.case_id,
        "identity_id": case.identity_id,
        "session_id": case.session_id,
        "session_risk": case.session_risk,
        "identity_risk": case.identity_risk,
        "confidence": case.confidence,
        "band": case.band.value,
        "status": case.status.value,
        "created_at": case.created_at,
        "updated_at": case.updated_at,
    }], db_path=tmp_db)

    # Process PB-03: returns immediate restrict applied + revoke pending approval
    out = agent.process(ctx.new_message(topic="cases", payload=case), state, ctx)
    assert len(out) == 2

    # Verify immediate restrict action
    act_restr = out[0].payload
    assert isinstance(act_restr, Action)
    assert act_restr.action_kind == ActionKind.restrict
    assert act_restr.state == ActionState.applied

    # Verify revoke action pending approval
    act_revoke = out[1].payload
    assert isinstance(act_revoke, Action)
    assert act_revoke.action_kind == ActionKind.revoke_sessions
    assert act_revoke.state == ActionState.pending_approval
    assert act_revoke.approval_required is True

    # Check case status transitioned to awaiting_approval
    c_row = fetch_one("SELECT status FROM cases_v3 WHERE case_id = ?", (case.case_id,), db_path=tmp_db)
    assert c_row is not None
    assert c_row["status"] == CaseStatus.awaiting_approval.value

    # Analyst approves the revoke action
    approve_msg = ctx.new_message(
        topic="approvals",
        payload=Action(
            action_id=act_revoke.action_id,
            case_id=case.case_id,
            playbook_id="PB-03",
            action_kind=ActionKind.revoke_sessions,
            approval_required=True,
            state=ActionState.approved,
            reason="Approved by analyst",
            created_at=act_revoke.created_at,
            updated_at=fixed_clock.isoformat(),
            approved_by="analyst_alice",
        ),
    )
    approve_out = agent.process(approve_msg, state, ctx)
    assert len(approve_out) == 1
    applied_act = approve_out[0].payload
    assert isinstance(applied_act, Action)
    assert applied_act.state == ActionState.applied
    assert applied_act.approved_by == "analyst_alice"

    # Case status updated to contained
    c_row2 = fetch_one("SELECT status FROM cases_v3 WHERE case_id = ?", (case.case_id,), db_path=tmp_db)
    assert c_row2 is not None
    assert c_row2["status"] == CaseStatus.contained.value

    # Verify simulator was called for revoke
    assert any(c["action"] == "revoke" for c in mock_sim.calls)


def test_revoke_rejection(tmp_db: Path, fixed_clock: Any) -> None:
    set_db_path(tmp_db)
    create_tables(tmp_db)

    agent = ResponseAgent()
    state = agent.init_state()
    ctx = AgentContext(clock=fixed_clock)

    case = _make_sample_case(case_id="case-rej-1", identity_id="bob", band=Band.revoke, risk=92.0)
    out = agent.process(ctx.new_message(topic="cases", payload=case), state, ctx)
    act_revoke = out[1].payload
    assert isinstance(act_revoke, Action)

    reject_msg = ctx.new_message(
        topic="approvals",
        payload=Action(
            action_id=act_revoke.action_id,
            case_id=case.case_id,
            playbook_id="PB-03",
            action_kind=ActionKind.revoke_sessions,
            approval_required=True,
            state=ActionState.rejected,
            reason="Analyst rejected",
            created_at=act_revoke.created_at,
            updated_at=fixed_clock.isoformat(),
            approved_by="analyst_bob",
        ),
    )
    rej_out = agent.process(reject_msg, state, ctx)
    assert len(rej_out) == 1
    rejected_act = rej_out[0].payload
    assert isinstance(rejected_act, Action)
    assert rejected_act.state == ActionState.rejected


def test_approval_expiry_on_tick(tmp_db: Path) -> None:
    set_db_path(tmp_db)
    create_tables(tmp_db)

    t0 = datetime(2026, 10, 28, 12, 0, 0, tzinfo=UTC)
    agent = ResponseAgent()
    state = agent.init_state()
    ctx0 = AgentContext(clock=lambda: t0)

    case = _make_sample_case(case_id="case-exp-1", band=Band.revoke, risk=95.0)
    agent.process(ctx0.new_message(topic="cases", payload=case), state, ctx0)

    # Tick 10 minutes later: not expired yet
    ctx1 = AgentContext(clock=lambda: t0 + timedelta(minutes=10))
    assert agent.on_tick(state, ctx1) == []

    # Tick 35 minutes later: exceeds APPROVAL_TIMEOUT_MINUTES (30 min) -> expired
    ctx2 = AgentContext(clock=lambda: t0 + timedelta(minutes=35))
    tick_out = agent.on_tick(state, ctx2)
    assert len(tick_out) >= 1
    expired_act = tick_out[0].payload
    assert isinstance(expired_act, Action)
    assert expired_act.state == ActionState.expired


def test_restrict_ttl_auto_rollback_on_tick(tmp_db: Path) -> None:
    set_db_path(tmp_db)
    create_tables(tmp_db)

    t0 = datetime(2026, 10, 28, 12, 0, 0, tzinfo=UTC)
    mock_sim = MockSimulator()
    sim_client = SimulatorClient(simulator_instance=mock_sim)
    agent = ResponseAgent(simulator=sim_client)
    state = agent.init_state()
    ctx0 = AgentContext(clock=lambda: t0)

    case = _make_sample_case(case_id="case-ttl-1", identity_id="alice", band=Band.restrict, risk=75.0)
    out = agent.process(ctx0.new_message(topic="cases", payload=case), state, ctx0)
    assert len(out) == 1
    applied_act = out[0].payload
    assert isinstance(applied_act, Action)
    assert applied_act.state == ActionState.applied
    assert applied_act.expires_at is not None

    # Advance clock beyond 240 minutes TTL (e.g. 245 minutes)
    ctx_future = AgentContext(clock=lambda: t0 + timedelta(minutes=245))
    tick_out = agent.on_tick(state, ctx_future)
    assert len(tick_out) == 1
    rb_act = tick_out[0].payload
    assert isinstance(rb_act, Action)
    assert rb_act.state == ActionState.rolled_back


# ---------------------------------------------------------------------------
# 5. Simulator Idempotency
# ---------------------------------------------------------------------------


def test_simulator_idempotency() -> None:
    mock_sim = MockSimulator()
    client = SimulatorClient(simulator_instance=mock_sim)

    # Calling execute with the same action_id multiple times
    ref1 = client.execute("step_up", identity_id="user1", action_id="act-idem-1", caller=14)
    ref2 = client.execute("step_up", identity_id="user1", action_id="act-idem-1", caller=14)
    ref3 = client.execute("step_up", identity_id="user1", action_id="act-idem-1", caller="a14")

    assert ref1 == ref2 == ref3 == "simulated:step_up:ok"
    # Underlying simulator method called only once
    assert len(mock_sim.calls) == 1


# ---------------------------------------------------------------------------
# 6. Capability Check: Agent 13 Attempting Simulator Call is Blocked
# ---------------------------------------------------------------------------


def test_agent_13_simulator_blocked() -> None:
    client = SimulatorClient()
    dummy_a13 = DummyAgent13()

    # Calling simulator with Agent 13 raises CapabilityError
    with pytest.raises(CapabilityError):
        client.execute("step_up", identity_id="user1", caller=dummy_a13)

    with pytest.raises(CapabilityError):
        execute_simulator_action("restrict", identity_id="user1", caller="a13")

    with pytest.raises(CapabilityError):
        execute_simulator_action("revoke", identity_id="user1", caller=13)


# ---------------------------------------------------------------------------
# 7. Email Sent Once Per Case (Deduplication)
# ---------------------------------------------------------------------------


def test_email_sent_once_per_case(tmp_db: Path, fixed_clock: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    set_db_path(tmp_db)
    create_tables(tmp_db)

    # Track deliver calls
    from app import notify

    notify_init = getattr(notify, "init_tables", None)
    if notify_init:
        notify_init()

    delivered_fingerprints: list[str] = []
    orig_deliver = notify.deliver

    def mock_deliver(msg: Any, text: str, kind: str, alert_ids: list[str], fps: list[str]) -> dict:
        delivered_fingerprints.extend(fps)
        return orig_deliver(msg, text, kind, alert_ids, fps)

    monkeypatch.setattr(notify, "deliver", mock_deliver)

    agent = ResponseAgent()
    state = agent.init_state()
    ctx = AgentContext(clock=fixed_clock)

    case = _make_sample_case(case_id="case-email-1", identity_id="target_user", band=Band.restrict, risk=80.0)
    msg = ctx.new_message(topic="cases", payload=case)

    # Process first time -> email delivered
    agent.process(msg, state, ctx)
    assert len(delivered_fingerprints) == 1

    # Process second time -> deduplicated, no second email
    agent.process(msg, state, ctx)
    assert len(delivered_fingerprints) == 1


# ---------------------------------------------------------------------------
# 8. Feedback: FP Lowers Weight But Not Below Floor
# ---------------------------------------------------------------------------


def test_feedback_fp_lowers_weight_with_floors(tmp_db: Path, fixed_clock: Any) -> None:
    set_db_path(tmp_db)
    create_tables(tmp_db)

    agent = FeedbackAgent()
    state = agent.init_state()
    ctx = AgentContext(clock=fixed_clock)

    # Seed a case with D-PE-02 and D-ACC-02 signals
    case = _make_sample_case(
        case_id="case-fp-1",
        signal_ids=["sig-D-PE-02-1", "sig-D-ACC-02-1"],
        reasons=["D-PE-02 privilege escalation detected", "D-ACC-02 new ASN"],
    )
    insert_many("cases_v3", [{
        "case_id": case.case_id,
        "identity_id": case.identity_id,
        "session_id": case.session_id,
        "session_risk": 70.0,
        "identity_risk": 70.0,
        "confidence": 0.9,
        "band": "restrict",
        "status": "investigating",
        "signal_ids": case.signal_ids,
        "chain": [],
        "reasons": [{"text": "D-PE-02"}],
        "created_at": fixed_clock.isoformat(),
        "updated_at": fixed_clock.isoformat(),
    }], db_path=tmp_db)

    # Label as false positive
    label_msg = ctx.new_message(
        topic="labels",
        payload=Label(
            case_id=case.case_id,
            verdict=Verdict.false_positive,
            analyst="analyst_charlie",
            note="FP confirmed by IT team",
            time=fixed_clock.isoformat(),
        ),
    )

    out = agent.process(label_msg, state, ctx)
    assert len(out) == 1
    assert out[0].topic == "config.updates"

    # D-ACC-02 dropped from 1.0 to 0.95
    assert agent.get_weight("D-ACC-02") == 0.95
    # D-PE-02 dropped from 1.0 to 0.95
    assert agent.get_weight("D-PE-02") == 0.95

    # Apply 10 more FP labels on D-PE-02: must NOT fall below 0.6 floor
    for _ in range(10):
        agent.process(label_msg, state, ctx)

    assert agent.get_weight("D-PE-02") >= 0.60
    assert agent.get_weight("D-PE-02") == 0.60

    # Verify proposed suppression created
    props = agent.get_proposed_suppressions()
    assert len(props) >= 1
    assert props[0]["status"] == "proposed"


# ---------------------------------------------------------------------------
# 9. Config Rollback Restores Weights
# ---------------------------------------------------------------------------


def test_config_rollback_restores_weights(tmp_db: Path, fixed_clock: Any) -> None:
    set_db_path(tmp_db)
    create_tables(tmp_db)

    agent = FeedbackAgent()
    state = agent.init_state()
    ctx = AgentContext(clock=fixed_clock)

    # Initial state: weight is 1.0
    assert agent.get_weight("D-ACC-02") == 1.0

    # Version 1 created by 1st FP label
    case = _make_sample_case(case_id="case-rb-1", signal_ids=["sig-D-ACC-02-1"])
    insert_many("cases_v3", [{
        "case_id": case.case_id,
        "identity_id": case.identity_id,
        "session_id": case.session_id,
        "session_risk": 50.0,
        "identity_risk": 50.0,
        "confidence": 0.8,
        "band": "step_up",
        "status": "investigating",
        "signal_ids": case.signal_ids,
        "created_at": fixed_clock.isoformat(),
        "updated_at": fixed_clock.isoformat(),
    }], db_path=tmp_db)

    msg = ctx.new_message(
        topic="labels",
        payload=Label(
            case_id=case.case_id,
            verdict=Verdict.false_positive,
            analyst="analyst_alice",
            note="FP",
            time=fixed_clock.isoformat(),
        ),
    )
    agent.process(msg, state, ctx)
    v1_weight = agent.get_weight("D-ACC-02")
    assert v1_weight == 0.95

    # Version 2 created by 2nd FP label
    agent.process(msg, state, ctx)
    v2_weight = agent.get_weight("D-ACC-02")
    assert v2_weight == 0.90

    # Rollback to Version 1: should restore weight to 0.95
    rollback_update = agent.rollback(target_version=1, analyst="admin")
    assert rollback_update.version == 3
    assert agent.get_weight("D-ACC-02") == 0.95


# ---------------------------------------------------------------------------
# 10. Bus and Supervisor Full Integration
# ---------------------------------------------------------------------------


def test_bus_integration_response_and_feedback(tmp_db: Path, fixed_clock: Any) -> None:
    set_db_path(tmp_db)
    create_tables(tmp_db)

    sup = Supervisor()
    bus = Bus(supervisor=sup, ctx=AgentContext(clock=fixed_clock))

    mock_sim = MockSimulator()
    sim_client = SimulatorClient(simulator_instance=mock_sim)
    resp_agent = ResponseAgent(simulator=sim_client)
    fb_agent = FeedbackAgent()

    sup.register_agent(resp_agent)
    sup.register_agent(fb_agent)
    bus.subscribe(resp_agent)
    bus.subscribe(fb_agent)

    # Publish a case to cases topic
    case = _make_sample_case(case_id="case-int-1", band=Band.restrict, risk=75.0)
    bus.publish(bus.ctx.new_message(topic="cases", payload=case))
    bus.run_until_idle()

    # Verify action was emitted and persisted
    rows = fetch_all("SELECT * FROM actions_v3 WHERE case_id = ?", (case.case_id,), db_path=tmp_db)
    assert len(rows) == 1
    assert rows[0]["state"] == ActionState.applied.value
