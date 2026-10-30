"""Unit and integration tests for Risk Fusion (Phase P9).

Covers:
- Noisy-OR mathematics (single 0.8 -> 80, two 0.5 -> 75 before multipliers)
- Multipliers per PRD §14 table (privilege, sensitivity, action)
- Kill-chain expansion factor and cap at 1.6
- Max 100 risk score cap
- Exponential decay half-life (80 -> 40 after 24 hours)
- Identity max rule (max of decayed previous and current session score)
- Counterfactual analysis: E1-like attack chain shows "without escalation chain" as largest drop
- Agent 12: Weight floors respected on config.updates (D-PE >= 0.6, D-DEF >= 0.6)
- Agent 12: Threshold suppression (no publish when delta < 1.0 point and band unchanged)
- Agent 12: Pre-emptive scrutiny flag (identity risk >= 60 lowers step-up threshold)
- Full supervisor capability check and bus drain
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar

import pytest

from app.v3.agents.a12_fusion import RiskFusion
from app.v3.agents.base import AgentContext
from app.v3.bus import Bus
from app.v3.fusion import (
    chain_factor,
    confidence,
    counterfactuals,
    identity_risk,
    multipliers,
    noisy_or,
    session_risk,
)
from app.v3.models import (
    ConfigUpdate,
    Message,
    RiskUpdate,
    Signal,
    Stage,
)
from app.v3.supervisor import Supervisor


class FixedClock:
    def __init__(self, fixed_dt: datetime) -> None:
        self._dt = fixed_dt

    def now(self) -> datetime:
        return self._dt

    def __call__(self) -> datetime:
        return self._dt

    def tick(self, seconds: float) -> None:
        self._dt = self._dt + timedelta(seconds=seconds)


def _make_signal(
    det_id: str,
    strength: float = 0.5,
    conf: float = 1.0,
    stage: Stage = Stage.initial_access,
    session_id: str = "sess-1",
    identity_id: str = "user-1",
    details: dict | None = None,
) -> Signal:
    return Signal(
        signal_id=f"sig-{det_id}-{session_id}",
        detection_id=det_id,
        agent_num=5,
        identity_id=identity_id,
        session_id=session_id,
        strength=strength,
        confidence=conf,
        evidence_event_ids=["ev-1"],
        stage=stage,
        summary=f"Test signal for {det_id}",
        details=details or {},
    )


def test_noisy_or_math() -> None:
    # Single 0.8 with weight 1.0, confidence 1.0 -> P = 0.8
    s1 = _make_signal("D-ACC-01", strength=0.8, conf=1.0)
    p1 = noisy_or([s1])
    assert pytest.approx(p1, rel=1e-3) == 0.8

    # Neutral context: privilege=2, sensitivity=2, action="read", 1 stage -> all mults = 1.0
    neutral_cx = {
        "privilege_level": 2,
        "resource_sensitivity": 2,
        "worst_action": "read",
    }
    score1, factors1 = session_risk([s1], neutral_cx)
    assert score1 == 80.0
    assert factors1["noisy_or_p"] == 0.8

    # Two 0.5 signals with weight 1.0, conf 1.0 -> P = 1 - (1-0.5)(1-0.5) = 0.75
    s2 = _make_signal("D-ACC-02", strength=0.5, conf=1.0)
    s3 = _make_signal("D-SES-01", strength=0.5, conf=1.0)
    p2 = noisy_or([s2, s3])
    assert pytest.approx(p2, rel=1e-3) == 0.75

    score2, factors2 = session_risk([s2, s3], neutral_cx)
    assert score2 == 75.0
    assert factors2["noisy_or_p"] == 0.75


def test_multipliers_per_table() -> None:
    # Privilege levels 1..5: [0.8, 1.0, 1.15, 1.3, 1.5]
    assert multipliers({"privilege_level": 1})[0] == 0.8
    assert multipliers({"privilege_level": 2})[0] == 1.0
    assert multipliers({"privilege_level": 3})[0] == 1.15
    assert multipliers({"privilege_level": 4})[0] == 1.3
    assert multipliers({"privilege_level": 5})[0] == 1.5

    # Resource sensitivity levels 1..5: [0.9, 1.0, 1.1, 1.25, 1.4]
    assert multipliers({"resource_sensitivity": 1})[1] == 0.9
    assert multipliers({"resource_sensitivity": 2})[1] == 1.0
    assert multipliers({"resource_sensitivity": 3})[1] == 1.1
    assert multipliers({"resource_sensitivity": 4})[1] == 1.25
    assert multipliers({"resource_sensitivity": 5})[1] == 1.4

    # Action severity
    assert multipliers({"worst_action": "read"})[2] == 1.0
    assert multipliers({"worst_action": "write"})[2] == 1.1
    assert multipliers({"worst_action": "permission"})[2] == 1.25
    assert multipliers({"worst_action": "permission_change"})[2] == 1.25
    assert multipliers({"worst_action": "credential"})[2] == 1.25
    assert multipliers({"worst_action": "credential_change"})[2] == 1.25
    assert multipliers({"worst_action": "destructive"})[2] == 1.4
    assert multipliers({"worst_action": "defense_evasion"})[2] == 1.4


def test_chain_factor_and_cap() -> None:
    # 0 or 1 stage -> 1.0
    assert chain_factor([]) == 1.0
    assert chain_factor([Stage.initial_access]) == 1.0

    # 2 stages -> 1 + 0.15 * 1 = 1.15
    assert pytest.approx(chain_factor([Stage.initial_access, Stage.credential_access])) == 1.15

    # 5 stages -> 1 + 0.15 * 4 = 1.6
    stages_5 = [
        Stage.initial_access,
        Stage.credential_access,
        Stage.privilege_escalation,
        Stage.defense_evasion,
        Stage.collection,
    ]
    assert pytest.approx(chain_factor(stages_5)) == 1.6

    # 6 stages -> capped at 1.6
    stages_6 = stages_5 + [Stage.exfiltration]
    assert chain_factor(stages_6) == 1.6

    # Max 100 cap
    high_context = {
        "privilege_level": 5,
        "resource_sensitivity": 5,
        "worst_action": "destructive",
        "stages": stages_6,
    }
    s = _make_signal("D-PE-01", strength=0.9, conf=1.0, stage=Stage.privilege_escalation)
    score, _ = session_risk([s], high_context)
    assert score == 100.0


def test_identity_decay_and_max_rule() -> None:
    # 80 -> 40 after 24h decay with zero current session score
    decayed_40 = identity_risk(
        previous_score=80.0,
        last_update_ts=1000.0,
        now_ts=1000.0 + 24.0 * 3600.0,
        current_session_score=0.0,
    )
    assert pytest.approx(decayed_40, abs=0.1) == 40.0

    # Max rule: decayed previous (40.0) vs new session score (65.0) -> 65.0
    result_max = identity_risk(
        previous_score=80.0,
        last_update_ts=1000.0,
        now_ts=1000.0 + 24.0 * 3600.0,
        current_session_score=65.0,
    )
    assert result_max == 65.0

    # Max rule: decayed previous (70.0) vs lower session score (30.0) -> 70.0
    result_prev = identity_risk(
        previous_score=70.0,
        last_update_ts=1000.0,
        now_ts=1000.0,  # dt = 0
        current_session_score=30.0,
    )
    assert result_prev == 70.0


def test_confidence_calculation() -> None:
    s1 = _make_signal("D-ACC-01", conf=0.8)
    s2 = _make_signal("D-SES-01", conf=0.9)
    # mean = 0.85; context_complete = 0.9; res_conf = 0.95 -> 0.85 * 0.9 * 0.95 = 0.72675 -> 0.73
    c = confidence([s1, s2], context_completeness=0.9, identity_resolution_confidence=0.95)
    assert c == 0.73


def test_counterfactual_e1_escalation_chain_largest_drop() -> None:
    # E1 hero scenario: new-country Okta login -> SAML role -> CreateAccessKey -> AttachUserPolicy -> AssumeRole
    signals = [
        _make_signal("D-ACC-02", strength=0.4, conf=0.8, stage=Stage.initial_access),
        _make_signal("D-PE-02", strength=0.85, conf=0.9, stage=Stage.privilege_escalation),
    ]
    cx = {
        "privilege_level": 2,
        "resource_sensitivity": 3,
        "worst_action": "permission_change",
    }

    base_score, _ = session_risk(signals, cx)
    assert base_score >= 90.0

    cfs = counterfactuals(signals, cx)
    assert len(cfs) >= 1

    # Largest drop must be without escalation chain
    top_cf = cfs[0]
    assert top_cf.removed_factor == "without escalation chain"
    # Around 44 per context.md Section 19
    assert pytest.approx(top_cf.score_without, abs=1.0) == 44.0
    assert top_cf.delta > 50.0
    assert top_cf.score_without < base_score


def test_agent12_weight_floors_enforced() -> None:
    agent = RiskFusion()
    ctx = AgentContext(clock=FixedClock(datetime(2026, 10, 30, 12, 0, 0, tzinfo=UTC)))
    state: dict = {}

    # Attempt to lower D-PE-01 and D-DEF-01 below the 0.6 floor
    config_update = ConfigUpdate(
        version=1,
        changes={
            "weights": {
                "D-PE-01": 0.1,
                "D-DEF-01": 0.2,
                "D-ACC-01": 0.4,
            }
        },
        reason="Test floor enforcement",
        created_at="2026-10-30T12:00:00Z",
    )
    config_msg = ctx.new_message(
        topic="config.updates",
        payload=config_update,
        producer="agent15",
    )

    out = agent.process(config_msg, state, ctx)
    assert out == []
    weights = state.get("weights", {})
    assert weights["D-PE-01"] == 0.6
    assert weights["D-DEF-01"] == 0.6
    assert weights["D-ACC-01"] == 0.4


def test_agent12_suppression_when_delta_under_one_point() -> None:
    agent = RiskFusion()
    ctx = AgentContext(clock=FixedClock(datetime(2026, 10, 30, 12, 0, 0, tzinfo=UTC)))
    state: dict = {}

    # Initial signal producing moderate risk
    sig1 = _make_signal("D-ACC-01", strength=0.6, conf=0.9, session_id="sess-sub", identity_id="alice")
    msg1 = ctx.new_message(topic="signals", payload=sig1, producer="agent5")
    out1 = agent.process(msg1, state, ctx)
    assert len(out1) == 1
    up1: RiskUpdate = out1[0].payload
    initial_score = up1.session_risk.score
    assert initial_score > 30.0

    # Second very weak signal that alters score by < 1.0 point within same band
    sig_tiny = _make_signal(
        "D-ACC-03",
        strength=0.005,
        conf=0.2,
        session_id="sess-sub",
        identity_id="alice",
    )
    msg2 = ctx.new_message(topic="signals", payload=sig_tiny, producer="agent5")
    out2 = agent.process(msg2, state, ctx)
    # Should not publish since delta is < 1.0 and band remains the same
    assert len(out2) == 0

    # Third strong signal pushing score up by >= 1.0 point
    sig3 = _make_signal("D-PE-01", strength=0.8, conf=0.95, session_id="sess-sub", identity_id="alice")
    msg3 = ctx.new_message(topic="signals", payload=sig3, producer="agent8")
    out3 = agent.process(msg3, state, ctx)
    assert len(out3) == 1
    up3: RiskUpdate = out3[0].payload
    assert up3.session_risk.score > initial_score + 10.0


def test_agent12_lowered_step_up_threshold_flag() -> None:
    agent = RiskFusion()
    ctx = AgentContext(clock=FixedClock(datetime(2026, 10, 30, 12, 0, 0, tzinfo=UTC)))
    state: dict = {}

    # Signal resulting in identity risk >= 60
    sig = _make_signal(
        "D-PE-02",
        strength=0.9,
        conf=1.0,
        session_id="sess-scrutiny",
        identity_id="bob",
        details={"privilege_level": 4, "resource_sensitivity": 4, "action_type": "destructive"},
    )
    msg = ctx.new_message(topic="signals", payload=sig, producer="agent8")
    out = agent.process(msg, state, ctx)

    assert len(out) == 1
    up: RiskUpdate = out[0].payload
    assert up.identity_risk.score >= 60.0
    assert state["lowered_step_up"]["bob"] is True
    assert up.session_risk.factors["lowered_step_up_threshold"] == 1.0
    assert up.identity_risk.factors["lowered_step_up_threshold"] == 1.0


class MockRiskConsumer(RiskFusion):
    num: ClassVar[int] = 13
    agent_id: ClassVar[str] = "agent13_mock"
    name: ClassVar[str] = "mock_consumer"
    layer: ClassVar[str] = "decision"
    path: ClassVar[str] = "warm"
    subscribes: ClassVar[list[str]] = ["risk"]
    publishes: ClassVar[list[str]] = ["cases", "deadletter"]

    def process(self, msg: Message, state: dict[str, Any], ctx: AgentContext) -> list[Message]:
        state.setdefault("received_updates", []).append(msg.payload)
        return []


def test_agent12_with_supervisor_and_bus() -> None:
    supervisor = Supervisor()
    clock = FixedClock(datetime(2026, 10, 30, 12, 0, 0, tzinfo=UTC))
    ctx = AgentContext(clock=clock)
    bus = Bus(supervisor=supervisor, ctx=ctx)

    agent = RiskFusion()
    consumer = MockRiskConsumer()

    bus.subscribe(agent)
    bus.subscribe(consumer)

    sig = _make_signal("D-ACC-01", strength=0.7, conf=0.9, session_id="s-bus", identity_id="charlie")
    msg = ctx.new_message(topic="signals", payload=sig, producer="agent5")

    bus.publish(msg)
    bus.run_until_idle()

    consumer_state = bus._agent_states.get(consumer.agent_id, {})
    received = consumer_state.get("received_updates", [])
    assert len(received) == 1
    update = received[0]
    assert isinstance(update, RiskUpdate)
    assert update.identity_id == "charlie"
    assert update.session_id == "s-bus"
    assert update.session_risk.score > 0.0
