from datetime import datetime, timezone
import pandas as pd
import pytest

from app import store
from app.decision.feedback import apply_feedback
from app.decision.respond import apply_action, recommend
from app.decision.scoring import decayed, score_session
from app.models import Alert, Signal
from app.simulator.mock import MockSimulator
from app.utils import to_band


def test_bands():
    thresholds = [39.9, 40.0, 69.9, 70.0, 89.9, 90.0]
    expected = ["monitor", "step_up", "step_up", "restrict", "restrict", "revoke"]
    assert [to_band(x) for x in thresholds] == expected
    assert [recommend(x) for x in thresholds] == expected


def test_more_distinct_patterns_higher_risk():
    now = datetime.now(timezone.utc)
    s1 = Signal(
        pattern="P1",
        severity=0.8,
        identity_id="user-1",
        agent="test",
        reason="test P1",
        evidence_event_ids=["e1"],
        timestamp=now,
    )
    s2 = Signal(
        pattern="P3",
        severity=0.8,
        identity_id="user-1",
        agent="test",
        reason="test P3",
        evidence_event_ids=["e2"],
        timestamp=now,
    )

    ev_df = pd.DataFrame([{"privilege_level": 1, "resource_sensitivity": 1}])
    r1, _ = score_session([s1], ev_df)
    r2, _ = score_session([s1, s2], ev_df)

    assert r2 > r1


def test_decayed_halves_at_half_life():
    initial_risk = 80.0
    # At 6 hours (RISK_HALF_LIFE_HOURS), risk should decay by 50%
    assert abs(decayed(initial_risk, 6.0) - 40.0) < 0.2
    # At 12 hours, decay by 75%
    assert abs(decayed(initial_risk, 12.0) - 20.0) < 0.2
    # Confirmed True Positive does not decay
    assert decayed(initial_risk, 6.0, confirmed=True) == 80.0


def test_revoke_without_approval_refused():
    store.init_db()
    sim = MockSimulator()
    now = datetime.now(timezone.utc)
    alert = Alert(
        alert_id="AL-REV-TEST",
        identity_id="test-user",
        risk=95.0,
        confidence=0.9,
        band="revoke",
        patterns=["P3"],
        mitre=["T1098"],
        reasons=["Critical escalation"],
        evidence_event_ids=["e1"],
        recommended_action="revoke",
        first_seen=now,
        last_seen=now,
    )

    # Revoke without approval should be refused
    res_no_approval = apply_action(alert, "revoke", approved_by=None, sim=sim)
    assert res_no_approval.status == "refused"

    # Revoke with analyst approval should be applied
    res_approved = apply_action(alert, "revoke", approved_by="analyst_jane", sim=sim)
    assert res_approved.status == "applied"
    assert "simulated:revoke:ok" in res_approved.detail


def test_feedback_tp_raises_weight():
    store.init_db()
    now = datetime.now(timezone.utc)
    alert = Alert(
        alert_id="AL-FB-TEST",
        identity_id="test-user",
        risk=50.0,
        confidence=0.8,
        band="step_up",
        patterns=["P4"],
        mitre=["T1526"],
        reasons=["Unusual API"],
        evidence_event_ids=["e1"],
        recommended_action="step_up",
        first_seen=now,
        last_seen=now,
    )

    w_before = store.get_weights()["P4"]
    updated_weights = apply_feedback(alert, "tp")
    w_after = updated_weights["P4"]

    assert w_after > w_before
    assert store.get_weights()["P4"] == w_after
