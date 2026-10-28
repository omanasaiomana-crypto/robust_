"""Integration and unit tests for rule detection agents on sample dataset."""
from pathlib import Path
import pytest

from app import sample_data
from app.agents.api_anomaly import ApiAnomalyAgent
from app.agents.dormant import DormantAgent
from app.agents.impossible_travel import ImpossibleTravelAgent
from app.agents.priv_escalation import PrivEscalationAgent
from app.agents.token_abuse import TokenAbuseAgent
from app.config import SAMPLE_DIR
from app.correlate.sessions import assign_sessions
from app.ingest.loaders import load_cloudtrail, load_okta
from app.ingest.normalize import normalize_all


@pytest.fixture(scope="module")
def sample_events():
    """Ensure sample data exists and return normalized, session-correlated DataFrame."""
    if not (SAMPLE_DIR / "cloudtrail.json").exists() or not (SAMPLE_DIR / "okta.json").exists():
        sample_data.generate(SAMPLE_DIR)

    raw_ct, _ = load_cloudtrail(SAMPLE_DIR)
    raw_okta, _ = load_okta(SAMPLE_DIR)
    df, _ = normalize_all(raw_ct, raw_okta)
    df = assign_sessions(df)
    return df


def test_p1_impossible_travel(sample_events):
    agent = ImpossibleTravelAgent()
    signals = agent.detect(sample_events)
    assert len(signals) > 0

    p1_identities = {s.identity_id for s in signals if s.pattern == "P1"}
    assert "anita.rao" in p1_identities

    anita_sigs = [s for s in signals if s.identity_id == "anita.rao"]
    assert len(anita_sigs) >= 1
    sig = anita_sigs[0]
    assert sig.pattern == "P1"
    assert sig.severity == 1.0
    assert len(sig.evidence_event_ids) >= 2
    assert "T1078" in sig.mitre


def test_p2_dormant_reactivation(sample_events):
    agent = DormantAgent()
    signals = agent.detect(sample_events)
    assert len(signals) > 0

    p2_identities = {s.identity_id for s in signals if s.pattern == "P2"}
    assert "svc-report" in p2_identities

    svc_sigs = [s for s in signals if s.identity_id == "svc-report"]
    assert len(svc_sigs) >= 1
    assert svc_sigs[0].pattern == "P2"
    assert "T1078.004" in svc_sigs[0].mitre


def test_p3_privilege_escalation(sample_events):
    agent = PrivEscalationAgent()
    signals = agent.detect(sample_events)
    assert len(signals) > 0

    p3_identities = {s.identity_id for s in signals if s.pattern == "P3"}
    assert "svc-report" in p3_identities

    svc_p3 = [s for s in signals if s.identity_id == "svc-report" and s.pattern == "P3"]
    assert len(svc_p3) >= 1
    assert svc_p3[0].severity == 1.0
    assert len(svc_p3[0].evidence_event_ids) >= 3
    assert hasattr(agent, "last_chains")
    assert len(agent.last_chains) > 0


def test_p4_unusual_api(sample_events):
    agent = ApiAnomalyAgent()
    signals = agent.detect(sample_events)
    assert len(signals) > 0

    p4_identities = {s.identity_id for s in signals if s.pattern == "P4"}
    assert "dev.kumar" in p4_identities


def test_p5_token_abuse(sample_events):
    agent = TokenAbuseAgent()
    signals = agent.detect(sample_events)
    assert len(signals) > 0

    p5_identities = {s.identity_id for s in signals if s.pattern == "P5"}
    assert "meera.n" in p5_identities

    meera_sigs = [s for s in signals if s.identity_id == "meera.n" and s.pattern == "P5"]
    assert len(meera_sigs) >= 1
    assert "T1539" in meera_sigs[0].mitre


def test_benign_users_no_critical_escalation(sample_events):
    """Benign users without attack scenarios should not trigger privilege escalation or token abuse."""
    p3_agent = PrivEscalationAgent()
    p5_agent = TokenAbuseAgent()

    benign_df = sample_events[sample_events["identity_id"].isin(["rohit.sharma", "priya.patel"])]
    assert len(p3_agent.detect(benign_df)) == 0
    assert len(p5_agent.detect(benign_df)) == 0
