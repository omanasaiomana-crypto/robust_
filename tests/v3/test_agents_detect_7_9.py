"""Tests for Agents 7, 8, 9 (Credentials, Privilege Escalation, Defense Evasion).

Covers:
- D-CRD-01..05 positive and negative cases
- D-CRD-04 with foreign VPC endpoint and non-AWS IP
- PE-01..08 path matching, 2-step match
- Slow chain matching (gap < 168 h vs gap > 168 h)
- Signal upgrade with stable signal_id (not duplicated)
- PE-08 full chain (Discovery burst -> PrivEsc -> Data access)
- D-DEF-01..07 positive and negative cases
- PutEventSelectors negative case (management events included)
- Mass deletion threshold (49 vs 50)
- Secret harvesting threshold (4 vs 5 distinct)
- Anomaly boost (+0.1) for defense evasion
- Supervisor and Bus registration for Agents 1 through 9
"""
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.v3 import store
from app.v3.agents import register_all
from app.v3.agents.a07_credentials import (
    CredentialLifecycle,
    detect_credential_anomalies,
    is_ec2_instance_role,
)
from app.v3.agents.a08_privesc import (
    PrivilegeEscalation,
    load_privesc_paths,
    match_privesc_paths,
)
from app.v3.agents.a09_evasion import (
    DefenseEvasion,
    check_put_event_selectors_excludes_management,
    detect_defense_evasion,
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


@pytest.fixture
def test_ctx(tmp_path: Path) -> AgentContext:
    db_file = tmp_path / "test_store_7_9.db"
    store.create_tables(db_file)
    clock = FixedClock(datetime(2026, 10, 30, 12, 0, 0, tzinfo=UTC))
    settings = get_settings()
    return AgentContext(
        run_id="run-test-7-9",
        clock=clock,
        store=db_file,
        settings=settings,
    )


def make_enriched_event(
    event_id: str,
    identity_id: str,
    action: str,
    raw_principal: str = "",
    session_id: str | None = None,
    event_class: EventClass = EventClass.api_activity,
    outcome: str = "success",
    src_ip: str = "198.51.100.10",
    read_only: bool = False,
    asn: int = 15169,
    action_type: ActionType = ActionType.write,
    privilege_level: int = 2,
    attrs: dict | None = None,
    ts: float = 1793280000.0,
) -> EnrichedEvent:
    ev = Event(
        event_id=event_id,
        time=datetime.fromtimestamp(ts, tz=UTC).isoformat(),
        source=Source.cloudtrail,
        event_class=event_class,
        action=action,
        identity_id=identity_id,
        raw_principal=raw_principal or identity_id,
        session_id=session_id,
        src_ip=src_ip,
        user_agent="aws-cli/2.15.0",
        outcome=outcome,
        read_only=read_only,
        resolution_confidence=1.0,
        attrs=attrs or {},
    )
    cx = Context(
        country="US",
        city="San Jose",
        lat=37.33,
        lon=-121.88,
        asn=asn,
        as_org="Google LLC",
        is_proxy=False,
        is_tor=False,
        is_hosting=False,
        trusted_ip=False,
        privilege_level=privilege_level,
        resource_sensitivity=1,
        action_type=action_type,
    )
    return EnrichedEvent(event=ev, context=cx)


# ---------------------------------------------------------------------------
# Agent 7: Credential Lifecycle Tests (D-CRD-01..05)
# ---------------------------------------------------------------------------


def test_d_crd_01_dormant_account_wakes() -> None:
    state: dict = {"last_seen": {"bob": 1000.0}}
    # t = 1000 + 35 days (35 * 86400 = 3024000)
    curr_ts = 1000.0 + 35 * 86400
    event_dict = {
        "event_id": "ev-dormant",
        "identity_id": "bob",
        "action": "PutObject",
        "outcome": "success",
        "read_only": False,
        "timestamp": curr_ts,
    }
    context_dict = {"action_type": ActionType.write}

    sigs = detect_credential_anomalies(event_dict, context_dict, state, dormant_days=30)
    assert len(sigs) == 1
    assert sigs[0]["detection_id"] == "D-CRD-01"
    assert sigs[0]["strength"] == 0.5
    assert "35.0 days" in sigs[0]["summary"]


def test_d_crd_01_negative_cases() -> None:
    state: dict = {"last_seen": {"bob": 1000.0}}
    # Only 10 days inactive -> no signal
    event_dict = {
        "event_id": "ev-active",
        "identity_id": "bob",
        "action": "PutObject",
        "outcome": "success",
        "read_only": False,
        "timestamp": 1000.0 + 10 * 86400,
    }
    context_dict = {"action_type": ActionType.write}
    assert not detect_credential_anomalies(event_dict, context_dict, state, dormant_days=30)

    # 35 days inactive but read-only read -> no signal
    state["last_seen"]["bob"] = 1000.0
    event_dict["read_only"] = True
    context_dict["action_type"] = ActionType.read
    event_dict["timestamp"] = 1000.0 + 35 * 86400
    assert not detect_credential_anomalies(event_dict, context_dict, state, dormant_days=30)


def test_d_crd_02_key_for_another_user() -> None:
    state: dict = {}
    event_dict = {
        "event_id": "ev-key-other",
        "identity_id": "admin-alice",
        "action": "CreateAccessKey",
        "outcome": "success",
        "attrs": {"target_user": "target-charlie", "created_access_key": "AKIA999"},
        "timestamp": 2000.0,
    }
    context_dict = {"action_type": ActionType.credential_change}

    sigs = detect_credential_anomalies(event_dict, context_dict, state)
    d02 = [s for s in sigs if s["detection_id"] == "D-CRD-02"]
    assert len(d02) == 1
    assert d02[0]["strength"] == 0.7
    assert d02[0]["stage"] == Stage.privilege_escalation

    # Negative case: creating key for self
    event_dict_self = {
        "event_id": "ev-key-self",
        "identity_id": "admin-alice",
        "action": "CreateAccessKey",
        "outcome": "success",
        "attrs": {"target_user": "admin-alice"},
        "timestamp": 2001.0,
    }
    sigs_self = detect_credential_anomalies(event_dict_self, context_dict, state)
    assert not any(s["detection_id"] == "D-CRD-02" for s in sigs_self)


def test_d_crd_03_new_key_new_place() -> None:
    state: dict = {}
    # Step 1: Alice creates key AKIA-NEW from 198.51.100.1, ASN 15169
    create_ev = {
        "event_id": "ev-create",
        "identity_id": "alice",
        "action": "CreateAccessKey",
        "outcome": "success",
        "src_ip": "198.51.100.1",
        "attrs": {"created_access_key": "AKIA-NEW"},
        "timestamp": 1000.0,
    }
    detect_credential_anomalies(create_ev, {"asn": 15169}, state)

    # Step 2: Key first used 20 minutes later from 203.0.113.5, new ASN 8075
    use_ev = {
        "event_id": "ev-use",
        "identity_id": "alice",
        "action": "ListBuckets",
        "outcome": "success",
        "src_ip": "203.0.113.5",
        "attrs": {"access_key_id": "AKIA-NEW"},
        "timestamp": 1000.0 + 1200.0,  # 20 min later
    }
    sigs = detect_credential_anomalies(use_ev, {"asn": 8075}, state)
    d03 = [s for s in sigs if s["detection_id"] == "D-CRD-03"]
    assert len(d03) == 1
    assert d03[0]["strength"] == 0.6

    # Negative case: same key used again -> already checked
    sigs2 = detect_credential_anomalies(use_ev, {"asn": 8075}, state)
    assert not any(s["detection_id"] == "D-CRD-03" for s in sigs2)


def test_is_ec2_instance_role() -> None:
    assert is_ec2_instance_role({"raw_principal": "arn:aws:iam::123:role/ec2.amazonaws.com"})
    assert is_ec2_instance_role({"session_id": "i-0123456789abcdef0"})
    assert is_ec2_instance_role({"attrs": {"user_identity_type": "AssumedRole", "session_issuer": "ec2-instance-role"}})
    assert not is_ec2_instance_role({"raw_principal": "arn:aws:iam::123:user/alice", "session_id": "sess-user"})


def test_d_crd_04_instance_credential_misuse_non_aws_ip() -> None:
    state: dict = {}
    event_dict = {
        "event_id": "ev-ec2-leak",
        "identity_id": "role-ec2-backend",
        "raw_principal": "arn:aws:sts::123:assumed-role/backend/i-0123456789abcdef0",
        "session_id": "i-0123456789abcdef0",
        "action": "DescribeInstances",
        "src_ip": "198.51.100.99",  # Public non-AWS IP
        "attrs": {"user_identity_type": "AssumedRole"},
        "timestamp": 3000.0,
    }
    # Non-AWS ASN (e.g. 15169 Google, not 16509/14618 AWS)
    sigs = detect_credential_anomalies(event_dict, {"asn": 15169}, state)
    d04 = [s for s in sigs if s["detection_id"] == "D-CRD-04"]
    assert len(d04) == 1
    assert d04[0]["strength"] == 0.85
    assert "non-AWS" in d04[0]["summary"]


def test_d_crd_04_instance_credential_foreign_vpc_endpoint() -> None:
    state: dict = {}
    expected_vpce_map = {"role-ec2-backend": ["vpce-allowed1", "vpce-allowed2"]}
    event_dict = {
        "event_id": "ev-ec2-vpce",
        "identity_id": "role-ec2-backend",
        "raw_principal": "arn:aws:sts::123:assumed-role/backend/i-0123456789abcdef0",
        "action": "GetObject",
        "src_ip": "10.0.1.5",  # Internal IP
        "attrs": {"vpc_endpoint_id": "vpce-foreign999", "user_identity_type": "AssumedRole"},
        "timestamp": 4000.0,
    }
    sigs = detect_credential_anomalies(
        event_dict,
        {"asn": 16509},
        state,
        expected_vpce_map=expected_vpce_map,
    )
    d04 = [s for s in sigs if s["detection_id"] == "D-CRD-04"]
    assert len(d04) == 1
    assert "vpce-foreign999" in d04[0]["summary"]


def test_d_crd_05_login_profile_change_for_another_user() -> None:
    state: dict = {}
    event_dict = {
        "event_id": "ev-prof",
        "identity_id": "attacker-eve",
        "action": "UpdateLoginProfile",
        "outcome": "success",
        "attrs": {"target_user": "victim-dan"},
        "timestamp": 5000.0,
    }
    sigs = detect_credential_anomalies(event_dict, {}, state)
    d05 = [s for s in sigs if s["detection_id"] == "D-CRD-05"]
    assert len(d05) == 1
    assert d05[0]["strength"] == 0.7


# ---------------------------------------------------------------------------
# Agent 8: Privilege Escalation Tests (PE-01..PE-08)
# ---------------------------------------------------------------------------


def test_pe_02_two_step_match() -> None:
    paths = load_privesc_paths()
    state: dict = {}

    # Step 1: AttachUserPolicy with AdministratorAccess
    ev1 = {
        "event_id": "ev-pe1",
        "identity_id": "mallory",
        "action": "AttachUserPolicy",
        "attrs": {"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
        "timestamp": 1000.0,
    }
    cx1 = {"action_type": ActionType.permission_change}
    sigs1 = match_privesc_paths(ev1, cx1, state, paths)
    # Only 1 step matched of length 2 -> no signal yet
    assert not sigs1

    # Step 2: Use new permission (privileged write)
    ev2 = {
        "event_id": "ev-pe2",
        "identity_id": "mallory",
        "action": "CreateUser",
        "read_only": False,
        "timestamp": 1050.0,
    }
    cx2 = {"action_type": ActionType.write, "privilege_level": 4}
    sigs2 = match_privesc_paths(ev2, cx2, state, paths)

    pe02 = [s for s in sigs2 if s["detection_id"] == "D-PE-02"]
    assert len(pe02) == 1
    assert pe02[0]["strength"] == 0.9
    assert pe02[0]["evidence_event_ids"] == ["ev-pe1", "ev-pe2"]


def test_pe_slow_chain_gap_window() -> None:
    paths = load_privesc_paths()

    # Case A: Steps 2 days apart (48 h < 168 h) -> MATCHES
    state_a: dict = {}
    ev1 = {
        "event_id": "ev-a1",
        "identity_id": "slow-attacker",
        "action": "AttachUserPolicy",
        "attrs": {"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
        "timestamp": 1000.0,
    }
    match_privesc_paths(ev1, {"action_type": ActionType.permission_change}, state_a, paths)

    ev2 = {
        "event_id": "ev-a2",
        "identity_id": "slow-attacker",
        "action": "CreateRole",
        "read_only": False,
        "timestamp": 1000.0 + 48 * 3600.0,  # 2 days later
    }
    sigs_a = match_privesc_paths(ev2, {"action_type": ActionType.write}, state_a, paths)
    assert any(s["detection_id"] == "D-PE-02" for s in sigs_a)

    # Case B: Steps 9 days apart (216 h > 168 h) -> EXPIRED, DOES NOT MATCH
    state_b: dict = {}
    match_privesc_paths(ev1, {"action_type": ActionType.permission_change}, state_b, paths)
    ev3 = {
        "event_id": "ev-b2",
        "identity_id": "slow-attacker",
        "action": "CreateRole",
        "read_only": False,
        "timestamp": 1000.0 + 216 * 3600.0,  # 9 days later
    }
    sigs_b = match_privesc_paths(ev3, {"action_type": ActionType.write}, state_b, paths)
    assert not any(s["detection_id"] == "D-PE-02" for s in sigs_b)


def test_signal_upgraded_not_duplicated() -> None:
    paths = load_privesc_paths()
    state: dict = {}

    # PE-04: PassRole -> CreateFunction -> Invoke
    # Step 1: PassRole
    ev1 = {"event_id": "ev-step1", "identity_id": "lambda-user", "action": "PassRole", "timestamp": 100.0}
    match_privesc_paths(ev1, {}, state, paths)

    # Step 2: CreateFunction (2/3 steps matched)
    ev2 = {"event_id": "ev-step2", "identity_id": "lambda-user", "action": "CreateFunction", "timestamp": 200.0}
    sigs_step2 = match_privesc_paths(ev2, {}, state, paths)
    pe04_2 = [s for s in sigs_step2 if s["detection_id"] == "D-PE-04"]
    assert len(pe04_2) == 1
    sig_id_step2 = pe04_2[0]["signal_id"]
    strength_step2 = pe04_2[0]["strength"]
    assert strength_step2 == pytest.approx(0.57, abs=0.01)

    # Step 3: Invoke (3/3 steps matched)
    ev3 = {"event_id": "ev-step3", "identity_id": "lambda-user", "action": "Invoke", "timestamp": 300.0}
    sigs_step3 = match_privesc_paths(ev3, {}, state, paths)
    pe04_3 = [s for s in sigs_step3 if s["detection_id"] == "D-PE-04"]
    assert len(pe04_3) == 1
    sig_id_step3 = pe04_3[0]["signal_id"]
    strength_step3 = pe04_3[0]["strength"]

    # Same signal_id upgraded, not duplicated!
    assert sig_id_step2 == sig_id_step3
    assert strength_step3 == 0.85
    assert pe04_3[0]["evidence_event_ids"] == ["ev-step1", "ev-step2", "ev-step3"]


def test_pe_08_full_chain() -> None:
    paths = load_privesc_paths()
    state: dict = {}
    base_ts = 1000.0

    # 1. Discovery burst across 5 distinct services in 30 min
    services = ["s3:ListBuckets", "iam:ListUsers", "ec2:DescribeInstances", "rds:DescribeDBInstances", "sts:GetCallerIdentity"]
    for i, action in enumerate(services):
        ev = {"event_id": f"ev-disc-{i}", "identity_id": "chain-user", "action": action, "timestamp": base_ts + i * 10}
        match_privesc_paths(ev, {}, state, paths)

    # 2. PrivEsc step: PE-01 CreatePolicyVersion
    ev_pe = {
        "event_id": "ev-pe-ver",
        "identity_id": "chain-user",
        "action": "CreatePolicyVersion",
        "attrs": {"setAsDefault": True},
        "timestamp": base_ts + 200.0,
    }
    match_privesc_paths(ev_pe, {}, state, paths)

    # 3. Secrets / Data access
    ev_secret = {
        "event_id": "ev-secret-harvest",
        "identity_id": "chain-user",
        "action": "GetSecretValue",
        "timestamp": base_ts + 300.0,
    }
    sigs = match_privesc_paths(ev_secret, {}, state, paths)
    pe08 = [s for s in sigs if s["detection_id"] == "D-PE-08"]
    assert len(pe08) == 1
    assert pe08[0]["strength"] == 1.0


# ---------------------------------------------------------------------------
# Agent 9: Defense Evasion Tests (D-DEF-01..07)
# ---------------------------------------------------------------------------


def test_d_def_01_stop_logging() -> None:
    state: dict = {}
    ev = {"event_id": "ev-stop", "identity_id": "attacker", "action": "StopLogging", "timestamp": 1000.0}
    sigs = detect_defense_evasion(ev, {}, state)
    d01 = [s for s in sigs if s["detection_id"] == "D-DEF-01"]
    assert len(d01) == 1
    assert d01[0]["strength"] == 0.9


def test_check_put_event_selectors_excludes_management() -> None:
    assert check_put_event_selectors_excludes_management({"IncludeManagementEvents": False})
    assert check_put_event_selectors_excludes_management({"requestParameters": {"includeManagementEvents": "false"}})
    assert check_put_event_selectors_excludes_management({"eventSelectors": [{"readWriteType": "ReadOnly"}]})
    assert not check_put_event_selectors_excludes_management({"IncludeManagementEvents": True})


def test_d_def_01_put_event_selectors_positive_and_negative() -> None:
    state: dict = {}

    # Negative case: Management events ARE included -> NO signal
    ev_included = {
        "event_id": "ev-sel-ok",
        "identity_id": "auditor",
        "action": "PutEventSelectors",
        "attrs": {"IncludeManagementEvents": True},
        "timestamp": 1000.0,
    }
    assert not detect_defense_evasion(ev_included, {}, state)

    # Positive case: Management events EXCLUDED -> SIGNAL
    ev_excluded = {
        "event_id": "ev-sel-bad",
        "identity_id": "attacker",
        "action": "PutEventSelectors",
        "attrs": {"IncludeManagementEvents": False},
        "timestamp": 1010.0,
    }
    sigs = detect_defense_evasion(ev_excluded, {}, state)
    assert any(s["detection_id"] == "D-DEF-01" for s in sigs)


def test_d_def_02_to_05_tampering() -> None:
    state: dict = {}

    # D-DEF-02: GuardDuty DeleteDetector
    ev2 = {"event_id": "ev-gd", "identity_id": "attacker", "action": "DeleteDetector", "timestamp": 1000.0}
    sigs2 = detect_defense_evasion(ev2, {}, state)
    assert any(s["detection_id"] == "D-DEF-02" for s in sigs2)

    # D-DEF-03: DeleteFlowLogs
    ev3 = {"event_id": "ev-flow", "identity_id": "attacker", "action": "DeleteFlowLogs", "timestamp": 1010.0}
    sigs3 = detect_defense_evasion(ev3, {}, state)
    assert any(s["detection_id"] == "D-DEF-03" for s in sigs3)

    # D-DEF-04: DeletePublicAccessBlock
    ev4 = {"event_id": "ev-pab", "identity_id": "attacker", "action": "DeletePublicAccessBlock", "timestamp": 1020.0}
    sigs4 = detect_defense_evasion(ev4, {}, state)
    assert any(s["detection_id"] == "D-DEF-04" for s in sigs4)

    # D-DEF-05: ScheduleKeyDeletion
    ev5 = {"event_id": "ev-kms", "identity_id": "attacker", "action": "ScheduleKeyDeletion", "timestamp": 1030.0}
    sigs5 = detect_defense_evasion(ev5, {}, state)
    assert any(s["detection_id"] == "D-DEF-05" for s in sigs5)


def test_d_def_06_mass_delete_threshold() -> None:
    state: dict = {}
    base_ts = 1000.0

    # 49 deletes -> no signal
    for i in range(49):
        ev = {"event_id": f"del-{i}", "identity_id": "destroyer", "action": "DeleteObject", "timestamp": base_ts + i}
        sigs = detect_defense_evasion(ev, {}, state, mass_delete_threshold=50)
        assert not any(s["detection_id"] == "D-DEF-06" for s in sigs)

    # 50th delete -> triggers D-DEF-06
    ev50 = {"event_id": "del-50", "identity_id": "destroyer", "action": "DeleteObject", "timestamp": base_ts + 49}
    sigs50 = detect_defense_evasion(ev50, {}, state, mass_delete_threshold=50)
    d06 = [s for s in sigs50 if s["detection_id"] == "D-DEF-06"]
    assert len(d06) == 1
    assert d06[0]["strength"] == 0.8
    assert len(d06[0]["evidence_event_ids"]) == 50


def test_d_def_07_secret_harvesting_threshold() -> None:
    state: dict = {}
    base_ts = 2000.0

    # 4 distinct secrets -> no signal
    for i in range(4):
        ev = {
            "event_id": f"sec-{i}",
            "identity_id": "harvester",
            "action": "GetSecretValue",
            "attrs": {"secretId": f"secret-prod-{i}"},
            "timestamp": base_ts + i * 10,
        }
        sigs = detect_defense_evasion(ev, {}, state, secret_harvest_threshold=5)
        assert not any(s["detection_id"] == "D-DEF-07" for s in sigs)

    # 5th distinct secret -> triggers D-DEF-07
    ev5 = {
        "event_id": "sec-5",
        "identity_id": "harvester",
        "action": "GetSecretValue",
        "attrs": {"secretId": "secret-prod-5"},
        "timestamp": base_ts + 50,
    }
    sigs5 = detect_defense_evasion(ev5, {}, state, secret_harvest_threshold=5)
    d07 = [s for s in sigs5 if s["detection_id"] == "D-DEF-07"]
    assert len(d07) == 1
    assert d07[0]["strength"] == 0.7


def test_defense_evasion_anomaly_boost() -> None:
    state: dict = {}
    ev = {"event_id": "ev-boost", "identity_id": "compromised-user", "action": "StopLogging", "timestamp": 1000.0}

    # Without prior anomaly: base strength 0.9
    sigs_unboosted = detect_defense_evasion(ev, {}, state, has_prior_anomaly=False)
    assert sigs_unboosted[0]["strength"] == 0.9

    # With prior anomaly in last 24 h: boosted +0.1 -> 1.0 (capped at 1.0)
    sigs_boosted = detect_defense_evasion(ev, {}, state, has_prior_anomaly=True)
    assert sigs_boosted[0]["strength"] == 1.0


# ---------------------------------------------------------------------------
# Integration and Supervisor Registration Tests (Agents 1 through 9)
# ---------------------------------------------------------------------------


def test_supervisor_and_bus_registers_agents_1_to_9() -> None:
    sup = Supervisor()
    bus = Bus(supervisor=sup)
    registered = register_all(sup, bus)

    nums = [ag.num for ag in registered]
    for n in range(1, 10):
        assert n in nums


def test_agent_integration_credentials_privesc_evasion(test_ctx: AgentContext) -> None:
    crd_agent = CredentialLifecycle()
    crd_state = crd_agent.init_state()

    pe_agent = PrivilegeEscalation()
    pe_state = pe_agent.init_state()

    def_agent = DefenseEvasion()
    def_state = def_agent.init_state()

    # Step 1: Send StopLogging event to evasion agent
    enr_event = make_enriched_event(
        event_id="ev-int-stop",
        identity_id="david",
        action="StopLogging",
        action_type=ActionType.defense_evasion,
    )
    enr_msg = test_ctx.new_message(topic="events.enriched", payload=enr_event)

    msgs_crd = crd_agent.process(enr_msg, crd_state, test_ctx)
    msgs_pe = pe_agent.process(enr_msg, pe_state, test_ctx)
    msgs_def = def_agent.process(enr_msg, def_state, test_ctx)

    assert isinstance(msgs_crd, list)
    assert isinstance(msgs_pe, list)
    assert len(msgs_def) == 1
    assert isinstance(msgs_def[0].payload, Signal)
    assert msgs_def[0].payload.detection_id == "D-DEF-01"
