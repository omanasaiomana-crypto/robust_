"""Unit tests for app/v3/models.py and app/v3/config.py.

Validates frozen contracts, bounds, band_for edge thresholds, discriminated unions,
and secret masking in repr.
"""
from dataclasses import FrozenInstanceError

import pytest
from pydantic import ValidationError

from app.v3.config import Settings
from app.v3.models import (
    Action,
    ActionKind,
    ActionState,
    ActionType,
    Band,
    Case,
    CaseReason,
    CaseStatus,
    CaseStep,
    ConfigUpdate,
    Context,
    Counterfactual,
    DeadletterPayload,
    EnrichedEvent,
    Event,
    EventClass,
    GraphDelta,
    GraphEdge,
    GraphNode,
    IngestEnvelope,
    IngestResult,
    Label,
    Message,
    NextStep,
    RawLog,
    RiskScore,
    RiskUpdate,
    Signal,
    Source,
    Stage,
    TraceEvent,
    Verdict,
    band_for,
)


def _make_event(event_id: str = "ev-1", res_conf: float = 0.95) -> Event:
    return Event(
        event_id=event_id,
        time="2026-10-30T12:00:00Z",
        source=Source.okta,
        event_class=EventClass.authentication,
        action="user.session.start",
        identity_id="alice",
        raw_principal="alice@corp.example",
        src_ip="198.51.100.1",
        user_agent="Mozilla/5.0",
        outcome="success",
        read_only=True,
        resolution_confidence=res_conf,
    )


def _make_context(priv: int = 2, sens: int = 3) -> Context:
    return Context(
        privilege_level=priv,
        resource_sensitivity=sens,
        action_type=ActionType.read,
        stage_hint=Stage.initial_access,
        context_complete=True,
    )


def _make_signal(sig_id: str = "sig-1", strength: float = 0.8, conf: float = 0.9) -> Signal:
    return Signal(
        signal_id=sig_id,
        detection_id="D-ACC-01",
        agent_num=5,
        identity_id="alice",
        strength=strength,
        confidence=conf,
        evidence_event_ids=["ev-1"],
        mitre=["T1078.004"],
        stage=Stage.initial_access,
        summary="Impossible travel detected",
    )


def _make_risk_score(score: float = 75.0, conf: float = 0.85) -> RiskScore:
    return RiskScore(
        subject_id="alice",
        score=score,
        confidence=conf,
        band=band_for(score),
        factors={"signals": 0.8},
        computed_at="2026-10-30T12:00:00Z",
    )


# ---------------------------------------------------------------------------
# Test band_for edge thresholds
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0.0, Band.monitor),
        (39.99, Band.monitor),
        (40.0, Band.step_up),
        (55.0, Band.step_up),
        (69.99, Band.step_up),
        (70.0, Band.restrict),
        (85.0, Band.restrict),
        (89.99, Band.restrict),
        (90.0, Band.revoke),
        (100.0, Band.revoke),
    ],
)
def test_band_for_edges(score: float, expected: Band) -> None:
    assert band_for(score) == expected


# ---------------------------------------------------------------------------
# Test frozen behavior and extra="forbid"
# ---------------------------------------------------------------------------


def test_frozen_behavior() -> None:
    ev = _make_event()
    with pytest.raises((ValidationError, TypeError, FrozenInstanceError)):
        ev.identity_id = "bob"


def test_extra_fields_forbidden() -> None:
    with pytest.raises(ValidationError):
        Event(
            event_id="ev-1",
            time="2026-10-30T12:00:00Z",
            source=Source.okta,
            event_class=EventClass.authentication,
            action="user.session.start",
            identity_id="alice",
            raw_principal="alice@corp.example",
            src_ip="198.51.100.1",
            user_agent="Mozilla/5.0",
            outcome="success",
            read_only=True,
            resolution_confidence=0.9,
            unexpected_field="disallowed",
        )


# ---------------------------------------------------------------------------
# Test Bounds and Validators
# ---------------------------------------------------------------------------


def test_resolution_confidence_validator() -> None:
    assert _make_event(res_conf=0.0).resolution_confidence == 0.0
    assert _make_event(res_conf=1.0).resolution_confidence == 1.0
    with pytest.raises(ValidationError):
        _make_event(res_conf=-0.01)
    with pytest.raises(ValidationError):
        _make_event(res_conf=1.01)


def test_privilege_and_sensitivity_validators() -> None:
    ctx = _make_context(priv=1, sens=5)
    assert ctx.privilege_level == 1
    assert ctx.resource_sensitivity == 5

    with pytest.raises(ValidationError):
        _make_context(priv=0, sens=3)
    with pytest.raises(ValidationError):
        _make_context(priv=6, sens=3)
    with pytest.raises(ValidationError):
        _make_context(priv=3, sens=0)
    with pytest.raises(ValidationError):
        _make_context(priv=3, sens=6)


def test_signal_validators() -> None:
    sig = _make_signal(strength=0.5, conf=0.5)
    assert sig.strength == 0.5
    assert sig.confidence == 0.5

    with pytest.raises(ValidationError):
        _make_signal(strength=-0.1)
    with pytest.raises(ValidationError):
        _make_signal(strength=1.1)
    with pytest.raises(ValidationError):
        _make_signal(conf=-0.1)
    with pytest.raises(ValidationError):
        _make_signal(conf=1.1)

    # Empty evidence_event_ids forbidden
    with pytest.raises(ValidationError):
        Signal(
            signal_id="sig-bad",
            detection_id="D-ACC-01",
            agent_num=5,
            identity_id="alice",
            strength=0.8,
            confidence=0.9,
            evidence_event_ids=[],
            stage=Stage.initial_access,
            summary="No evidence",
        )


def test_risk_score_validator() -> None:
    rs = _make_risk_score(score=0.0)
    assert rs.score == 0.0
    rs100 = _make_risk_score(score=100.0)
    assert rs100.score == 100.0

    with pytest.raises(ValidationError):
        _make_risk_score(score=-0.1)
    with pytest.raises(ValidationError):
        _make_risk_score(score=100.1)


def test_ingest_envelope_events_validator() -> None:
    valid_env = IngestEnvelope(
        source=Source.okta,
        sender_id="sender-1",
        batch_id="batch-1",
        events=[{"foo": "bar"}],
    )
    assert len(valid_env.events) == 1

    # Empty events
    with pytest.raises(ValidationError):
        IngestEnvelope(
            source=Source.okta,
            sender_id="sender-1",
            batch_id="batch-1",
            events=[],
        )

    # Over 500 events
    with pytest.raises(ValidationError):
        IngestEnvelope(
            source=Source.okta,
            sender_id="sender-1",
            batch_id="batch-1",
            events=[{"idx": i} for i in range(501)],
        )


# ---------------------------------------------------------------------------
# Test Valid Construction for All Models
# ---------------------------------------------------------------------------


def test_all_models_valid_construction() -> None:
    ev = _make_event()
    ctx = _make_context()
    enriched = EnrichedEvent(event=ev, context=ctx)
    assert enriched.event.event_id == "ev-1"

    node = GraphNode(id="n1", kind="identity", label="alice")
    edge = GraphEdge(source="n1", target="n2", kind="used", event_id="ev-1", time="2026-10-30T12:00:00Z")
    delta = GraphDelta(nodes=[node], edges=[edge])
    assert len(delta.nodes) == 1

    sig = _make_signal()
    assert sig.signal_id == "sig-1"
    rs = _make_risk_score()
    ru = RiskUpdate(identity_id="alice", session_id="s-1", session_risk=rs, identity_risk=rs, signal_ids=["sig-1"])
    assert ru.identity_id == "alice"

    c_step = CaseStep(time="2026-10-30T12:00:00Z", event_id="ev-1", action="ConsoleLogin", stage=Stage.initial_access)
    c_reason = CaseReason(text="Impossible travel from foreign ASN", evidence_event_ids=["ev-1"])
    cf = Counterfactual(removed_factor="ACC", score_without=35.0, delta=40.0)
    ns = NextStep(action="GetSecretValue", probability=0.6)

    case = Case(
        case_id="case-1",
        identity_id="alice",
        session_id="s-1",
        session_risk=75.0,
        identity_risk=75.0,
        confidence=0.9,
        band=Band.restrict,
        status=CaseStatus.new,
        signal_ids=["sig-1"],
        chain=[c_step],
        reasons=[c_reason],
        counterfactuals=[cf],
        next_steps=[ns],
        created_at="2026-10-30T12:00:00Z",
        updated_at="2026-10-30T12:00:00Z",
    )
    assert case.case_id == "case-1"

    act = Action(
        action_id="act-1",
        case_id="case-1",
        playbook_id="PB-01",
        action_kind=ActionKind.restrict,
        approval_required=False,
        state=ActionState.proposed,
        reason="Exceeded risk 70",
        created_at="2026-10-30T12:00:00Z",
        updated_at="2026-10-30T12:00:00Z",
    )
    assert act.action_kind == ActionKind.restrict

    lbl = Label(case_id="case-1", verdict=Verdict.true_positive, analyst="sec-ops", note="Real attack", time="2026-10-30T12:00:00Z")
    assert lbl.verdict == Verdict.true_positive

    cfg_up = ConfigUpdate(version=2, changes={"LEARNING_RATE": 0.08}, reason="Tuning", created_at="2026-10-30T12:00:00Z")
    assert cfg_up.version == 2

    trace = TraceEvent(
        seq=1, run_id="run-1", ts="2026-10-30T12:00:00Z", agent_id="collector", agent_num=1,
        agent_name="Collector", layer="data", state="done", level="ok", message="Ingested 10 events",
    )
    assert trace.seq == 1

    res = IngestResult(batch_id="b1", accepted=10, received_at="2026-10-30T12:00:00Z")
    assert res.accepted == 10

    raw = RawLog(source=Source.cloudtrail, raw_text="{}")
    assert raw.source == Source.cloudtrail

    dl = DeadletterPayload(failed_topic="events", error="Decode failed")
    assert dl.failed_topic == "events"


# ---------------------------------------------------------------------------
# Test Discriminated Union on Message.payload
# ---------------------------------------------------------------------------


def test_message_discriminated_union() -> None:
    ev = _make_event()
    msg_ev = Message(
        topic="events",
        msg_id="m-1",
        producer="a01_collector",
        run_id="run-test",
        created_at="2026-10-30T12:00:00Z",
        payload=ev,
    )
    assert msg_ev.payload.kind == "event"
    assert isinstance(msg_ev.payload, Event)

    # Test JSON round-trip through discriminated union
    raw_dict = msg_ev.model_dump()
    parsed_msg = Message.model_validate(raw_dict)
    assert isinstance(parsed_msg.payload, Event)
    assert parsed_msg.payload.event_id == "ev-1"

    # Test with Signal payload
    sig = _make_signal()
    msg_sig = Message(
        topic="signals",
        msg_id="m-2",
        producer="a05_access",
        run_id="run-test",
        created_at="2026-10-30T12:00:00Z",
        payload=sig,
    )
    parsed_sig_msg = Message.model_validate(msg_sig.model_dump())
    assert isinstance(parsed_sig_msg.payload, Signal)
    assert parsed_sig_msg.payload.signal_id == "sig-1"


# ---------------------------------------------------------------------------
# Test Settings repr masking
# ---------------------------------------------------------------------------


def test_settings_repr_never_leaks_secrets() -> None:
    secret_key = "super_secret_ingest_key_32bytes"
    analyst_token = "secret_analyst_token_value"
    smtp_pwd = "secret_smtp_password"
    gemini_key = "secret_gemini_api_key"

    custom_settings = Settings(
        v3_enabled=True,
        analyst_token=analyst_token,
        dry_run=False,
        console_base_url="http://127.0.0.1:8000",
        ingest_keys={"key1": secret_key},
        ingest_allowed_origins=[],
        enrich_providers=["ipinfo_lite"],
        ipinfo_token="secret_ipinfo_token",
        abuseipdb_key="secret_abuseipdb_key",
        greynoise_key="secret_greynoise_key",
        otx_key="secret_otx_key",
        vt_key="secret_vt_key",
        maxmind_license_key="secret_maxmind_key",
        llm_enabled=True,
        llm_provider="gemini",
        gemini_api_key=gemini_key,
        groq_api_key="secret_groq_key",
        ollama_url="http://127.0.0.1:11434",
        openrouter_api_key="secret_openrouter_key",
        email_mode="smtp",
        admin_email="admin@corp.example",
        alert_email_to=["admin@corp.example"],
        alert_email_from="shield@corp.example",
        email_min_risk=70.0,
        email_max_per_hour=10,
        smtp_host="smtp.example.com",
        smtp_port=587,
        smtp_user="user@example.com",
        smtp_password=smtp_pwd,
        smtp_starttls=True,
        smtp_ssl=False,
        smtp_timeout_seconds=10,
        ngrok_authtoken="secret_ngrok_token",
    )

    r = repr(custom_settings)

    # Ensure none of the secret strings are present in repr
    assert secret_key not in r
    assert analyst_token not in r
    assert smtp_pwd not in r
    assert gemini_key not in r
    assert "secret_ipinfo_token" not in r
    assert "secret_abuseipdb_key" not in r
    assert "secret_greynoise_key" not in r
    assert "secret_otx_key" not in r
    assert "secret_vt_key" not in r
    assert "secret_maxmind_key" not in r
    assert "secret_groq_key" not in r
    assert "secret_openrouter_key" not in r
    assert "secret_ngrok_token" not in r

    # Ensure masking markers are shown
    assert "***" in r
