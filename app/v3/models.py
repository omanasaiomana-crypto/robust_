"""Frozen data contracts for IdentityShield v3 (context.md Section 8).

All models are frozen Pydantic v2 models with extra="forbid".
Message.payload is a discriminated union with a 'kind' literal field.
"""
from enum import Enum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.v3 import config

# ---------------------------------------------------------------------------
# Enums (all as str Enums)
# ---------------------------------------------------------------------------


class Source(str, Enum):
    okta = "okta"
    cloudtrail = "cloudtrail"
    manual = "manual"
    generator = "generator"


class EventClass(str, Enum):
    authentication = "authentication"
    account_change = "account_change"
    api_activity = "api_activity"
    entity_management = "entity_management"
    data_access = "data_access"


class ActionType(str, Enum):
    read = "read"
    write = "write"
    permission_change = "permission_change"
    credential_change = "credential_change"
    destructive = "destructive"
    defense_evasion = "defense_evasion"


class Stage(str, Enum):
    initial_access = "initial_access"
    credential_access = "credential_access"
    discovery = "discovery"
    privilege_escalation = "privilege_escalation"
    persistence = "persistence"
    defense_evasion = "defense_evasion"
    collection = "collection"
    exfiltration = "exfiltration"
    impact = "impact"


class Band(str, Enum):
    monitor = "monitor"
    step_up = "step_up"
    restrict = "restrict"
    revoke = "revoke"


class CaseStatus(str, Enum):
    new = "new"
    investigating = "investigating"
    contained = "contained"
    awaiting_approval = "awaiting_approval"
    resolved_tp = "resolved_tp"
    resolved_fp = "resolved_fp"
    resolved_benign = "resolved_benign"


class ActionKind(str, Enum):
    monitor = "monitor"
    step_up = "step_up"
    restrict = "restrict"
    revoke_sessions = "revoke_sessions"
    disable_key = "disable_key"
    block_ip = "block_ip"
    quarantine_identity = "quarantine_identity"


class ActionState(str, Enum):
    proposed = "proposed"
    pending_approval = "pending_approval"
    approved = "approved"
    executing = "executing"
    applied = "applied"
    failed = "failed"
    rejected = "rejected"
    expired = "expired"
    rolled_back = "rolled_back"


class Verdict(str, Enum):
    true_positive = "true_positive"
    false_positive = "false_positive"
    benign_true_positive = "benign_true_positive"


# ---------------------------------------------------------------------------
# Helper: band_for(score) -> Band
# ---------------------------------------------------------------------------


def band_for(score: float) -> Band:
    """Classify risk score into operational Band using config thresholds."""
    if score >= config.BAND_REVOKE:
        return Band.revoke
    if score >= config.BAND_RESTRICT:
        return Band.restrict
    if score >= config.BAND_STEP_UP:
        return Band.step_up
    return Band.monitor


# ---------------------------------------------------------------------------
# Base Models
# ---------------------------------------------------------------------------


class FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


# ---------------------------------------------------------------------------
# Domain Models & Message Payloads
# ---------------------------------------------------------------------------


class Event(FrozenModel):
    kind: Literal["event"] = "event"
    event_id: str
    time: str
    source: Source
    event_class: EventClass
    action: str
    identity_id: str
    raw_principal: str
    session_id: str | None = None
    src_ip: str
    user_agent: str
    outcome: str
    resource_arn: str | None = None
    read_only: bool
    region: str | None = None
    late: bool = False
    uncatalogued: bool = False
    resolution_confidence: float
    raw_ref: str | None = None
    attrs: dict[str, Any] = Field(default_factory=dict)

    @field_validator("resolution_confidence")
    @classmethod
    def validate_resolution_confidence(cls, v: float) -> float:
        if not (0.0 <= v <= 1.0):
            raise ValueError(f"resolution_confidence must be in [0, 1], got {v}")
        return v


class Context(FrozenModel):
    kind: Literal["context"] = "context"
    country: str | None = None
    city: str | None = None
    lat: float | None = None
    lon: float | None = None
    asn: int | None = None
    as_org: str | None = None
    is_proxy: bool = False
    is_tor: bool = False
    is_hosting: bool = False
    trusted_ip: bool = False
    privilege_level: int = 1
    resource_sensitivity: int = 1
    action_type: ActionType
    stage_hint: Stage | None = None
    context_complete: bool = False

    @field_validator("privilege_level")
    @classmethod
    def validate_privilege_level(cls, v: int) -> int:
        if not (1 <= v <= 5):
            raise ValueError(f"privilege_level must be between 1 and 5, got {v}")
        return v

    @field_validator("resource_sensitivity")
    @classmethod
    def validate_resource_sensitivity(cls, v: int) -> int:
        if not (1 <= v <= 5):
            raise ValueError(f"resource_sensitivity must be between 1 and 5, got {v}")
        return v


class EnrichedEvent(FrozenModel):
    kind: Literal["enriched_event"] = "enriched_event"
    event: Event
    context: Context


class Session(FrozenModel):
    kind: Literal["session"] = "session"
    session_id: str
    identity_id: str
    start: str
    end: str | None = None
    event_ids: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    asns: list[int] = Field(default_factory=list)
    devices: list[str] = Field(default_factory=list)
    providers: list[str] = Field(default_factory=list)
    state: str = "open"
    fingerprint: dict[str, Any] = Field(default_factory=dict)


class GraphNode(FrozenModel):
    id: str
    kind: str
    label: str
    attrs: dict[str, Any] = Field(default_factory=dict)


class GraphEdge(FrozenModel):
    source: str
    target: str
    kind: str
    event_id: str
    time: str


class GraphDelta(FrozenModel):
    kind: Literal["graph_delta"] = "graph_delta"
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)


class Signal(FrozenModel):
    kind: Literal["signal"] = "signal"
    signal_id: str
    detection_id: str
    agent_num: int
    identity_id: str
    session_id: str | None = None
    strength: float
    confidence: float
    evidence_event_ids: list[str]
    mitre: list[str] = Field(default_factory=list)
    stage: Stage
    summary: str
    details: dict[str, Any] = Field(default_factory=dict)

    @field_validator("strength")
    @classmethod
    def validate_strength(cls, v: float) -> float:
        if not (0.0 <= v <= 1.0):
            raise ValueError(f"strength must be in [0, 1], got {v}")
        return v

    @field_validator("confidence")
    @classmethod
    def validate_confidence(cls, v: float) -> float:
        if not (0.0 <= v <= 1.0):
            raise ValueError(f"confidence must be in [0, 1], got {v}")
        return v

    @field_validator("evidence_event_ids")
    @classmethod
    def validate_evidence(cls, v: list[str]) -> list[str]:
        if len(v) < 1:
            raise ValueError("evidence_event_ids must have minimum length 1")
        return v


class RiskScore(FrozenModel):
    kind: Literal["risk_score"] = "risk_score"
    subject_id: str
    score: float
    confidence: float
    band: Band
    factors: dict[str, float] = Field(default_factory=dict)
    computed_at: str
    score_kind: str = "session"

    @field_validator("score")
    @classmethod
    def validate_score(cls, v: float) -> float:
        if not (0.0 <= v <= 100.0):
            raise ValueError(f"score must be in [0, 100], got {v}")
        return v

    @field_validator("confidence")
    @classmethod
    def validate_confidence(cls, v: float) -> float:
        if not (0.0 <= v <= 1.0):
            raise ValueError(f"confidence must be in [0, 1], got {v}")
        return v


class RiskUpdate(FrozenModel):
    kind: Literal["risk_update"] = "risk_update"
    identity_id: str
    session_id: str
    session_risk: RiskScore
    identity_risk: RiskScore
    signal_ids: list[str] = Field(default_factory=list)


class CaseStep(FrozenModel):
    time: str
    event_id: str
    action: str
    resource: str | None = None
    stage: Stage
    mitre: list[str] = Field(default_factory=list)


class Counterfactual(FrozenModel):
    removed_factor: str
    score_without: float
    delta: float

    @field_validator("score_without")
    @classmethod
    def validate_score_without(cls, v: float) -> float:
        if not (0.0 <= v <= 100.0):
            raise ValueError(f"score_without must be in [0, 100], got {v}")
        return v


class NextStep(FrozenModel):
    action: str
    probability: float

    @field_validator("probability")
    @classmethod
    def validate_probability(cls, v: float) -> float:
        if not (0.0 <= v <= 1.0):
            raise ValueError(f"probability must be in [0, 1], got {v}")
        return v


class CaseReason(FrozenModel):
    text: str
    evidence_event_ids: list[str] = Field(default_factory=list)


class Case(FrozenModel):
    kind: Literal["case"] = "case"
    case_id: str
    identity_id: str
    session_id: str
    session_risk: float
    identity_risk: float
    confidence: float
    band: Band
    status: CaseStatus
    signal_ids: list[str] = Field(default_factory=list)
    chain: list[CaseStep] = Field(default_factory=list)
    reasons: list[CaseReason] = Field(default_factory=list)
    counterfactuals: list[Counterfactual] = Field(default_factory=list)
    next_steps: list[NextStep] = Field(default_factory=list)
    blast_radius: int = 1
    related_identities: list[str] = Field(default_factory=list)
    narrative: str = ""
    narrative_source: str = "template"
    created_at: str
    updated_at: str

    @field_validator("session_risk", "identity_risk")
    @classmethod
    def validate_risk_scores(cls, v: float) -> float:
        if not (0.0 <= v <= 100.0):
            raise ValueError(f"score must be in [0, 100], got {v}")
        return v

    @field_validator("confidence")
    @classmethod
    def validate_confidence(cls, v: float) -> float:
        if not (0.0 <= v <= 1.0):
            raise ValueError(f"confidence must be in [0, 1], got {v}")
        return v


class Action(FrozenModel):
    kind: Literal["action"] = "action"
    action_id: str
    case_id: str
    playbook_id: str
    action_kind: ActionKind
    approval_required: bool
    state: ActionState
    simulator_ref: str | None = None
    reason: str
    created_at: str
    updated_at: str
    expires_at: str | None = None
    approved_by: str | None = None


class Label(FrozenModel):
    kind: Literal["label"] = "label"
    case_id: str
    verdict: Verdict
    analyst: str
    note: str
    time: str


class ConfigUpdate(FrozenModel):
    kind: Literal["config_update"] = "config_update"
    version: int
    changes: dict[str, Any]
    reason: str
    created_at: str
    created_by: str = "agent15"


class TraceEvent(FrozenModel):
    kind: Literal["trace_event"] = "trace_event"
    seq: int
    run_id: str
    ts: str
    agent_id: str
    agent_num: int
    agent_name: str
    layer: str
    state: str
    level: str
    message: str
    duration_ms: float | None = None
    data: Any = None


class IngestEnvelope(FrozenModel):
    kind: Literal["ingest_envelope"] = "ingest_envelope"
    source: Source
    sender_id: str
    batch_id: str
    events: list[dict[str, Any]]

    @field_validator("events")
    @classmethod
    def validate_events(cls, v: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if not (1 <= len(v) <= 500):
            raise ValueError(f"events length must be between 1 and 500, got {len(v)}")
        return v


class IngestRejectedItem(FrozenModel):
    index: int
    reason: str


class IngestResult(FrozenModel):
    kind: Literal["ingest_result"] = "ingest_result"
    batch_id: str
    accepted: int
    rejected: list[IngestRejectedItem] = Field(default_factory=list)
    received_at: str


class RawLog(FrozenModel):
    kind: Literal["raw_log"] = "raw_log"
    source: Source
    records: list[dict[str, Any]] = Field(default_factory=list)
    raw_text: str = ""


class DeadletterPayload(FrozenModel):
    kind: Literal["deadletter"] = "deadletter"
    failed_topic: str
    failed_msg_id: str | None = None
    error: str = ""
    producer: str = ""
    raw: Any = None


# ---------------------------------------------------------------------------
# Discriminated Union for Message Payload
# ---------------------------------------------------------------------------

Payload = Annotated[
    Event | Context | EnrichedEvent | Session | GraphDelta | Signal | RiskScore | RiskUpdate | Case | Action | Label | ConfigUpdate | TraceEvent | IngestEnvelope | IngestResult | RawLog | DeadletterPayload,
    Field(discriminator="kind"),
]


class Message(FrozenModel):
    topic: str
    msg_id: str
    producer: str
    run_id: str
    created_at: str
    schema_version: str = "3.0"
    partition_key: str = ""
    payload: Payload
