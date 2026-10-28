"""Frozen data contracts. Do not rename, remove or retype any field."""
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class Source(str, Enum):
    cloudtrail = "cloudtrail"
    okta = "okta"


class Category(str, Enum):
    auth = "auth"
    session = "session"
    api = "api"


class Event(BaseModel):
    event_id: str
    source: Source
    timestamp: datetime
    identity_id: str
    session_id: str | None = None
    action: str
    category: Category
    outcome: str = "success"
    src_ip: str | None = None
    country: str | None = None
    city: str | None = None
    lat: float | None = None
    lon: float | None = None
    asn: str | None = None
    user_agent: str | None = None
    device_id: str | None = None
    token_id: str | None = None
    region: str | None = None
    resource: str | None = None
    resource_sensitivity: int = 1
    privilege_level: int = 1
    label: str | None = None


class Signal(BaseModel):
    pattern: str
    severity: float = Field(ge=0.0, le=1.0)
    identity_id: str
    session_id: str | None = None
    agent: str
    reason: str
    evidence_event_ids: list[str]
    mitre: list[str] = []
    timestamp: datetime


class ChainStep(BaseModel):
    event_id: str
    action: str
    state: str
    timestamp: datetime


class Prediction(BaseModel):
    next_state: str
    probability: float


class Counterfactual(BaseModel):
    without: str
    risk: float


class Alert(BaseModel):
    alert_id: str
    level: str = "session"
    identity_id: str
    session_id: str | None = None
    risk: float
    confidence: float
    blast_radius: int = 0
    band: str
    patterns: list[str]
    mitre: list[str]
    reasons: list[str]
    evidence_event_ids: list[str]
    chain: list[ChainStep] = []
    prediction: Prediction | None = None
    counterfactuals: list[Counterfactual] = []
    recommended_action: str
    action_status: str = "pending"
    feedback: str | None = None
    first_seen: datetime
    last_seen: datetime


class ActionRequest(BaseModel):
    action: str
    approved_by: str = "analyst"


class ActionResult(BaseModel):
    alert_id: str
    action: str
    status: str
    detail: str


class FeedbackRequest(BaseModel):
    label: str


class Metrics(BaseModel):
    event_precision: float | None = None
    event_recall: float | None = None
    event_f1: float | None = None
    session_precision: float | None = None
    baseline_event_f1: float | None = None
    median_latency_ms: float | None = None
    total_events: int = 0
    total_alerts: int = 0
    skipped_records: int = 0


class Health(BaseModel):
    status: str
    pipeline: str
    detail: str = ""
    data_mode: str
    events: int = 0
    alerts: int = 0


class GraphNode(BaseModel):
    id: str
    label: str
    kind: str
    risk: float = 0.0


class GraphEdge(BaseModel):
    source: str
    target: str
    label: str
    event_id: str | None = None
    suspicious: bool = False


class IdentityGraph(BaseModel):
    identity_id: str
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    escalation_paths: list[list[str]] = []


class AuditEntry(BaseModel):
    seq: int
    timestamp: datetime
    agent: str
    action: str
    detail: str
    prev_hash: str
    hash: str


class ErrorResponse(BaseModel):
    error: str
    detail: str
    request_id: str
