"""Agent 9: Defense Evasion & Impact.

Detects attempts to blind monitors, tamper with security controls, or destroy data:
- D-DEF-01: Logging stopped or reduced (StopLogging, DeleteTrail, UpdateTrail, PutEventSelectors excluding management).
- D-DEF-02: Detector disabled (GuardDuty DeleteDetector, UpdateDetector disabled, DisassociateMembers).
- D-DEF-03: Flow logs deleted (DeleteFlowLogs).
- D-DEF-04: Data made public (PutBucketPolicy/Acl public access, DeletePublicAccessBlock).
- D-DEF-05: Key destruction (ScheduleKeyDeletion, DisableKey on KMS keys).
- D-DEF-06: Mass deletion (>= 50 delete calls in 5 min by one identity).
- D-DEF-07: Secret harvesting (>= 5 GetSecretValue on distinct secrets in 10 min).

Boost: +0.1 strength (capped at 1.0) if the identity had any signal from agents 5–7 in the last 24 h.
Hot path (<= 5 ms), consumes events.enriched; publishes signals, deadletter.
"""
from __future__ import annotations

import logging
import sqlite3
import uuid
from datetime import datetime, timedelta
from typing import Any, ClassVar

from app.v3 import config, store
from app.v3.agents.base import Agent, AgentContext
from app.v3.models import (
    EnrichedEvent,
    Message,
    Signal,
    Stage,
)

log = logging.getLogger(__name__)


def check_put_event_selectors_excludes_management(attrs: dict[str, Any]) -> bool:
    """Check if PutEventSelectors request parameter excludes management events."""
    # Direct field
    if "IncludeManagementEvents" in attrs:
        val = attrs["IncludeManagementEvents"]
        return str(val).lower() in ("false", "0")
    if "includeManagementEvents" in attrs:
        val = attrs["includeManagementEvents"]
        return str(val).lower() in ("false", "0")

    # Inside requestParameters
    req_params = attrs.get("requestParameters") or {}
    if "IncludeManagementEvents" in req_params:
        return str(req_params["IncludeManagementEvents"]).lower() in ("false", "0")
    if "includeManagementEvents" in req_params:
        return str(req_params["includeManagementEvents"]).lower() in ("false", "0")

    # Inside eventSelectors list
    selectors = attrs.get("eventSelectors") or req_params.get("eventSelectors") or []
    if isinstance(selectors, list) and selectors:
        for s in selectors:
            if isinstance(s, dict):
                inc = s.get("includeManagementEvents") or s.get("IncludeManagementEvents")
                if inc is not None and str(inc).lower() in ("false", "0"):
                    return True
                # If readWriteType is None or excludes All
                rw = str(s.get("readWriteType") or s.get("ReadWriteType") or "").lower()
                if rw in ("none", "readonly") and "readwrite" not in rw:
                    return True
        return False

    return False


def is_public_policy_or_acl(attrs: dict[str, Any]) -> bool:
    """Check if PutBucketPolicy or PutBucketAcl grants public access."""
    canned_acl = str(attrs.get("cannedAcl") or attrs.get("x-amz-acl") or "").lower()
    if any(p in canned_acl for p in ("public-read", "public-read-write", "authenticated-read")):
        return True

    policy_doc = str(
        attrs.get("bucketPolicy")
        or attrs.get("policyDocument")
        or attrs.get("policy")
        or attrs.get("requestParameters", {}).get("bucketPolicy")
        or ""
    )
    if not policy_doc:
        return True  # If event indicates policy change on S3 bucket without details, assume relevant

    # Check for wildcards in Principal
    return bool(
        '"Principal": "*"' in policy_doc
        or "'Principal': '*'" in policy_doc
        or '"Principal":{"AWS":"*"}' in policy_doc.replace(" ", "")
    )


def detect_defense_evasion(
    event_dict: dict[str, Any],
    context_dict: dict[str, Any],
    state: dict[str, Any],
    mass_delete_threshold: int = 50,
    mass_delete_window_seconds: float = 300.0,
    secret_harvest_threshold: int = 5,
    secret_harvest_window_seconds: float = 600.0,
    has_prior_anomaly: bool = False,
) -> list[dict[str, Any]]:
    """Pure detection function for defense evasion and impact anomalies."""
    ev_id = event_dict.get("event_id", "")
    identity_id = str(event_dict.get("identity_id") or "")
    action = str(event_dict.get("action", ""))
    action_lower = action.lower()
    curr_ts = float(event_dict.get("timestamp", 0.0))
    attrs = event_dict.get("attrs") or {}

    delete_calls = state.setdefault("delete_calls", {}).setdefault(identity_id, [])
    secret_calls = state.setdefault("secret_calls", {}).setdefault(identity_id, [])

    candidate_signals: list[dict[str, Any]] = []

    def calc_strength(base: float) -> float:
        if has_prior_anomaly:
            return round(min(1.0, base + 0.1), 2)
        return round(base, 2)

    # 1. D-DEF-01: Logging Stopped or Reduced
    # Actions: StopLogging, DeleteTrail, UpdateTrail, PutEventSelectors (excluding management)
    if action_lower in ("stoplogging", "deletetrail", "updatetrail"):
        candidate_signals.append(
            {
                "detection_id": "D-DEF-01",
                "strength": calc_strength(0.9),
                "confidence": 0.95,
                "evidence_event_ids": [ev_id],
                "mitre": ["T1562.008"],
                "stage": Stage.defense_evasion,
                "summary": f"CloudTrail audit logging halted or deleted via {action} by {identity_id}",
                "details": {"action": action, "trail": attrs.get("trailName") or attrs.get("name")},
            }
        )
    elif action_lower == "puteventselectors" and check_put_event_selectors_excludes_management(attrs):
        candidate_signals.append(
            {
                "detection_id": "D-DEF-01",
                "strength": calc_strength(0.9),
                "confidence": 0.95,
                "evidence_event_ids": [ev_id],
                "mitre": ["T1562.008"],
                "stage": Stage.defense_evasion,
                "summary": f"CloudTrail event selectors modified to exclude management events by {identity_id}",
                "details": {"action": action},
            }
        )

    # 2. D-DEF-02: Detector Disabled
    # GuardDuty DeleteDetector, UpdateDetector (disable), DisassociateMembers
    if action_lower in ("deletedetector", "disassociatemembers"):
        candidate_signals.append(
            {
                "detection_id": "D-DEF-02",
                "strength": calc_strength(0.9),
                "confidence": 0.95,
                "evidence_event_ids": [ev_id],
                "mitre": ["T1562.001"],
                "stage": Stage.defense_evasion,
                "summary": f"Security detector impaired via {action} by {identity_id}",
                "details": {"action": action},
            }
        )
    elif action_lower == "updatedetector":
        enabled_val = attrs.get("enable") or attrs.get("Enable") or attrs.get("requestParameters", {}).get("enable")
        if enabled_val is not None and str(enabled_val).lower() in ("false", "0"):
            candidate_signals.append(
                {
                    "detection_id": "D-DEF-02",
                    "strength": calc_strength(0.9),
                    "confidence": 0.95,
                    "evidence_event_ids": [ev_id],
                    "mitre": ["T1562.001"],
                    "stage": Stage.defense_evasion,
                    "summary": f"GuardDuty detector disabled via UpdateDetector by {identity_id}",
                    "details": {"action": action, "enabled": enabled_val},
                }
            )

    # 3. D-DEF-03: Flow Logs Deleted
    # DeleteFlowLogs
    if action_lower == "deleteflowlogs":
        candidate_signals.append(
            {
                "detection_id": "D-DEF-03",
                "strength": calc_strength(0.7),
                "confidence": 0.9,
                "evidence_event_ids": [ev_id],
                "mitre": ["T1562.008"],
                "stage": Stage.defense_evasion,
                "summary": f"VPC Flow Logs deleted by {identity_id}",
                "details": {"action": action, "flow_log_ids": attrs.get("flowLogIds")},
            }
        )

    # 4. D-DEF-04: Data Made Public
    # PutBucketPolicy / PutBucketAcl granting public access, DeletePublicAccessBlock
    if action_lower in ("deletepublicaccessblock", "deleteaccountpublicaccessblock"):
        candidate_signals.append(
            {
                "detection_id": "D-DEF-04",
                "strength": calc_strength(0.8),
                "confidence": 0.9,
                "evidence_event_ids": [ev_id],
                "mitre": ["T1530"],
                "stage": Stage.defense_evasion,
                "summary": f"S3 Public Access Block deleted via {action} by {identity_id}",
                "details": {"action": action},
            }
        )
    elif action_lower in ("putbucketpolicy", "putbucketacl") and is_public_policy_or_acl(attrs):
        candidate_signals.append(
            {
                "detection_id": "D-DEF-04",
                "strength": calc_strength(0.8),
                "confidence": 0.85,
                "evidence_event_ids": [ev_id],
                "mitre": ["T1530"],
                "stage": Stage.defense_evasion,
                "summary": f"Bucket exposure modified to permit public access via {action} by {identity_id}",
                "details": {"action": action},
            }
        )

    # 5. D-DEF-05: Key Destruction
    # ScheduleKeyDeletion, DisableKey
    if action_lower in ("schedulekeydeletion", "disablekey"):
        candidate_signals.append(
            {
                "detection_id": "D-DEF-05",
                "strength": calc_strength(0.85),
                "confidence": 0.95,
                "evidence_event_ids": [ev_id],
                "mitre": ["T1485"],
                "stage": Stage.impact,
                "summary": f"KMS key scheduled for deletion or disabled via {action} by {identity_id}",
                "details": {"action": action, "key_id": attrs.get("keyId")},
            }
        )

    # 6. D-DEF-06: Mass Deletion
    # >= 50 delete calls in 5 min by one identity
    if action_lower.startswith("delete"):
        delete_calls.append({"event_id": ev_id, "timestamp": curr_ts})
        cutoff = curr_ts - mass_delete_window_seconds
        delete_calls[:] = [c for c in delete_calls if c["timestamp"] >= cutoff]
        if len(delete_calls) >= mass_delete_threshold:
            evidence_ids = [c["event_id"] for c in delete_calls]
            candidate_signals.append(
                {
                    "detection_id": "D-DEF-06",
                    "strength": calc_strength(0.8),
                    "confidence": 0.95,
                    "evidence_event_ids": evidence_ids,
                    "mitre": ["T1485"],
                    "stage": Stage.impact,
                    "summary": f"Mass deletion burst ({len(delete_calls)} delete actions in 5 min) by {identity_id}",
                    "details": {
                        "count": len(delete_calls),
                        "window_seconds": mass_delete_window_seconds,
                    },
                }
            )

    # 7. D-DEF-07: Secret Harvesting
    # >= 5 GetSecretValue on distinct secrets in 10 min
    if action_lower == "getsecretvalue":
        secret_id = str(
            attrs.get("secretId")
            or attrs.get("secret_id")
            or attrs.get("requestParameters", {}).get("secretId")
            or event_dict.get("resource_arn")
            or ev_id
        )
        secret_calls.append({"event_id": ev_id, "secret_id": secret_id, "timestamp": curr_ts})
        cutoff = curr_ts - secret_harvest_window_seconds
        secret_calls[:] = [c for c in secret_calls if c["timestamp"] >= cutoff]

        distinct_secrets = {c["secret_id"] for c in secret_calls}
        if len(distinct_secrets) >= secret_harvest_threshold:
            evidence_ids = [c["event_id"] for c in secret_calls]
            candidate_signals.append(
                {
                    "detection_id": "D-DEF-07",
                    "strength": calc_strength(0.7),
                    "confidence": 0.9,
                    "evidence_event_ids": evidence_ids,
                    "mitre": ["T1555.006"],
                    "stage": Stage.credential_access,
                    "summary": f"Secret harvesting burst ({len(distinct_secrets)} distinct secrets in 10 min) by {identity_id}",
                    "details": {
                        "distinct_secrets_count": len(distinct_secrets),
                        "window_seconds": secret_harvest_window_seconds,
                    },
                }
            )

    return candidate_signals


class DefenseEvasion(Agent):
    """Agent 9: Defense Evasion & Impact detector (D-DEF-01 to D-DEF-07)."""

    num: ClassVar[int] = 9
    agent_id: ClassVar[str] = "agent09"
    name: ClassVar[str] = "evasion"
    layer: ClassVar[str] = "detection"
    subscribes: ClassVar[list[str]] = ["events.enriched"]
    publishes: ClassVar[list[str]] = ["signals", "deadletter"]
    path: ClassVar[str] = "hot"

    def init_state(self) -> dict[str, Any]:
        """Initialize state for tracking sliding delete and secret calls."""
        return {
            "delete_calls": {},
            "secret_calls": {},
            "recent_anomalies": {},
        }

    def has_prior_anomaly_in_24h(self, identity_id: str, state: dict[str, Any], ctx: AgentContext) -> bool:
        """Check if identity has any signal from agents 5–7 in the last 24 h."""
        now_dt = ctx.clock() if callable(ctx.clock) else ctx.clock.now()
        now_ts = now_dt.timestamp() if hasattr(now_dt, "timestamp") else 0.0

        # 1. Check in-memory index
        recent_ts = state.get("recent_anomalies", {}).get(identity_id)
        if recent_ts and (now_ts - recent_ts) <= 86400.0:
            return True

        # 2. Check store signals_v3 table if available
        try:
            db_path = getattr(ctx.store, "db_path", ctx.store) if ctx.store else None
            cutoff_iso = (now_dt - timedelta(hours=24)).isoformat()
            query = """
                SELECT 1 FROM signals_v3
                WHERE identity_id = ?
                  AND agent_num IN (5, 6, 7)
                  AND created_at >= ?
                LIMIT 1
            """
            row = store.fetch_one(query, (identity_id, cutoff_iso), db_path=db_path)
            if row:
                state.setdefault("recent_anomalies", {})[identity_id] = now_ts
                return True
        except (sqlite3.Error, OSError, ValueError, TypeError) as err:
            log.debug("Recent anomaly store query skipped: %s", err)

        return False

    def process(
        self,
        msg: Message,
        state: dict[str, Any],
        ctx: AgentContext,
    ) -> list[Message]:
        """Process incoming enriched events for defense evasion and impact."""
        if msg.topic != "events.enriched":
            return []

        payload = msg.payload
        if not isinstance(payload, EnrichedEvent):
            return []

        ev = payload.event
        cx = payload.context

        if isinstance(ev.time, str):
            try:
                event_ts = datetime.fromisoformat(ev.time).timestamp()
            except (ValueError, TypeError):
                now_dt = ctx.clock() if callable(ctx.clock) else ctx.clock.now()
                event_ts = now_dt.timestamp() if hasattr(now_dt, "timestamp") else 0.0
        elif hasattr(ev.time, "timestamp"):
            event_ts = ev.time.timestamp()
        else:
            now_dt = ctx.clock() if callable(ctx.clock) else ctx.clock.now()
            event_ts = now_dt.timestamp() if hasattr(now_dt, "timestamp") else 0.0

        event_dict: dict[str, Any] = {
            "event_id": ev.event_id,
            "identity_id": ev.identity_id,
            "raw_principal": ev.raw_principal,
            "session_id": ev.session_id,
            "action": ev.action,
            "event_class": ev.event_class,
            "outcome": ev.outcome,
            "resource_arn": ev.resource_arn,
            "attrs": ev.attrs,
            "timestamp": event_ts,
        }

        context_dict: dict[str, Any] = {
            "action_type": cx.action_type,
            "resource_sensitivity": cx.resource_sensitivity,
        }

        has_prior = self.has_prior_anomaly_in_24h(ev.identity_id, state, ctx)

        try:
            candidates = detect_defense_evasion(
                event_dict,
                context_dict,
                state,
                mass_delete_threshold=config.MASS_DELETE_COUNT,
                mass_delete_window_seconds=config.MASS_DELETE_WINDOW_MIN * 60.0,
                secret_harvest_threshold=config.SECRET_HARVEST_COUNT,
                secret_harvest_window_seconds=config.SECRET_HARVEST_WINDOW_MIN * 60.0,
                has_prior_anomaly=has_prior,
            )
        except Exception:
            log.exception("Error detecting defense evasion on event %s", ev.event_id)
            return []

        messages: list[Message] = []
        for cand in candidates:
            sig = Signal(
                signal_id=f"sig-{cand['detection_id'].lower()}-{uuid.uuid4().hex[:8]}",
                detection_id=cand["detection_id"],
                agent_num=self.num,
                identity_id=ev.identity_id,
                session_id=ev.session_id,
                strength=cand["strength"],
                confidence=cand["confidence"],
                evidence_event_ids=cand["evidence_event_ids"],
                mitre=cand["mitre"],
                stage=cand["stage"],
                summary=cand["summary"],
                details=cand.get("details", {}),
            )
            messages.append(
                ctx.new_message(
                    topic="signals",
                    payload=sig,
                    partition_key=ev.identity_id,
                    producer=self.agent_id,
                )
            )

        return messages
