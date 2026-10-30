"""Agent 11: Campaign Detector.

Detects multi-identity coordinated attacks:
- D-CMP-01: Password spray (one IP or ASN with failures on >= 10 identities in 10 min).
- D-CMP-02: Stuffing success (spray source then achieves a success on any targeted identity).
- D-CMP-03: Shared infrastructure (same IP, key, or UA hash used by >= 3 identities with signals in 24 h).

Emits a signal for every affected identity, sharing details.campaign_id.
Warm path, consumes events.enriched, signals; publishes signals, deadletter.
"""
from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import datetime
from typing import Any, ClassVar

from app.v3 import config
from app.v3.agents.base import Agent, AgentContext
from app.v3.models import (
    EnrichedEvent,
    EventClass,
    Message,
    Signal,
    Stage,
)

log = logging.getLogger(__name__)


def hash_ua(ua: str) -> str:
    """Compute truncated SHA-256 hash for User-Agent string."""
    if not ua:
        return "empty"
    return hashlib.sha256(ua.strip().encode("utf-8")).hexdigest()[:12]


def detect_campaign_anomalies(
    event_dict: dict[str, Any],
    context_dict: dict[str, Any],
    state: dict[str, Any],
    spray_min_users: int = 10,
    spray_window_seconds: float = 600.0,
    shared_infra_min_identities: int = 3,
) -> list[dict[str, Any]]:
    """Pure detection function for campaign anomalies (D-CMP-01 to D-CMP-03)."""
    ev_id = event_dict.get("event_id", "")
    identity_id = str(event_dict.get("identity_id") or "")
    action = str(event_dict.get("action", ""))
    outcome = str(event_dict.get("outcome", "")).lower()
    event_class = event_dict.get("event_class")
    src_ip = str(event_dict.get("src_ip", "") or "")
    user_agent = str(event_dict.get("user_agent", "") or "")
    curr_ts = float(event_dict.get("timestamp", 0.0))
    attrs = event_dict.get("attrs") or {}
    access_key_id = str(attrs.get("access_key_id") or attrs.get("created_access_key") or "")
    asn = context_dict.get("asn")

    ip_failures: dict[str, list[dict[str, Any]]] = state.setdefault("ip_failures", {})
    asn_failures: dict[int, list[dict[str, Any]]] = state.setdefault("asn_failures", {})
    active_sprays: dict[str, dict[str, Any]] = state.setdefault("active_sprays", {})
    shared_infra: dict[str, dict[str, float]] = state.setdefault("shared_infra", {})
    identities_with_signals: dict[str, float] = state.setdefault("identities_with_signals", {})
    emitted_campaigns: set[str] = state.setdefault("emitted_campaigns", set())

    candidate_signals: list[dict[str, Any]] = []

    is_auth = (
        event_class == EventClass.authentication
        or "login" in action.lower()
        or "authenticate" in action.lower()
        or "session.start" in action.lower()
    )

    is_failure = outcome in ("failure", "deny", "denied", "failed", "error")
    is_success = outcome in ("success", "successful")

    # 1. Track Failures for D-CMP-01 (Password Spray)
    if is_auth and is_failure and identity_id:
        # 1a. IP failures
        ip_spray_emitted = False
        if src_ip:
            failures = ip_failures.setdefault(src_ip, [])
            failures.append({"identity_id": identity_id, "timestamp": curr_ts, "event_id": ev_id})
            cutoff = curr_ts - spray_window_seconds
            ip_failures[src_ip] = [f for f in failures if f["timestamp"] >= cutoff]

            unique_targets = {f["identity_id"] for f in ip_failures[src_ip]}
            if len(unique_targets) >= spray_min_users:
                campaign_id = f"cmp-spray-ip-{src_ip}"
                evidence_ids = [f["event_id"] for f in ip_failures[src_ip]]
                active_sprays[src_ip] = {
                    "campaign_id": campaign_id,
                    "timestamp": curr_ts,
                    "targets": unique_targets,
                    "evidence_ids": evidence_ids,
                }

                # Emit once per spray window bucket
                if campaign_id not in emitted_campaigns:
                    ip_spray_emitted = True
                    emitted_campaigns.add(campaign_id)
                    for target_ident in unique_targets:
                        target_evs = [f["event_id"] for f in ip_failures[src_ip] if f["identity_id"] == target_ident]
                        candidate_signals.append(
                            {
                                "detection_id": "D-CMP-01",
                                "identity_id": target_ident,
                                "strength": 0.6,
                                "confidence": 0.95,
                                "evidence_event_ids": target_evs or [ev_id],
                                "mitre": ["T1110.003"],
                                "stage": Stage.credential_access,
                                "summary": f"Password spray attack detected from IP {src_ip} targeting {len(unique_targets)} accounts",
                                "details": {
                                    "campaign_id": campaign_id,
                                    "src_ip": src_ip,
                                    "unique_targets_count": len(unique_targets),
                                    "targets": list(unique_targets),
                                },
                            }
                        )

        # 1b. ASN failures
        if asn is not None and not ip_spray_emitted:
            a_failures = asn_failures.setdefault(asn, [])
            a_failures.append({"identity_id": identity_id, "timestamp": curr_ts, "event_id": ev_id})
            cutoff = curr_ts - spray_window_seconds
            asn_failures[asn] = [f for f in a_failures if f["timestamp"] >= cutoff]

            a_unique_targets = {f["identity_id"] for f in asn_failures[asn]}
            if len(a_unique_targets) >= spray_min_users:
                campaign_id = f"cmp-spray-asn-{asn}"
                evidence_ids = [f["event_id"] for f in asn_failures[asn]]
                active_sprays[f"asn-{asn}"] = {
                    "campaign_id": campaign_id,
                    "timestamp": curr_ts,
                    "targets": a_unique_targets,
                    "evidence_ids": evidence_ids,
                }
                if campaign_id not in emitted_campaigns:
                    emitted_campaigns.add(campaign_id)
                    for target_ident in a_unique_targets:
                        target_evs = [f["event_id"] for f in asn_failures[asn] if f["identity_id"] == target_ident]
                        candidate_signals.append(
                            {
                                "detection_id": "D-CMP-01",
                                "identity_id": target_ident,
                                "strength": 0.6,
                                "confidence": 0.9,
                                "evidence_event_ids": target_evs or [ev_id],
                                "mitre": ["T1110.003"],
                                "stage": Stage.credential_access,
                                "summary": f"Password spray attack detected from ASN {asn} targeting {len(a_unique_targets)} accounts",
                                "details": {
                                    "campaign_id": campaign_id,
                                    "asn": asn,
                                    "unique_targets_count": len(a_unique_targets),
                                },
                            }
                        )

    # 2. D-CMP-02: Stuffing Success (Spray source then succeeds on any targeted identity)
    if is_auth and is_success and identity_id:
        spray_match = None
        if src_ip in active_sprays:
            spray_match = active_sprays[src_ip]
        elif asn is not None and f"asn-{asn}" in active_sprays:
            spray_match = active_sprays[f"asn-{asn}"]

        if spray_match and (curr_ts - spray_match["timestamp"]) <= 3600.0:
            campaign_id = spray_match["campaign_id"]
            stuffing_key = f"stuffing-{campaign_id}-{identity_id}"
            if stuffing_key not in emitted_campaigns:
                emitted_campaigns.add(stuffing_key)
                evidence = list(set([ev_id] + spray_match["evidence_ids"][:5]))
                candidate_signals.append(
                    {
                        "detection_id": "D-CMP-02",
                        "identity_id": identity_id,
                        "strength": 0.85,
                        "confidence": 0.95,
                        "evidence_event_ids": evidence,
                        "mitre": ["T1110.004"],
                        "stage": Stage.initial_access,
                        "summary": f"Credential stuffing success on {identity_id} from spray source ({src_ip or asn})",
                        "details": {
                            "campaign_id": campaign_id,
                            "src_ip": src_ip,
                            "asn": asn,
                        },
                    }
                )

    # 3. D-CMP-03: Shared Infrastructure (Same IP, key, or UA hash across >= 3 identities with signals in 24 h)
    # Check infrastructure keys if identity has signals
    if identity_id and identities_with_signals.get(identity_id):
        keys_to_track: list[tuple[str, str]] = []
        if src_ip:
            keys_to_track.append(("ip", src_ip))
        if access_key_id:
            keys_to_track.append(("key", access_key_id))
        if user_agent:
            keys_to_track.append(("ua", hash_ua(user_agent)))

        for k_type, k_val in keys_to_track:
            infra_key = f"{k_type}:{k_val}"
            ident_records = shared_infra.setdefault(infra_key, {})
            ident_records[identity_id] = curr_ts

            # Prune > 24 h
            cutoff_24h = curr_ts - 86400.0
            active_idents = {i for i, ts in ident_records.items() if ts >= cutoff_24h}

            if len(active_idents) >= shared_infra_min_identities:
                campaign_id = f"cmp-infra-{k_type}-{k_val}"
                if campaign_id not in emitted_campaigns:
                    emitted_campaigns.add(campaign_id)
                    for target_ident in active_idents:
                        candidate_signals.append(
                            {
                                "detection_id": "D-CMP-03",
                                "identity_id": target_ident,
                                "strength": 0.5,
                                "confidence": 0.85,
                                "evidence_event_ids": [ev_id],
                                "mitre": ["T1078"],
                                "stage": Stage.initial_access,
                                "summary": f"Shared attack infrastructure ({k_type} {k_val}) used across {len(active_idents)} compromised accounts",
                                "details": {
                                    "campaign_id": campaign_id,
                                    "infra_type": k_type,
                                    "infra_value": k_val,
                                    "shared_identities": list(active_idents),
                                },
                            }
                        )

    return candidate_signals


class Campaign(Agent):
    """Agent 11: Campaign detector (D-CMP-01 to D-CMP-03)."""

    num: ClassVar[int] = 11
    agent_id: ClassVar[str] = "agent11"
    name: ClassVar[str] = "campaign"
    layer: ClassVar[str] = "detection"
    subscribes: ClassVar[list[str]] = ["events.enriched", "signals"]
    publishes: ClassVar[list[str]] = ["signals", "deadletter"]
    path: ClassVar[str] = "warm"

    def init_state(self) -> dict[str, Any]:
        """Initialize in-memory sliding windows for campaign tracking."""
        return {
            "ip_failures": {},
            "asn_failures": {},
            "active_sprays": {},
            "shared_infra": {},
            "identities_with_signals": {},
            "emitted_campaigns": set(),
        }

    def process(
        self,
        msg: Message,
        state: dict[str, Any],
        ctx: AgentContext,
    ) -> list[Message]:
        """Process enriched events and signals for multi-account campaign activity."""
        now_dt = ctx.clock() if callable(ctx.clock) else ctx.clock.now()
        now_ts = now_dt.timestamp() if hasattr(now_dt, "timestamp") else 0.0

        # When a Signal message arrives, record identity in identities_with_signals
        if msg.topic == "signals":
            payload = msg.payload
            if isinstance(payload, Signal) and payload.identity_id:
                state.setdefault("identities_with_signals", {})[payload.identity_id] = now_ts
            return []

        if msg.topic != "events.enriched":
            return []

        payload = msg.payload
        if not isinstance(payload, EnrichedEvent):
            return []

        ev = payload.event
        cx = payload.context

        event_ts = now_ts
        if isinstance(ev.time, str):
            try:
                event_ts = datetime.fromisoformat(ev.time).timestamp()
            except (ValueError, TypeError):
                pass
        elif hasattr(ev.time, "timestamp"):
            event_ts = ev.time.timestamp()

        event_dict: dict[str, Any] = {
            "event_id": ev.event_id,
            "identity_id": ev.identity_id,
            "raw_principal": ev.raw_principal,
            "session_id": ev.session_id,
            "action": ev.action,
            "event_class": ev.event_class,
            "outcome": ev.outcome,
            "src_ip": ev.src_ip,
            "user_agent": ev.user_agent,
            "attrs": ev.attrs,
            "timestamp": event_ts,
        }

        context_dict: dict[str, Any] = {
            "asn": cx.asn,
            "action_type": cx.action_type,
        }

        try:
            candidates = detect_campaign_anomalies(
                event_dict,
                context_dict,
                state,
                spray_min_users=config.SPRAY_MIN_USERS,
                spray_window_seconds=config.SPRAY_WINDOW_MINUTES * 60.0,
                shared_infra_min_identities=config.SHARED_INFRA_MIN_IDENTITIES,
            )
        except Exception:
            log.exception("Error detecting campaign anomalies on event %s", ev.event_id)
            return []

        messages: list[Message] = []
        for cand in candidates:
            ident = cand["identity_id"]
            sig = Signal(
                signal_id=f"sig-{cand['detection_id'].lower()}-{uuid.uuid4().hex[:8]}",
                detection_id=cand["detection_id"],
                agent_num=self.num,
                identity_id=ident,
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
                    partition_key=ident,
                    producer=self.agent_id,
                )
            )

        return messages
