"""Agent 7: Credential Lifecycle.

Detects misuse of keys, dormant accounts, and instance credentials:
- D-CRD-01: Dormant account wakes (>= 30 days inactivity followed by write).
- D-CRD-02: Key created for another user (CreateAccessKey target user != caller).
- D-CRD-03: New key from new place (created and first used from new IP/ASN within 60 min).
- D-CRD-04: Instance credential misuse (EC2 instance role used from non-AWS IP or unexpected VPC endpoint).
- D-CRD-05: Login profile change for another user (CreateLoginProfile/UpdateLoginProfile target != caller).

Warm path, consumes events.enriched, sessions, graph.updates; publishes signals, deadletter.
"""
from __future__ import annotations

import logging
import re
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, ClassVar

import yaml

from app.v3 import config
from app.v3.agents.base import Agent, AgentContext
from app.v3.models import (
    ActionType,
    EnrichedEvent,
    Message,
    Signal,
    Stage,
)

log = logging.getLogger(__name__)

AWS_HOSTING_ASNS = {16509, 14618}
EC2_SESSION_PATTERN = re.compile(r"i-[0-9a-fA-F]{8,17}")


def load_expected_vpce(file_path: Path | str | None = None) -> dict[str, list[str]]:
    """Load optional expected VPC endpoint baseline mapping."""
    if file_path is None:
        file_path = Path(__file__).resolve().parent.parent / "data" / "expected_vpce.yaml"
    p = Path(file_path)
    if not p.is_file():
        return {}
    try:
        with open(p, encoding="utf-8") as f:
            data = yaml.safe_load(f)
            return data if isinstance(data, dict) else {}
    except (yaml.YAMLError, OSError, ValueError):
        log.warning("Could not load expected VPC endpoints from %s", p)
        return {}


def is_ec2_instance_role(event_dict: dict[str, Any]) -> bool:
    """Determine whether the event is from an EC2 instance role."""
    raw_principal = str(event_dict.get("raw_principal", "")).lower()
    session_id = str(event_dict.get("session_id", "") or "")
    identity_id = str(event_dict.get("identity_id", "")).lower()
    attrs = event_dict.get("attrs") or {}

    if "ec2.amazonaws.com" in raw_principal:
        return True
    if EC2_SESSION_PATTERN.search(session_id) or EC2_SESSION_PATTERN.search(raw_principal):
        return True
    if attrs.get("user_identity_type") == "AssumedRole":
        issuer = str(attrs.get("session_issuer") or "").lower()
        if "ec2" in issuer or "instance" in issuer or "instance-profile" in raw_principal:
            return True
    return bool("i-" in identity_id and EC2_SESSION_PATTERN.search(identity_id))


def detect_credential_anomalies(
    event_dict: dict[str, Any],
    context_dict: dict[str, Any],
    state: dict[str, Any],
    dormant_days: int = 30,
    new_key_window_seconds: float = 3600.0,
    expected_vpce_map: dict[str, list[str]] | None = None,
) -> list[dict[str, Any]]:
    """Pure detection function for credential anomalies (D-CRD-01 to D-CRD-05)."""
    ev_id = event_dict.get("event_id", "")
    identity_id = event_dict.get("identity_id", "")
    raw_principal = event_dict.get("raw_principal", "")
    action = event_dict.get("action", "")
    outcome = event_dict.get("outcome", "").lower()
    src_ip = event_dict.get("src_ip", "")
    curr_ts = float(event_dict.get("timestamp", 0.0))
    attrs = event_dict.get("attrs") or {}
    read_only = event_dict.get("read_only", False)
    action_type = context_dict.get("action_type")
    asn = context_dict.get("asn")

    candidate_signals: list[dict[str, Any]] = []

    last_seen_map = state.setdefault("last_seen", {})
    created_keys = state.setdefault("created_keys", {})
    seen_asns = state.setdefault("seen_asns", {})
    vpce_learned = state.setdefault("vpce_learned", {})
    vpce_counts = state.setdefault("vpce_counts", {})

    if identity_id and asn is not None:
        seen_asns.setdefault(identity_id, set()).add(asn)

    # 1. D-CRD-01: Dormant Account Wakes
    # No activity >= 30 days, then success + any write
    if identity_id:
        if identity_id in last_seen_map:
            prev_ts = last_seen_map[identity_id]
            gap_seconds = curr_ts - prev_ts
            is_success = outcome in ("success", "successful")
            is_write = (not read_only) or action_type in (
                ActionType.write,
                ActionType.permission_change,
                ActionType.credential_change,
                ActionType.destructive,
            )
            if gap_seconds >= dormant_days * 86400 and is_success and is_write:
                candidate_signals.append(
                    {
                        "detection_id": "D-CRD-01",
                        "strength": 0.5,
                        "confidence": 0.9,
                        "evidence_event_ids": [ev_id],
                        "mitre": ["T1078.004"],
                        "stage": Stage.initial_access,
                        "summary": f"Dormant account {identity_id} awakened with write activity after {gap_seconds / 86400:.1f} days",
                        "details": {
                            "days_inactive": round(gap_seconds / 86400, 1),
                            "action": action,
                        },
                    }
                )
        last_seen_map[identity_id] = curr_ts

    # 2. D-CRD-02: Key Created for Another User
    # CreateAccessKey where target user != caller
    if action.lower() == "createaccesskey":
        target_user = attrs.get("target_user") or attrs.get("userName") or ""
        caller_name = identity_id or raw_principal
        if target_user and caller_name and target_user.lower() != caller_name.lower():
            candidate_signals.append(
                {
                    "detection_id": "D-CRD-02",
                    "strength": 0.7,
                    "confidence": 0.95,
                    "evidence_event_ids": [ev_id],
                    "mitre": ["T1098.001"],
                    "stage": Stage.privilege_escalation,
                    "summary": f"Access key created for another user ({target_user}) by caller ({caller_name})",
                    "details": {
                        "target_user": target_user,
                        "caller": caller_name,
                    },
                }
            )

        # Track created key for D-CRD-03
        created_key_id = attrs.get("created_access_key") or attrs.get("access_key_id")
        if created_key_id and outcome in ("success", "successful"):
            created_keys[created_key_id] = {
                "owner": target_user or identity_id,
                "created_ts": curr_ts,
                "ip": src_ip,
                "asn": asn,
                "used": False,
            }

    # 3. D-CRD-03: New Key From New Place
    # Key created and first used from an IP/ASN never seen for the owner within 60 min
    used_key_id = attrs.get("access_key_id")
    if used_key_id and used_key_id in created_keys:
        rec = created_keys[used_key_id]
        if not rec.get("used"):
            rec["used"] = True
            time_delta = curr_ts - rec["created_ts"]
            if 0 <= time_delta <= new_key_window_seconds:
                owner = rec["owner"]
                owner_known_asns = seen_asns.get(owner, set())
                ip_differs = bool(src_ip and rec["ip"] and src_ip != rec["ip"])
                asn_differs = bool(asn is not None and rec["asn"] is not None and asn != rec["asn"])
                asn_is_new = bool(asn is not None and asn not in owner_known_asns)
                if ip_differs and (asn_differs or asn_is_new):
                    candidate_signals.append(
                        {
                            "detection_id": "D-CRD-03",
                            "strength": 0.6,
                            "confidence": 0.85,
                            "evidence_event_ids": [ev_id],
                            "mitre": ["T1098.001"],
                            "stage": Stage.credential_access,
                            "summary": f"New access key {used_key_id} used within {time_delta / 60:.1f} min from new network ({src_ip}, ASN {asn})",
                            "details": {
                                "key_id": used_key_id,
                                "owner": owner,
                                "created_ip": rec["ip"],
                                "used_ip": src_ip,
                                "created_asn": rec["asn"],
                                "used_asn": asn,
                            },
                        }
                    )

    # 4. D-CRD-04: Instance Credential Misuse
    # EC2 instance role session used from non-AWS IP or unexpected VPC endpoint ID
    if is_ec2_instance_role(event_dict):
        # 4a: Non-AWS IP
        is_private_ip = bool(
            src_ip.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "127.", "::1", "fe80:"))
        )
        if src_ip and not is_private_ip and asn is not None and asn not in AWS_HOSTING_ASNS:
            candidate_signals.append(
                {
                    "detection_id": "D-CRD-04",
                    "strength": 0.85,
                    "confidence": 0.95,
                    "evidence_event_ids": [ev_id],
                    "mitre": ["T1552.005"],
                    "stage": Stage.credential_access,
                    "summary": f"EC2 instance role credentials used from non-AWS network (IP {src_ip}, ASN {asn})",
                    "details": {
                        "src_ip": src_ip,
                        "asn": asn,
                        "role": identity_id or raw_principal,
                    },
                }
            )

        # 4b: Unexpected VPC Endpoint ID
        vpce_id = attrs.get("vpc_endpoint_id")
        if vpce_id:
            lookup_key = identity_id or raw_principal
            if expected_vpce_map and lookup_key in expected_vpce_map:
                allowed = set(expected_vpce_map[lookup_key])
                if vpce_id not in allowed:
                    candidate_signals.append(
                        {
                            "detection_id": "D-CRD-04",
                            "strength": 0.85,
                            "confidence": 0.95,
                            "evidence_event_ids": [ev_id],
                            "mitre": ["T1552.005"],
                            "stage": Stage.credential_access,
                            "summary": f"EC2 instance credential used via unexpected VPC endpoint {vpce_id} (allowed: {allowed})",
                            "details": {
                                "vpc_endpoint_id": vpce_id,
                                "allowed": list(allowed),
                            },
                        }
                    )
            else:
                # Learned baseline from first 20 events
                counts = vpce_counts.get(lookup_key, 0)
                learned = vpce_learned.setdefault(lookup_key, set())
                if counts < 20:
                    learned.add(vpce_id)
                    vpce_counts[lookup_key] = counts + 1
                elif vpce_id not in learned:
                    candidate_signals.append(
                        {
                            "detection_id": "D-CRD-04",
                            "strength": 0.85,
                            "confidence": 0.9,
                            "evidence_event_ids": [ev_id],
                            "mitre": ["T1552.005"],
                            "stage": Stage.credential_access,
                            "summary": f"EC2 instance credential used via foreign VPC endpoint {vpce_id} outside learned baseline",
                            "details": {
                                "vpc_endpoint_id": vpce_id,
                                "baseline": list(learned),
                            },
                        }
                    )

    # 5. D-CRD-05: Login Profile Change for Another User
    # CreateLoginProfile / UpdateLoginProfile on a different user
    if action.lower() in ("createloginprofile", "updateloginprofile"):
        target_user = attrs.get("target_user") or attrs.get("userName") or ""
        caller_name = identity_id or raw_principal
        if target_user and caller_name and target_user.lower() != caller_name.lower():
            candidate_signals.append(
                {
                    "detection_id": "D-CRD-05",
                    "strength": 0.7,
                    "confidence": 0.9,
                    "evidence_event_ids": [ev_id],
                    "mitre": ["T1098"],
                    "stage": Stage.privilege_escalation,
                    "summary": f"Login profile changed for target user ({target_user}) by caller ({caller_name})",
                    "details": {
                        "target_user": target_user,
                        "caller": caller_name,
                        "action": action,
                    },
                }
            )

    return candidate_signals


class CredentialLifecycle(Agent):
    """Agent 7: Credential Lifecycle detector (D-CRD-01 to D-CRD-05)."""

    num: ClassVar[int] = 7
    agent_id: ClassVar[str] = "agent07"
    name: ClassVar[str] = "credentials"
    layer: ClassVar[str] = "detection"
    subscribes: ClassVar[list[str]] = ["events.enriched", "sessions", "graph.updates"]
    publishes: ClassVar[list[str]] = ["signals", "deadletter"]
    path: ClassVar[str] = "warm"

    def __init__(self, vpce_config_path: Path | str | None = None) -> None:
        self.expected_vpce = load_expected_vpce(vpce_config_path)

    def init_state(self) -> dict[str, Any]:
        """Initialize state for tracking identities, keys, and VPC baselines."""
        return {
            "last_seen": {},
            "created_keys": {},
            "seen_asns": {},
            "vpce_learned": {},
            "vpce_counts": {},
        }

    def process(
        self,
        msg: Message,
        state: dict[str, Any],
        ctx: AgentContext,
    ) -> list[Message]:
        """Process enriched events or sessions for credential misuse."""
        if msg.topic != "events.enriched":
            return []

        payload = msg.payload
        if not isinstance(payload, EnrichedEvent):
            return []

        ev = payload.event
        cx = payload.context

        # Convert Event time to epoch float
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
            "src_ip": ev.src_ip,
            "user_agent": ev.user_agent,
            "read_only": ev.read_only,
            "attrs": ev.attrs,
            "timestamp": event_ts,
        }

        context_dict: dict[str, Any] = {
            "asn": cx.asn,
            "is_hosting": cx.is_hosting,
            "action_type": cx.action_type,
            "privilege_level": cx.privilege_level,
        }

        try:
            candidates = detect_credential_anomalies(
                event_dict,
                context_dict,
                state,
                dormant_days=config.DORMANT_DAYS,
                new_key_window_seconds=config.NEW_KEY_WINDOW_MINUTES * 60.0,
                expected_vpce_map=self.expected_vpce,
            )
        except Exception:
            log.exception("Error detecting credential anomalies on event %s", ev.event_id)
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
