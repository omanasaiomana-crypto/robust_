"""Agent 6: Session & Token Integrity Detector for IdentityShield v3.

Follows context.md Section 7, 12, 13 and PRD §12, §13.1:
- Subscribes: events.enriched, sessions
- Publishes: signals, deadletter
- Tracks per-session fingerprint (first ip, asn, ua family, device, has_mfa)
- Tracks per-identity MFA push history (window 10 minutes)
- Detections D-SES-01..04:
  - D-SES-01: Token replay when same session appears from new ASN without re-auth (strength 0.8; IP change in same ASN = 0.3)
  - D-SES-02: MFA fatigue (>= 5 denied pushes in 10 min followed by accept -> 0.85; evidence = all denies + accept)
  - D-SES-03: UA family and device change mid-session (strength capped at 0.2; UA is weak)
  - D-SES-04: Privileged session (>= 4) without MFA event (strength 0.5)
"""
import logging
import uuid
from typing import Any, ClassVar

from app.v3 import config
from app.v3.agents.base import Agent, AgentContext
from app.v3.models import (
    EnrichedEvent,
    EventClass,
    Message,
    Session,
    Signal,
    Stage,
)

log = logging.getLogger(__name__)


def parse_ua_family(ua: str) -> str:
    """Classify user agent into high-level browser/tool family."""
    if not ua:
        return "unknown"
    s = ua.lower()
    if "edg" in s:
        return "Edge"
    if "chrome" in s:
        return "Chrome"
    if "firefox" in s:
        return "Firefox"
    if "safari" in s:
        return "Safari"
    if "curl" in s:
        return "curl"
    if "boto3" in s or "python" in s:
        return "python/boto3"
    if "aws-cli" in s:
        return "aws-cli"
    return "other"


def detect_session_anomalies(
    event_dict: dict[str, Any],
    context_dict: dict[str, Any],
    fingerprint: dict[str, Any] | None,
    mfa_history: list[dict[str, Any]],
    mfa_fatigue_denies: int = 5,
    mfa_window_seconds: float = 600.0,
) -> list[dict[str, Any]]:
    """Pure detection function for session anomalies (D-SES-01 to D-SES-04)."""
    ev_id = event_dict.get("event_id", "")
    identity_id = event_dict.get("identity_id", "")
    session_id = event_dict.get("session_id")
    action = event_dict.get("action", "")
    outcome = event_dict.get("outcome", "").lower()
    src_ip = event_dict.get("src_ip", "")
    user_agent = event_dict.get("user_agent", "")
    curr_ts = event_dict.get("timestamp", 0.0)

    asn = context_dict.get("asn")
    privilege_level = int(context_dict.get("privilege_level", 1))

    candidate_signals: list[dict[str, Any]] = []

    # 1. D-SES-02: MFA Fatigue Check
    # Check if this is an MFA accept
    is_mfa_accept = False
    if "mfa" in action.lower() or "verify" in action.lower():
        if outcome in ("success", "successful"):
            is_mfa_accept = True
    elif (
        event_dict.get("event_class") == EventClass.authentication
        and outcome in ("success", "successful")
        and any(p.get("outcome") == "deny" for p in mfa_history)
    ):
        is_mfa_accept = True

    if is_mfa_accept and mfa_history:
        # Check denies in window
        cutoff = curr_ts - mfa_window_seconds
        recent_denies = [
            p for p in mfa_history
            if p.get("outcome") == "deny" and p.get("timestamp", 0.0) >= cutoff
        ]
        if len(recent_denies) >= mfa_fatigue_denies:
            evidence_ids = [d["event_id"] for d in recent_denies] + [ev_id]
            candidate_signals.append(
                {
                    "detection_id": "D-SES-02",
                    "strength": 0.85,
                    "confidence": 0.95,
                    "evidence_event_ids": evidence_ids,
                    "mitre": ["T1621"],
                    "stage": Stage.credential_access,
                    "summary": f"MFA fatigue: {len(recent_denies)} denied pushes within {int(mfa_window_seconds / 60)} min followed by an accept for {identity_id}",
                    "details": {
                        "denied_count": len(recent_denies),
                        "window_minutes": int(mfa_window_seconds / 60),
                        "accept_event_id": ev_id,
                    },
                }
            )

    # 2. Existing Session Checks (D-SES-01, D-SES-03, D-SES-04)
    if fingerprint is not None:
        first_ev_id = fingerprint.get("first_event_id", ev_id)
        fp_ip = fingerprint.get("ip")
        fp_asn = fingerprint.get("asn")
        fp_device = fingerprint.get("device", "")
        fp_family = fingerprint.get("ua_family", "")
        has_mfa = bool(fingerprint.get("has_mfa", False))

        # Check if event is re-authentication
        is_reauth = (
            action in ("user.session.start", "user.authentication.auth_via_mfa", "user.authentication.verify")
            and outcome == "success"
        )

        # D-SES-01: Token Replay
        if not is_reauth and session_id:
            # Check ASN change
            if asn is not None and fp_asn is not None and asn != fp_asn:
                candidate_signals.append(
                    {
                        "detection_id": "D-SES-01",
                        "strength": 0.8,
                        "confidence": 0.9,
                        "evidence_event_ids": [first_ev_id, ev_id],
                        "mitre": ["T1550.004", "T1539"],
                        "stage": Stage.credential_access,
                        "summary": f"Token replay: session {session_id} used from new ASN (AS{asn} vs initial AS{fp_asn}) without re-auth",
                        "details": {
                            "initial_asn": fp_asn,
                            "current_asn": asn,
                            "initial_ip": fp_ip,
                            "current_ip": src_ip,
                        },
                    }
                )
            # Check IP change within same ASN
            elif src_ip and fp_ip and src_ip != fp_ip:
                candidate_signals.append(
                    {
                        "detection_id": "D-SES-01",
                        "strength": 0.3,
                        "confidence": 0.8,
                        "evidence_event_ids": [first_ev_id, ev_id],
                        "mitre": ["T1550.004", "T1539"],
                        "stage": Stage.credential_access,
                        "summary": f"Token replay: session {session_id} IP changed ({src_ip} vs initial {fp_ip}) within ASN without re-auth",
                        "details": {
                            "initial_ip": fp_ip,
                            "current_ip": src_ip,
                            "asn": asn,
                        },
                    }
                )

        # D-SES-03: Session Fingerprint Drift (UA change)
        if not is_reauth and user_agent and fp_device and user_agent != fp_device:
            curr_family = parse_ua_family(user_agent)
            if curr_family != fp_family:
                candidate_signals.append(
                    {
                        "detection_id": "D-SES-03",
                        "strength": 0.2,  # capped at 0.2
                        "confidence": 0.6,
                        "evidence_event_ids": [first_ev_id, ev_id],
                        "mitre": ["T1550"],
                        "stage": Stage.credential_access,
                        "summary": f"Session fingerprint drift: client changed mid-session ({curr_family} vs initial {fp_family})",
                        "details": {
                            "initial_device": fp_device[:100],
                            "current_device": user_agent[:100],
                            "initial_family": fp_family,
                            "current_family": curr_family,
                        },
                    }
                )

        # D-SES-04: Privileged session without MFA
        if privilege_level >= 4 and not has_mfa:
            candidate_signals.append(
                {
                    "detection_id": "D-SES-04",
                    "strength": 0.5,
                    "confidence": 0.85,
                    "evidence_event_ids": [ev_id],
                    "mitre": ["T1556"],
                    "stage": Stage.initial_access,
                    "summary": f"Privileged session (level {privilege_level}) active without required MFA for {identity_id}",
                    "details": {
                        "privilege_level": privilege_level,
                        "session_id": session_id,
                    },
                }
            )

    return candidate_signals


class SessionTokenIntegrity(Agent):
    """Agent 6: Session and Token Integrity Detector."""

    num = 6
    agent_id = "a06"
    name = "Session & Token Integrity"
    layer = "detection"
    subscribes: ClassVar[list[str]] = ["events.enriched", "sessions"]
    publishes: ClassVar[list[str]] = ["signals", "deadletter"]
    path = "hot"

    def init_state(self) -> dict[str, Any]:
        return {
            "session_fingerprints": {},  # session_id -> dict
            "mfa_pushes": {},  # identity_id -> list[dict]
        }

    def process(
        self,
        msg: Message,
        state: dict[str, Any],
        ctx: AgentContext,
    ) -> list[Message]:
        # Handle Session messages to record initial session metadata
        if isinstance(msg.payload, Session):
            sess: Session = msg.payload
            s_id = sess.session_id
            fps = state["session_fingerprints"]
            if s_id not in fps and sess.ips:
                first_ev = sess.event_ids[0] if sess.event_ids else f"sess-{s_id}"
                fps[s_id] = {
                    "first_event_id": first_ev,
                    "ip": sess.ips[0],
                    "asn": sess.asns[0] if sess.asns else None,
                    "ua_family": parse_ua_family(sess.devices[0]) if sess.devices else "unknown",
                    "device": sess.devices[0] if sess.devices else "",
                    "has_mfa": False,
                }
            return []

        if not isinstance(msg.payload, EnrichedEvent):
            return []

        enriched: EnrichedEvent = msg.payload
        ev = enriched.event
        c = enriched.context

        now_dt = ctx.clock() if callable(ctx.clock) else ctx.clock.now()
        ts = now_dt.timestamp() if hasattr(now_dt, "timestamp") else 0.0

        session_id = ev.session_id or ev.attrs.get("external_session_id") or ev.attrs.get("okta_session_id")
        fps = state["session_fingerprints"]
        mfa_history = state["mfa_pushes"].setdefault(ev.identity_id, [])

        event_dict = {
            "event_id": ev.event_id,
            "identity_id": ev.identity_id,
            "session_id": session_id,
            "action": ev.action,
            "event_class": ev.event_class,
            "outcome": ev.outcome,
            "src_ip": ev.src_ip,
            "user_agent": ev.user_agent,
            "timestamp": ts,
        }
        context_dict = {
            "asn": c.asn,
            "privilege_level": c.privilege_level,
        }

        # Check existing fingerprint
        fp = fps.get(session_id) if session_id else None

        # Run pure detection
        candidates = detect_session_anomalies(
            event_dict,
            context_dict,
            fp,
            mfa_history,
            mfa_fatigue_denies=getattr(ctx.settings, "mfa_fatigue_denies", config.MFA_FATIGUE_DENIES),
            mfa_window_seconds=getattr(ctx.settings, "mfa_window_minutes", config.MFA_WINDOW_MINUTES) * 60.0,
        )

        # Update MFA push tracking if MFA event
        is_mfa_event = (
            "mfa" in ev.action.lower()
            or "verify" in ev.action.lower()
            or "push" in ev.action.lower()
            or ev.attrs.get("mfa_result") is not None
        )
        if is_mfa_event:
            res_outcome = "deny" if (ev.outcome in ("deny", "failure") or ev.attrs.get("mfa_result") == "DENY") else "success"
            mfa_history.append(
                {
                    "event_id": ev.event_id,
                    "timestamp": ts,
                    "outcome": res_outcome,
                }
            )
            # Prune old pushes (> 1 hour)
            state["mfa_pushes"][ev.identity_id] = [p for p in mfa_history if (ts - p["timestamp"]) <= 3600.0]

            # Mark session has_mfa if accepted
            if res_outcome == "success" and fp is not None:
                fp["has_mfa"] = True

        # If new session, establish initial fingerprint
        if session_id and session_id not in fps:
            has_mfa = (
                ev.action in ("user.authentication.auth_via_mfa", "user.authentication.verify")
                or ev.attrs.get("mfa_result") == "SUCCESS"
            )
            fps[session_id] = {
                "first_event_id": ev.event_id,
                "ip": ev.src_ip,
                "asn": c.asn,
                "ua_family": parse_ua_family(ev.user_agent),
                "device": ev.user_agent,
                "has_mfa": has_mfa,
            }

        out_messages: list[Message] = []
        for cand in candidates:
            sig = Signal(
                signal_id=f"sig-{uuid.uuid4().hex[:12]}",
                detection_id=cand["detection_id"],
                agent_num=self.num,
                identity_id=ev.identity_id,
                session_id=session_id,
                strength=cand["strength"],
                confidence=cand["confidence"],
                evidence_event_ids=cand["evidence_event_ids"],
                mitre=cand["mitre"],
                stage=cand["stage"],
                summary=cand["summary"],
                details=cand["details"],
            )
            out_messages.append(
                ctx.new_message(topic="signals", payload=sig, partition_key=ev.identity_id, producer=self.agent_id)
            )

        return out_messages
