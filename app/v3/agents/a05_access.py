"""Agent 5: Access Anomaly Detector for IdentityShield v3.

Follows context.md Section 7, 12, 13 and PRD §12, §13.1:
- Subscribes: events.enriched, sessions
- Publishes: signals, deadletter
- Tracks per-identity login history (last 30 successful logins: lat/lon, asn, device, hour)
- Detections D-ACC-01..04:
  - D-ACC-01: Impossible travel (speed > 900 km/h, distance > 500 km); strength = min(1, 0.7 * (speed / MAX_SPEED_KMH))
  - D-ACC-02: New device or ASN (0.4; 0.5 if both new); suppressed on trusted IPs
  - D-ACC-03: Unusual hour outside 5th-95th percentile window (0.25 scaled)
  - D-ACC-04: Anonymizing network on privileged identity (0.5 for privilege_level >= 4); suppressed on trusted IPs
- Cold start (< 5 logins): confidence * 0.6
"""
import logging
import math
import uuid
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


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculate the great-circle distance between two points in kilometers."""
    r = 6371.0  # Earth radius in kilometers
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)

    a = math.sin(dphi / 2.0) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2.0) ** 2
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
    return r * c


def _parse_hour(time_str: str) -> int:
    """Extract hour (0-23) from ISO timestamp."""
    try:
        s = time_str.strip()
        if "T" in s:
            return int(s.split("T")[1].split(":")[0])
    except (ValueError, IndexError):
        pass
    return 12


def detect_access_anomalies(
    event_dict: dict[str, Any],
    context_dict: dict[str, Any],
    history: list[dict[str, Any]],
    peer_history: list[dict[str, Any]] | None = None,
    max_speed_kmh: float = 900.0,
    min_distance_km: float = 500.0,
    min_history_logins: int = 5,
) -> list[dict[str, Any]]:
    """Pure detection function for access anomalies (D-ACC-01 to D-ACC-04)."""
    ev_id = event_dict.get("event_id", "")
    identity_id = event_dict.get("identity_id", "")
    time_str = event_dict.get("time", "")
    src_ip = event_dict.get("src_ip", "")
    user_agent = event_dict.get("user_agent", "")

    lat = context_dict.get("lat")
    lon = context_dict.get("lon")
    asn = context_dict.get("asn")
    is_tor = bool(context_dict.get("is_tor", False))
    is_hosting = bool(context_dict.get("is_hosting", False))
    is_proxy = bool(context_dict.get("is_proxy", False))
    trusted_ip = bool(context_dict.get("trusted_ip", False))
    privilege_level = int(context_dict.get("privilege_level", 1))

    candidate_signals: list[dict[str, Any]] = []

    # Check cold start
    eff_history = history if len(history) >= min_history_logins else (peer_history or history)
    is_cold_start = len(history) < min_history_logins
    base_confidence = 0.9
    confidence = base_confidence * 0.6 if is_cold_start else base_confidence

    # 1. D-ACC-01: Impossible Travel
    if lat is not None and lon is not None and history:
        # Find latest previous login with coordinates
        prev_login = None
        for old in reversed(history):
            if old.get("lat") is not None and old.get("lon") is not None:
                prev_login = old
                break

        if prev_login is not None:
            prev_lat = prev_login["lat"]
            prev_lon = prev_login["lon"]
            prev_ts = prev_login.get("timestamp", 0.0)
            curr_ts = event_dict.get("timestamp", 0.0)

            delta_hours = max((curr_ts - prev_ts) / 3600.0, 0.001)
            dist_km = haversine_km(prev_lat, prev_lon, lat, lon)
            speed = dist_km / delta_hours

            if dist_km > min_distance_km and speed > max_speed_kmh:
                raw_strength = 0.7 * (speed / max_speed_kmh)
                strength = min(1.0, max(0.1, raw_strength))
                candidate_signals.append(
                    {
                        "detection_id": "D-ACC-01",
                        "strength": round(strength, 2),
                        "confidence": round(confidence, 2),
                        "evidence_event_ids": [prev_login["event_id"], ev_id],
                        "mitre": ["T1078.004"],
                        "stage": Stage.initial_access,
                        "summary": f"Impossible travel: {dist_km:.0f} km in {delta_hours:.2f} h ({speed:.0f} km/h > {max_speed_kmh:.0f} km/h)",
                        "details": {
                            "distance_km": round(dist_km, 1),
                            "speed_kmh": round(speed, 1),
                            "prev_event_id": prev_login["event_id"],
                            "prev_ip": prev_login.get("src_ip"),
                            "curr_ip": src_ip,
                        },
                    }
                )

    # 2. D-ACC-02: New Device or ASN (Suppressed on trusted IPs)
    if not trusted_ip and history:
        known_asns = {h["asn"] for h in history if h.get("asn") is not None}
        known_devices = {h["device"] for h in history if h.get("device")}

        new_asn = asn is not None and asn not in known_asns
        new_device = bool(user_agent and user_agent not in known_devices)

        if new_asn or new_device:
            strength = 0.5 if (new_asn and new_device) else 0.4
            candidate_signals.append(
                {
                    "detection_id": "D-ACC-02",
                    "strength": strength,
                    "confidence": round(confidence, 2),
                    "evidence_event_ids": [ev_id],
                    "mitre": ["T1078"],
                    "stage": Stage.initial_access,
                    "summary": f"New {'device and ASN' if new_asn and new_device else ('ASN' if new_asn else 'device')} for {identity_id}",
                    "details": {
                        "new_asn": new_asn,
                        "new_device": new_device,
                        "asn": asn,
                        "device": user_agent[:100],
                    },
                }
            )

    # 3. D-ACC-03: Unusual Hour
    if len(eff_history) >= min_history_logins:
        curr_hour = _parse_hour(time_str)
        hours = sorted([h.get("hour", 12) for h in eff_history])
        n = len(hours)
        p05 = hours[int(0.05 * (n - 1))]
        p95 = hours[int(0.95 * (n - 1))]

        if curr_hour < p05 or curr_hour > p95:
            dist = min(abs(curr_hour - p05), abs(curr_hour - p95))
            strength = min(0.6, 0.25 * (1.0 + 0.05 * dist))
            candidate_signals.append(
                {
                    "detection_id": "D-ACC-03",
                    "strength": round(strength, 2),
                    "confidence": round(confidence, 2),
                    "evidence_event_ids": [ev_id],
                    "mitre": ["T1078"],
                    "stage": Stage.initial_access,
                    "summary": f"Unusual login hour ({curr_hour}:00 outside typical [{p05}:00 - {p95}:00]) for {identity_id}",
                    "details": {
                        "login_hour": curr_hour,
                        "p05": p05,
                        "p95": p95,
                    },
                }
            )

    # 4. D-ACC-04: Anonymizing Network on Privileged Identity (Suppressed on trusted IPs)
    if not trusted_ip and privilege_level >= 4 and (is_tor or is_hosting or is_proxy):
        reasons = []
        if is_tor:
            reasons.append("Tor exit")
        if is_hosting:
            reasons.append("hosting provider ASN")
        if is_proxy:
            reasons.append("proxy network")

        candidate_signals.append(
            {
                "detection_id": "D-ACC-04",
                "strength": 0.5,
                "confidence": round(confidence, 2),
                "evidence_event_ids": [ev_id],
                "mitre": ["T1090.003"],
                "stage": Stage.initial_access,
                "summary": f"Anonymizing network login ({', '.join(reasons)}) on privileged identity ({identity_id})",
                "details": {
                    "is_tor": is_tor,
                    "is_hosting": is_hosting,
                    "is_proxy": is_proxy,
                    "privilege_level": privilege_level,
                },
            }
        )

    return candidate_signals


class AccessAnomaly(Agent):
    """Agent 5: Access Anomaly Detector."""

    num = 5
    agent_id = "a05"
    name = "Access Anomaly"
    layer = "detection"
    subscribes: ClassVar[list[str]] = ["events.enriched", "sessions"]
    publishes: ClassVar[list[str]] = ["signals", "deadletter"]
    path = "hot"

    def init_state(self) -> dict[str, Any]:
        return {
            "login_history": {},  # identity_id -> list[dict]
            "peer_history": {},  # peer_group -> list[dict]
        }

    def process(
        self,
        msg: Message,
        state: dict[str, Any],
        ctx: AgentContext,
    ) -> list[Message]:
        if not isinstance(msg.payload, EnrichedEvent):
            return []

        enriched: EnrichedEvent = msg.payload
        ev = enriched.event
        c = enriched.context

        # Only evaluate on authentication / login events
        is_login = (
            ev.event_class == EventClass.authentication
            or ev.action in ("user.session.start", "user.authentication.auth_via_mfa", "user.authentication.sso", "user.authentication.verify")
        )
        if not is_login or ev.outcome != "success":
            return []

        now_dt = ctx.clock() if callable(ctx.clock) else ctx.clock.now()
        ts = now_dt.timestamp() if hasattr(now_dt, "timestamp") else 0.0

        histories: dict[str, list[dict[str, Any]]] = state["login_history"]
        history = histories.setdefault(ev.identity_id, [])

        event_dict = {
            "event_id": ev.event_id,
            "identity_id": ev.identity_id,
            "session_id": ev.session_id,
            "time": ev.time,
            "timestamp": ts,
            "src_ip": ev.src_ip,
            "user_agent": ev.user_agent,
        }
        context_dict = {
            "lat": c.lat,
            "lon": c.lon,
            "asn": c.asn,
            "is_tor": c.is_tor,
            "is_hosting": c.is_hosting,
            "is_proxy": c.is_proxy,
            "trusted_ip": c.trusted_ip,
            "privilege_level": c.privilege_level,
        }

        # Run detection
        candidates = detect_access_anomalies(
            event_dict,
            context_dict,
            history,
            max_speed_kmh=getattr(ctx.settings, "max_speed_kmh", config.MAX_SPEED_KMH),
            min_distance_km=getattr(ctx.settings, "min_distance_km", config.MIN_DISTANCE_KM),
            min_history_logins=getattr(ctx.settings, "min_history_logins", config.MIN_HISTORY_LOGINS),
        )

        # Update login history (keep last 30 successful logins)
        history.append(
            {
                "event_id": ev.event_id,
                "time": ev.time,
                "timestamp": ts,
                "lat": c.lat,
                "lon": c.lon,
                "asn": c.asn,
                "device": ev.user_agent,
                "hour": _parse_hour(ev.time),
                "src_ip": ev.src_ip,
                "is_trusted": c.trusted_ip,
            }
        )
        if len(history) > 30:
            history.pop(0)

        out_messages: list[Message] = []
        for cand in candidates:
            sig = Signal(
                signal_id=f"sig-{uuid.uuid4().hex[:12]}",
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
                details=cand["details"],
            )
            out_messages.append(
                ctx.new_message(topic="signals", payload=sig, partition_key=ev.identity_id, producer=self.agent_id)
            )

        return out_messages
