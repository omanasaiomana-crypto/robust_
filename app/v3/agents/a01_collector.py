"""Agent 1: Collector for IdentityShield v3.

Follows context.md Section 5, 8, 10, 13 and PRD §8, §12:
- Subscribes: raw.okta, raw.cloudtrail
- Publishes: events, deadletter
- Deduplication: exact set of last 100k event IDs + 24-hour time-based expiry
- Watermark reordering: buffers events up to WATERMARK_SECONDS by event time
  and releases them in time order on message or tick (in drain mode, flushes all on tick)
- Late events flagged late=True
- Minimal parsing to Event model with raw dict in attrs["_raw"]
- Malformed records directed to deadletter topic with reason
"""
import json
import logging
from collections import deque
from datetime import UTC, datetime
from typing import Any, ClassVar

from app.v3.agents.base import Agent, AgentContext
from app.v3.models import (
    DeadletterPayload,
    Event,
    EventClass,
    Message,
    RawLog,
    Source,
)

log = logging.getLogger(__name__)

DEDUPE_WINDOW_SECONDS = 86400.0  # 24 hours
DEDUPE_MAX_SET = 100_000


def to_timestamp(time_val: Any) -> float:
    """Convert ISO time string, datetime, or number to UTC timestamp float."""
    if isinstance(time_val, (int, float)):
        return float(time_val)
    if isinstance(time_val, datetime):
        if time_val.tzinfo is None:
            time_val = time_val.replace(tzinfo=UTC)
        return time_val.timestamp()
    if isinstance(time_val, str):
        # Normalize trailing Z for Python fromisoformat
        s = time_val.strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            return dt.timestamp()
        except ValueError:
            pass
    return 0.0


def parse_okta(raw: dict[str, Any]) -> dict[str, Any]:
    """Parse minimal required fields from raw Okta record.

    Raises ValueError if required fields (uuid, published) are missing.
    """
    if not isinstance(raw, dict):
        raise TypeError(f"Okta record must be a dict, got {type(raw).__name__}")

    event_id = raw.get("uuid") or raw.get("eventId") or raw.get("id")
    if not event_id or not isinstance(event_id, str):
        raise ValueError("Missing or invalid Okta event ID ('uuid')")

    time_str = raw.get("published") or raw.get("eventTime")
    if not time_str or not isinstance(time_str, str):
        raise ValueError("Missing or invalid Okta timestamp ('published')")

    action = raw.get("eventType") or "unknown"
    client = raw.get("client") or {}
    src_ip = client.get("ipAddress") or "127.0.0.1"
    ua_obj = client.get("userAgent") or {}
    user_agent = ua_obj.get("rawUserAgent") if isinstance(ua_obj, dict) else str(ua_obj)
    if not user_agent:
        user_agent = "unknown"

    actor = raw.get("actor") or {}
    raw_principal = actor.get("alternateId") or actor.get("id") or "unknown"

    return {
        "event_id": str(event_id),
        "time": str(time_str),
        "action": str(action),
        "source": Source.okta,
        "src_ip": str(src_ip),
        "user_agent": str(user_agent),
        "raw_principal": str(raw_principal),
        "raw": raw,
    }


def parse_cloudtrail(raw: dict[str, Any]) -> dict[str, Any]:
    """Parse minimal required fields from raw CloudTrail record.

    Raises ValueError if required fields (eventID, eventTime) are missing.
    """
    if not isinstance(raw, dict):
        raise TypeError(f"CloudTrail record must be a dict, got {type(raw).__name__}")

    event_id = raw.get("eventID") or raw.get("eventId") or raw.get("uuid")
    if not event_id or not isinstance(event_id, str):
        raise ValueError("Missing or invalid CloudTrail event ID ('eventID')")

    time_str = raw.get("eventTime") or raw.get("published")
    if not time_str or not isinstance(time_str, str):
        raise ValueError("Missing or invalid CloudTrail timestamp ('eventTime')")

    action = raw.get("eventName") or "unknown"
    src_ip = raw.get("sourceIPAddress") or "127.0.0.1"
    user_agent = raw.get("userAgent") or "unknown"

    user_identity = raw.get("userIdentity") or {}
    raw_principal = (
        user_identity.get("arn")
        or user_identity.get("userName")
        or user_identity.get("principalId")
        or user_identity.get("type")
        or "unknown"
    )

    return {
        "event_id": str(event_id),
        "time": str(time_str),
        "action": str(action),
        "source": Source.cloudtrail,
        "src_ip": str(src_ip),
        "user_agent": str(user_agent),
        "raw_principal": str(raw_principal),
        "region": raw.get("awsRegion"),
        "raw": raw,
    }


class Collector(Agent):
    """Agent 1: Collector.

    Deduplicates, reorders by watermark, parses minimal events, and
    forwards malformed records to deadletter.
    """

    num = 1
    agent_id = "a01"
    name = "Collector"
    layer = "data"
    subscribes: ClassVar[list[str]] = ["raw.okta", "raw.cloudtrail"]
    publishes: ClassVar[list[str]] = ["events", "deadletter"]
    path = "hot"

    def init_state(self) -> dict[str, Any]:
        return {
            "seen_ids": set(),
            "seen_history": deque(),  # (event_id, timestamp)
            "watermark": None,  # float
            "buffer": [],  # list of tuples: (event_ts, late_flag, parsed_dict, raw_ref)
        }

    def _prune_dedupe(self, state: dict[str, Any], current_time: float) -> None:
        """Evict seen IDs older than 24h or exceeding 100k size."""
        seen_ids: set[str] = state["seen_ids"]
        seen_history: deque[tuple[str, float]] = state["seen_history"]

        while seen_history and (current_time - seen_history[0][1] > DEDUPE_WINDOW_SECONDS):
            old_id, _ = seen_history.popleft()
            seen_ids.discard(old_id)

        while len(seen_ids) > DEDUPE_MAX_SET and seen_history:
            old_id, _ = seen_history.popleft()
            seen_ids.discard(old_id)

    def _make_event(self, item: dict[str, Any], late: bool, raw_ref: str | None) -> Event:
        """Construct minimal Event payload with raw dict in attrs['_raw']."""
        raw_dict = item.get("raw", {})
        return Event(
            event_id=item["event_id"],
            time=item["time"],
            source=item["source"],
            event_class=EventClass.api_activity,
            action=item["action"],
            identity_id="",
            raw_principal=item["raw_principal"],
            session_id=None,
            src_ip=item["src_ip"],
            user_agent=item["user_agent"],
            outcome="unknown",
            resource_arn=None,
            read_only=False,
            region=item.get("region"),
            late=late,
            uncatalogued=False,
            resolution_confidence=0.0,
            raw_ref=raw_ref,
            attrs={"_raw": raw_dict},
        )

    def process(
        self,
        msg: Message,
        state: dict[str, Any],
        ctx: AgentContext,
    ) -> list[Message]:
        now_dt = ctx.clock() if callable(ctx.clock) else ctx.clock.now()
        current_ts = now_dt.timestamp() if hasattr(now_dt, "timestamp") else to_timestamp(now_dt)

        self._prune_dedupe(state, current_ts)
        watermark_sec = getattr(ctx.settings, "watermark_seconds", 120)

        # 1. Extract records from message payload
        records: list[dict[str, Any]] = []
        raw_ref: str | None = None
        source_hint = Source.okta if msg.topic == "raw.okta" else Source.cloudtrail

        if isinstance(msg.payload, RawLog):
            source_hint = msg.payload.source
            if msg.payload.records:
                records = list(msg.payload.records)
            elif msg.payload.raw_text:
                try:
                    parsed_json = json.loads(msg.payload.raw_text)
                    if isinstance(parsed_json, list):
                        records = parsed_json
                    elif isinstance(parsed_json, dict):
                        if "Records" in parsed_json and isinstance(parsed_json["Records"], list):
                            records = parsed_json["Records"]
                        else:
                            records = [parsed_json]
                    else:
                        raise TypeError(f"Parsed JSON must be dict or list, got {type(parsed_json).__name__}")
                except (json.JSONDecodeError, ValueError, TypeError) as exc:
                    dl = DeadletterPayload(
                        failed_topic=msg.topic,
                        failed_msg_id=msg.msg_id,
                        error=f"Malformed raw_text JSON: {exc}",
                        producer=self.agent_id,
                        raw=msg.payload.raw_text[:500],
                    )
                    return [ctx.new_message(topic="deadletter", payload=dl, producer=self.agent_id)]
        elif isinstance(msg.payload, Event):
            # Already an Event
            return [ctx.new_message(topic="events", payload=msg.payload, producer=self.agent_id)]
        elif isinstance(msg.payload, dict):
            records = [msg.payload]
        else:
            # Handle other payload representations
            payload_dict = getattr(msg.payload, "__dict__", {})
            if "records" in payload_dict and isinstance(payload_dict["records"], list):
                records = payload_dict["records"]
            elif "event" in payload_dict and isinstance(payload_dict["event"], dict):
                records = [payload_dict["event"]]

        out_messages: list[Message] = []

        # 2. Process each record
        for rec in records:
            # Parse record
            try:
                if source_hint == Source.okta or (isinstance(rec, dict) and "eventType" in rec):
                    parsed = parse_okta(rec)
                else:
                    parsed = parse_cloudtrail(rec)
            except (ValueError, TypeError, KeyError) as exc:
                dl = DeadletterPayload(
                    failed_topic=msg.topic,
                    failed_msg_id=msg.msg_id,
                    error=f"Malformed event record: {exc}",
                    producer=self.agent_id,
                    raw=rec if isinstance(rec, dict) else str(rec),
                )
                out_messages.append(ctx.new_message(topic="deadletter", payload=dl, producer=self.agent_id))
                continue

            ev_id = parsed["event_id"]

            # Deduplication
            if ev_id in state["seen_ids"]:
                # Drop duplicate silently
                continue

            state["seen_ids"].add(ev_id)
            state["seen_history"].append((ev_id, current_ts))

            # Watermark and late check
            ev_ts = to_timestamp(parsed["time"])
            if state["watermark"] is None:
                state["watermark"] = ev_ts

            cutoff = state["watermark"] - watermark_sec
            if ev_ts < cutoff:
                # Late event
                is_late = True
            else:
                is_late = False
                state["watermark"] = max(state["watermark"], ev_ts)

            state["buffer"].append((ev_ts, is_late, parsed, raw_ref))

        # 3. Release events older than release threshold if watermark window exceeded
        if state["watermark"] is not None and state["buffer"]:
            release_cutoff = state["watermark"] - watermark_sec
            ready: list[tuple[float, bool, dict[str, Any], str | None]] = []
            remaining: list[tuple[float, bool, dict[str, Any], str | None]] = []

            for entry in state["buffer"]:
                ev_ts, is_late, parsed, ref = entry
                # Late events or events that have passed the watermark window are released
                if is_late or ev_ts <= release_cutoff:
                    ready.append(entry)
                else:
                    remaining.append(entry)

            state["buffer"] = remaining

            # Sort ready events chronologically
            ready.sort(key=lambda x: x[0])
            for _, is_late, parsed, ref in ready:
                ev = self._make_event(parsed, is_late, ref)
                out_messages.append(
                    ctx.new_message(
                        topic="events",
                        payload=ev,
                        partition_key=ev.event_id,
                        producer=self.agent_id,
                    )
                )

        return out_messages

    def on_tick(
        self,
        state: dict[str, Any],
        ctx: AgentContext,
    ) -> list[Message]:
        """Flush all buffered events in chronological order."""
        buffer: list[tuple[float, bool, dict[str, Any], str | None]] = state.get("buffer", [])
        if not buffer:
            return []

        # Sort remaining buffered events by event timestamp
        buffer.sort(key=lambda x: x[0])
        state["buffer"] = []

        out_messages: list[Message] = []
        for _, is_late, parsed, ref in buffer:
            ev = self._make_event(parsed, is_late, ref)
            out_messages.append(
                ctx.new_message(
                    topic="events",
                    payload=ev,
                    partition_key=ev.event_id,
                    producer=self.agent_id,
                )
            )
        return out_messages
