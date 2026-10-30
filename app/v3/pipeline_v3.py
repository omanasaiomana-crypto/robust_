"""Pipeline V3: Dataset execution and replay engine for IdentityShield v3.

Follows context.md Section 12, 17 and P12 specification:
- run_dataset(paths=None, input_only=False, pace=0):
  * Builds a fresh bus + supervisor with all 15 agents registered via register_all
  * Replays official dataset files or input folder data through raw.okta / raw.cloudtrail
  * Supports deterministic drain mode or paced live simulation
  * Drains bus queues, executes final tick, returns comprehensive summary
"""
import json
import logging
import time
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.v3 import audit, config, store
from app.v3.agents import register_all
from app.v3.agents.a01_collector import to_timestamp
from app.v3.agents.base import Agent, AgentContext
from app.v3.bus import Bus
from app.v3.models import Event, Message, RawLog, Signal, Source
from app.v3.sse import broadcaster
from app.v3.supervisor import Supervisor

log = logging.getLogger("identityshield.pipeline_v3")

_last_summary: dict[str, Any] | None = None
_is_running: bool = False


class StoreAdapter:
    """Storage adapter bridging AgentContext to SQLite storage helpers."""

    def __init__(self, db_path: Path | str) -> None:
        self.db_path = Path(db_path)

    def execute(self, sql: str, params: tuple | list = ()) -> None:
        store.execute(sql, params, db_path=self.db_path)

    def fetch_all(self, sql: str, params: tuple | list = ()) -> list[dict[str, Any]]:
        return store.fetch_all(sql, params, db_path=self.db_path)

    def fetch_one(self, sql: str, params: tuple | list = ()) -> dict[str, Any] | None:
        return store.fetch_one(sql, params, db_path=self.db_path)

    def insert_many(self, table: str, rows: list[dict[str, Any]]) -> int:
        return store.insert_many(table, rows, db_path=self.db_path)


def _persist_event(adapter: StoreAdapter, event: Event) -> None:
    try:
        adapter.execute(
            """INSERT OR REPLACE INTO events_v3
               (event_id, time, source, event_class, action, identity_id, raw_principal,
                session_id, src_ip, user_agent, outcome, resource_arn, read_only, region,
                late, uncatalogued, resolution_confidence, raw_ref, attrs)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event.event_id,
                event.time,
                event.source.value if hasattr(event.source, "value") else str(event.source),
                event.event_class.value if hasattr(event.event_class, "value") else str(event.event_class),
                event.action,
                event.identity_id,
                event.raw_principal,
                event.session_id,
                event.src_ip,
                event.user_agent,
                event.outcome,
                event.resource_arn,
                int(event.read_only),
                event.region,
                int(event.late),
                int(event.uncatalogued),
                event.resolution_confidence,
                event.raw_ref,
                json.dumps(event.attrs),
            ),
        )
    except Exception as exc:  # noqa: BLE001
        log.debug("Auto-persist event failed: %s", exc)


def _persist_signal(adapter: StoreAdapter, signal: Signal, created_at: str) -> None:
    try:
        adapter.execute(
            """INSERT OR REPLACE INTO signals_v3
               (signal_id, detection_id, agent_num, identity_id, session_id,
                strength, confidence, evidence_event_ids, mitre, stage, summary, details, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                signal.signal_id,
                signal.detection_id,
                signal.agent_num,
                signal.identity_id,
                signal.session_id,
                signal.strength,
                signal.confidence,
                json.dumps(signal.evidence_event_ids),
                json.dumps(signal.mitre),
                signal.stage.value if hasattr(signal.stage, "value") else str(signal.stage),
                signal.summary,
                json.dumps(signal.details),
                created_at,
            ),
        )
    except Exception as exc:  # noqa: BLE001
        log.debug("Auto-persist signal failed: %s", exc)


def get_run_status() -> dict[str, Any]:
    """Return status of latest or currently executing dataset run."""
    return {
        "running": _is_running,
        "last_run": _last_summary,
    }


def _load_records_from_file(file_path: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Parse records from JSON or JSONL file and split into (okta_records, cloudtrail_records)."""
    okta_records: list[dict[str, Any]] = []
    cloudtrail_records: list[dict[str, Any]] = []

    if not file_path.is_file():
        log.warning("Dataset file not found: %s", file_path)
        return okta_records, cloudtrail_records

    content = file_path.read_text(encoding="utf-8").strip()
    if not content:
        return okta_records, cloudtrail_records

    parsed_items: list[dict[str, Any]] = []

    # Check if JSON Lines
    if file_path.suffix == ".jsonl" or ("\n" in content and not content.startswith(("[", "{"))):
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                parsed_items.append(json.loads(line))
            except (json.JSONDecodeError, ValueError):
                continue
    else:
        try:
            raw_data = json.loads(content)
            if isinstance(raw_data, list):
                parsed_items = raw_data
            elif isinstance(raw_data, dict):
                if "okta" in raw_data and isinstance(raw_data["okta"], list):
                    okta_records.extend(raw_data["okta"])
                if "cloudtrail" in raw_data and isinstance(raw_data["cloudtrail"], list):
                    cloudtrail_records.extend(raw_data["cloudtrail"])
                if "Records" in raw_data and isinstance(raw_data["Records"], list):
                    cloudtrail_records.extend(raw_data["Records"])
                if not (okta_records or cloudtrail_records):
                    parsed_items = [raw_data]
        except Exception as exc:  # noqa: BLE001
            log.warning("Failed to parse JSON file %s: %s", file_path, exc)
            return okta_records, cloudtrail_records

    # Classify parsed items by schema markers
    for item in parsed_items:
        if not isinstance(item, dict):
            continue
        if "uuid" in item or "eventType" in item or "published" in item or "actor" in item:
            okta_records.append(item)
        elif "eventID" in item or "eventName" in item or "eventTime" in item or "userIdentity" in item:
            cloudtrail_records.append(item)
        else:
            # Fallback based on filename
            name_lower = file_path.name.lower()
            if "okta" in name_lower:
                okta_records.append(item)
            else:
                cloudtrail_records.append(item)

    return okta_records, cloudtrail_records


def run_dataset(
    paths: str | Path | Sequence[str | Path] | None = None,
    input_only: bool = False,
    pace: float = 0.0,
    db_path: Path | str | None = None,
) -> dict[str, Any]:
    """Run an entire dataset replay through the 15-agent pipeline."""
    global _last_summary, _is_running
    _is_running = True
    start_time = time.monotonic()

    active_db = Path(db_path) if db_path else store.get_db_path()
    store.create_tables(db_path=active_db)
    adapter = StoreAdapter(active_db)

    # Build fresh supervisor and bus
    sup = Supervisor()
    bus = Bus(supervisor=sup, ctx=AgentContext(settings=config.get_settings(), store=adapter))
    register_all(sup, bus)

    # Attach auto-persist hook on bus publication
    orig_bus_publish = bus.publish

    def _auto_persist_publish(message: Message, agent: Agent | None = None) -> bool:
        res = orig_bus_publish(message, agent=agent)
        if res:
            if message.topic == "signals" and isinstance(message.payload, Signal):
                _persist_signal(adapter, message.payload, message.created_at)
            elif message.topic == "events" and isinstance(message.payload, Event):
                _persist_event(adapter, message.payload)
        return res

    bus.publish = _auto_persist_publish

    if pace > 0.0:
        sup.set_pace(pace)

    # 1. Resolve dataset files
    file_paths: list[Path] = []
    if paths is not None:
        if isinstance(paths, (str, Path)):
            file_paths = [Path(paths)]
        else:
            file_paths = [Path(p) for p in paths]
    elif input_only:
        # Load from data/input/
        input_dir = config.ROOT_DIR / "data" / "input"
        if input_dir.is_dir():
            file_paths.extend(input_dir.glob("**/*.json"))
            file_paths.extend(input_dir.glob("**/*.jsonl"))
    else:
        # Default official sample dataset
        sample_dir = config.ROOT_DIR / "data" / "sample"
        file_paths = [
            sample_dir / "okta.json",
            sample_dir / "cloudtrail.json",
        ]

    # 2. Extract and timestamp-sort all records
    stamped_events: list[tuple[float, Source, dict[str, Any]]] = []
    for fp in file_paths:
        okta_list, ct_list = _load_records_from_file(fp)
        for ev in okta_list:
            t = to_timestamp(ev.get("published") or ev.get("eventTime"))
            stamped_events.append((t, Source.okta, ev))
        for ev in ct_list:
            t = to_timestamp(ev.get("eventTime") or ev.get("published"))
            stamped_events.append((t, Source.cloudtrail, ev))

    stamped_events.sort(key=lambda x: x[0])

    # 3. Replay records through bus
    events_replayed = len(stamped_events)
    for _, source, ev in stamped_events:
        topic = "raw.okta" if source == Source.okta else "raw.cloudtrail"
        raw_msg = bus.ctx.new_message(
            topic=topic,
            payload=RawLog(source=source, records=[ev]),
            producer="pipeline_v3",
        )
        bus.publish(raw_msg)
        if pace > 0.0:
            time.sleep(pace)

    # 4. Drain bus deterministically
    bus.run_until_idle()

    # 5. Execute final tick across all registered agents and drain remaining
    for ag in sup.get_registered_agents():
        ag_state = bus._agent_states.get(ag.agent_id, {})
        tick_msgs = ag.on_tick(ag_state, bus.ctx)
        for t_msg in tick_msgs:
            bus.publish(t_msg)
    bus.run_until_idle()

    duration_ms = round((time.monotonic() - start_time) * 1000.0, 2)

    # 6. Gather counts from v3 SQLite store
    def _count(table: str) -> int:
        try:
            r = store.fetch_one(f"SELECT COUNT(*) AS c FROM {table}", db_path=active_db)
            return int(r["c"]) if r else 0
        except Exception:  # noqa: BLE001
            return 0

    signals_count = _count("signals_v3")
    cases_count = _count("cases_v3")
    actions_count = _count("actions_v3")
    events_stored = _count("events_v3")

    health_list = sup.get_health()
    per_agent = {h["agent_id"]: h for h in health_list}

    summary = {
        "status": "completed",
        "events": events_replayed or events_stored,
        "signals": signals_count,
        "cases": cases_count,
        "actions": actions_count,
        "duration_ms": duration_ms,
        "pace": pace,
        "per_agent": per_agent,
        "timestamp": datetime.now(UTC).isoformat(),
    }

    _last_summary = summary
    _is_running = False

    audit.append("pipeline_v3", "run_dataset", summary, db_path=db_path)
    broadcaster.publish("metrics", summary)

    return summary
