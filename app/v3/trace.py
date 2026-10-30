"""Trace adapter for IdentityShield v3.

Delegates to app/trace.py or maintains a thread-safe ring buffer of 5,000 events.
"""
import logging
import threading
from collections import deque
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any

try:
    from app import trace as _v2_trace
except ImportError:
    _v2_trace = None

log = logging.getLogger(__name__)

_lock = threading.RLock()
_local_events: deque = deque(maxlen=5000)
_seq = 0


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def emit(
    agent_id: str,
    state: str,
    message: str,
    data: Any = None,
    level: str | None = None,
    duration_ms: float | None = None,
    run_id: str = "live",
) -> dict[str, Any]:
    """Emit a trace telemetry event."""
    global _seq
    if _v2_trace is not None and hasattr(_v2_trace, "emit"):
        try:
            return _v2_trace.emit(agent_id, state, message, data, level, duration_ms)
        except Exception:
            log.exception("v2 trace emit failed; falling back to local trace")

    with _lock:
        _seq += 1
        ev = {
            "seq": _seq,
            "run_id": run_id,
            "ts": _now_iso(),
            "agent_id": agent_id,
            "agent_num": 0,
            "agent_name": agent_id,
            "layer": "platform",
            "state": state,
            "level": level or ("ok" if state == "done" else "info"),
            "message": str(message)[:500],
            "duration_ms": duration_ms,
            "data": data,
        }
        _local_events.append(ev)
        return ev


def progress(agent_id: str, message: str, data: Any = None) -> None:
    if _v2_trace is not None and hasattr(_v2_trace, "progress"):
        try:
            _v2_trace.progress(agent_id, message, data)
            return
        except Exception as exc:  # noqa: BLE001
            log.debug("v2 trace progress fallback: %s", exc)
    emit(agent_id, "progress", message, data)


def finding(agent_id: str, message: str, data: Any = None) -> None:
    if _v2_trace is not None and hasattr(_v2_trace, "finding"):
        try:
            _v2_trace.finding(agent_id, message, data)
            return
        except Exception as exc:  # noqa: BLE001
            log.debug("v2 trace finding fallback: %s", exc)
    emit(agent_id, "finding", message, data, level="warn")


@contextmanager
def step(agent_id: str, message: str, data: Any = None) -> Iterator[Any]:
    if _v2_trace is not None and hasattr(_v2_trace, "step"):
        try:
            with _v2_trace.step(agent_id, message, data) as handle:
                yield handle
            return
        except Exception as exc:  # noqa: BLE001
            log.debug("v2 trace step fallback: %s", exc)
    emit(agent_id, "started", message, data)
    try:
        yield None
    except Exception as exc:
        emit(agent_id, "failed", f"{type(exc).__name__}: {exc}")
        raise
    emit(agent_id, "done", f"{agent_id} completed")


def get_events(after: int = 0, limit: int = 500) -> list[dict[str, Any]]:
    if _v2_trace is not None and hasattr(_v2_trace, "events"):
        try:
            return _v2_trace.events(after=after, limit=limit)
        except Exception as exc:  # noqa: BLE001
            log.debug("v2 trace get_events fallback: %s", exc)
    with _lock:
        items = [e for e in _local_events if e["seq"] > after]
        return items[:limit]
