"""15-agent registry, live scan trace, and one audit entry per detected threat.

- Pipeline steps call `with trace.step("<agent_id>", "message") as s: ... s.output({...})`.
- The runner calls begin_run() / log_threats() / end_run().
- The UI polls events(after=seq); the terminal scan (app/scan.py) uses add_listener() + render_ansi().
Thread-safe. emit() never raises; listener errors are swallowed; payloads are JSON-safe and size-capped.
"""
import json
import logging
import re
import threading
import time
import uuid
from collections import deque
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterator

from app import audit, config, store
from app.models import Alert
from app.utils import clean_json

log = logging.getLogger(__name__)

LAYERS = ("data", "detection", "decision", "learning", "oversight")

AGENTS: list[dict] = [
    {"id": "ingestion", "num": 1, "name": "Log Ingestion Agent", "layer": "data", "pattern": None,
     "role": "Reads CloudTrail and Okta files and replays events in time order", "permissions": ["read:raw_logs"]},
    {"id": "normalization", "num": 2, "name": "Normalization Agent", "layer": "data", "pattern": None,
     "role": "Maps both log formats into one event schema", "permissions": ["read:raw_logs", "write:events"]},
    {"id": "enrichment", "num": 3, "name": "Enrichment Agent", "layer": "data", "pattern": None,
     "role": "Adds geo, privilege level and resource sensitivity", "permissions": ["read:metadata", "write:events"]},
    {"id": "correlation", "num": 4, "name": "Session Correlation Agent", "layer": "data", "pattern": None,
     "role": "Links Okta sessions to AWS activity and builds the identity graph", "permissions": ["read:events", "write:graph"]},
    {"id": "impossible_travel", "num": 5, "name": "Impossible Travel Agent", "layer": "detection", "pattern": "P1",
     "role": "Flags logins too far apart for the time between them", "permissions": ["read:events"]},
    {"id": "dormant", "num": 6, "name": "Dormant Account Agent", "layer": "detection", "pattern": "P2",
     "role": "Flags accounts that wake up after a long silence", "permissions": ["read:events"]},
    {"id": "priv_escalation", "num": 7, "name": "Privilege Escalation Agent", "layer": "detection", "pattern": "P3",
     "role": "Reconstructs multi-step escalation chains", "permissions": ["read:events", "read:graph"]},
    {"id": "api_anomaly", "num": 8, "name": "API Anomaly Agent", "layer": "detection", "pattern": "P4",
     "role": "Flags rare, sensitive or new-region API calls", "permissions": ["read:events"]},
    {"id": "token_abuse", "num": 9, "name": "Token Abuse Agent", "layer": "detection", "pattern": "P5",
     "role": "Flags session or token reuse from new places or after logout", "permissions": ["read:events"]},
    {"id": "baseline_ml", "num": 10, "name": "Behavior Baseline Agent (ML)", "layer": "detection", "pattern": "ML",
     "role": "Isolation Forest anomaly score per session", "permissions": ["read:features"]},
    {"id": "risk_scoring", "num": 11, "name": "Risk Scoring Agent", "layer": "decision", "pattern": None,
     "role": "Combines signals x privilege x sensitivity into a 0-100 risk", "permissions": ["read:signals", "write:scores"]},
    {"id": "explanation", "num": 12, "name": "Explanation Agent", "layer": "decision", "pattern": None,
     "role": "Writes reasons, counterfactuals and MITRE tags with evidence", "permissions": ["read:signals"]},
    {"id": "response", "num": 13, "name": "Response Agent", "layer": "decision", "pattern": None,
     "role": "Recommends and applies actions through the simulator only", "permissions": ["call:simulator"]},
    {"id": "feedback", "num": 14, "name": "Feedback Learning Agent", "layer": "learning", "pattern": None,
     "role": "Tunes detector weights from analyst labels", "permissions": ["write:weights"]},
    {"id": "orchestrator", "num": 15, "name": "Orchestrator & Supervisor Agent", "layer": "oversight", "pattern": None,
     "role": "Runs the agents in order, deduplicates, guards safety, logs threats", "permissions": ["coordinate", "write:audit"]},
]
AGENT_BY_ID = {a["id"]: a for a in AGENTS}
PATTERN_AGENT = {a["pattern"]: a["id"] for a in AGENTS if a["pattern"]}
SCAN_AGENT_IDS = [a["id"] for a in AGENTS if 1 <= a["num"] <= 13]       # the steps of one scan

STATE_LEVEL = {"started": "info", "progress": "info", "done": "ok", "failed": "crit", "threat": "crit",
               "info": "info", "skipped": "warn"}

_lock = threading.RLock()
_events: deque = deque(maxlen=config.TRACE_MAX_EVENTS)
_listeners: list[Callable[[dict], None]] = []
_seq = 0


def _new_run() -> dict:
    return {"run_id": None, "mode": None, "state": "idle", "started_at": None, "finished_at": None,
            "duration_ms": None, "current": None, "completed": [], "failed": [], "threats": 0, "summary": None}


def _new_stats() -> dict:
    return {a["id"]: {"state": "idle", "runs": 0, "last_started": None, "last_finished": None,
                      "last_duration_ms": None, "last_message": "", "last_output": None, "last_error": "",
                      "signals": None} for a in AGENTS}


_run: dict = _new_run()
_stats: dict = _new_stats()
_t0: float = 0.0


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_data(data: Any) -> Any:
    if data is None:
        return None
    try:
        clean = clean_json(data)
        text = json.dumps(clean, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return {"unserializable": type(data).__name__}
    if len(text) > config.TRACE_MAX_DATA_CHARS:
        return {"truncated": True, "chars": len(text), "preview": text[: config.TRACE_MAX_DATA_CHARS // 4]}
    return clean


def add_listener(fn: Callable[[dict], None]) -> None:
    with _lock:
        _listeners.append(fn)


def remove_listener(fn: Callable[[dict], None]) -> None:
    with _lock:
        if fn in _listeners:
            _listeners.remove(fn)


def emit(agent_id: str, state: str, message: str, data: Any = None, level: str | None = None,
         duration_ms: float | None = None) -> dict:
    """Record one trace event. Never raises."""
    global _seq
    agent = AGENT_BY_ID.get(agent_id, {"id": str(agent_id), "num": 0, "name": str(agent_id), "layer": "oversight"})
    try:
        with _lock:
            _seq += 1
            ev = {"seq": _seq, "run_id": _run["run_id"] or "live", "ts": _now_iso(),
                  "agent_id": agent["id"], "agent_num": agent["num"], "agent_name": agent["name"],
                  "layer": agent["layer"], "state": state, "level": level or STATE_LEVEL.get(state, "info"),
                  "message": str(message)[:500],
                  "duration_ms": None if duration_ms is None else round(float(duration_ms), 1),
                  "data": _safe_data(data)}
            _events.append(ev)
            st = _stats.get(agent["id"])
            if st is not None and state != "threat":
                if state == "started":
                    st.update(state="running", last_started=ev["ts"], last_message=ev["message"], last_error="")
                elif state == "progress":
                    st["last_message"] = ev["message"]
                elif state in ("done", "skipped"):
                    st.update(state="done" if state == "done" else "skipped", last_finished=ev["ts"],
                              last_duration_ms=ev["duration_ms"], last_message=ev["message"],
                              last_output=ev["data"], runs=st["runs"] + 1)
                    if isinstance(ev["data"], dict) and isinstance(ev["data"].get("signals"), int):
                        st["signals"] = ev["data"]["signals"]
                elif state == "failed":
                    st.update(state="failed", last_finished=ev["ts"], last_duration_ms=ev["duration_ms"],
                              last_error=ev["message"], runs=st["runs"] + 1)
            if agent["id"] in SCAN_AGENT_IDS:
                if state in ("started", "progress"):
                    _run["current"] = {"agent_id": agent["id"], "agent_num": agent["num"],
                                       "agent_name": agent["name"], "message": ev["message"], "seq": ev["seq"]}
                elif state in ("done", "skipped") and agent["id"] not in _run["completed"]:
                    _run["completed"].append(agent["id"])
                elif state == "failed" and agent["id"] not in _run["failed"]:
                    _run["failed"].append(agent["id"])
            if state == "threat":
                _run["threats"] += 1
            listeners = list(_listeners)
    except Exception:  # noqa: BLE001 - tracing must never break the pipeline
        log.exception("trace.emit failed")
        return {}
    for fn in listeners:
        try:
            fn(ev)
        except Exception:  # noqa: BLE001
            log.exception("trace listener failed")
    return ev


class StepHandle:
    def __init__(self, agent_id: str) -> None:
        self.agent_id = agent_id
        self._output: Any = None
        self._message: str | None = None

    def output(self, data: Any = None, message: str | None = None) -> None:
        """Set the JSON payload (and optional message) reported when the step finishes."""
        self._output = data
        if message:
            self._message = message

    def progress(self, message: str, data: Any = None) -> None:
        emit(self.agent_id, "progress", message, data)


@contextmanager
def step(agent_id: str, message: str, data: Any = None) -> Iterator[StepHandle]:
    """Trace one agent step: emits started, then done (with duration) or failed (and re-raises)."""
    emit(agent_id, "started", message, data)
    handle = StepHandle(agent_id)
    t0 = time.perf_counter()
    try:
        yield handle
    except Exception as exc:
        emit(agent_id, "failed", f"{type(exc).__name__}: {exc}", handle._output,
             duration_ms=(time.perf_counter() - t0) * 1000)
        raise
    name = AGENT_BY_ID.get(agent_id, {}).get("name", agent_id)
    emit(agent_id, "done", handle._message or f"{name} finished", handle._output,
         duration_ms=(time.perf_counter() - t0) * 1000)


def skip(agent_id: str, reason: str) -> None:
    emit(agent_id, "skipped", reason)


def begin_run(mode: str = "dataset") -> str:
    global _t0
    run_id = f"scan-{datetime.now(timezone.utc):%Y%m%d-%H%M%S}-{uuid.uuid4().hex[:4]}"
    with _lock:
        _run.clear()
        _run.update(_new_run())
        _run.update(run_id=run_id, mode=mode, state="running", started_at=_now_iso())
        for aid in SCAN_AGENT_IDS:
            _stats[aid]["state"] = "waiting"
        _t0 = time.perf_counter()
    emit("orchestrator", "started", f"Scan started · mode {mode} · {len(AGENTS)} agents on duty",
         {"run_id": run_id, "mode": mode, "agents": [a["name"] for a in AGENTS]})
    return run_id


def end_run(state: str, summary: Any = None) -> None:
    with _lock:
        duration = round((time.perf_counter() - _t0) * 1000, 1) if _run["run_id"] else None
        _run.update(state=state, finished_at=_now_iso(), duration_ms=duration, current=None,
                    summary=_safe_data(summary))
    emit("orchestrator", "done" if state == "done" else "failed",
         f"Scan {'complete' if state == 'done' else 'failed'} · {_run['threats']} threat(s) logged",
         summary, duration_ms=duration)


def run_status() -> dict:
    with _lock:
        out = json.loads(json.dumps(_run, default=str))
    out["total_steps"] = len(SCAN_AGENT_IDS)
    out["progress"] = round(len(out["completed"]) / len(SCAN_AGENT_IDS), 3)
    out["last_seq"] = _seq
    return out


def events(after: int = 0, limit: int = 500, run_id: str | None = None) -> list[dict]:
    limit = max(1, min(int(limit), 2000))
    with _lock:
        items = [e for e in _events if e["seq"] > after and (run_id is None or e["run_id"] == run_id)]
    return items[:limit]


def agents_status() -> list[dict]:
    with _lock:
        return [{**a, **json.loads(json.dumps(_stats[a["id"]], default=str))} for a in AGENTS]


def reset() -> None:
    """For tests only."""
    global _seq
    with _lock:
        _events.clear()
        _seq = 0
        _run.clear()
        _run.update(_new_run())
        _stats.clear()
        _stats.update(_new_stats())


def fingerprint(alert: Alert) -> str:
    return f"{alert.identity_id}|{alert.session_id or '-'}|{alert.band}"


def _logged_fingerprints() -> set[str]:
    done: set[str] = set()
    try:
        rows = store.execute("SELECT detail FROM audit WHERE action = 'threat_detected'")
    except Exception:  # noqa: BLE001
        log.exception("Could not read threat audit entries")
        return done
    for r in rows:
        try:
            done.add(json.loads(r["detail"])["fingerprint"])
        except (ValueError, KeyError, TypeError):
            continue
    return done


def log_threats(alerts: list[Alert], min_risk: float | None = None) -> list[dict]:
    """Write ONE separate audit entry per new threat (alert at/above min_risk) and emit a threat event.

    Deduplicated by fingerprint (identity|session|band) across runs; an escalated band is logged again.
    """
    threshold = config.THREAT_AUDIT_MIN_RISK if min_risk is None else min_risk
    threats = sorted((a for a in alerts or [] if a.risk >= threshold), key=lambda a: a.risk, reverse=True)
    if not threats:
        return []
    seen = _logged_fingerprints()
    logged: list[dict] = []
    for a in threats:
        fp = fingerprint(a)
        if fp in seen:
            continue
        detectors = sorted({PATTERN_AGENT.get(p, p) for p in a.patterns})
        detail = {"fingerprint": fp, "alert_id": a.alert_id, "identity_id": a.identity_id,
                  "session_id": a.session_id, "risk": round(float(a.risk), 1), "band": a.band,
                  "patterns": list(a.patterns), "mitre": list(a.mitre), "detectors": detectors,
                  "evidence_count": len(a.evidence_event_ids), "evidence_sample": a.evidence_event_ids[:5],
                  "recommended_action": a.recommended_action,
                  "reason": (a.reasons[0] if a.reasons else "")[:300], "run_id": _run.get("run_id")}
        try:
            audit.append("threat_detection", "threat_detected", json.dumps(detail, sort_keys=True, ensure_ascii=False))
        except Exception:  # noqa: BLE001
            log.exception("Could not write threat audit entry for %s", a.alert_id)
            continue
        seen.add(fp)
        names = ", ".join(config.PATTERN_NAMES.get(p, p) for p in a.patterns)
        primary = PATTERN_AGENT.get(a.patterns[0]) if a.patterns else None    # detector of the main pattern
        emit(primary or "orchestrator", "threat",
             f"THREAT DETECTED · {a.identity_id} · risk {a.risk:.0f} ({a.band}) · {names}", detail)
        logged.append(detail)
    return logged


# ---------------------------------------------------------------------------
# Terminal rendering (full-color output + full JSON) used by app/scan.py
# ---------------------------------------------------------------------------
_LAYER_COLOR = {"data": "36", "detection": "35", "decision": "33", "learning": "32", "oversight": "34"}
_LEVEL_COLOR = {"info": "37", "ok": "32", "warn": "33", "crit": "1;31", "debug": "90"}
_STATE_SYMBOL = {"started": ">>", "progress": "..", "done": "OK", "failed": "XX", "threat": "!!",
                 "info": "--", "skipped": "~~"}
_JSON_TOKEN = re.compile(r'("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false)\b|\b(null)\b|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)')


def _c(code: str, text: str, color: bool) -> str:
    return f"\x1b[{code}m{text}\x1b[0m" if color else text


def color_json(text: str, color: bool = True) -> str:
    if not color:
        return text

    def repl(m: re.Match) -> str:
        if m.group(1):
            return _c("36" if m.group(2) else "32", m.group(1), True) + (m.group(2) or "")
        if m.group(3):
            return _c("35", m.group(3), True)
        if m.group(4):
            return _c("90", m.group(4), True)
        return _c("33", m.group(5), True)

    return _JSON_TOKEN.sub(repl, text)


def _local_time(ts: str) -> str:
    try:
        dt = datetime.fromisoformat(ts).astimezone(timezone(timedelta(minutes=config.DISPLAY_UTC_OFFSET_MINUTES)))
        return dt.strftime("%H:%M:%S.%f")[:-3]
    except (TypeError, ValueError):
        return str(ts)[11:23]


def render_ansi(ev: dict, show_json: bool = False, color: bool = True) -> str:
    """One colored terminal line per event; optional indented, colored JSON payload below it."""
    state = ev.get("state", "info")
    level = ev.get("level", "info")
    tag = f"[{int(ev.get('agent_num') or 0):02d} {str(ev.get('agent_id', '')).upper()}]"
    dur = f"  ({ev['duration_ms']:.0f} ms)" if ev.get("duration_ms") is not None else ""
    line = (f"{_c('90', _local_time(ev.get('ts', '')), color)}  "
            f"{_c(_LAYER_COLOR.get(ev.get('layer'), '37'), tag.ljust(24), color)} "
            f"{_c(_LEVEL_COLOR.get(level, '37'), _STATE_SYMBOL.get(state, '--'), color)}  "
            f"{_c('1;31', ev.get('message', ''), color) if state == 'threat' else ev.get('message', '')}"
            f"{_c('90', dur, color)}")
    if state == "threat":
        line = _c("1;37;41", " THREAT ", color) + " " + line
    if show_json and ev.get("data") is not None:
        body = json.dumps(ev["data"], indent=2, ensure_ascii=False)
        line += "\n" + "\n".join("        " + row for row in color_json(body, color).splitlines())
    return line
