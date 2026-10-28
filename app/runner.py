"""Background pipeline runs: at most one at a time; the result is swapped in atomically.

v2.1: every run is traced (15-agent scan trace), each new threat gets its own audit entry,
and the run can analyze only user-entered input (input_mode="only") or input + dataset ("merge").
"""
import logging
import threading
import time
from datetime import datetime, timezone

from app import notify, trace

log = logging.getLogger(__name__)

_run_lock = threading.Lock()
_state: dict = {"state": "idle", "run_id": 0, "started_at": None, "finished_at": None,
                "duration_ms": None, "detail": "", "alerts": None, "threats": None, "mode": None}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def status() -> dict:
    return dict(_state)


def is_running() -> bool:
    return _state["state"] == "running"


def run_now(app, use_sample: bool | None = None, input_mode: str | None = None) -> None:
    """Synchronous run used at startup and by the terminal scan. Never raises."""
    _execute(app, use_sample, input_mode)


def start(app, use_sample: bool | None = None, input_mode: str | None = None) -> tuple[bool, dict]:
    """Start a background run. Returns (started, status). started=False if one is already running."""
    if not _run_lock.acquire(blocking=False):
        return False, status()
    _state.update(state="running", run_id=_state["run_id"] + 1, started_at=_now(), finished_at=None,
                  duration_ms=None, detail="", alerts=None, threats=None, mode=_mode(use_sample, input_mode))

    def _job() -> None:
        try:
            _execute(app, use_sample, input_mode, locked=True)
        finally:
            _run_lock.release()

    threading.Thread(target=_job, name="pipeline-run", daemon=True).start()
    return True, status()


def _mode(use_sample: bool | None, input_mode: str | None) -> str:
    if input_mode == "only":
        return "input"
    if input_mode == "merge":
        return "dataset+input"
    return "sample" if use_sample else "dataset"


def _execute(app, use_sample: bool | None, input_mode: str | None = None, locked: bool = False) -> None:
    t0 = time.perf_counter()
    mode = _mode(use_sample, input_mode)
    if not locked:
        _state.update(state="running", run_id=_state["run_id"] + 1, started_at=_now(), finished_at=None,
                      mode=mode)
    trace.begin_run(mode)
    try:
        from app.pipeline import run_pipeline  # imported lazily so a broken pipeline cannot break startup
        kwargs: dict = {"use_sample": use_sample}
        if input_mode:
            kwargs["input_mode"] = input_mode
        result = run_pipeline(**kwargs)
        previous = getattr(app.state, "result", None)
        if result.status == "failed" and previous is not None:
            # keep showing the last good results instead of an empty console
            _state.update(state="failed", detail=f"Run failed, showing previous results: {result.detail}",
                          alerts=len(previous.alerts), threats=0)
            trace.end_run("failed", {"status": result.status, "detail": result.detail,
                                     "kept_previous_results": True})
            return
        app.state.result = result                       # single reference swap = atomic for readers
        app.state.startup_error = ""
        threats = trace.log_threats(result.alerts)      # one separate audit entry per new threat
        _state.update(state="failed" if result.status == "failed" else "done",
                      detail=result.detail or "", alerts=len(result.alerts), threats=len(threats))
        notify.notify_new_alerts(result.alerts, total_open=len(result.alerts))   # async, never raises
        trace.end_run("failed" if result.status == "failed" else "done",
                      {"status": result.status, "alerts": len(result.alerts), "threats_logged": len(threats),
                       "detail": result.detail or ""})
    except Exception as exc:  # noqa: BLE001 - server must keep running
        log.exception("Pipeline run failed")
        app.state.startup_error = f"{type(exc).__name__}: {exc}"
        _state.update(state="failed", detail=app.state.startup_error)
        trace.end_run("failed", {"error": app.state.startup_error})
    finally:
        _state.update(finished_at=_now(), duration_ms=round((time.perf_counter() - t0) * 1000, 1))
