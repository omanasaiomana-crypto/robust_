import time
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from app import config, pipeline, runner, scan, store, trace
from app.models import Alert, Signal

T0 = datetime(2026, 10, 28, 4, 10, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    store.init_db()
    trace.reset()
    monkeypatch.setattr(config, "EMAIL_MODE", "off")
    yield
    trace.set_pace(0)
    trace.reset()


def _sig(ident, sev):
    return Signal(pattern="P1", severity=sev, identity_id=ident, session_id=f"s-{ident}", agent="impossible_travel",
                  reason=f"{ident} moved too fast", evidence_event_ids=["e1"], mitre=["T1078"], timestamp=T0)


def _fake(alerts=()):
    def run_pipeline(use_sample=None, input_mode=None):
        for aid in trace.SCAN_AGENT_IDS:
            with trace.step(aid, f"{aid} working") as s:
                if aid == "ingestion":
                    trace.progress(aid, "Read CloudTrail · 2,214 records")
                if aid == "impossible_travel":
                    trace.signal_findings(aid, [_sig("anita.rao", 0.9), _sig("x", 0.4)])
                s.output({"ok": True})
        return SimpleNamespace(status="ok", detail="", alerts=list(alerts))
    return run_pipeline


def test_set_pace_clamps():
    assert trace.set_pace(99) == trace.MAX_PACE_SECONDS and trace.set_pace(-1) == 0 and trace.set_pace("x") == 0


def test_findings_and_progress_are_traced():
    trace.begin_run("dataset")
    with trace.step("impossible_travel", "scan") as s:
        trace.signal_findings("impossible_travel", [_sig("a", 0.3), _sig("b", 0.95)], limit=1)
        s.finding("manual finding")
    evs = trace.events()
    states = [e["state"] for e in evs]
    assert states.count("finding") == 2 and "progress" in states            # +1 more signal(s)
    first = next(e for e in evs if e["state"] == "finding")
    assert first["data"]["identity_id"] == "b" and first["level"] == "warn"   # highest severity first
    assert trace.run_status()["findings"] == 2
    assert "\x1b[33m" in trace.render_ansi(first)


def test_paced_run_is_really_slower_and_streams_live(monkeypatch):
    monkeypatch.setattr(pipeline, "run_pipeline", _fake())
    app = SimpleNamespace(state=SimpleNamespace(result=None, startup_error=""))
    t0 = time.perf_counter()
    runner.run_now(app, pace=0)
    fast = time.perf_counter() - t0
    trace.reset()
    started, _ = runner.start(app, pace=0.15)
    assert started
    time.sleep(0.6)
    mid = trace.events()
    assert trace.run_status()["state"] == "running" and 2 < len(mid) < 40      # events arrive while it runs
    while runner.is_running():
        time.sleep(0.05)
    slow = runner.status()["duration_ms"] / 1000
    assert slow > fast + 1.0 and slow > 13 * 0.15 * 0.7
    assert trace.run_status()["pace"] == 0.15 and trace.get_pace() == 0       # pace reset after the run
    assert trace.events()[0]["data"]["pace_seconds_per_step"] == 0.15


def test_cli_pace(monkeypatch, capsys):
    monkeypatch.setattr(pipeline, "run_pipeline", _fake())
    t0 = time.perf_counter()
    assert scan.main(["--pace", "0.05", "--no-color"]) == 0
    out = capsys.readouterr().out
    assert "**" in out and "anita.rao moved too fast" in out and "live pace 0.1s/step" in out or "live pace" in out
    assert time.perf_counter() - t0 > 13 * 0.05 * 0.7
