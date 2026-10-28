import time
from types import SimpleNamespace

from app import pipeline, runner


def _app():
    return SimpleNamespace(state=SimpleNamespace(result=None, startup_error=""))


def _ok(use_sample=None):
    time.sleep(0.2)
    return SimpleNamespace(status="ok", detail="", alerts=[])


def test_single_flight_background_run(monkeypatch):
    monkeypatch.setattr(pipeline, "run_pipeline", _ok)
    app = _app()
    started, st = runner.start(app)
    assert started and st["state"] == "running"
    assert runner.start(app)[0] is False            # second run refused while first is running
    for _ in range(100):
        if not runner.is_running():
            break
        time.sleep(0.05)
    assert runner.status()["state"] == "done" and app.state.result.status == "ok"


def test_exception_is_contained(monkeypatch):
    def boom(use_sample=None):
        raise RuntimeError("boom")
    monkeypatch.setattr(pipeline, "run_pipeline", boom)
    app = _app()
    runner.run_now(app)
    assert runner.status()["state"] == "failed" and "boom" in app.state.startup_error


def test_failed_run_keeps_previous_result(monkeypatch):
    app = _app()
    monkeypatch.setattr(pipeline, "run_pipeline", _ok)
    runner.run_now(app)
    good = app.state.result
    monkeypatch.setattr(pipeline, "run_pipeline",
                        lambda use_sample=None: SimpleNamespace(status="failed", detail="bad", alerts=[]))
    runner.run_now(app)
    assert app.state.result is good and "previous results" in runner.status()["detail"]
