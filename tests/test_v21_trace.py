import json
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from app import audit, config, pipeline, runner, scan, store, trace
from app.models import Alert

T0 = datetime(2026, 10, 28, 4, 10, tzinfo=timezone.utc)


def _alert(ident, risk=94.0, band="revoke", patterns=("P3", "P2")):
    return Alert(alert_id=f"AL-{uuid.uuid4().hex[:6]}", identity_id=ident, session_id=f"s-{ident}", risk=risk,
                 confidence=0.9, band=band, patterns=list(patterns), mitre=["T1098"], reasons=["chain found"],
                 evidence_event_ids=["e1", "e2"], recommended_action=band, first_seen=T0, last_seen=T0)


@pytest.fixture(autouse=True)
def _clean():
    store.init_db()
    trace.reset()
    yield
    trace.reset()


# ---------------- trace + agents ----------------

def test_registry_has_15_agents_in_5_layers():
    assert len(trace.AGENTS) == 15 and [a["num"] for a in trace.AGENTS] == list(range(1, 16))
    assert {a["layer"] for a in trace.AGENTS} == set(trace.LAYERS)
    assert trace.PATTERN_AGENT == {"P1": "impossible_travel", "P2": "dormant", "P3": "priv_escalation",
                                   "P4": "api_anomaly", "P5": "token_abuse", "ML": "baseline_ml"}


def test_step_success_failure_and_status():
    trace.begin_run("dataset")
    with trace.step("ingestion", "Loading files") as s:
        s.output({"records": 10}, "Loaded 10 records")
    with pytest.raises(RuntimeError):
        with trace.step("normalization", "Normalizing"):
            raise RuntimeError("bad field")
    with trace.step("priv_escalation", "Scanning") as s:
        s.output({"signals": 3})
    st = {a["id"]: a for a in trace.agents_status()}
    assert st["ingestion"]["state"] == "done" and st["ingestion"]["last_output"] == {"records": 10}
    assert st["normalization"]["state"] == "failed" and "bad field" in st["normalization"]["last_error"]
    assert st["priv_escalation"]["signals"] == 3 and st["dormant"]["state"] == "waiting"
    run = trace.run_status()
    assert run["state"] == "running" and run["completed"] == ["ingestion", "priv_escalation"]
    assert run["failed"] == ["normalization"] and run["total_steps"] == 13
    evs = trace.events()
    assert [e["state"] for e in evs][:3] == ["started", "started", "done"]
    assert all(e["run_id"] == run["run_id"] for e in evs)
    assert trace.events(after=evs[-1]["seq"]) == []


def test_payload_is_json_safe_and_capped(monkeypatch):
    monkeypatch.setattr(config, "TRACE_MAX_DATA_CHARS", 100)
    ev = trace.emit("ingestion", "info", "big", {"x": "y" * 500, "n": float("nan")})
    assert ev["data"]["truncated"] is True
    assert trace.emit("ingestion", "info", "nan", {"n": float("nan")})["data"] == {"n": None}


def test_listener_errors_are_swallowed():
    def bad(_ev):
        raise ValueError("listener broke")
    trace.add_listener(bad)
    try:
        assert trace.emit("orchestrator", "info", "still works")["message"] == "still works"
    finally:
        trace.remove_listener(bad)


def test_each_threat_gets_its_own_audit_entry_and_dedupes():
    who = f"user-{uuid.uuid4().hex[:6]}"
    alerts = [_alert(who), _alert(who + "b", 72, "restrict", ("P1",)), _alert(who + "c", 20, "monitor", ("ML",))]
    trace.begin_run("dataset")
    logged = trace.log_threats(alerts)
    assert [d["identity_id"] for d in logged] == [who, who + "b"]           # monitor-band alert not logged
    rows = store.execute("SELECT detail FROM audit WHERE action = 'threat_detected'")
    mine = [json.loads(r["detail"]) for r in rows if json.loads(r["detail"])["identity_id"].startswith(who)]
    assert len(mine) == 2 and mine[0]["detectors"] == ["dormant", "priv_escalation"]
    assert trace.log_threats(alerts) == []                                   # same threats again -> nothing new
    assert trace.log_threats([_alert(who + "b", 95, "revoke", ("P1",))])     # escalation -> logged again
    threat_events = [e for e in trace.events() if e["state"] == "threat"]
    assert len(threat_events) == 3 and threat_events[0]["agent_id"] == "priv_escalation"
    assert trace.run_status()["threats"] == 3
    assert audit.verify() == (True, None)


def test_render_ansi_color_and_json():
    trace.begin_run("dataset")
    ev = trace.log_threats([_alert(f"r-{uuid.uuid4().hex[:6]}")])
    line = trace.render_ansi(trace.events()[-1], show_json=True, color=True)
    assert "\x1b[" in line and "THREAT" in line and '"fingerprint"' in line
    plain = trace.render_ansi(trace.events()[-1], show_json=True, color=False)
    assert "\x1b[" not in plain and json.loads("{" + plain.split("{", 1)[1])["risk"] == 94.0
    assert ev


# ---------------- runner + terminal scan ----------------

def _fake_pipeline(alerts):
    def run_pipeline(use_sample=None, input_mode=None):
        for aid in trace.SCAN_AGENT_IDS:
            with trace.step(aid, f"{aid} working") as s:
                s.output({"signals": 1} if aid == "priv_escalation" else {"ok": True})
        return SimpleNamespace(status="ok", detail="", alerts=alerts)
    return run_pipeline


def test_runner_traces_run_and_logs_threats(monkeypatch):
    monkeypatch.setattr(config, "EMAIL_MODE", "off")
    who = f"run-{uuid.uuid4().hex[:6]}"
    monkeypatch.setattr(pipeline, "run_pipeline", _fake_pipeline([_alert(who)]))
    app = SimpleNamespace(state=SimpleNamespace(result=None, startup_error=""))
    runner.run_now(app, input_mode="only")
    st, run = runner.status(), trace.run_status()
    assert st["state"] == "done" and st["threats"] == 1 and st["mode"] == "input"
    assert run["state"] == "done" and run["progress"] == 1.0 and run["threats"] == 1
    assert trace.events()[-1]["agent_id"] == "orchestrator" and trace.events()[-1]["state"] == "done"


def test_terminal_scan_outputs_color_and_json(monkeypatch, capsys):
    monkeypatch.setattr(pipeline, "run_pipeline", _fake_pipeline([_alert(f"cli-{uuid.uuid4().hex[:6]}")]))
    assert scan.main(["--json"]) == 0
    out = capsys.readouterr().out
    assert "\x1b[" in out and "THREAT" in out and "PRIV_ESCALATION" in out and '"signals"' in out
    assert "SCAN COMPLETE" in out
    assert config.EMAIL_MODE == "off"


def test_terminal_scan_jsonl(monkeypatch, capsys):
    monkeypatch.setattr(pipeline, "run_pipeline", _fake_pipeline([]))
    assert scan.main(["--jsonl"]) == 0
    lines = [json.loads(x) for x in capsys.readouterr().out.strip().splitlines()]
    assert lines[0]["state"] == "started" and "summary" in lines[-1]
