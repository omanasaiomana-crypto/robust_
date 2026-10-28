import sys
import types
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import pandas as pd
import pytest

from app import config, inputs, pipeline, runner, trace, v21_service as svc
from app.models import Alert, Signal

T0 = datetime(2026, 10, 28, 4, 10, tzinfo=timezone.utc)


def _alert(ident, risk, ev, aid=None):
    return Alert(alert_id=aid or f"AL-{uuid.uuid4().hex[:5]}", identity_id=ident, session_id=f"s-{ident}", risk=risk,
                 confidence=.9, band="revoke" if risk >= 90 else "restrict", patterns=["P3"], mitre=[], reasons=["r"],
                 evidence_event_ids=ev, recommended_action="revoke", first_seen=T0, last_seen=T0, blast_radius=3)


@pytest.fixture()
def res():
    return SimpleNamespace(
        alerts=[_alert("svc", 94, ["e1", "e2"], "AL-1"), _alert("svc", 50, ["e9"]), _alert("meera", 88, ["e5"])],
        signals=[Signal(pattern="P3", severity=.8, identity_id="svc", session_id="s-svc", agent="x", reason="r",
                        evidence_event_ids=["e1"], timestamp=T0)],
        events=pd.DataFrame([{"event_id": "e1", "session_id": "s-svc", "timestamp": T0, "label": "privilege_escalation"}]),
        graph=object())


@pytest.fixture()
def fake_graph(monkeypatch):
    mod = types.ModuleType("app.correlate.graph")
    def identity_subgraph(g, identity_id, suspicious):
        return {"identity_id": identity_id,
                "nodes": [{"id": f"user:{identity_id}", "label": identity_id, "kind": "user", "risk": 0},
                          {"id": "role:Admin", "label": "Admin", "kind": "role", "risk": 0}],
                "edges": [{"source": f"user:{identity_id}", "target": "role:Admin", "label": "assumed",
                           "event_id": "e1" if identity_id == "svc" else "e5", "suspicious": False}],
                "escalation_paths": []}
    mod.identity_subgraph = identity_subgraph
    mod.blast_radius = lambda g, i: 4
    monkeypatch.setitem(sys.modules, "app.correlate.graph", mod)
    import app.correlate
    monkeypatch.setattr(app.correlate, "graph", mod, raising=False)
    return mod


def test_identity_attack_and_global(res, fake_graph):
    out = svc.identity_attack(res, "svc")
    assert out["alert"]["alert_id"] == "AL-1" and out["blast_radius"] == 4 and len(out["graph"]["edges"]) == 1
    assert svc.identity_attack(res, "nobody") is not None   # fake graph always returns nodes
    g = svc.global_graph(res, top=2)
    assert g["identities"] == ["svc", "meera"] and len(g["nodes"]) == 3 and all(e["suspicious"] for e in g["edges"])
    assert svc.global_graph(res, top=2, max_nodes=2)["truncated"] is True


def test_identity_attack_without_graph_module(res, monkeypatch):
    monkeypatch.setitem(sys.modules, "app.correlate.graph", None)
    out = svc.identity_attack(res, "svc")
    assert out["graph"]["nodes"] == [] and out["blast_radius"] == 3          # falls back to alert.blast_radius
    assert svc.identity_attack(res, "nobody") is None


def test_analytics_wrappers(res):
    assert svc.analytics_detectors(res)["labeled"] is True
    assert svc.analytics_time(res, 999)["tz"].startswith("UTC")
    assert svc.analytics_identities(SimpleNamespace(), 5)["identities"] == []
    assert svc.find_alert(res, "AL-1").identity_id == "svc" and svc.find_alert(res, "x") is None


def test_scan_trace_and_start_rules(tmp_path, monkeypatch):
    trace.reset()
    assert svc.scan_trace()["state"] == "idle"
    monkeypatch.setattr(config, "INPUT_DIR", tmp_path / "input")
    app = SimpleNamespace(state=SimpleNamespace(result=None, startup_error=""))
    assert svc.start_scan(app, None, "weird")[0] == "invalid"
    monkeypatch.setattr(pipeline, "run_pipeline", lambda use_sample=None: SimpleNamespace(status="ok", detail="", alerts=[]))
    assert "integration prompt" in svc.start_scan(app, None, "only")[1]        # pipeline lacks input_mode
    monkeypatch.setattr(pipeline, "run_pipeline",
                        lambda use_sample=None, input_mode=None: SimpleNamespace(status="ok", detail="", alerts=[]))
    assert "No input data" in svc.start_scan(app, None, "only")[1]
    monkeypatch.setattr(config, "EMAIL_MODE", "off")
    outcome, st = svc.start_scan(app, None, "dataset")
    assert outcome == "started" and st["state"] in ("running", "done")
    for _ in range(100):
        if not runner.is_running():
            break
        import time; time.sleep(0.02)
    t = svc.scan_trace()
    assert t["state"] == "done" and t["events"][0]["agent_id"] == "orchestrator"
    assert svc.agents_payload()["run"]["state"] == "done"
