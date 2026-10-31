"""Tests for the 30-day identity memory (app/memory30). No network, no sleeping: time comes from event data."""
from __future__ import annotations

import json
from collections import defaultdict
from datetime import date, datetime, timedelta, timezone

import pytest

from app.memory30 import config, synth
from app.memory30.engine import MemoryEngine
from app.memory30.normalize import cloudtrail_identity, network_of, normalize, parse_json_text

END = date(2026, 10, 31)


def _ct(eid, when, name, ip="198.51.100.9", email="dev@acme.example", params=None, source="iam", error=None):
    rec = {"eventID": eid, "eventTime": when.strftime("%Y-%m-%dT%H:%M:%SZ"), "eventName": name,
           "eventSource": f"{source}.amazonaws.com", "sourceIPAddress": ip,
           "userIdentity": {"type": "AssumedRole", "arn": f"arn:aws:sts::1:assumed-role/eng-role/{email}"},
           "requestParameters": params or {}}
    if error:
        rec["errorCode"] = error
    return rec


def _okta(eid, when, email="dev@acme.example", ip="198.51.100.9", asn=64500, proxy=False):
    return {"uuid": eid, "published": when.strftime("%Y-%m-%dT%H:%M:%S.000Z"), "eventType": "user.session.start",
            "actor": {"alternateId": email}, "client": {"ipAddress": ip},
            "securityContext": {"asNumber": asn, "isProxy": proxy}, "outcome": {"result": "SUCCESS"}}


def _t(day: int, hour: int = 10) -> datetime:
    d = END - timedelta(days=40) + timedelta(days=day)
    return datetime(d.year, d.month, d.day, hour, tzinfo=timezone.utc)


def _normal_history(days=range(0, 5), email="dev@acme.example"):
    out = []
    for d in days:
        out.append(_okta(f"n-okta-{email}-{d}", _t(d, 9), email=email))
        out.append(_ct(f"n-ct-{email}-{d}", _t(d, 10), "GetObject", email=email, source="s3",
                       params={"bucketName": "acme-eng-shared", "key": "a.txt"}))
    return out


@pytest.fixture()
def eng(tmp_path):
    e = MemoryEngine(tmp_path / "mem.sqlite")
    yield e
    e.close()


# ---------------------------------------------------------------- normalization
def test_normalize_okta_and_cloudtrail_identity_resolution():
    o = normalize(_okta("u1", _t(1), email="Alice@Acme.example", proxy=True))
    assert o["identity"] == "alice@acme.example" and o["source"] == "okta"
    assert o["net"] == "asn:64500" and o["is_proxy"] is True and o["category"] == "login"
    c = normalize(_ct("e1", _t(1), "AttachUserPolicy", email="alice@acme.example",
                      params={"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}))
    assert c["identity"] == "alice@acme.example" and c["category"] == "privesc"
    assert cloudtrail_identity({"type": "SAMLUser", "userName": "Bob@acme.example"})[0] == "bob@acme.example"
    assert cloudtrail_identity({"type": "IAMUser", "userName": "svc-report"})[0] == "svc-report"
    assert network_of("198.51.100.7") == "v4:198.51.0.0" and network_of("s3.amazonaws.com") is None
    assert normalize({"foo": 1}) is None


def test_parse_json_formats():
    assert len(parse_json_text(json.dumps({"Records": [{"a": 1}, {"b": 2}]}))) == 2
    assert len(parse_json_text(json.dumps([{"a": 1}]))) == 1
    assert len(parse_json_text('{"a": 1}\n{"b": 2}\n')) == 2
    assert parse_json_text("") == []


# ---------------------------------------------------------------- ingest
def test_ingest_is_idempotent(eng):
    recs = _normal_history()
    first = eng.ingest_records(recs)
    second = eng.ingest_records(recs)
    assert first["inserted"] == len(recs) and second["inserted"] == 0 and second["duplicates"] == len(recs)
    assert eng.stats()["rows"]["events"] == len(recs)


def test_slow_chain_over_14_days_is_linked(eng):
    recs = _normal_history(range(0, 6))
    recs += [_okta("a1", _t(6, 21), ip="185.220.101.23", asn=64510, proxy=True),
             _ct("a2", _t(11, 22), "CreateAccessKey", ip="185.220.101.23", params={"userName": "dev"})]
    recs += [_ct(f"a3-{i}", _t(15, 22) + timedelta(minutes=i), n, ip="185.220.101.23", source=s)
             for i, (n, s) in enumerate([("ListUsers", "iam"), ("ListRoles", "iam"), ("ListBuckets", "s3"),
                                         ("DescribeInstances", "ec2"), ("ListSecrets", "secretsmanager")])]
    recs += [_ct("a4", _t(20, 22), "AttachUserPolicy", ip="185.220.101.23",
                 params={"userName": "dev", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"})]
    eng.ingest_records(recs)
    fs = eng.findings(identity="dev@acme.example")
    assert len(fs) == 1
    f = fs[0]
    assert {"initial_access", "persistence", "discovery", "privilege_escalation"} <= set(f["stages"])
    assert f["risk"] >= 90 and f["days_spanned"] >= 4
    assert "okta:a1" in f["evidence"] and "cloudtrail:a4" in f["evidence"]


def test_steps_32_days_apart_are_not_linked(eng):
    recs = _normal_history(range(0, 4))
    recs += [_ct("g1", _t(4), "AttachRolePolicy", params={"roleName": "x"}),
             _ct("g2", _t(36), "CreateAccessKey", params={"userName": "dev"})]
    eng.ingest_records(recs)
    for f in eng.findings(identity="dev@acme.example"):
        assert not {"cloudtrail:g1", "cloudtrail:g2"} <= set(f["evidence"])


def test_routine_team_writes_are_not_suspicious(eng):
    recs = []
    for who in ("f1", "f2", "f3", "f4"):
        email = f"{who}@acme.example"
        recs += _normal_history(range(0, 6), email=email)
        day = 1 if who != "f4" else 5          # f4 writes for the first time after the baseline period
        recs.append(_ct(f"w-{who}", _t(day, 11), "PutObject", email=email, source="s3",
                        params={"bucketName": "acme-finance-shared", "key": "r.pdf"}))
    eng.ingest_records(recs)
    assert eng.findings() == []
    hits = eng.store.query("SELECT * FROM chain_hits WHERE kind='modify_sensitive'")
    assert hits == []   # shared team resource: >= 3 other writers


def test_prune_keeps_evidence_and_findings(eng):
    test_slow_chain_over_14_days_is_linked(eng)
    before = eng.stats()["rows"]["events"]
    out = eng.prune(now=_t(30))
    assert out["events_deleted"] > 0
    left = eng.store.query("SELECT event_id, evidence FROM events")
    assert all(r["evidence"] == 1 for r in left if r["event_id"] < "zzz" and r["event_id"].startswith(
        ("cloudtrail:a", "okta:a")))
    assert len(eng.findings()) == 1 and eng.stats()["rows"]["events"] < before
    assert out["evidence_kept"] >= 4


def test_memory_survives_restart(tmp_path):
    db = tmp_path / "restart.sqlite"
    e1 = MemoryEngine(db)
    e1.ingest_records(_normal_history(range(0, 6)) + [
        _okta("r1", _t(6, 21), ip="185.220.101.23", asn=64510, proxy=True),
        _ct("r2", _t(9, 22), "CreateAccessKey", ip="185.220.101.23", params={"userName": "dev"})])
    before = e1.findings(identity="dev@acme.example")
    assert len(before) == 1 and "privilege_escalation" not in before[0]["stages"]
    e1.close()
    e2 = MemoryEngine(db)                       # "app restarted"
    e2.ingest_records([_ct("r3", _t(18, 22), "AttachUserPolicy", ip="185.220.101.23",
                           params={"userName": "dev", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"})])
    fs = e2.findings(identity="dev@acme.example")
    assert len(fs) == 1 and fs[0]["finding_id"] == before[0]["finding_id"]      # same case, extended
    assert "okta:r1" in fs[0]["evidence"] and "cloudtrail:r3" in fs[0]["evidence"]
    assert "privilege_escalation" in fs[0]["stages"] and fs[0]["risk"] >= before[0]["risk"]
    e2.close()


def test_identity_view_has_30_days(eng):
    test_slow_chain_over_14_days_is_linked(eng)
    v = eng.identity_view("dev@acme.example", days=30)
    assert len(v["days"]) == 30 and v["risk_peak"] >= 90
    assert any(d["max_risk"] > 0 for d in v["days"]) and v["findings"]
    assert eng.identity_view("nobody@x", 30) is None


# ---------------------------------------------------------------- full synthetic 30 days
@pytest.fixture(scope="module")
def synth_run(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("synth")
    okta, ct, labels = synth.generate(days=30, identities=60, seed=42, end=END)
    e = MemoryEngine(tmp / "s.sqlite")
    e.ingest_records(okta + ct)
    yield e, labels, okta, ct
    e.close()


def test_synthetic_30_days_detects_all_scenarios_without_false_positives(synth_run):
    e, labels, _, _ = synth_run
    rep = synth.report(e, labels)
    assert rep["total"] == 3 and rep["passed"] == 3, rep
    assert rep["false_positive_count"] == 0, rep["false_positive_identities"]
    heist = next(f for f in e.findings() if f["identity"] == "safe.dev@acme.example")
    assert heist["days_spanned"] >= 10      # slow heist evidence spans many days
    insider = next(f for f in e.findings() if f["identity"] == "meera.ops@acme.example")
    assert insider["days_spanned"] >= 3


def test_day_by_day_live_ingest_matches_batch(synth_run, tmp_path):
    e_batch, labels, okta, ct = synth_run
    by_day = defaultdict(list)
    for r in okta:
        by_day[r["published"][:10]].append(r)
    for r in ct:
        by_day[r["eventTime"][:10]].append(r)
    live = MemoryEngine(tmp_path / "live.sqlite")
    for d in sorted(by_day):
        live.ingest_records(by_day[d])
    batch_ids = {f["identity"] for f in e_batch.findings()}
    live_ids = {f["identity"] for f in live.findings()}
    assert live_ids == batch_ids
    assert synth.report(live, labels)["passed"] == 3
    live.close()


def test_storage_stays_small(synth_run):
    e, _, _, _ = synth_run
    st = e.stats()
    assert st["db_size_mb"] < 200 and st["rows"]["identity_daily"] > 0
    assert st["retention"]["memory_days"] == config.MEMORY_RETENTION_DAYS


def test_gap_scenario_in_40_day_synthetic(tmp_path):
    okta, ct, labels = synth.generate(days=40, identities=30, seed=7, end=END)
    e = MemoryEngine(tmp_path / "g.sqlite")
    e.ingest_records(okta + ct)
    rep = synth.report(e, labels)
    gap = next(r for r in rep["scenarios"] if r["scenario"] == "gap_32_days")
    assert gap["passed"] and rep["passed"] == rep["total"]
    e.close()


# ---------------------------------------------------------------- API (runs where FastAPI is installed)
def test_api_routes(tmp_path, monkeypatch):
    fastapi = pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    monkeypatch.setattr(config, "DB_PATH", tmp_path / "api.sqlite")
    monkeypatch.setattr(config, "SYNTH_DIR", tmp_path / "synth")
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setenv("ANALYST_TOKEN", "t0k3n")
    from app.memory30 import api
    monkeypatch.setattr(api, "_engine", None)
    app = fastapi.FastAPI()
    app.include_router(api.router, prefix="/api/memory")
    client = TestClient(app)
    assert client.post("/api/memory/synth", json={"days": 30, "identities": 20}).status_code == 401
    r = client.post("/api/memory/synth", json={"days": 30, "identities": 20},
                    headers={"X-Analyst-Token": "t0k3n"})
    assert r.status_code == 200 and r.json()["report"]["passed"] == 3
    assert client.get("/api/memory/stats").json()["rows"]["events"] > 0
    fs = client.get("/api/memory/findings").json()["findings"]
    assert fs
    v = client.get(f"/api/memory/identity/{fs[0]['identity']}").json()
    assert len(v["days"]) == 30
    ev = client.get("/api/memory/evidence", params={"ids": ",".join(fs[0]["evidence"][:3])}).json()
    assert len(ev["events"]) >= 1
    assert client.get("/api/memory/identity/nobody").status_code == 404
    assert client.post("/api/memory/ingest", json={"paths": ["/etc"]},
                       headers={"X-Analyst-Token": "t0k3n"}).status_code == 422
    assert client.post("/api/memory/prune", json={}, headers={"X-Analyst-Token": "t0k3n"}).status_code == 200
