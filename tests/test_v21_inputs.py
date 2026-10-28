import json

import pytest

from app import config, inputs


# ---------------- data input ----------------

@pytest.fixture()
def inbox(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "INPUT_DIR", tmp_path / "input")
    return tmp_path / "input"


CT = {"eventID": "c1", "eventTime": "2026-10-28T04:00:00Z", "eventName": "AttachUserPolicy",
      "eventSource": "iam.amazonaws.com", "userIdentity": {"userName": "svc-report"}}
OK = {"uuid": "o1", "published": "2026-10-28T03:59:00Z", "eventType": "user.session.start",
      "actor": {"alternateId": "svc-report@corp.example"}, "outcome": {"result": "SUCCESS"}}


def test_upload_formats_and_autodetect(inbox):
    r = inputs.save_input(json.dumps({"Records": [CT, CT]}), "auto", "trail.json")
    assert r["accepted"] == {"cloudtrail": 2, "okta": 0} and r["files"][0]["file"].startswith("cloudtrail_")
    r = inputs.save_input(json.dumps([CT, OK, {"foo": 1}]))
    assert r["accepted"] == {"cloudtrail": 1, "okta": 1} and r["rejected"] == 1
    r = inputs.save_input(json.dumps(OK) + "\n" + "{bad json\n" + json.dumps(OK))
    assert r["accepted"]["okta"] == 2 and r["rejected"] == 1
    listed = inputs.list_inputs()
    assert listed["totals"] == {"cloudtrail": 3, "okta": 3} and inputs.has_input()
    assert inputs.clear_inputs() == 4 and not inputs.has_input()


def test_upload_rejections(inbox, monkeypatch):
    with pytest.raises(inputs.InputError):
        inputs.save_input("   ")
    with pytest.raises(inputs.InputError):
        inputs.save_input(json.dumps([{"foo": 1}]))
    with pytest.raises(inputs.InputError):
        inputs.save_input(json.dumps(CT), source="evil")
    monkeypatch.setattr(config, "INPUT_MAX_BYTES", 50)
    with pytest.raises(inputs.InputError):
        inputs.save_input(json.dumps([CT, CT, CT]))


def test_filename_is_sanitized(inbox):
    r = inputs.save_input(json.dumps(CT), "cloudtrail", "../../etc/passwd")
    path = inbox / "cloudtrail" / r["files"][0]["file"]
    assert path.exists() and path.parent == inbox / "cloudtrail" and ".." not in path.name


def test_manual_records(inbox):
    src, rec = inputs.build_manual_record("okta_login", {
        "user": "anita.rao", "ip": "203.0.113.9", "time": "2026-10-28T04:00:00Z", "country": "Germany",
        "city": "Frankfurt", "lat": "50.11", "lon": "8.68", "label": "impossible_travel"})
    assert src == "okta" and rec["actor"]["alternateId"] == "anita.rao@corp.example"
    assert rec["client"]["geographicalContext"]["geolocation"] == {"lat": 50.11, "lon": 8.68}
    src, rec = inputs.build_manual_record("cloudtrail_api", {
        "user": "svc-report", "ip": "198.51.100.7", "event_name": "AttachUserPolicy",
        "resource": "arn:aws:iam::aws:policy/AdministratorAccess"})
    assert src == "cloudtrail" and rec["resources"][0]["ARN"].endswith("AdministratorAccess")
    for bad in ({"user": "x", "ip": "999.1.1.1"}, {"user": "bad user!", "ip": "1.1.1.1"},
                {"user": "x", "ip": "1.1.1.1", "lat": "123"}, {"user": "x", "ip": "1.1.1.1", "time": "yesterday"}):
        with pytest.raises(inputs.InputError):
            inputs.build_manual_record("okta_login", bad)
    with pytest.raises(inputs.InputError):
        inputs.build_manual_record("cloudtrail_api", {"user": "x", "ip": "1.1.1.1", "event_name": "Drop;Table"})
    inputs.add_manual("okta_logout", {"user": "meera.n", "ip": "2001:db8::1"})
    inputs.add_manual("okta_login", {"user": "meera.n", "ip": "2001:db8::1"})
    assert inputs.list_inputs()["totals"]["okta"] == 2
