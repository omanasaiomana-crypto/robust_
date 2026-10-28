from datetime import timezone

from app import audit, store
from app.models import Alert
from app.utils import clean_json, haversine_km, parse_ts, to_band


def test_parse_ts_variants():
    assert parse_ts("2026-10-28T09:00:00Z").tzinfo == timezone.utc
    assert parse_ts("2026-10-28T09:00:00+05:30").hour == 3
    assert parse_ts(0).year == 1970
    assert parse_ts("garbage") is None
    assert parse_ts(None) is None


def test_bands():
    assert [to_band(x) for x in (39.9, 40, 69.9, 70, 89.9, 90)] == [
        "monitor", "step_up", "step_up", "restrict", "restrict", "revoke"]


def test_haversine():
    assert 7400 < haversine_km(12.97, 77.59, 50.11, 8.68) < 7800


def test_clean_json_nan():
    assert clean_json({"a": float("nan"), "b": [1.5]}) == {"a": None, "b": [1.5]}


def test_store_and_audit_roundtrip():
    store.init_db()
    a = Alert(alert_id="AL-TEST", identity_id="x", risk=95, confidence=0.9, band="revoke",
              patterns=["P3"], mitre=["T1098"], reasons=["r"], evidence_event_ids=["e1"],
              recommended_action="revoke", first_seen="2026-10-28T09:00:00Z",
              last_seen="2026-10-28T09:10:00Z")
    store.update_alert(a)
    assert store.load_alert("AL-TEST").risk == 95
    store.execute("DELETE FROM alerts WHERE alert_id = 'AL-TEST'")
    audit.append("test", "check", "ok")
    assert audit.verify() == (True, None)
    store.friction_increment("x", "2026-10-28")
    assert store.friction_used("x", "2026-10-28") >= 1
    assert "P1" in store.get_weights()
