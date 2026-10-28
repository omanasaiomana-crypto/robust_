from datetime import datetime, timedelta, timezone

import pandas as pd
import pytest

from app import analytics, audit, config, notify, store
from app.models import Alert, Signal

T0 = datetime(2026, 10, 27, 4, 0, tzinfo=timezone.utc)


def _alert(aid, ident, sess, risk, band, patterns=("P3",), evidence=("e1",)):
    return Alert(alert_id=aid, identity_id=ident, session_id=sess, risk=risk, confidence=0.9, band=band,
                 patterns=list(patterns), mitre=["T1098"], reasons=[f"reason for {ident}"],
                 evidence_event_ids=list(evidence), recommended_action=band, first_seen=T0, last_seen=T0)


def _sig(pattern, ident, sess, eid="e1"):
    return Signal(pattern=pattern, severity=0.8, identity_id=ident, session_id=sess, agent="x",
                  reason="r", evidence_event_ids=[eid], timestamp=T0)


@pytest.fixture()
def data():
    events = pd.DataFrame([
        {"event_id": "e1", "session_id": "s1", "timestamp": T0, "label": "privilege_escalation"},
        {"event_id": "e2", "session_id": "s2", "timestamp": T0 + timedelta(hours=1), "label": "impossible_travel"},
        {"event_id": "e3", "session_id": "s3", "timestamp": T0 + timedelta(days=1), "label": "benign"},
        {"event_id": "e4", "session_id": "s4", "timestamp": T0, "label": "token_abuse"},
    ])
    signals = [_sig("P3", "svc", "s1", "e1"), _sig("P1", "anita", "s2", "e2"), _sig("ML", "svc", "s1", "e1"),
               _sig("ML", "bob", "s3", "e3")]
    alerts = [_alert("AL-1", "svc", "s1", 94, "revoke", ("P3", "ML"), ("e1",)),
              _alert("AL-2", "anita", "s2", 72, "restrict", ("P1",), ("e2",)),
              _alert("AL-3", "bob", "s3", 30, "monitor", ("ML",), ("e3",))]
    return events, signals, alerts


def test_comparison_labeled(data):
    events, signals, alerts = data
    out = analytics.detector_comparison(events, signals, alerts)
    rows = {r["id"]: r for r in out["rows"]}
    assert out["labeled"] and out["malicious_sessions"] == 3
    assert rows["rules"]["tp"] == 2 and rows["rules"]["fp"] == 0 and rows["rules"]["fn"] == 1
    assert rows["ml"]["tp"] == 1 and rows["ml"]["fp"] == 1
    assert rows["hybrid"]["flagged"] == 2          # AL-3 below step-up threshold
    assert out["winner"]["id"] in {"rules", "hybrid"}
    assert out["scenarios"] == ["impossible_travel", "privilege_escalation", "token_abuse"]
    ml_row = next(m for m in out["matrix"] if m["id"] == "ml")
    assert [c["caught"] for c in ml_row["cells"]] == [0, 1, 0] and ml_row["false_alarms"] == 1
    assert out["agreement"]["both"] == 1 and out["agreement"]["missed_by_both"] == 1


def test_comparison_unlabeled_and_empty(data):
    events, signals, alerts = data
    out = analytics.detector_comparison(events.assign(label=None), signals, alerts)
    assert out["labeled"] is False and out["winner"] is None and out["matrix"] == []
    assert analytics.detector_comparison(pd.DataFrame(), [], [])["rows"][0]["flagged"] == 0


def test_heatmaps(data):
    events, signals, alerts = data
    hm = analytics.attack_time_heatmap(events, alerts, days=3, offset_minutes=330)
    assert hm["total"] == 2 and len(hm["days"]) == 3 and len(hm["cells"][0]) == 24
    assert hm["tz"] == "UTC+05:30" and hm["cells"][-1][9] == 1  # 04:00Z -> 09:30 IST
    assert analytics.attack_time_heatmap(pd.DataFrame(), [], days=3)["cells"] == []
    ip = analytics.identity_pattern_heatmap(signals, alerts)
    assert ip["identities"][0] == "svc" and ip["cells"][0][2] == 1


@pytest.fixture()
def mailer(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "OUTBOX_DIR", tmp_path / "outbox")
    monkeypatch.setattr(config, "EMAIL_MODE", "outbox")
    monkeypatch.setattr(config, "ALERT_EMAIL_TO", ["admin@corp.example"])
    store.init_db()
    notify.init_tables()
    store.execute("DELETE FROM notifications")
    return tmp_path


def test_digest_dedupe_and_outbox(mailer, data):
    _, _, alerts = data
    notify.notify_new_alerts(alerts, async_=False)
    rows = notify.list_notifications()
    assert len(rows) == 1 and rows[0]["status"] == "outbox" and rows[0]["alert_ids"] == ["AL-1", "AL-2"]
    assert "CRITICAL" in rows[0]["subject"] and len(list((mailer / "outbox").glob("*.eml"))) == 1
    notify.notify_new_alerts(alerts, async_=False)          # same alerts again -> no new email
    assert len(notify.list_notifications()) == 1
    assert audit.verify() == (True, None)


def test_header_injection_blocked(mailer):
    evil = _alert("AL-9", "evil\r\nBcc: attacker@x.com", "s9", 95, "revoke")
    msg, text = notify.build_digest([evil])
    assert "\n" not in msg["Subject"] and msg["Bcc"] is None
    assert "<script>" not in notify.build_digest([_alert("A", "<script>", "s", 95, "revoke")])[0] \
        .get_body(("html",)).get_content()


def test_smtp_failure_falls_back(mailer, monkeypatch, data):
    monkeypatch.setattr(config, "EMAIL_MODE", "smtp")
    monkeypatch.setattr(config, "SMTP_HOST", "127.0.0.1")
    monkeypatch.setattr(config, "SMTP_PORT", 1)
    monkeypatch.setattr(config, "SMTP_TIMEOUT_SECONDS", 2)
    rec = notify.send_test()
    assert rec["status"] == "failed" and "outbox" in rec["detail"]


def test_rate_limit_and_off(mailer, monkeypatch):
    monkeypatch.setattr(config, "EMAIL_MAX_PER_HOUR", 1)
    assert notify.send_test()["status"] == "outbox"
    assert notify.send_test()["status"] == "rate_limited"
    monkeypatch.setattr(config, "EMAIL_MODE", "off")
    assert notify.send_test() is None
