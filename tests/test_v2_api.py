"""Integration tests for v2 analytics API endpoints."""
from fastapi.testclient import TestClient

from app.main import app


def test_analytics_endpoints_and_keys():
    with TestClient(app) as client:
        # Detectors comparison
        r = client.get("/api/analytics/detectors")
        assert r.status_code == 200
        d = r.json()
        for k in ("labeled", "rows", "matrix", "agreement", "winner"):
            assert k in d

        # Attack time heatmap
        r = client.get("/api/analytics/heatmap/time")
        assert r.status_code == 200
        t = r.json()
        for k in ("days", "hours", "cells", "max", "total", "tz"):
            assert k in t

        # Identity pattern heatmap
        r = client.get("/api/analytics/heatmap/identities")
        assert r.status_code == 200
        i = r.json()
        for k in ("identities", "patterns", "cells", "max"):
            assert k in i


def test_heatmap_days_clamp():
    with TestClient(app) as client:
        r = client.get("/api/analytics/heatmap/time?days=999")
        assert r.status_code == 200
        data = r.json()
        assert len(data["days"]) <= 60


def test_detectors_sample_data_properties():
    with TestClient(app) as client:
        r = client.get("/api/analytics/detectors")
        assert r.status_code == 200
        data = r.json()
        assert data["labeled"] is True
        first_three = [row["id"] for row in data["rows"][:3]]
        assert first_three == ["rules", "ml", "hybrid"]
        if data.get("winner"):
            assert "text" in data["winner"]


def test_pipeline_not_ready_503(monkeypatch):
    with TestClient(app) as client:
        orig = app.state.result
        try:
            app.state.result = None
            r = client.get("/api/analytics/detectors")
            assert r.status_code == 503
            assert r.json().get("error") == "pipeline_not_ready"
        finally:
            app.state.result = orig


def test_notifications_status_and_no_password():
    with TestClient(app) as client:
        r = client.get("/api/notifications/status")
        assert r.status_code == 200
        data = r.json()
        for k in ("mode", "recipients", "min_risk"):
            assert k in data
        assert "password" not in r.text.lower()


def test_notifications_test_send():
    with TestClient(app) as client:
        r = client.post("/api/notifications/test")
        assert r.status_code == 200
        data = r.json()
        assert data.get("status") in {"outbox", "sent", "failed", "rate_limited", "off"}


def test_alert_notify_not_found():
    with TestClient(app) as client:
        r = client.post("/api/alerts/DOES-NOT-EXIST/notify")
        assert r.status_code == 404
        assert r.json().get("error") == "not_found"


def test_startup_digest_notification():
    import time
    with TestClient(app) as client:
        found = False
        for _ in range(30):
            r = client.get("/api/notifications")
            if r.status_code == 200:
                recs = r.json()
                if any(rec.get("kind") == "digest" for rec in recs):
                    found = True
                    break
            time.sleep(0.1)
        assert found, "Expected startup digest notification in list_notifications"


def test_pipeline_run_background_and_status():
    import time
    with TestClient(app) as client:
        r = client.post("/api/pipeline/run", json={"use_sample": True})
        assert r.status_code in (202, 409)

        r_st = client.get("/api/pipeline/status")
        assert r_st.status_code == 200
        st = r_st.json()
        assert "state" in st

        t0 = time.time()
        while time.time() - t0 < 30:
            st = client.get("/api/pipeline/status").json()
            if st.get("state") != "running":
                break
            time.sleep(0.2)

        assert st.get("state") in ("done", "idle", "failed")

        r_alerts = client.get("/api/alerts")
        assert r_alerts.status_code == 200

