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
