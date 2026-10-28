"""API integration tests matching TECH_PRD Section 20.2 and Phase 17 specifications."""
from fastapi.testclient import TestClient

from app.main import app


def test_health_and_alerts():
    with TestClient(app) as client:
        r = client.get("/api/health")
        assert r.status_code == 200
        assert r.json()["pipeline"] in {"ok", "failed", "not_run"}

        r = client.get("/api/alerts")
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)
        assert len(data) > 0


def test_unknown_alert_404():
    with TestClient(app) as client:
        r = client.get("/api/alerts/DOES-NOT-EXIST")
        assert r.status_code == 404
        body = r.json()
        assert {"error", "detail", "request_id"} <= set(body.keys())
        assert body["error"] == "not_found"


def test_action_unknown_alert_404():
    with TestClient(app) as client:
        r = client.post("/api/alerts/DOES-NOT-EXIST/action", json={"action": "step_up"})
        assert r.status_code == 404
        body = r.json()
        assert body["error"] == "not_found"


def test_revoke_without_approved_by_409():
    with TestClient(app) as client:
        # Get alerts to find a valid alert ID
        r = client.get("/api/alerts")
        assert r.status_code == 200
        alerts = r.json()
        assert len(alerts) > 0
        alert_id = alerts[0]["alert_id"]

        # Revoke without approved_by should return 409 Conflict
        r_refused = client.post(f"/api/alerts/{alert_id}/action", json={"action": "revoke"})
        assert r_refused.status_code == 409
        assert "approval" in r_refused.json().get("detail", "").lower()

        # Revoke with analyst approval should succeed with 200 and status="applied"
        r_approved = client.post(
            f"/api/alerts/{alert_id}/action",
            json={"action": "revoke", "approved_by": "lead-sec-ops"},
        )
        assert r_approved.status_code == 200
        act_res = r_approved.json()
        assert act_res["status"] == "applied"
        assert act_res["action"] == "revoke"


def test_feedback_returns_alert():
    with TestClient(app) as client:
        r = client.get("/api/alerts")
        assert r.status_code == 200
        alerts = r.json()
        assert len(alerts) > 0
        alert_id = alerts[0]["alert_id"]

        # Submit analyst feedback
        r_fb = client.post(
            f"/api/alerts/{alert_id}/feedback",
            json={"label": "tp"},
        )
        assert r_fb.status_code == 200
        updated_alert = r_fb.json()

        # Check response matches Alert model structure
        required_alert_fields = {
            "alert_id",
            "identity_id",
            "risk",
            "confidence",
            "band",
            "patterns",
            "mitre",
            "reasons",
            "evidence_event_ids",
            "recommended_action",
            "feedback",
        }
        assert required_alert_fields <= set(updated_alert.keys())
        assert updated_alert["alert_id"] == alert_id
        assert updated_alert["feedback"] == "tp"


def test_supporting_endpoints():
    with TestClient(app) as client:
        # Summary
        r_sum = client.get("/api/summary")
        assert r_sum.status_code == 200
        assert "totals" in r_sum.json()
        assert "alerts" in r_sum.json()["totals"]

        # Identities
        r_ids = client.get("/api/identities")
        assert r_ids.status_code == 200
        assert isinstance(r_ids.json(), list)

        # Audit verify
        r_audit = client.get("/api/audit/verify")
        assert r_audit.status_code == 200
        assert r_audit.json()["valid"] is True

        # Metrics
        r_metrics = client.get("/api/metrics")
        assert r_metrics.status_code == 200
        assert "total_events" in r_metrics.json()
