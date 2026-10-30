import json
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app


def test_p14_html_pages_exist():
    expected_html = [
        "static/v3/index.html",
        "static/v3/cases.html",
        "static/v3/case.html",
        "static/v3/live.html",
        "static/v3/agents.html",
    ]
    for p in expected_html:
        path = Path(p)
        assert path.exists(), f"Missing HTML page: {p}"
        content = path.read_text(encoding="utf-8")
        assert "<title>IdentityShield" in content
        assert "/v3/css/theme.css" in content
        assert "bg3d-canvas" in content


def test_p14_page_controllers_exist():
    expected_js = [
        "static/v3/js/pages/dashboard.js",
        "static/v3/js/pages/cases.js",
        "static/v3/js/pages/case.js",
        "static/v3/js/pages/live.js",
        "static/v3/js/pages/agents.js",
    ]
    for p in expected_js:
        path = Path(p)
        assert path.exists(), f"Missing page JS controller: {p}"
        content = path.read_text(encoding="utf-8")
        assert len(content) > 200


def test_p14_mock_fixtures():
    mock_dir = Path("static/v3/mock")
    expected_fixtures = [
        "identities.json",
        "actions.json",
        "run_status.json",
        "playbooks.json",
    ]
    for f in expected_fixtures:
        p = mock_dir / f
        assert p.exists(), f"Missing mock fixture: {f}"
        data = json.loads(p.read_text(encoding="utf-8"))
        assert data is not None


def test_p14_endpoints_served():
    with TestClient(app) as client:
        # Dashboard
        r = client.get("/v3/index.html")
        assert r.status_code == 200
        assert "btn-run-dataset" in r.text
        assert "top-identities-table" in r.text

        # Cases list
        r = client.get("/v3/cases.html")
        assert r.status_code == 200
        assert "filter-search" in r.text
        assert "cases-table" in r.text

        # Case detail
        r = client.get("/v3/case.html?id=case-e1-svcreport")
        assert r.status_code == 200
        assert "gauge-arc" in r.text
        assert "attack-chain-container" in r.text
        assert "evidence-drawer" in r.text

        # Live constellation
        r = client.get("/v3/live.html")
        assert r.status_code == 200
        assert "constellation-container" in r.text
        assert "terminal-trace-log" in r.text

        # Agents list
        r = client.get("/v3/agents.html")
        assert r.status_code == 200
        assert "agents-layers-container" in r.text
        assert "agent-drawer" in r.text
