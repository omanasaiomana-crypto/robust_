import json
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app


def test_p15_html_pages_exist():
    expected_pages = [
        "static/v3/graph.html",
        "static/v3/globe.html",
        "static/v3/analytics.html",
        "static/v3/performance.html",
        "static/v3/settings.html",
        "static/v3/input.html",
        "static/v3/audit.html",
    ]
    for p in expected_pages:
        path = Path(p)
        assert path.exists(), f"Missing HTML page: {p}"
        content = path.read_text(encoding="utf-8")
        assert "<title>IdentityShield" in content
        assert "/v3/css/theme.css" in content
        assert "bg3d-canvas" in content


def test_p15_js_controllers_exist():
    expected_js = [
        "static/v3/js/pages/graph.js",
        "static/v3/js/pages/globe.js",
        "static/v3/js/pages/analytics.js",
        "static/v3/js/pages/performance.js",
        "static/v3/js/pages/settings.js",
        "static/v3/js/pages/input.js",
        "static/v3/js/pages/audit.js",
    ]
    for p in expected_js:
        path = Path(p)
        assert path.exists(), f"Missing page JS controller: {p}"
        content = path.read_text(encoding="utf-8")
        assert len(content) > 200


def test_p15_mock_fixtures_valid():
    mock_dir = Path("static/v3/mock")
    required = [
        "config.json",
        "config_versions.json",
        "audit.json",
        "audit_verify.json",
        "graph.json",
        "geo.json",
    ]
    for r in required:
        p = mock_dir / r
        assert p.exists(), f"Missing mock fixture: {r}"
        data = json.loads(p.read_text(encoding="utf-8"))
        assert data is not None


def test_p15_endpoints_served():
    with TestClient(app) as client:
        # 1. Graph
        r = client.get("/v3/graph.html")
        assert r.status_code == 200
        assert "graph-canvas-container" in r.text
        assert "select-graph-identity" in r.text

        # 2. Globe
        r = client.get("/v3/globe.html")
        assert r.status_code == 200
        assert "globe-container" in r.text
        assert "select-globe-identity" in r.text

        # 3. Analytics
        r = client.get("/v3/analytics.html")
        assert r.status_code == 200
        assert "chart-models-comparison" in r.text
        assert "detector-performance-table" in r.text

        # 4. Performance
        r = client.get("/v3/performance.html")
        assert r.status_code == 200
        assert "btn-run-benchmark" in r.text
        assert "tile-hot-p50" in r.text

        # 5. Settings
        r = client.get("/v3/settings.html")
        assert r.status_code == 200
        assert "input-analyst-token" in r.text
        assert "config-versions-list" in r.text

        # 6. Input
        r = client.get("/v3/input.html")
        assert r.status_code == 200
        assert "input-json-editor" in r.text
        assert "btn-scan-input" in r.text

        # 7. Audit
        r = client.get("/v3/audit.html")
        assert r.status_code == 200
        assert "btn-verify-audit" in r.text
        assert "audit-table" in r.text
