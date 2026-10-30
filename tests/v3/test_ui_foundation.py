import hashlib
import json
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app


def test_vendor_libraries_exist_and_hashes_match():
    vendor_dir = Path("static/vendor")
    assert vendor_dir.exists()

    versions_file = vendor_dir / "VERSIONS.md"
    assert versions_file.exists()
    versions_text = versions_file.read_text(encoding="utf-8")

    expected_files = [
        "three.min.js",
        "3d-force-graph.min.js",
        "globe.gl.min.js",
        "chart.umd.min.js",
    ]

    for filename in expected_files:
        file_path = vendor_dir / filename
        assert file_path.exists(), f"Missing vendored library: {filename}"
        assert file_path.stat().st_size > 10000

        # Verify sha256 matches what is recorded in VERSIONS.md
        sha256 = hashlib.sha256(file_path.read_bytes()).hexdigest()
        assert sha256 in versions_text, f"SHA256 for {filename} not recorded in VERSIONS.md"


def test_theme_css_tokens():
    theme_path = Path("static/v3/css/theme.css")
    assert theme_path.exists()
    content = theme_path.read_text(encoding="utf-8")

    required_tokens = [
        "--bg: #05070D",
        "--bg-2: #0B0F17",
        "--panel: rgba(17, 24, 39, 0.62)",
        "--panel-border: rgba(148, 163, 184, 0.14)",
        "--text: #E5E7EB",
        "--muted: #94A3B8",
        "--brand: #3B82F6",
        "--cyan: #22D3EE",
        "--violet: #8B5CF6",
        "--ok: #10B981",
        "--warn: #F59E0B",
        "--crit: #EF4444",
        "--radius-panel: 14px",
        "--radius-control: 10px",
        ".glass",
        ".btn-primary",
        ".btn-ghost",
        ".btn-danger",
        "badge-band",
        "mitre-chip",
        ".skeleton",
        "prefers-reduced-motion",
    ]

    for token in required_tokens:
        assert token in content, f"Missing token or class in theme.css: {token}"


def test_core_and_fx_js_files_exist():
    core_files = [
        "static/v3/js/core/dom.js",
        "static/v3/js/core/api.js",
        "static/v3/js/core/sse.js",
        "static/v3/js/core/shell.js",
        "static/v3/js/fx/bg3d.js",
        "static/v3/js/fx/tilt.js",
        "static/v3/js/pages/dashboard.js",
    ]

    for p in core_files:
        path = Path(p)
        assert path.exists(), f"Missing script file: {p}"
        content = path.read_text(encoding="utf-8")
        assert len(content) > 100


def test_mock_fixtures_validity():
    mock_dir = Path("static/v3/mock")
    assert mock_dir.exists()

    required_fixtures = [
        "health.json",
        "agents.json",
        "cases.json",
        "case_detail.json",
        "graph.json",
        "geo.json",
        "metrics.json",
    ]

    for fix in required_fixtures:
        p = mock_dir / fix
        assert p.exists(), f"Missing mock fixture: {fix}"
        data = json.loads(p.read_text(encoding="utf-8"))
        assert data is not None

    # Specific fixture checks
    agents = json.loads((mock_dir / "agents.json").read_text(encoding="utf-8"))
    assert len(agents) == 15, "Mock agents fixture must contain exactly 15 agents"

    case_detail = json.loads((mock_dir / "case_detail.json").read_text(encoding="utf-8"))
    assert case_detail["case_id"] == "case-e1-svcreport"
    assert len(case_detail["steps"]) >= 6
    assert len(case_detail["reasons"]) >= 3
    assert len(case_detail["counterfactuals"]) >= 3


def test_fastapi_serves_v3_static_assets():
    with TestClient(app) as client:
        # Index HTML
        resp = client.get("/v3/index.html")
        assert resp.status_code == 200
        assert "<title>IdentityShield · Dashboard</title>" in resp.text
        assert "bg3d-canvas" in resp.text
        assert "data-tilt" in resp.text

        # Theme CSS
        resp_css = client.get("/v3/css/theme.css")
        assert resp_css.status_code == 200
        assert "--bg: #05070D" in resp_css.text

        # Shell JS
        resp_js = client.get("/v3/js/core/shell.js")
        assert resp_js.status_code == 200
        assert "IdentityShield" in resp_js.text

        # Vendor Three.js
        resp_vendor = client.get("/vendor/three.min.js")
        assert resp_vendor.status_code == 200
        assert len(resp_vendor.content) > 100000

        # Mock JSON
        resp_mock = client.get("/v3/mock/health.json")
        assert resp_mock.status_code == 200
        assert resp_mock.json()["status"] == "ok"
