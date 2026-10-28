"""Tests for vendored offline assets and their integration."""
from pathlib import Path
from fastapi.testclient import TestClient

from app.config import STATIC_DIR
from app.main import app

VENDOR_FILES = [
    "tailwind.js",
    "chart.umd.min.js",
    "vis-network.min.js",
]


def test_vendor_files_exist_and_sized():
    vendor_dir = STATIC_DIR / "vendor"
    assert vendor_dir.is_dir()
    for fname in VENDOR_FILES:
        fpath = vendor_dir / fname
        assert fpath.is_file(), f"Missing vendor file: {fname}"
        sz = fpath.stat().st_size
        assert sz > 50_000, f"Vendor file {fname} is too small ({sz} bytes)"


def test_vendor_served_by_fastapi():
    with TestClient(app) as client:
        r = client.get("/vendor/tailwind.js")
        assert r.status_code == 200
        assert len(r.content) > 50_000


def test_no_cdn_references_in_html():
    html_files = list(STATIC_DIR.glob("*.html"))
    assert len(html_files) > 0
    forbidden = ["cdn.tailwindcss.com", "cdn.jsdelivr.net", "unpkg.com"]
    for hf in html_files:
        content = hf.read_text(encoding="utf-8")
        for bad in forbidden:
            assert bad not in content, f"Found {bad} in {hf.name}"
