"""Tests for predictions export functionality in app/export.py."""
import csv
from pathlib import Path
import pytest

from app.export import export_all


def test_export_sample_data(tmp_path: Path):
    """Verify export_all writes all four artifacts and satisfies contract constraints."""
    summary = export_all(tmp_path, use_sample=True)

    event_csv = tmp_path / "event_predictions.csv"
    session_csv = tmp_path / "session_predictions.csv"
    alerts_jsonl = tmp_path / "alerts.jsonl"
    summary_json = tmp_path / "summary.json"

    assert event_csv.exists()
    assert session_csv.exists()
    assert alerts_jsonl.exists()
    assert summary_json.exists()

    # Read event predictions CSV
    with open(event_csv, "rt", encoding="utf-8") as f:
        reader = list(csv.DictReader(f))
        assert len(reader) == summary["total_events"]
        assert len(reader) > 0
        for row in reader:
            assert row["predicted"] in ("0", "1")
            assert "event_id" in row
            assert "session_id" in row
            assert "identity_id" in row
            assert "risk" in row

    # Read session predictions CSV
    with open(session_csv, "rt", encoding="utf-8") as f:
        reader = list(csv.DictReader(f))
        assert len(reader) > 0
        for row in reader:
            assert row["predicted"] in ("0", "1")
            assert "session_id" in row
            assert "identity_id" in row
            assert "band" in row

    # Alerts jsonl count equals total alerts
    with open(alerts_jsonl, "rt", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]
        assert len(lines) == summary["total_alerts"]
