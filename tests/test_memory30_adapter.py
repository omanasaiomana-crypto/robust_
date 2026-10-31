"""Unit tests for the official dataset adapter (Task M2)."""
import csv
import json
from pathlib import Path

from app.memory30.engine import MemoryEngine
from app.memory30.store import Store
from app.memory30_adapter import adapt_record, load_official


def test_okta_like_row_converts():
    raw_row = {
        "event_id": "okta-row-001",
        "timestamp": "2026-10-15T12:00:00Z",
        "event_type": "user.session.start",
        "user": "alice@corp.example",
        "ip": "198.51.100.25",
        "status": "SUCCESS",
    }
    adapted = adapt_record(raw_row)
    assert adapted is not None
    assert adapted["uuid"] == "okta-row-001"
    assert adapted["published"].startswith("2026-10-15T12:00:00")
    assert adapted["eventType"] == "user.session.start"
    assert adapted["actor"]["alternateId"] == "alice@corp.example"
    assert adapted["client"]["ipAddress"] == "198.51.100.25"
    assert adapted["outcome"]["result"] == "SUCCESS"


def test_cloudtrail_like_row_converts():
    raw_row = {
        "event_id": "ct-row-002",
        "timestamp": "2026-10-15T12:05:00Z",
        "action": "GetObject",
        "username": "bob.analyst",
        "service": "s3",
        "ip": "203.0.113.10",
        "resource": "confidential-data/report.pdf",
    }
    adapted = adapt_record(raw_row)
    assert adapted is not None
    assert adapted["eventID"] == "ct-row-002"
    assert adapted["eventTime"].startswith("2026-10-15T12:05:00")
    assert adapted["eventName"] == "GetObject"
    assert adapted["userIdentity"]["userName"] == "bob.analyst"
    assert adapted["sourceIPAddress"] == "203.0.113.10"
    assert adapted["requestParameters"]["resourceName"] == "confidential-data/report.pdf"


def test_bad_row_skipped():
    # Missing identity
    assert adapt_record({"event_id": "bad-1", "timestamp": "2026-10-15T12:00:00Z", "action": "login"}) is None

    # Missing action
    assert adapt_record({"event_id": "bad-2", "timestamp": "2026-10-15T12:00:00Z", "user": "alice"}) is None

    # Missing timestamp
    assert adapt_record({"event_id": "bad-3", "user": "alice", "action": "login"}) is None

    # Not a dict
    assert adapt_record("not a dict") is None  # type: ignore


def test_end_to_end_ingest_inserts(tmp_path: Path):
    csv_file = tmp_path / "events.csv"
    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["event_id", "timestamp", "action", "user", "ip", "status"])
        writer.writeheader()
        writer.writerow({
            "event_id": "csv-001",
            "timestamp": "2026-10-15T14:00:00Z",
            "action": "user.session.start",
            "user": "claire@corp.example",
            "ip": "198.51.100.55",
            "status": "SUCCESS",
        })
        writer.writerow({
            "event_id": "csv-002",
            "timestamp": "2026-10-15T14:10:00Z",
            "action": "DescribeInstances",
            "user": "claire@corp.example",
            "ip": "198.51.100.55",
            "status": "SUCCESS",
        })
        # Bad row should be ignored
        writer.writerow({
            "event_id": "",
            "timestamp": "",
            "action": "",
            "user": "",
            "ip": "",
            "status": "",
        })

    records = load_official(tmp_path)
    assert len(records) == 2

    # Ingest using a temporary database
    engine = MemoryEngine(db_path=tmp_path / "test_mem.sqlite")
    result = engine.ingest_records(records)

    assert result["inserted"] == 2
    assert result["duplicates"] == 0
    assert result["identities_touched"] == 1
