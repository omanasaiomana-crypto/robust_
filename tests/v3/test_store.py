"""Unit tests for app/v3/store.py and app/v3/audit.py."""
import sqlite3
from pathlib import Path

from app.v3 import audit, store


def test_store_table_creation_and_indexes(tmp_db: Path) -> None:
    store.create_tables(tmp_db)
    conn = store.get_connection(tmp_db)
    cur = conn.cursor()

    # Verify key v3 tables exist
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = {r[0] for r in cur.fetchall()}
    assert "events_v3" in tables
    assert "sessions_v3" in tables
    assert "signals_v3" in tables
    assert "risk_v3" in tables
    assert "cases_v3" in tables
    assert "actions_v3" in tables

    # Verify indexes exist
    cur.execute("SELECT name FROM sqlite_master WHERE type='index'")
    indexes = {r[0] for r in cur.fetchall()}
    assert "idx_events_v3_identity_time" in indexes
    assert "idx_cases_v3_status" in indexes


def test_store_round_trip_and_batch_insert(tmp_db: Path) -> None:
    store.create_tables(tmp_db)

    # Insert batch of events
    rows = [
        {
            "event_id": f"ev-{i}",
            "time": "2026-10-30T12:00:00Z",
            "source": "okta",
            "event_class": "authentication",
            "action": "user.session.start",
            "identity_id": "alice",
            "raw_principal": "alice@corp.example",
            "src_ip": "1.2.3.4",
            "user_agent": "Mozilla",
            "outcome": "success",
            "read_only": 1,
            "resolution_confidence": 0.95,
            "attrs": {"ip": "1.2.3.4", "asn": 1234},
        }
        for i in range(5)
    ]
    inserted = store.insert_many("events_v3", rows, db_path=tmp_db)
    assert inserted == 5

    # Fetch all
    fetched = store.fetch_all("SELECT * FROM events_v3 WHERE identity_id = ?", ("alice",), db_path=tmp_db)
    assert len(fetched) == 5

    # Fetch one
    one = store.fetch_one("SELECT * FROM events_v3 WHERE event_id = ?", ("ev-0",), db_path=tmp_db)
    assert one is not None
    assert one["event_id"] == "ev-0"
    assert one["identity_id"] == "alice"


# ---------------------------------------------------------------------------
# Test Tamper-Evident Audit Hash Chain Verification
# ---------------------------------------------------------------------------


def test_audit_hash_chain_verify_and_tamper_detection(tmp_db: Path) -> None:
    # Append 3 valid entries
    audit.append("agent01", "collect_logs", {"records": 10}, db_path=tmp_db)
    audit.append("agent02", "normalize_events", {"events": 10}, db_path=tmp_db)
    audit.append("agent05", "signal_impossible_travel", {"risk": 80}, db_path=tmp_db)

    # Chain should be fully valid
    valid, failed_seq = audit.verify(db_path=tmp_db)
    assert valid is True
    assert failed_seq is None

    # Tamper with the 2nd row's detail in the database
    conn = sqlite3.connect(str(tmp_db))
    try:
        conn.execute("UPDATE audit SET detail = 'tampered_malicious_edit' WHERE seq = 2")
        conn.commit()
    finally:
        conn.close()

    # Verification must fail and identify the tampered sequence number
    valid_after_tamper, failed_seq_after = audit.verify(db_path=tmp_db)
    assert valid_after_tamper is False
    assert failed_seq_after == 2
