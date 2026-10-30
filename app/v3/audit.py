"""Tamper-evident audit log adapter for IdentityShield v3.

Maintains SHA-256 hash chaining over entries (timestamp, agent, action, detail, prev_hash, hash).
Delegates to app/audit.py or uses the local SQLite store.
"""
import hashlib
import json
import logging
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)
GENESIS = "0" * 64
_lock = threading.RLock()


def _body(ts: str, agent: str, action: str, detail: str) -> str:
    return json.dumps({"t": ts, "a": agent, "x": action, "d": detail}, sort_keys=True)


def _ensure_audit_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS audit (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            agent TEXT NOT NULL,
            action TEXT NOT NULL,
            detail TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            hash TEXT NOT NULL
        )
        """
    )
    conn.commit()


def append(
    agent: str,
    action: str,
    detail: Any,
    db_path: Path | str | None = None,
) -> None:
    """Append a tamper-evident audit entry."""
    detail_str = json.dumps(detail, sort_keys=True) if isinstance(detail, (dict, list)) else str(detail)

    if db_path is None:
        try:
            from app import audit as _v2_audit

            if _v2_audit is not None and hasattr(_v2_audit, "append"):
                _v2_audit.append(agent, action, detail_str)
                return
        except Exception as exc:  # noqa: BLE001
            log.debug("v2 audit append fallback to local store: %s", exc)

    # Local SQLite fallback or explicit db_path
    from app.v3 import store as v3_store

    target_db = Path(db_path) if db_path else v3_store.get_db_path()
    with _lock:
        conn = sqlite3.connect(str(target_db), timeout=10.0)
        try:
            _ensure_audit_table(conn)
            cur = conn.cursor()
            cur.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1")
            row = cur.fetchone()
            prev = row[0] if row else GENESIS
            ts = datetime.now(UTC).isoformat()
            h = hashlib.sha256((prev + _body(ts, agent, action, detail_str)).encode("utf-8")).hexdigest()
            cur.execute(
                "INSERT INTO audit (timestamp, agent, action, detail, prev_hash, hash) VALUES (?,?,?,?,?,?)",
                (ts, agent, action, detail_str, prev, h),
            )
            conn.commit()
        finally:
            conn.close()


def verify(db_path: Path | str | None = None) -> tuple[bool, int | None]:
    """Verify hash chain integrity across all audit records.

    Returns (True, None) if intact, or (False, seq) of the first tampered row.
    """
    if db_path is None:
        try:
            from app import audit as _v2_audit

            if _v2_audit is not None and hasattr(_v2_audit, "verify"):
                return _v2_audit.verify()
        except Exception as exc:  # noqa: BLE001
            log.debug("v2 audit verify fallback to local store: %s", exc)

    from app.v3 import store as v3_store

    target_db = Path(db_path) if db_path else v3_store.get_db_path()
    with _lock:
        conn = sqlite3.connect(str(target_db), timeout=10.0)
        try:
            _ensure_audit_table(conn)
            cur = conn.cursor()
            cur.execute("SELECT seq, timestamp, agent, action, detail, prev_hash, hash FROM audit ORDER BY seq ASC")
            rows = cur.fetchall()
            prev = GENESIS
            for seq, ts, agent, action, detail, prev_hash, h in rows:
                expected = hashlib.sha256((prev + _body(ts, agent, action, detail)).encode("utf-8")).hexdigest()
                if prev_hash != prev or h != expected:
                    return False, int(seq)
                prev = h
            return True, None
        finally:
            conn.close()
