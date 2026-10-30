"""SQLite storage adapter for IdentityShield v3.

Follows context.md Section 11:
- WAL mode, thread-local connections, busy timeout
- All v3 tables created with indexes
- Parameterized batch inserts and query helpers
- JSON fields automatically stored as TEXT
"""
import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

from app.v3.config import ROOT_DIR

DEFAULT_DB_PATH = ROOT_DIR / "data" / "identityshield.db"
_local = threading.local()
_override_db_path: Path | None = None


def set_db_path(path: Path | str | None) -> None:
    """Set global database path override (e.g. for testing with tmp_db)."""
    global _override_db_path
    _override_db_path = Path(path) if path else None


def get_db_path() -> Path:
    """Return active SQLite database path."""
    if _override_db_path is not None:
        return _override_db_path
    return DEFAULT_DB_PATH


def get_connection(db_path: Path | str | None = None) -> sqlite3.Connection:
    """Get thread-local SQLite connection with WAL mode enabled."""
    target_path = Path(db_path) if db_path else get_db_path()
    target_path.parent.mkdir(parents=True, exist_ok=True)

    thread_key = f"conn_{target_path.resolve()}"
    conn = getattr(_local, thread_key, None)
    if conn is None:
        conn = sqlite3.connect(str(target_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        setattr(_local, thread_key, conn)
    return conn


TABLES_SCHEMA = """
CREATE TABLE IF NOT EXISTS events_v3 (
    event_id TEXT PRIMARY KEY,
    time TEXT NOT NULL,
    source TEXT NOT NULL,
    event_class TEXT NOT NULL,
    action TEXT NOT NULL,
    identity_id TEXT NOT NULL,
    raw_principal TEXT NOT NULL,
    session_id TEXT,
    src_ip TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    outcome TEXT NOT NULL,
    resource_arn TEXT,
    read_only INTEGER NOT NULL,
    region TEXT,
    late INTEGER NOT NULL DEFAULT 0,
    uncatalogued INTEGER NOT NULL DEFAULT 0,
    resolution_confidence REAL NOT NULL,
    raw_ref TEXT,
    attrs TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS identities_v3 (
    identity_id TEXT PRIMARY KEY,
    primary_user TEXT NOT NULL,
    email TEXT,
    department TEXT,
    privilege_level INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS identity_aliases_v3 (
    alias TEXT PRIMARY KEY,
    identity_id TEXT NOT NULL,
    alias_type TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions_v3 (
    session_id TEXT PRIMARY KEY,
    identity_id TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT,
    event_ids TEXT NOT NULL DEFAULT '[]',
    ips TEXT NOT NULL DEFAULT '[]',
    asns TEXT NOT NULL DEFAULT '[]',
    devices TEXT NOT NULL DEFAULT '[]',
    providers TEXT NOT NULL DEFAULT '[]',
    state TEXT NOT NULL DEFAULT 'open',
    fingerprint TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS signals_v3 (
    signal_id TEXT PRIMARY KEY,
    detection_id TEXT NOT NULL,
    agent_num INTEGER NOT NULL,
    identity_id TEXT NOT NULL,
    session_id TEXT,
    strength REAL NOT NULL,
    confidence REAL NOT NULL,
    evidence_event_ids TEXT NOT NULL,
    mitre TEXT NOT NULL DEFAULT '[]',
    stage TEXT NOT NULL,
    summary TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS risk_v3 (
    subject_id TEXT PRIMARY KEY,
    subject_type TEXT NOT NULL,
    score REAL NOT NULL,
    confidence REAL NOT NULL,
    band TEXT NOT NULL,
    factors TEXT NOT NULL DEFAULT '{}',
    computed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cases_v3 (
    case_id TEXT PRIMARY KEY,
    identity_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    session_risk REAL NOT NULL,
    identity_risk REAL NOT NULL,
    confidence REAL NOT NULL,
    band TEXT NOT NULL,
    status TEXT NOT NULL,
    signal_ids TEXT NOT NULL DEFAULT '[]',
    chain TEXT NOT NULL DEFAULT '[]',
    reasons TEXT NOT NULL DEFAULT '[]',
    counterfactuals TEXT NOT NULL DEFAULT '[]',
    next_steps TEXT NOT NULL DEFAULT '[]',
    blast_radius INTEGER NOT NULL DEFAULT 1,
    related_identities TEXT NOT NULL DEFAULT '[]',
    narrative TEXT NOT NULL DEFAULT '',
    narrative_source TEXT NOT NULL DEFAULT 'template',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS actions_v3 (
    action_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    playbook_id TEXT NOT NULL,
    action_kind TEXT NOT NULL,
    approval_required INTEGER NOT NULL,
    state TEXT NOT NULL,
    simulator_ref TEXT,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    expires_at TEXT,
    approved_by TEXT
);

CREATE TABLE IF NOT EXISTS labels_v3 (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    verdict TEXT NOT NULL,
    analyst TEXT NOT NULL,
    note TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS config_versions_v3 (
    version INTEGER PRIMARY KEY,
    changes TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS agent_state_v3 (
    agent_id TEXT PRIMARY KEY,
    state_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS enrich_cache_v3 (
    ip TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    data_json TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ingest_batches_v3 (
    batch_id TEXT PRIMARY KEY,
    sender_id TEXT NOT NULL,
    source TEXT NOT NULL,
    event_count INTEGER NOT NULL,
    accepted INTEGER NOT NULL,
    rejected INTEGER NOT NULL,
    received_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS metrics_v3 (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    metric_name TEXT NOT NULL,
    metric_value REAL NOT NULL,
    tags_json TEXT NOT NULL DEFAULT '{}',
    recorded_at TEXT NOT NULL
);

-- Indexes specified in context.md Section 11
CREATE INDEX IF NOT EXISTS idx_events_v3_identity_time ON events_v3(identity_id, time);
CREATE INDEX IF NOT EXISTS idx_events_v3_session ON events_v3(session_id);
CREATE INDEX IF NOT EXISTS idx_sessions_v3_identity ON sessions_v3(identity_id);
CREATE INDEX IF NOT EXISTS idx_sessions_v3_session ON sessions_v3(session_id);
CREATE INDEX IF NOT EXISTS idx_signals_v3_session ON signals_v3(session_id);
CREATE INDEX IF NOT EXISTS idx_signals_v3_identity ON signals_v3(identity_id);
CREATE INDEX IF NOT EXISTS idx_cases_v3_case_id ON cases_v3(case_id);
CREATE INDEX IF NOT EXISTS idx_cases_v3_status ON cases_v3(status);
CREATE INDEX IF NOT EXISTS idx_cases_v3_identity ON cases_v3(identity_id);
CREATE INDEX IF NOT EXISTS idx_actions_v3_case_id ON actions_v3(case_id);
"""


def create_tables(db_path: Path | str | None = None) -> None:
    """Create all v3 database tables and indexes."""
    conn = get_connection(db_path)
    conn.executescript(TABLES_SCHEMA)
    conn.commit()


def _json_serialize_value(val: Any) -> Any:
    if isinstance(val, (dict, list)):
        return json.dumps(val, sort_keys=True)
    if isinstance(val, bool):
        return int(val)
    return val


def insert_many(
    table: str,
    rows: list[dict[str, Any]],
    db_path: Path | str | None = None,
) -> int:
    """Batch insert multiple rows into a table using parameterized queries."""
    if not rows:
        return 0
    conn = get_connection(db_path)
    cols = list(rows[0].keys())
    col_str = ", ".join(cols)
    placeholders = ", ".join(["?"] * len(cols))
    sql = f"INSERT OR REPLACE INTO {table} ({col_str}) VALUES ({placeholders})"

    param_rows = []
    for row in rows:
        param_rows.append([_json_serialize_value(row.get(col)) for col in cols])

    with conn:
        conn.executemany(sql, param_rows)
    return len(rows)


def execute(
    sql: str,
    params: tuple | list = (),
    db_path: Path | str | None = None,
) -> None:
    """Execute a parameterized SQL statement."""
    conn = get_connection(db_path)
    with conn:
        conn.execute(sql, params)


def fetch_all(
    sql: str,
    params: tuple | list = (),
    db_path: Path | str | None = None,
) -> list[dict[str, Any]]:
    """Execute query and return list of dictionaries."""
    conn = get_connection(db_path)
    cur = conn.cursor()
    cur.execute(sql, params)
    return [dict(row) for row in cur.fetchall()]


def fetch_one(
    sql: str,
    params: tuple | list = (),
    db_path: Path | str | None = None,
) -> dict[str, Any] | None:
    """Execute query and return a single row as dict, or None."""
    conn = get_connection(db_path)
    cur = conn.cursor()
    cur.execute(sql, params)
    row = cur.fetchone()
    return dict(row) if row else None
