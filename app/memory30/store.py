"""SQLite storage for the 30-day memory (WAL mode, parameterized queries, one lock for thread safety)."""
from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    event_id   TEXT PRIMARY KEY,
    time       TEXT NOT NULL,
    day        TEXT NOT NULL,
    source     TEXT NOT NULL,
    identity   TEXT NOT NULL,
    action     TEXT NOT NULL,
    category   TEXT NOT NULL,
    service    TEXT,
    outcome    TEXT,
    ip         TEXT,
    net        TEXT,
    country    TEXT,
    is_proxy   INTEGER NOT NULL DEFAULT 0,
    resource   TEXT,
    sensitive  INTEGER NOT NULL DEFAULT 0,
    read_only  INTEGER NOT NULL DEFAULT 1,
    session    TEXT,
    evidence   INTEGER NOT NULL DEFAULT 0,
    raw        TEXT
);
CREATE INDEX IF NOT EXISTS ix_events_identity_time ON events(identity, time);
CREATE INDEX IF NOT EXISTS ix_events_time ON events(time);
CREATE INDEX IF NOT EXISTS ix_events_identity_day_cat ON events(identity, day, category);

CREATE TABLE IF NOT EXISTS identity_daily (
    identity         TEXT NOT NULL,
    day              TEXT NOT NULL,
    events           INTEGER NOT NULL DEFAULT 0,
    logins           INTEGER NOT NULL DEFAULT 0,
    login_failures   INTEGER NOT NULL DEFAULT 0,
    discovery        INTEGER NOT NULL DEFAULT 0,
    data_reads       INTEGER NOT NULL DEFAULT 0,
    sensitive_reads  INTEGER NOT NULL DEFAULT 0,
    writes           INTEGER NOT NULL DEFAULT 0,
    privesc          INTEGER NOT NULL DEFAULT 0,
    credential       INTEGER NOT NULL DEFAULT 0,
    exfil            INTEGER NOT NULL DEFAULT 0,
    evasion          INTEGER NOT NULL DEFAULT 0,
    new_networks     INTEGER NOT NULL DEFAULT 0,
    max_risk         REAL NOT NULL DEFAULT 0,
    PRIMARY KEY (identity, day)
);

CREATE TABLE IF NOT EXISTS daily_services (
    identity TEXT NOT NULL,
    day      TEXT NOT NULL,
    service  TEXT NOT NULL,
    PRIMARY KEY (identity, day, service)
);

CREATE TABLE IF NOT EXISTS identity_meta (
    identity     TEXT PRIMARY KEY,
    first_seen   TEXT NOT NULL,
    last_seen    TEXT NOT NULL,
    risk         REAL NOT NULL DEFAULT 0,
    risk_updated TEXT
);

CREATE TABLE IF NOT EXISTS identity_networks (
    identity   TEXT NOT NULL,
    net        TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    count      INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (identity, net)
);

CREATE TABLE IF NOT EXISTS identity_write_targets (
    identity   TEXT NOT NULL,
    target     TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    count      INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (identity, target)
);

CREATE TABLE IF NOT EXISTS chain_hits (
    identity   TEXT NOT NULL,
    kind       TEXT NOT NULL,
    day        TEXT NOT NULL,
    stage      TEXT NOT NULL,
    severity   REAL NOT NULL,
    first_time TEXT NOT NULL,
    last_time  TEXT NOT NULL,
    event_ids  TEXT NOT NULL,
    detail     TEXT,
    PRIMARY KEY (identity, kind, day)
);
CREATE INDEX IF NOT EXISTS ix_hits_identity_time ON chain_hits(identity, first_time);

CREATE TABLE IF NOT EXISTS findings (
    finding_id   TEXT PRIMARY KEY,
    identity     TEXT NOT NULL,
    risk         REAL NOT NULL,
    stages       TEXT NOT NULL,
    steps        TEXT NOT NULL,
    evidence     TEXT NOT NULL,
    first_time   TEXT NOT NULL,
    last_time    TEXT NOT NULL,
    days_spanned INTEGER NOT NULL,
    status       TEXT NOT NULL DEFAULT 'open',
    narrative    TEXT NOT NULL,
    updated      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_findings_identity ON findings(identity);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""

TABLES = ("events", "identity_daily", "daily_services", "identity_meta", "identity_networks",
          "identity_write_targets", "chain_hits", "findings")


class Store:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(str(self.path), check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        with self._lock:
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA synchronous=NORMAL")
            self.conn.execute("PRAGMA foreign_keys=ON")
            self.conn.executescript(SCHEMA)

    # ---------------------------------------------------------------- basics
    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                yield self.conn
            except BaseException:
                self.conn.execute("ROLLBACK")
                raise
            else:
                self.conn.execute("COMMIT")

    def query(self, sql: str, params: tuple | list = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self.conn.execute(sql, params).fetchall()

    def one(self, sql: str, params: tuple | list = ()) -> sqlite3.Row | None:
        with self._lock:
            return self.conn.execute(sql, params).fetchone()

    def execute(self, sql: str, params: tuple | list = ()) -> int:
        with self._lock:
            return self.conn.execute(sql, params).rowcount

    def get_meta(self, key: str, default: Any = None) -> Any:
        row = self.one("SELECT value FROM meta WHERE key=?", (key,))
        return row["value"] if row else default

    def set_meta(self, key: str, value: str) -> None:
        self.execute("INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                     (key, value))

    def vacuum(self) -> None:
        with self._lock:
            self.conn.execute("VACUUM")

    def checkpoint(self) -> None:
        with self._lock:
            self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    def size_bytes(self) -> int:
        total = 0
        for suffix in ("", "-wal", "-shm"):
            p = Path(str(self.path) + suffix)
            if p.exists():
                total += p.stat().st_size
        return total

    def close(self) -> None:
        with self._lock:
            try:
                self.conn.close()
            except sqlite3.Error:
                pass
