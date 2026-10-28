"""SQLite storage. All access goes through execute(), which is thread-safe."""
import logging
import sqlite3
import threading
from datetime import datetime, timezone

from app.config import DB_PATH, SIGNAL_WEIGHTS
from app.models import Alert

log = logging.getLogger(__name__)

_lock = threading.RLock()
_conn: sqlite3.Connection | None = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    identity_id TEXT NOT NULL,
    session_id TEXT,
    risk REAL NOT NULL,
    band TEXT NOT NULL,
    json TEXT NOT NULL,
    action_status TEXT DEFAULT 'pending',
    feedback TEXT,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS weights (
    pattern TEXT PRIMARY KEY,
    weight REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS friction (
    identity_id TEXT NOT NULL,
    day TEXT NOT NULL,
    count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (identity_id, day)
);
CREATE TABLE IF NOT EXISTS audit (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    agent TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
);
"""


def conn() -> sqlite3.Connection:
    global _conn
    with _lock:
        if _conn is None:
            DB_PATH.parent.mkdir(parents=True, exist_ok=True)
            _conn = sqlite3.connect(DB_PATH, check_same_thread=False)
            _conn.row_factory = sqlite3.Row
        return _conn


def execute(sql: str, params: tuple = ()) -> list[sqlite3.Row]:
    with _lock:
        cur = conn().execute(sql, params)
        rows = cur.fetchall()
        conn().commit()
        return rows


def init_db() -> None:
    with _lock:
        conn().executescript(SCHEMA)
        conn().commit()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def save_alerts(alerts: list[Alert]) -> None:
    for a in alerts:
        update_alert(a)


def update_alert(alert: Alert) -> None:
    execute(
        "INSERT INTO alerts (alert_id, identity_id, session_id, risk, band, json, action_status, feedback, updated_at) "
        "VALUES (?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(alert_id) DO UPDATE SET identity_id=excluded.identity_id, session_id=excluded.session_id, "
        "risk=excluded.risk, band=excluded.band, json=excluded.json, action_status=excluded.action_status, "
        "feedback=excluded.feedback, updated_at=excluded.updated_at",
        (alert.alert_id, alert.identity_id, alert.session_id, float(alert.risk), alert.band,
         alert.model_dump_json(), alert.action_status, alert.feedback, _now()),
    )


def load_alert(alert_id: str) -> Alert | None:
    rows = execute("SELECT json FROM alerts WHERE alert_id = ?", (alert_id,))
    if not rows:
        return None
    try:
        return Alert.model_validate_json(rows[0]["json"])
    except ValueError:
        log.exception("Corrupt alert row %s", alert_id)
        return None


def load_alerts() -> list[Alert]:
    out: list[Alert] = []
    for r in execute("SELECT json FROM alerts ORDER BY risk DESC"):
        try:
            out.append(Alert.model_validate_json(r["json"]))
        except ValueError:
            log.warning("Skipping corrupt alert row")
    return out


def get_weights() -> dict[str, float]:
    weights = dict(SIGNAL_WEIGHTS)
    for r in execute("SELECT pattern, weight FROM weights"):
        weights[r["pattern"]] = float(r["weight"])
    return weights


def set_weight(pattern: str, weight: float) -> None:
    execute(
        "INSERT INTO weights (pattern, weight) VALUES (?, ?) "
        "ON CONFLICT(pattern) DO UPDATE SET weight=excluded.weight",
        (pattern, float(weight)),
    )


def friction_used(identity_id: str, day: str) -> int:
    rows = execute("SELECT count FROM friction WHERE identity_id = ? AND day = ?", (identity_id, day))
    return int(rows[0]["count"]) if rows else 0


def friction_increment(identity_id: str, day: str) -> None:
    execute(
        "INSERT INTO friction (identity_id, day, count) VALUES (?, ?, 1) "
        "ON CONFLICT(identity_id, day) DO UPDATE SET count = count + 1",
        (identity_id, day),
    )


def reset_run_tables() -> None:
    execute("DELETE FROM alerts")
