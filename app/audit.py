"""Tamper-evident audit log: each entry's hash covers the previous entry's hash."""
import hashlib
import json
from datetime import datetime, timezone

from app import store
from app.models import AuditEntry

GENESIS = "0" * 64


def _body(ts: str, agent: str, action: str, detail: str) -> str:
    return json.dumps({"t": ts, "a": agent, "x": action, "d": detail}, sort_keys=True)


def append(agent: str, action: str, detail: str) -> None:
    with store._lock:  # keep read-prev + insert atomic
        rows = store.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1")
        prev = rows[0]["hash"] if rows else GENESIS
        ts = datetime.now(timezone.utc).isoformat()
        h = hashlib.sha256((prev + _body(ts, agent, action, str(detail))).encode("utf-8")).hexdigest()
        store.execute(
            "INSERT INTO audit (timestamp, agent, action, detail, prev_hash, hash) VALUES (?,?,?,?,?,?)",
            (ts, agent, action, str(detail), prev, h),
        )


def verify() -> tuple[bool, int | None]:
    prev = GENESIS
    for r in store.execute("SELECT * FROM audit ORDER BY seq"):
        expected = hashlib.sha256(
            (prev + _body(r["timestamp"], r["agent"], r["action"], r["detail"])).encode("utf-8")
        ).hexdigest()
        if r["prev_hash"] != prev or r["hash"] != expected:
            return False, int(r["seq"])
        prev = r["hash"]
    return True, None


def count() -> int:
    rows = store.execute("SELECT COUNT(*) AS n FROM audit")
    return int(rows[0]["n"]) if rows else 0


def list_entries(limit: int = 200) -> list[AuditEntry]:
    limit = max(1, min(int(limit), 1000))
    rows = store.execute("SELECT * FROM audit ORDER BY seq DESC LIMIT ?", (limit,))
    return [
        AuditEntry(seq=r["seq"], timestamp=r["timestamp"], agent=r["agent"], action=r["action"],
                   detail=r["detail"], prev_hash=r["prev_hash"], hash=r["hash"])
        for r in rows
    ]
