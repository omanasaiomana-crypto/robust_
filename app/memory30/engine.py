"""MemoryEngine: tiered 30-day identity memory and slow attack-chain linking.

Design:
- Everything lives in SQLite, so the memory survives restarts by construction.
- Time is DATA time (event timestamps), never the wall clock, so replaying old or synthetic data behaves exactly
  like live data. The "data clock" is the newest event time seen.
- Ingest is idempotent (event_id primary key); recomputation of chains/findings is deterministic.
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import sqlite3
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from . import catalog, config
from .normalize import fmt_time, load_paths, normalize, parse_time
from .store import TABLES, Store

log = logging.getLogger(__name__)

_DAILY_COLS = {
    catalog.LOGIN: "logins",
    catalog.LOGIN_FAIL: "login_failures",
    catalog.DISCOVERY: "discovery",
    catalog.DATA_READ: "data_reads",
    catalog.DATA_WRITE: "writes",
    catalog.OTHER_WRITE: "writes",
    catalog.PRIVESC: "privesc",
    catalog.CREDENTIAL: "credential",
    catalog.MFA_CHANGE: "credential",
    catalog.EXFIL_SHARE: "exfil",
    catalog.DEFENSE_EVASION: "evasion",
}


def _day(d: str) -> date:
    return date.fromisoformat(d[:10])


def _decay(value: float, hours: float) -> float:
    if value <= 0 or hours <= 0:
        return max(value, 0.0)
    return value * math.exp(-math.log(2) * hours / max(config.HALF_LIFE_HOURS, 0.1))


class MemoryEngine:
    def __init__(self, db_path: Path | str | None = None):
        self.store = Store(db_path or config.DB_PATH)

    # ================================================================ ingest
    def ingest_paths(self, paths: Iterable[Path | str] | None = None) -> dict:
        sources = [Path(p) for p in (paths or config.DEFAULT_SOURCES)]
        existing = [p for p in sources if p.exists()]
        records, info = load_paths(existing)
        out = self.ingest_records(records)
        out.update({"files": info["files"], "bad_files": info["bad_files"],
                    "paths": [str(p) for p in existing],
                    "missing_paths": [str(p) for p in sources if not p.exists()]})
        return out

    def ingest_records(self, records: Iterable[dict]) -> dict:
        received = 0
        norm: list[dict] = []
        for r in records:
            received += 1
            n = normalize(r)
            if n is not None:
                norm.append(n)
        norm.sort(key=lambda n: (n["time"], n["event_id"]))
        inserted = duplicates = new_hits = 0
        touched_days: set[tuple[str, str]] = set()
        touched_ids: set[str] = set()
        findings_updated = 0
        with self.store.tx() as c:
            for n in norm:
                if not self._insert_event(c, n):
                    duplicates += 1
                    continue
                inserted += 1
                new_hits += self._per_event(c, n)
                touched_days.add((n["identity"], n["day"]))
                touched_ids.add(n["identity"])
            for identity, day in sorted(touched_days):
                new_hits += self._discovery_hit(c, identity, day)
            peer_cache: dict[str, list[int]] = {}
            for identity in sorted(touched_ids):
                new_hits += self._staircase_hit(c, identity, peer_cache)
            for identity in sorted(touched_ids):
                findings_updated += self._evaluate_chains(c, identity)
            if norm:
                newest = norm[-1]["time"]
                row = c.execute("SELECT value FROM meta WHERE key='data_clock'").fetchone()
                if row is None or newest > row["value"]:
                    c.execute("INSERT INTO meta(key, value) VALUES('data_clock', ?) "
                              "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (newest,))
        return {
            "received": received,
            "normalized": len(norm),
            "skipped": received - len(norm),
            "inserted": inserted,
            "duplicates": duplicates,
            "identities_touched": len(touched_ids),
            "new_hits": new_hits,
            "findings_updated": findings_updated,
            "data_clock": self.data_clock(),
        }

    # ---------------------------------------------------------------- per event
    @staticmethod
    def _insert_event(c: sqlite3.Connection, n: dict) -> bool:
        cur = c.execute(
            "INSERT OR IGNORE INTO events(event_id, time, day, source, identity, action, category, service, "
            "outcome, ip, net, country, is_proxy, resource, sensitive, read_only, session, raw) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (n["event_id"], n["time"], n["day"], n["source"], n["identity"], n["action"], n["category"],
             n.get("service"), n["outcome"], n.get("ip"), n.get("net"), n.get("country"), int(bool(n.get("is_proxy"))),
             n.get("resource"), int(bool(n.get("sensitive"))), int(bool(n.get("read_only"))), n.get("session"),
             n.get("raw")))
        return cur.rowcount == 1

    def _per_event(self, c: sqlite3.Connection, n: dict) -> int:
        identity, day, t = n["identity"], n["day"], n["time"]
        meta = c.execute("SELECT first_seen FROM identity_meta WHERE identity=?", (identity,)).fetchone()
        history_days = 0.0
        if meta:
            history_days = (parse_time(t) - parse_time(meta["first_seen"])).total_seconds() / 86400
        c.execute(
            "INSERT INTO identity_meta(identity, first_seen, last_seen) VALUES(?, ?, ?) "
            "ON CONFLICT(identity) DO UPDATE SET first_seen=min(first_seen, excluded.first_seen), "
            "last_seen=max(last_seen, excluded.last_seen)", (identity, t, t))

        # daily summary
        incr = {"events": 1}
        col = _DAILY_COLS.get(n["category"])
        if col:
            incr[col] = incr.get(col, 0) + 1
        if n["category"] == catalog.DATA_READ and n.get("sensitive"):
            incr["sensitive_reads"] = 1
        hits = 0
        new_net = False
        if n.get("net"):
            row = c.execute("SELECT 1 FROM identity_networks WHERE identity=? AND net=?",
                            (identity, n["net"])).fetchone()
            if row is None:
                c.execute("INSERT INTO identity_networks(identity, net, first_seen, last_seen, count) "
                          "VALUES(?, ?, ?, ?, 1)", (identity, n["net"], t, t))
                new_net = history_days >= config.MIN_HISTORY_DAYS
            else:
                c.execute("UPDATE identity_networks SET last_seen=max(last_seen, ?), count=count+1 "
                          "WHERE identity=? AND net=?", (t, identity, n["net"]))
        if new_net:
            incr["new_networks"] = 1
        cols = ", ".join(incr)
        placeholders = ", ".join("?" for _ in incr)
        updates = ", ".join(f"{k}={k}+excluded.{k}" for k in incr)
        c.execute(f"INSERT INTO identity_daily(identity, day, {cols}) VALUES(?, ?, {placeholders}) "
                  f"ON CONFLICT(identity, day) DO UPDATE SET {updates}", (identity, day, *incr.values()))
        if n["category"] == catalog.DISCOVERY and n.get("service"):
            c.execute("INSERT OR IGNORE INTO daily_services(identity, day, service) VALUES(?, ?, ?)",
                      (identity, day, n["service"]))

        # stage hits
        if new_net:
            hits += self._add_hit(c, identity, "new_network", day, t, t, [n["event_id"]],
                                  {"net": n.get("net"), "ip": n.get("ip")})
        if n.get("is_proxy") and n["category"] in (catalog.LOGIN, catalog.LOGIN_FAIL):
            hits += self._add_hit(c, identity, "proxy_login", day, t, t, [n["event_id"]], {"ip": n.get("ip")})
        kind = catalog.CATEGORY_HIT.get(n["category"])
        if kind:
            hits += self._add_hit(c, identity, kind, day, t, t, [n["event_id"]],
                                  {"action": n["action"], "resource": n.get("resource"), "outcome": n["outcome"]})
        if n["category"] in (catalog.DATA_WRITE, catalog.OTHER_WRITE) and n.get("resource"):
            target = self._target_of(n.get("service"), n["resource"])
            seen = c.execute("SELECT 1 FROM identity_write_targets WHERE identity=? AND target=?",
                             (identity, target)).fetchone()
            if seen is None:
                c.execute("INSERT INTO identity_write_targets(identity, target, first_seen, last_seen, count) "
                          "VALUES(?, ?, ?, ?, 1)", (identity, target, t, t))
            else:
                c.execute("UPDATE identity_write_targets SET last_seen=max(last_seen, ?), count=count+1 "
                          "WHERE identity=? AND target=?", (t, identity, target))
            # only a FIRST-EVER write to a sensitive target (after the baseline period) is suspicious;
            # routine writes to the identity's own sensitive resources are normal work
            peers = 0
            if seen is None and n.get("sensitive") and history_days >= config.MIN_HISTORY_DAYS:
                peers = c.execute("SELECT COUNT(*) FROM identity_write_targets WHERE target=? AND identity<>?",
                                  (target, identity)).fetchone()[0]
            if seen is None and n.get("sensitive") and history_days >= config.MIN_HISTORY_DAYS \
                    and peers < config.SHARED_TARGET_MIN_WRITERS:
                hits += self._add_hit(c, identity, "modify_sensitive", day, t, t, [n["event_id"]],
                                      {"action": n["action"], "resource": n.get("resource"),
                                       "reason": "first write by this identity to a sensitive resource",
                                       "other_writers": peers})
        return hits

    @staticmethod
    def _target_of(service: str | None, resource: str) -> str:
        """Write-baseline target: the bucket for S3 objects, otherwise the full resource name / ARN."""
        if service == "s3" and not resource.startswith("arn:"):
            return resource.split("/", 1)[0]
        return resource

    @staticmethod
    def _add_hit(c: sqlite3.Connection, identity: str, kind: str, day: str, first_time: str, last_time: str,
                 event_ids: list[str], detail: dict | None) -> int:
        stage, severity, _label = catalog.HIT_KINDS[kind]
        row = c.execute("SELECT first_time, last_time, event_ids FROM chain_hits WHERE identity=? AND kind=? "
                        "AND day=?", (identity, kind, day)).fetchone()
        if row is None:
            c.execute("INSERT INTO chain_hits(identity, kind, day, stage, severity, first_time, last_time, "
                      "event_ids, detail) VALUES(?,?,?,?,?,?,?,?,?)",
                      (identity, kind, day, stage, severity, first_time, last_time,
                       json.dumps(event_ids[: config.HIT_MAX_IDS]), json.dumps(detail or {}, default=str)))
            return 1
        ids = json.loads(row["event_ids"])
        for e in event_ids:
            if e not in ids and len(ids) < config.HIT_MAX_IDS:
                ids.append(e)
        c.execute("UPDATE chain_hits SET first_time=min(first_time, ?), last_time=max(last_time, ?), event_ids=? "
                  "WHERE identity=? AND kind=? AND day=?",
                  (first_time, last_time, json.dumps(ids), identity, kind, day))
        return 0

    # ---------------------------------------------------------------- per day / per week
    def _discovery_hit(self, c: sqlite3.Connection, identity: str, day: str) -> int:
        row = c.execute("SELECT discovery FROM identity_daily WHERE identity=? AND day=?", (identity, day)).fetchone()
        if not row or row["discovery"] <= 0:
            return 0
        services = c.execute("SELECT COUNT(*) AS n FROM daily_services WHERE identity=? AND day=?",
                             (identity, day)).fetchone()["n"]
        if row["discovery"] < config.DISCOVERY_DAILY_MIN or services < config.DISCOVERY_SERVICES_MIN:
            return 0
        # baseline = this identity's average discovery on its NORMAL days of the last 30 days
        # (days already flagged are excluded, so an attacker cannot teach the baseline that recon is normal)
        start = (_day(day) - timedelta(days=config.MEMORY_RETENTION_DAYS)).isoformat()
        base = c.execute(
            "SELECT AVG(d.discovery) AS a, COUNT(*) AS n FROM identity_daily d WHERE d.identity=? AND d.day>=? "
            "AND d.day<? AND NOT EXISTS (SELECT 1 FROM chain_hits h WHERE h.identity=d.identity AND h.day=d.day)",
            (identity, start, day)).fetchone()
        baseline = float(base["a"] or 0.0) if base["n"] else 0.0
        if row["discovery"] < 3.0 * max(baseline, 1.0):
            return 0
        evs = c.execute("SELECT event_id, time FROM events WHERE identity=? AND day=? AND category=? "
                        "ORDER BY time LIMIT ?", (identity, day, catalog.DISCOVERY, config.HIT_MAX_IDS)).fetchall()
        if not evs:
            return 0
        return self._add_hit(c, identity, "discovery", day, evs[0]["time"], evs[-1]["time"],
                             [e["event_id"] for e in evs], {"calls": row["discovery"], "services": services})

    def _staircase_hit(self, c: sqlite3.Connection, identity: str, peer_cache: dict[str, list[int]]) -> int:
        meta = c.execute("SELECT last_seen FROM identity_meta WHERE identity=?", (identity,)).fetchone()
        if not meta:
            return 0
        ref = _day(meta["last_seen"])
        windows = []
        for k in range(config.STAIRCASE_WEEKS + 1):
            end = ref - timedelta(days=7 * k)
            start = end - timedelta(days=6)
            windows.append((start.isoformat(), end.isoformat()))
        windows.reverse()  # oldest -> newest
        sums = []
        for start, end in windows:
            r = c.execute("SELECT COALESCE(SUM(sensitive_reads), 0) AS s FROM identity_daily WHERE identity=? "
                          "AND day BETWEEN ? AND ?", (identity, start, end)).fetchone()
            sums.append(int(r["s"]))
        if sums[0] <= 0 or sums[-1] < config.STAIRCASE_MIN_LAST_WEEK:
            return 0
        if any(sums[i + 1] < sums[i] * (1 + config.STAIRCASE_GROWTH) for i in range(len(sums) - 1)):
            return 0
        # peer check: last week must exceed the peer percentile
        key = windows[-1][1]
        if key not in peer_cache:
            rows = c.execute("SELECT identity, SUM(sensitive_reads) AS s FROM identity_daily WHERE day BETWEEN ? AND ? "
                             "GROUP BY identity", windows[-1]).fetchall()
            peer_cache[key] = [(r["identity"], int(r["s"] or 0)) for r in rows]
        peers = sorted(s for i, s in peer_cache[key] if i != identity)
        if len(peers) >= config.PEER_MIN_IDENTITIES:
            p = peers[int(config.PEER_PERCENTILE * (len(peers) - 1))]
            if sums[-1] <= p:
                return 0
        ids: list[str] = []
        times: list[str] = []
        for start, end in windows:
            evs = c.execute("SELECT event_id, time FROM events WHERE identity=? AND day BETWEEN ? AND ? AND "
                            "category=? AND sensitive=1 ORDER BY time LIMIT 2",
                            (identity, start, end, catalog.DATA_READ)).fetchall()
            ids.extend(e["event_id"] for e in evs)
            times.extend(e["time"] for e in evs)
        last_week = c.execute("SELECT MIN(time) AS a, MAX(time) AS b FROM events WHERE identity=? AND day BETWEEN ? "
                              "AND ? AND category=? AND sensitive=1", (identity, *windows[-1],
                                                                       catalog.DATA_READ)).fetchone()
        if not ids or not last_week["a"]:
            return 0
        return self._add_hit(c, identity, "read_staircase", ref.isoformat(), last_week["a"], last_week["b"], ids,
                             {"weekly_sensitive_reads": sums})

    # ---------------------------------------------------------------- chains and findings
    def _evaluate_chains(self, c: sqlite3.Connection, identity: str) -> int:
        hits = c.execute("SELECT * FROM chain_hits WHERE identity=? ORDER BY first_time, kind",
                         (identity,)).fetchall()
        chains: list[list[sqlite3.Row]] = []
        cur: list[sqlite3.Row] = []
        cur_start = cur_last = None
        for h in hits:
            ft, lt = parse_time(h["first_time"]), parse_time(h["last_time"])
            if cur and (ft - cur_last).total_seconds() / 86400 <= config.CHAIN_MAX_GAP_DAYS \
                    and (lt - cur_start).total_seconds() / 86400 <= config.CHAIN_MAX_SPAN_DAYS:
                cur.append(h)
                cur_last = max(cur_last, lt)
            else:
                if cur:
                    chains.append(cur)
                cur, cur_start, cur_last = [h], ft, lt
        if cur:
            chains.append(cur)

        updated = 0
        identity_risk, risk_time = 0.0, None
        for chain in chains:
            stage_max: dict[str, float] = {}
            day_risk: dict[str, float] = {}
            risk = 0.0
            for h in chain:
                stage_max[h["stage"]] = max(stage_max.get(h["stage"], 0.0), h["severity"])
                risk = self._chain_risk(stage_max)
                day_risk[h["day"]] = max(day_risk.get(h["day"], 0.0), risk)
            for d, r in day_risk.items():
                c.execute("UPDATE identity_daily SET max_risk=max(max_risk, ?) WHERE identity=? AND day=?",
                          (r, identity, d))
            chain_last = max(h["last_time"] for h in chain)
            if risk_time is not None:
                hours = (parse_time(chain_last) - parse_time(risk_time)).total_seconds() / 3600
                identity_risk = _decay(identity_risk, hours)
            identity_risk = max(identity_risk, risk)
            risk_time = chain_last if risk_time is None else max(risk_time, chain_last)
            if self._is_finding(stage_max, risk):
                self._upsert_finding(c, identity, chain, stage_max, risk)
                updated += 1
        c.execute("UPDATE identity_meta SET risk=?, risk_updated=? WHERE identity=?",
                  (round(identity_risk, 1), risk_time, identity))
        return updated

    @staticmethod
    def _is_finding(stage_max: dict[str, float], risk: float) -> bool:
        """Memory findings are about multi-step chains; single steps are left to the real-time detectors
        unless they are critical on their own (exfiltration, defense evasion)."""
        n = len(stage_max)
        if n >= config.FINDING_MIN_STAGES:
            return True
        if n >= 2 and risk >= config.FINDING_MIN_RISK:
            return True
        return n == 1 and max(stage_max.values()) >= config.SINGLE_STEP_MIN_SEVERITY

    @staticmethod
    def _chain_risk(stage_max: dict[str, float]) -> float:
        p = 1.0
        for s in stage_max.values():
            p *= (1.0 - s)
        factor = min(config.CHAIN_FACTOR_CAP, 1.0 + config.CHAIN_STEP_BONUS * (len(stage_max) - 1))
        return round(min(100.0, 100.0 * (1.0 - p) * factor), 1)

    def _upsert_finding(self, c: sqlite3.Connection, identity: str, chain: list[sqlite3.Row],
                        stage_max: dict[str, float], risk: float) -> None:
        first = chain[0]
        fid = "MEM-" + hashlib.sha1(f"{identity}|{first['kind']}|{first['day']}".encode()).hexdigest()[:10]
        steps, evidence = [], []
        for h in chain:
            ids = json.loads(h["event_ids"])
            steps.append({"day": h["day"], "kind": h["kind"], "stage": h["stage"], "severity": h["severity"],
                          "label": catalog.HIT_KINDS[h["kind"]][2], "event_ids": ids,
                          "detail": json.loads(h["detail"] or "{}")})
            for e in ids:
                if e not in evidence and len(evidence) < config.EVIDENCE_MAX_IDS:
                    evidence.append(e)
        for i in range(0, len(evidence), 500):
            chunk = evidence[i:i + 500]
            c.execute(f"UPDATE events SET evidence=1 WHERE event_id IN ({','.join('?' * len(chunk))})", chunk)
        ev_days = {s["day"] for s in steps}
        if evidence:
            rows = c.execute(f"SELECT DISTINCT day FROM events WHERE event_id IN ({','.join('?' * len(evidence))})",
                             evidence).fetchall()
            ev_days |= {r["day"] for r in rows}
        stages = [s for s in catalog.STAGE_ORDER if s in stage_max]
        first_time = min(h["first_time"] for h in chain)
        last_time = max(h["last_time"] for h in chain)
        narrative = self._narrative(identity, steps, len(ev_days), first_time, last_time, risk)
        now = fmt_time(datetime.now(timezone.utc))
        c.execute(
            "INSERT INTO findings(finding_id, identity, risk, stages, steps, evidence, first_time, last_time, "
            "days_spanned, narrative, updated) VALUES(?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(finding_id) DO UPDATE SET risk=excluded.risk, stages=excluded.stages, steps=excluded.steps, "
            "evidence=excluded.evidence, first_time=excluded.first_time, last_time=excluded.last_time, "
            "days_spanned=excluded.days_spanned, narrative=excluded.narrative, updated=excluded.updated",
            (fid, identity, risk, json.dumps(stages), json.dumps(steps, default=str), json.dumps(evidence),
             first_time, last_time, len(ev_days), narrative, now))

    @staticmethod
    def _narrative(identity: str, steps: list[dict], days: int, first_time: str, last_time: str,
                   risk: float) -> str:
        groups: dict[str, list[str]] = {}
        for s in steps:
            groups.setdefault(s["kind"], []).append(s["day"])
        parts = []
        for kind, ds in groups.items():
            label = catalog.HIT_KINDS[kind][2]
            if len(ds) == 1:
                parts.append(f"{label} ({ds[0]})")
            else:
                parts.append(f"{label} ({ds[0]} to {ds[-1]}, on {len(ds)} days)")
        return (f"Over {days} day(s) between {first_time[:10]} and {last_time[:10]}, {identity} showed "
                f"{len({s['stage'] for s in steps})} attack stage(s): " + "; ".join(parts)
                + f". Linked by the 30-day memory into one chain. Combined risk {risk:.0f}/100.")

    # ================================================================ retention
    def prune(self, now: datetime | None = None, vacuum: bool = False) -> dict:
        now = now or parse_time(self.data_clock()) or datetime.now(timezone.utc)
        cut_raw = fmt_time(now - timedelta(days=config.RAW_EVENT_RETENTION_DAYS))
        cut_mem_t = fmt_time(now - timedelta(days=config.MEMORY_RETENTION_DAYS))
        cut_mem_d = (now - timedelta(days=config.MEMORY_RETENTION_DAYS)).strftime("%Y-%m-%d")
        out: dict[str, Any] = {"now": fmt_time(now), "raw_cutoff": cut_raw, "memory_cutoff": cut_mem_t}
        with self.store.tx() as c:
            out["events_deleted"] = c.execute("DELETE FROM events WHERE time < ? AND evidence = 0",
                                              (cut_raw,)).rowcount
            out["daily_deleted"] = c.execute("DELETE FROM identity_daily WHERE day < ?", (cut_mem_d,)).rowcount
            out["services_deleted"] = c.execute("DELETE FROM daily_services WHERE day < ?", (cut_mem_d,)).rowcount
            out["hits_deleted"] = c.execute("DELETE FROM chain_hits WHERE last_time < ?", (cut_mem_t,)).rowcount
            out["networks_deleted"] = c.execute("DELETE FROM identity_networks WHERE last_seen < ?",
                                                (cut_mem_t,)).rowcount
            out["write_targets_deleted"] = c.execute("DELETE FROM identity_write_targets WHERE last_seen < ?",
                                                     (cut_mem_t,)).rowcount
            out["evidence_kept"] = c.execute("SELECT COUNT(*) FROM events WHERE evidence=1").fetchone()[0]
            out["findings_kept"] = c.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        self.store.checkpoint()
        if vacuum:
            self.store.vacuum()
        self.store.set_meta("last_prune", out["now"])
        return out

    # ================================================================ views
    def data_clock(self) -> str | None:
        return self.store.get_meta("data_clock")

    def current_risk(self, risk: float, risk_updated: str | None) -> float:
        clock = parse_time(self.data_clock())
        if not risk_updated or not clock:
            return round(risk, 1)
        hours = (clock - parse_time(risk_updated)).total_seconds() / 3600
        return round(_decay(risk, hours), 1)

    def stats(self) -> dict:
        rows = {t: self.store.one(f"SELECT COUNT(*) AS n FROM {t}")["n"] for t in TABLES}
        evidence = self.store.one("SELECT COUNT(*) AS n FROM events WHERE evidence=1")["n"]
        span = self.store.one("SELECT MIN(day) AS a, MAX(day) AS b FROM identity_daily")
        return {
            "db_path": str(self.store.path),
            "db_size_bytes": self.store.size_bytes(),
            "db_size_mb": round(self.store.size_bytes() / 1_048_576, 2),
            "rows": rows,
            "evidence_events": evidence,
            "memory_days": {"first": span["a"], "last": span["b"]},
            "data_clock": self.data_clock(),
            "last_prune": self.store.get_meta("last_prune"),
            "retention": {"raw_event_days": config.RAW_EVENT_RETENTION_DAYS,
                          "memory_days": config.MEMORY_RETENTION_DAYS,
                          "chain_max_gap_days": config.CHAIN_MAX_GAP_DAYS,
                          "chain_max_span_days": config.CHAIN_MAX_SPAN_DAYS},
        }

    def identities(self, limit: int = 50) -> list[dict]:
        rows = self.store.query(
            "SELECT m.identity, m.first_seen, m.last_seen, m.risk, m.risk_updated, "
            "(SELECT COUNT(*) FROM findings f WHERE f.identity=m.identity) AS findings, "
            "(SELECT COUNT(*) FROM chain_hits h WHERE h.identity=m.identity) AS hits "
            "FROM identity_meta m")
        out = [{"identity": r["identity"], "first_seen": r["first_seen"], "last_seen": r["last_seen"],
                "risk_peak": r["risk"], "risk_now": self.current_risk(r["risk"], r["risk_updated"]),
                "findings": r["findings"], "hits": r["hits"]} for r in rows]
        out.sort(key=lambda x: (-x["findings"], -x["risk_peak"], x["identity"]))
        return out[: max(1, min(int(limit), 1000))]

    def findings(self, limit: int = 100, identity: str | None = None) -> list[dict]:
        sql = "SELECT * FROM findings"
        params: list = []
        if identity:
            sql += " WHERE identity=?"
            params.append(identity)
        sql += " ORDER BY risk DESC, last_time DESC LIMIT ?"
        params.append(max(1, min(int(limit), 1000)))
        return [self._finding_row(r) for r in self.store.query(sql, params)]

    @staticmethod
    def _finding_row(r: sqlite3.Row) -> dict:
        return {"finding_id": r["finding_id"], "identity": r["identity"], "risk": r["risk"],
                "stages": json.loads(r["stages"]), "steps": json.loads(r["steps"]),
                "evidence": json.loads(r["evidence"]), "first_time": r["first_time"], "last_time": r["last_time"],
                "days_spanned": r["days_spanned"], "status": r["status"], "narrative": r["narrative"],
                "updated": r["updated"]}

    def identity_view(self, identity: str, days: int = 30) -> dict | None:
        meta = self.store.one("SELECT * FROM identity_meta WHERE identity=?", (identity,))
        if meta is None:
            return None
        days = max(1, min(int(days), 90))
        end = _day(self.data_clock() or meta["last_seen"])
        start = end - timedelta(days=days - 1)
        daily = {r["day"]: dict(r) for r in self.store.query(
            "SELECT * FROM identity_daily WHERE identity=? AND day BETWEEN ? AND ?",
            (identity, start.isoformat(), end.isoformat()))}
        hits = self.store.query("SELECT kind, day, stage, severity, first_time, last_time, event_ids, detail "
                                "FROM chain_hits WHERE identity=? AND day BETWEEN ? AND ? ORDER BY first_time",
                                (identity, start.isoformat(), end.isoformat()))
        hits_by_day: dict[str, list[str]] = {}
        for h in hits:
            hits_by_day.setdefault(h["day"], []).append(h["kind"])
        series = []
        for i in range(days):
            d = (start + timedelta(days=i)).isoformat()
            row = daily.get(d, {})
            series.append({
                "day": d,
                "events": row.get("events", 0), "logins": row.get("logins", 0),
                "discovery": row.get("discovery", 0), "data_reads": row.get("data_reads", 0),
                "sensitive_reads": row.get("sensitive_reads", 0), "writes": row.get("writes", 0),
                "privesc": row.get("privesc", 0), "credential": row.get("credential", 0),
                "exfil": row.get("exfil", 0), "evasion": row.get("evasion", 0),
                "new_networks": row.get("new_networks", 0), "max_risk": row.get("max_risk", 0.0),
                "hits": hits_by_day.get(d, []),
            })
        return {
            "identity": identity,
            "first_seen": meta["first_seen"], "last_seen": meta["last_seen"],
            "risk_peak": meta["risk"], "risk_now": self.current_risk(meta["risk"], meta["risk_updated"]),
            "window": {"start": start.isoformat(), "end": end.isoformat(), "days": days},
            "days": series,
            "hits": [{"kind": h["kind"], "label": catalog.HIT_KINDS[h["kind"]][2], "day": h["day"],
                      "stage": h["stage"], "severity": h["severity"], "first_time": h["first_time"],
                      "last_time": h["last_time"], "event_ids": json.loads(h["event_ids"]),
                      "detail": json.loads(h["detail"] or "{}")} for h in hits],
            "findings": self.findings(identity=identity, limit=20),
        }

    def evidence_events(self, event_ids: list[str]) -> list[dict]:
        ids = [str(e) for e in event_ids][:200]
        if not ids:
            return []
        rows = self.store.query(
            f"SELECT event_id, time, source, identity, action, category, ip, resource, outcome, raw FROM events "
            f"WHERE event_id IN ({','.join('?' * len(ids))}) ORDER BY time", ids)
        return [dict(r) for r in rows]

    def reset(self) -> None:
        with self.store.tx() as c:
            for t in TABLES + ("meta",):
                c.execute(f"DELETE FROM {t}")
        self.store.checkpoint()
        self.store.vacuum()

    def close(self) -> None:
        self.store.close()
