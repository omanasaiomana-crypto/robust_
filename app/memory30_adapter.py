"""Official Dataset Adapter for IdentityShield 30-Day Memory.

Reads official log files (CSV, JSON, JSONL, .gz) in varying or flat formats
and adapts them into Okta System Log or AWS CloudTrail records consumable by
the memory30 normalizer and engine.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import io
import json
import logging
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

log = logging.getLogger(__name__)

SUPPORTED_EXTS = (".json", ".jsonl", ".ndjson", ".csv", ".json.gz", ".jsonl.gz", ".csv.gz")


# ---------------------------------------------------------------- helpers
def _parse_iso_utc(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        try:
            ts = value / 1000.0 if value > 1e11 else float(value)
            dt = datetime.fromtimestamp(ts, tz=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        except (OverflowError, OSError, ValueError):
            return None
    s = str(value).strip()
    if not s:
        return None
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        pass

    # Try common formats
    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y/%m/%d %H:%M:%S",
        "%d/%m/%Y %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
    ):
        try:
            dt = datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        except ValueError:
            continue
    return None


def _first_val(row: dict, *keys: str) -> Any:
    for k in keys:
        if k in row and row[k] not in (None, ""):
            return row[k]
        # Case insensitive match
        low_k = k.lower()
        for rk, rv in row.items():
            if str(rk).strip().lower() == low_k and rv not in (None, ""):
                return rv
    return None


def _is_okta_action(action: str) -> bool:
    if not action:
        return False
    # Okta events typically have dots: user.session.start, etc.
    return "." in action or action.startswith("core.") or action.startswith("user.") or action.startswith("policy.")


# ---------------------------------------------------------------- row adaptation
def adapt_record(row: dict) -> dict | None:
    """Convert an arbitrary/official row into either an Okta or CloudTrail standard dict.
    
    Returns None if the record cannot be converted or is missing critical fields.
    """
    if not isinstance(row, dict):
        return None

    # Handle envelope wrapper e.g. {"event": {...}, "source": "okta"}
    if "event" in row and isinstance(row["event"], dict):
        unwrapped = dict(row["event"])
        if "source" in row and "source" not in unwrapped:
            unwrapped["source"] = row["source"]
        row = unwrapped

    # If it is already a fully formed Okta record
    if "eventType" in row and ("actor" in row or "uuid" in row) and isinstance(row.get("actor"), dict):
        return row

    # If it is already a fully formed CloudTrail record
    if "eventName" in row and ("userIdentity" in row or "eventSource" in row) and isinstance(row.get("userIdentity"), dict):
        return row

    # Extract generic fields across CSV/JSON
    event_id = _first_val(row, "event_id", "eventId", "eventID", "uuid", "id", "log_id")
    raw_time = _first_val(row, "timestamp", "time", "published", "eventTime", "datetime", "date", "@timestamp")
    time_iso = _parse_iso_utc(raw_time)

    identity = _first_val(row, "identity", "user", "username", "userName", "email", "user_name", "user_email", "actor_id")
    if not identity and isinstance(row.get("actor"), dict):
        identity = row["actor"].get("alternateId") or row["actor"].get("id") or row["actor"].get("displayName")
    if not identity and isinstance(row.get("userIdentity"), dict):
        identity = row["userIdentity"].get("userName") or row["userIdentity"].get("arn") or row["userIdentity"].get("principalId")

    action = _first_val(row, "action", "eventName", "eventType", "event_name", "event_type", "operation", "method")
    
    # Critical fields check
    if not event_id or not time_iso or not action or not identity:
        return None

    identity_str = str(identity).strip()
    event_id_str = str(event_id).strip()
    action_str = str(action).strip()

    source = _first_val(row, "source", "eventSource", "log_source", "log_type", "service", "system")
    source_str = str(source).lower() if source else ""

    ip = _first_val(row, "ip", "ip_address", "sourceIPAddress", "client_ip", "source_ip", "clientIp")
    if not ip and isinstance(row.get("client"), dict):
        ip = row["client"].get("ipAddress")

    raw_outcome = _first_val(row, "outcome", "result", "status", "success", "error", "errorCode", "error_code")
    is_failure = False
    if raw_outcome is not None:
        s_out = str(raw_outcome).strip().lower()
        if s_out in ("failure", "fail", "error", "deny", "denied", "false", "0"):
            is_failure = True
        elif s_out in ("accessdenied", "unauthorizedoperation", "client.unauthorizedoperation"):
            is_failure = True

    resource = _first_val(row, "resource", "target", "resource_name", "target_name", "bucket", "object")

    # Determine whether to shape as Okta or CloudTrail
    as_okta = False
    if "okta" in source_str:
        as_okta = True
    elif "cloudtrail" in source_str or "aws" in source_str:
        as_okta = False
    elif _is_okta_action(action_str):
        as_okta = True
    else:
        # Default to cloudtrail if looks like AWS API or standard verb, else Okta if email
        as_okta = False

    if as_okta:
        out: dict[str, Any] = {
            "uuid": event_id_str,
            "published": time_iso,
            "eventType": action_str,
            "actor": {
                "id": identity_str,
                "alternateId": identity_str,
            },
            "outcome": {
                "result": "FAILURE" if is_failure else "SUCCESS",
            },
        }
        if ip:
            out["client"] = {"ipAddress": str(ip).strip()}
        if resource:
            out["target"] = [{"alternateId": str(resource).strip()}]
        return out
    else:
        out = {
            "eventID": event_id_str,
            "eventTime": time_iso,
            "eventName": action_str,
            "eventSource": f"{source_str}.amazonaws.com" if source_str and "." not in source_str else (source_str or "aws.amazonaws.com"),
            "userIdentity": {
                "type": "IAMUser",
                "userName": identity_str,
            },
        }
        if ip:
            out["sourceIPAddress"] = str(ip).strip()
        if is_failure:
            out["errorCode"] = str(raw_outcome) if raw_outcome else "AccessDenied"
        if resource:
            out["requestParameters"] = {"resourceName": str(resource).strip()}
        return out


# ---------------------------------------------------------------- loader
def _read_file_records(path: Path) -> list[dict]:
    name = path.name.lower()
    is_gz = name.endswith(".gz")
    
    if is_gz:
        raw_bytes = path.read_bytes()
        text = gzip.decompress(raw_bytes).decode("utf-8", errors="replace")
    else:
        text = path.read_text(encoding="utf-8", errors="replace")

    text_stripped = text.strip()
    if not text_stripped:
        return []

    # Check for CSV
    if name.endswith(".csv") or name.endswith(".csv.gz"):
        reader = csv.DictReader(io.StringIO(text))
        return [dict(r) for r in reader]

    # Try JSON
    try:
        data = json.loads(text_stripped)
        if isinstance(data, list):
            return [d for d in data if isinstance(d, dict)]
        if isinstance(data, dict):
            for k in ("Records", "records", "events", "data", "rows"):
                if isinstance(data.get(k), list):
                    return [d for d in data[k] if isinstance(d, dict)]
            return [data]
    except json.JSONDecodeError:
        pass

    # Try JSON Lines
    out = []
    for line in text_stripped.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
            if isinstance(item, dict):
                out.append(item)
            elif isinstance(item, list):
                out.extend([d for d in item if isinstance(d, dict)])
        except json.JSONDecodeError:
            continue
    if out:
        return out

    # Fallback to CSV if not parsed yet
    try:
        reader = csv.DictReader(io.StringIO(text))
        rows = [dict(r) for r in reader]
        if rows and len(rows[0]) > 1:
            return rows
    except Exception:
        pass

    return []


def iter_paths(paths: Iterable[Path | str] | Path | str) -> list[Path]:
    if isinstance(paths, (str, Path)):
        paths = [paths]
    collected: list[Path] = []
    for p in paths:
        path = Path(p)
        if not path.exists():
            continue
        if path.is_file():
            if any(path.name.lower().endswith(ext) for ext in SUPPORTED_EXTS):
                collected.append(path)
        elif path.is_dir():
            for f in sorted(path.rglob("*")):
                if f.is_file() and any(f.name.lower().endswith(ext) for ext in SUPPORTED_EXTS):
                    collected.append(f)
    return collected


def load_official(paths: Iterable[Path | str] | Path | str) -> list[dict]:
    """Read official files from paths and return a list of Okta- or CloudTrail-shaped dicts."""
    adapted: list[dict] = []
    files = iter_paths(paths)
    for f in files:
        records = _read_file_records(f)
        for r in records:
            ad = adapt_record(r)
            if ad is not None:
                adapted.append(ad)
    return adapted


# ---------------------------------------------------------------- CLI
def main() -> None:
    parser = argparse.ArgumentParser(description="Official Dataset Adapter for 30-Day Memory")
    parser.add_argument("paths", nargs="*", default=["data/raw"], help="Files or directories to ingest")
    args = parser.parse_args()

    paths = [Path(p) for p in args.paths]
    records = load_official(paths)

    from app.memory30.engine import MemoryEngine
    engine = MemoryEngine()
    summary = engine.ingest_records(records)
    summary["adapted_count"] = len(records)
    summary["paths_scanned"] = [str(p) for p in paths]
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
