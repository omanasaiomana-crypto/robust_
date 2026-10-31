"""Load Okta System Log / AWS CloudTrail JSON and normalize records into flat dicts. Pure functions."""
from __future__ import annotations

import gzip
import ipaddress
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from . import catalog, config

log = logging.getLogger(__name__)

TIME_FMT = "%Y-%m-%dT%H:%M:%S.%fZ"
_EXTS = (".json", ".jsonl", ".ndjson", ".json.gz", ".jsonl.gz")


# ---------------------------------------------------------------- loading
def _read_text(path: Path) -> str:
    if path.name.endswith(".gz"):
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            return fh.read()
    return path.read_text(encoding="utf-8")


def parse_json_text(text: str) -> list[dict]:
    """Accept a JSON list, {"Records": [...]}, a single event object, or JSON Lines."""
    text = text.strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        out = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            out.extend(_unwrap(obj))
        return out
    return _unwrap(data)


def _unwrap(data: Any) -> list[dict]:
    if isinstance(data, list):
        return [d for d in data if isinstance(d, dict)]
    if isinstance(data, dict):
        for key in ("Records", "records", "events", "data"):
            if isinstance(data.get(key), list):
                return [d for d in data[key] if isinstance(d, dict)]
        return [data]
    return []


def iter_files(paths: Iterable[Path | str]) -> list[Path]:
    files: list[Path] = []
    for p in paths:
        p = Path(p)
        if p.is_file() and p.name.endswith(_EXTS):
            files.append(p)
        elif p.is_dir():
            files.extend(sorted(f for f in p.rglob("*") if f.is_file() and f.name.endswith(_EXTS)))
    return files


def load_paths(paths: Iterable[Path | str]) -> tuple[list[dict], dict]:
    records: list[dict] = []
    info = {"files": 0, "bad_files": 0}
    for f in iter_files(paths):
        try:
            records.extend(parse_json_text(_read_text(f)))
            info["files"] += 1
        except (OSError, UnicodeDecodeError) as exc:
            info["bad_files"] += 1
            log.warning("memory30: cannot read %s: %s", f, exc.__class__.__name__)
    return records, info


# ---------------------------------------------------------------- helpers
def parse_time(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        try:
            ts = value / 1000 if value > 1e11 else value
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    s = str(value).strip()
    if not s:
        return None
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def fmt_time(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime(TIME_FMT)


def network_of(ip: str | None) -> str | None:
    """Coarse network key: /16 for IPv4, /48 for IPv6. None for service names or invalid values."""
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return None
    if addr.is_loopback or addr.is_link_local:
        return None
    if addr.version == 4:
        return "v4:" + str(ipaddress.ip_network(f"{addr}/16", strict=False).network_address)
    return "v6:" + str(ipaddress.ip_network(f"{addr}/48", strict=False).network_address)


def is_sensitive(resource: str | None) -> bool:
    if not resource:
        return False
    low = resource.lower()
    return any(m in low for m in config.SENSITIVE_MARKERS)


def _g(d: Any, *keys: str) -> Any:
    for k in keys:
        if not isinstance(d, dict):
            return None
        d = d.get(k)
    return d


def _clip(raw: dict) -> str:
    try:
        s = json.dumps(raw, separators=(",", ":"), default=str)
    except (TypeError, ValueError):
        s = "{}"
    return s[: config.RAW_MAX_CHARS]


def detect_source(r: dict) -> str | None:
    if "eventType" in r and ("actor" in r or "uuid" in r):
        return "okta"
    if "eventName" in r and ("userIdentity" in r or "eventSource" in r):
        return "cloudtrail"
    return None


# ---------------------------------------------------------------- identity resolution
def cloudtrail_identity(ui: dict | None) -> tuple[str, str | None]:
    """Return (identity, session_name). SAML/SSO sessions named after an email resolve to that email."""
    ui = ui or {}
    typ = ui.get("type") or ""
    arn = ui.get("arn") or ""
    session_name = None
    if typ in ("AssumedRole", "FederatedUser") or ":assumed-role/" in arn:
        parts = arn.split("/")
        role = parts[1] if len(parts) > 2 else (_g(ui, "sessionContext", "sessionIssuer", "userName") or "role")
        session_name = parts[-1] if len(parts) > 2 else None
        if not session_name and ui.get("principalId") and ":" in str(ui["principalId"]):
            session_name = str(ui["principalId"]).split(":", 1)[1]
        src_identity = _g(ui, "sessionContext", "sourceIdentity") or ui.get("sourceIdentity")
        if src_identity:
            return str(src_identity).lower(), session_name
        if session_name and "@" in session_name:
            return session_name.lower(), session_name
        return f"{role}/{session_name}" if session_name else str(role), session_name
    if typ == "Root":
        return "root", None
    if ui.get("userName"):
        return str(ui["userName"]).lower() if "@" in str(ui["userName"]) else str(ui["userName"]), None
    if arn:
        return arn.split("/")[-1] or arn, None
    return str(ui.get("principalId") or "unknown"), None


_CT_RESOURCE_KEYS = ("bucketName", "secretId", "keyId", "snapshotId", "dBSnapshotIdentifier", "functionName",
                     "roleName", "userName", "policyArn", "groupName", "name", "trailName", "detectorId",
                     "logGroupName", "instanceId", "repositoryName", "tableName")


def cloudtrail_resource(r: dict) -> str | None:
    rp = r.get("requestParameters") if isinstance(r.get("requestParameters"), dict) else {}
    bucket = rp.get("bucketName")
    key = rp.get("key")
    if bucket:
        return f"{bucket}/{key}" if key else str(bucket)
    for k in _CT_RESOURCE_KEYS:
        if rp.get(k):
            return str(rp[k])
    res = r.get("resources")
    if isinstance(res, list) and res and isinstance(res[0], dict):
        return res[0].get("ARN") or res[0].get("arn")
    return None


# ---------------------------------------------------------------- normalize
def normalize(r: dict) -> dict | None:
    """Return a flat event dict or None if the record is not usable."""
    if not isinstance(r, dict):
        return None
    src = detect_source(r)
    if src == "okta":
        return _normalize_okta(r)
    if src == "cloudtrail":
        return _normalize_cloudtrail(r)
    return None


def _base(event_id: str, dt: datetime, source: str, identity: str, action: str, outcome: str) -> dict:
    return {
        "event_id": f"{source}:{event_id}",
        "time": fmt_time(dt),
        "day": dt.strftime("%Y-%m-%d"),
        "source": source,
        "identity": identity,
        "action": action,
        "outcome": outcome,
    }


def _normalize_okta(r: dict) -> dict | None:
    eid = r.get("uuid") or r.get("id")
    dt = parse_time(r.get("published"))
    actor = r.get("actor") or {}
    identity = (actor.get("alternateId") or actor.get("id") or "").strip()
    action = r.get("eventType") or ""
    if not eid or not dt or not identity or not action:
        return None
    identity = identity.lower()
    res = str(_g(r, "outcome", "result") or "").upper()
    outcome = "success" if res in ("SUCCESS", "ALLOW") else "failure" if res in ("FAILURE", "DENY") else "unknown"
    ip = _g(r, "client", "ipAddress")
    target = r.get("target") if isinstance(r.get("target"), list) else []
    resource = None
    if target and isinstance(target[0], dict):
        resource = target[0].get("alternateId") or target[0].get("displayName")
    n = _base(str(eid), dt, "okta", identity, action, outcome)
    asn = _g(r, "securityContext", "asNumber")
    n.update({
        "service": "okta",
        "ip": ip,
        "net": f"asn:{asn}" if asn else network_of(ip),
        "country": _g(r, "client", "geographicalContext", "country"),
        "is_proxy": bool(_g(r, "securityContext", "isProxy")),
        "resource": resource,
        "read_only": True,
        "session": _g(r, "authenticationContext", "externalSessionId"),
        "raw": _clip(r),
    })
    n["category"] = catalog.categorize("okta", action, outcome)
    n["sensitive"] = is_sensitive(resource)
    return n


def _normalize_cloudtrail(r: dict) -> dict | None:
    eid = r.get("eventID")
    dt = parse_time(r.get("eventTime"))
    action = r.get("eventName") or ""
    if not eid or not dt or not action:
        return None
    identity, session_name = cloudtrail_identity(r.get("userIdentity"))
    outcome = "failure" if r.get("errorCode") else "success"
    ip = r.get("sourceIPAddress")
    resource = cloudtrail_resource(r)
    read_only = r.get("readOnly")
    if read_only is None:
        read_only = action.startswith(("Get", "List", "Describe", "Head", "Lookup"))
    n = _base(str(eid), dt, "cloudtrail", identity, action, outcome)
    n.update({
        "service": str(r.get("eventSource") or "").split(".")[0] or "aws",
        "ip": ip,
        "net": network_of(ip),
        "country": None,
        "is_proxy": False,
        "resource": resource,
        "read_only": bool(read_only),
        "session": session_name,
        "raw": _clip(r),
    })
    n["category"] = catalog.categorize("cloudtrail", action, outcome)
    n["sensitive"] = is_sensitive(resource)
    return n
