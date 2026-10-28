"""Input-only data entry: paste/upload CloudTrail or Okta records, or add one event with a form.

Accepted records are written as JSON Lines to data/input/<source>/<source>_<stamp>_<name>.jsonl,
so the existing loaders read them unchanged. Input is only parsed as JSON, never executed.
Limits: config.INPUT_MAX_BYTES per request, config.INPUT_MAX_RECORDS records per request.
"""
import ipaddress
import json
import logging
import re
import uuid
from datetime import datetime, timezone

from app import config
from app.utils import parse_ts

log = logging.getLogger(__name__)

SOURCES = ("cloudtrail", "okta")
MANUAL_KINDS = ("okta_login", "okta_logout", "cloudtrail_api")

_SAFE_NAME = re.compile(r"[^A-Za-z0-9_-]+")
_CTRL = re.compile(r"[\x00-\x1f\x7f]")
_USER = re.compile(r"^[A-Za-z0-9._%+@-]{1,128}$")
_EVENT_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9]{1,63}$")
_EVENT_SOURCE = re.compile(r"^[a-z0-9.-]{3,64}$")
_REGION = re.compile(r"^[a-z]{2}(-[a-z]+)+-\d$")
_ACCESS_KEY = re.compile(r"^[A-Z0-9]{16,128}$")
_LABEL = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


class InputError(ValueError):
    """Invalid user input. The message is safe to show to the user."""


def source_dir(source: str):
    return config.INPUT_DIR / source


def detect_source(rec: object) -> str | None:
    if not isinstance(rec, dict):
        return None
    if "eventName" in rec or "eventSource" in rec or "userIdentity" in rec:
        return "cloudtrail"
    if "eventType" in rec or "published" in rec or ("actor" in rec and "outcome" in rec):
        return "okta"
    return None


def _invalid_reason(rec: dict, source: str) -> str | None:
    if source == "cloudtrail":
        if parse_ts(rec.get("eventTime")) is None:
            return "missing or invalid eventTime"
        if not rec.get("eventName"):
            return "missing eventName"
    else:
        if parse_ts(rec.get("published")) is None:
            return "missing or invalid published"
        if not rec.get("eventType"):
            return "missing eventType"
    return None


def parse_records(text: str) -> tuple[list, list[str]]:
    """Accept {"Records": [...]}, a JSON array, one JSON object, or JSON Lines. Returns (records, errors)."""
    text = (text or "").strip()
    if not text:
        raise InputError("No content provided")
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        doc = None
    if doc is not None:
        if isinstance(doc, dict) and isinstance(doc.get("Records"), list):
            return doc["Records"], []
        if isinstance(doc, list):
            return doc, []
        if isinstance(doc, dict):
            return [doc], []
        raise InputError('JSON must be an object, an array, or {"Records": [...]}')
    records: list = []
    errors: list[str] = []
    for n, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as exc:
            errors.append(f"Line {n}: not valid JSON ({exc.msg})")
    if not records:
        raise InputError("Content is not valid JSON or JSON Lines" + (f": {errors[0]}" if errors else ""))
    return records, errors


def _safe_filename(filename: str | None) -> str:
    base = str(filename or "paste").replace("\\", "/").split("/")[-1]
    base = base.rsplit(".", 1)[0] if "." in base else base
    return (_SAFE_NAME.sub("_", base).strip("_-") or "paste")[:40]


def _write_jsonl(source: str, name: str, records: list[dict], append: bool = False) -> str:
    folder = source_dir(source)
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / name
    with path.open("a" if append else "w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return path.name


def save_input(content: str, source: str = "auto", filename: str | None = None) -> dict:
    """Validate and store pasted/uploaded records. Raises InputError with a user-safe message."""
    if source not in ("auto",) + SOURCES:
        raise InputError("source must be auto, cloudtrail or okta")
    if not isinstance(content, str):
        raise InputError("content must be text")
    size = len(content.encode("utf-8"))
    if size > config.INPUT_MAX_BYTES:
        raise InputError(f"Content is {size:,} bytes; the limit is {config.INPUT_MAX_BYTES:,} bytes")
    records, errors = parse_records(content)
    if len(records) > config.INPUT_MAX_RECORDS:
        raise InputError(f"{len(records):,} records; the limit is {config.INPUT_MAX_RECORDS:,} per upload")

    groups: dict[str, list[dict]] = {s: [] for s in SOURCES}
    rejected = len(errors)
    for i, rec in enumerate(records, 1):
        src = detect_source(rec) if source == "auto" else (source if isinstance(rec, dict) else None)
        if src is None:
            rejected += 1
            errors.append(f"Record {i}: not a CloudTrail or Okta record")
            continue
        reason = _invalid_reason(rec, src)
        if reason:
            rejected += 1
            errors.append(f"Record {i}: {reason}")
            continue
        groups[src].append(rec)
    if not any(groups.values()):
        raise InputError("No valid CloudTrail or Okta records found. " + "; ".join(errors[:3]))

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f")
    safe = _safe_filename(filename)
    files = [{"source": src, "file": _write_jsonl(src, f"{src}_{stamp}_{safe}.jsonl", recs), "records": len(recs)}
             for src, recs in groups.items() if recs]
    log.info("Input saved: %s", files)
    return {"accepted": {s: len(groups[s]) for s in SOURCES}, "rejected": rejected,
            "errors": errors[:10], "files": files}


def _text(value: object, field: str, max_len: int = 128, required: bool = True) -> str:
    s = _CTRL.sub("", str(value if value is not None else "")).strip()
    if required and not s:
        raise InputError(f"{field} is required")
    if len(s) > max_len:
        raise InputError(f"{field} is too long (max {max_len} characters)")
    return s


def _ip(value: object, field: str = "ip") -> str:
    s = _text(value, field, 64)
    try:
        ipaddress.ip_address(s)
    except ValueError:
        raise InputError(f"{field} is not a valid IP address") from None
    return s


def _time(value: object) -> str:
    if value in (None, ""):
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    dt = parse_ts(value)
    if dt is None:
        raise InputError("time must be ISO 8601, e.g. 2026-10-28T09:40:00Z")
    return dt.isoformat().replace("+00:00", "Z")


def _num(value: object, field: str, lo: float, hi: float) -> float | None:
    if value in (None, ""):
        return None
    try:
        f = float(value)
    except (TypeError, ValueError):
        raise InputError(f"{field} must be a number") from None
    if not lo <= f <= hi:
        raise InputError(f"{field} must be between {lo} and {hi}")
    return f


def _match(value: str, pattern: re.Pattern, field: str, example: str) -> str:
    if not pattern.match(value):
        raise InputError(f"{field} has an invalid format (example: {example})")
    return value


def build_manual_record(kind: str, fields: dict | None) -> tuple[str, dict]:
    """Build one realistic Okta or CloudTrail record from form fields. Returns (source, record)."""
    f = fields or {}
    user = _match(_text(f.get("user"), "user"), _USER, "user", "dev.kumar or dev.kumar@corp.example")
    label = _text(f.get("label"), "label", 64, required=False)
    if label:
        _match(label, _LABEL, "label", "impossible_travel")
    hexid = uuid.uuid4().hex
    if kind in ("okta_login", "okta_logout"):
        outcome = _text(f.get("outcome") or "SUCCESS", "outcome", 16).upper()
        if outcome not in ("SUCCESS", "FAILURE"):
            raise InputError("outcome must be SUCCESS or FAILURE")
        lat = _num(f.get("lat"), "lat", -90, 90)
        lon = _num(f.get("lon"), "lon", -180, 180)
        asn = _num(f.get("asn"), "asn", 0, 4_294_967_295)
        rec: dict = {
            "uuid": f"manual-{hexid[:16]}",
            "published": _time(f.get("time")),
            "eventType": "user.session.start" if kind == "okta_login" else "user.session.end",
            "actor": {"id": f"manual-{user.split('@')[0]}", "alternateId": user if "@" in user else f"{user}@corp.example",
                      "type": "User"},
            "outcome": {"result": outcome},
            "client": {"ipAddress": _ip(f.get("ip")),
                       "userAgent": {"rawUserAgent": _text(f.get("user_agent") or "Mozilla/5.0", "user_agent", 256)},
                       "geographicalContext": {"country": _text(f.get("country"), "country", 64, required=False) or None,
                                               "city": _text(f.get("city"), "city", 64, required=False) or None,
                                               "geolocation": {"lat": lat, "lon": lon}}},
            "authenticationContext": {"externalSessionId": _text(f.get("session_id"), "session_id", 64, required=False)
                                      or f"manual-{hexid[16:28]}"},
            "securityContext": {"asNumber": int(asn) if asn is not None else None},
        }
        if label:
            rec["label"] = label
        return "okta", rec
    if kind == "cloudtrail_api":
        event_name = _match(_text(f.get("event_name"), "event_name", 64), _EVENT_NAME, "event_name", "AttachUserPolicy")
        event_source = _match(_text(f.get("event_source") or "iam.amazonaws.com", "event_source", 64),
                              _EVENT_SOURCE, "event_source", "iam.amazonaws.com")
        region = _match(_text(f.get("region") or "ap-south-1", "region", 32), _REGION, "region", "ap-south-1")
        key = _text(f.get("access_key_id"), "access_key_id", 128, required=False) or f"AKIAMANUAL{hexid[:10].upper()}"
        _match(key, _ACCESS_KEY, "access_key_id", "AKIAIOSFODNN7EXAMPLE")
        resource = _text(f.get("resource"), "resource", 256, required=False)
        error_code = _text(f.get("error_code"), "error_code", 64, required=False)
        rec = {
            "eventID": f"manual-{hexid[:16]}",
            "eventTime": _time(f.get("time")),
            "eventName": event_name,
            "eventSource": event_source,
            "awsRegion": region,
            "sourceIPAddress": _ip(f.get("ip")),
            "userAgent": _text(f.get("user_agent") or "aws-cli/2.15.0", "user_agent", 256),
            "userIdentity": {"type": "IAMUser", "userName": user.split("@")[0],
                             "arn": f"arn:aws:iam::123456789012:user/{user.split('@')[0]}", "accessKeyId": key},
            "requestParameters": {"resource": resource} if resource else {},
            "resources": [{"ARN": resource}] if resource.startswith("arn:") else [],
        }
        if error_code:
            rec["errorCode"] = error_code
        if label:
            rec["label"] = label
        return "cloudtrail", rec
    raise InputError("kind must be okta_login, okta_logout or cloudtrail_api")


def add_manual(kind: str, fields: dict | None) -> dict:
    source, rec = build_manual_record(kind, fields)
    name = _write_jsonl(source, f"{source}_manual.jsonl", [rec], append=True)
    return {"source": source, "file": name, "record": rec}


def list_inputs() -> dict:
    files = []
    for src in SOURCES:
        folder = source_dir(src)
        if not folder.is_dir():
            continue
        for path in sorted(folder.glob("*.jsonl")):
            try:
                with path.open(encoding="utf-8") as fh:
                    count = sum(1 for line in fh if line.strip())
                stat = path.stat()
            except OSError:
                continue
            files.append({"source": src, "file": path.name, "records": count, "bytes": stat.st_size,
                          "modified": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()})
    totals = {s: sum(f["records"] for f in files if f["source"] == s) for s in SOURCES}
    return {"files": files, "totals": totals, "total_records": sum(totals.values()),
            "limits": {"max_bytes": config.INPUT_MAX_BYTES, "max_records": config.INPUT_MAX_RECORDS}}


def has_input() -> bool:
    return list_inputs()["total_records"] > 0


def clear_inputs() -> int:
    removed = 0
    for src in SOURCES:
        folder = source_dir(src)
        if folder.is_dir():
            for path in folder.glob("*.jsonl"):
                try:
                    path.unlink()
                    removed += 1
                except OSError:
                    log.warning("Could not delete %s", path.name)
    return removed
