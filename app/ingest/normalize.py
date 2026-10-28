"""Normalize raw CloudTrail and Okta records into the unified Event contract."""
import logging
from typing import Any
import pandas as pd

from app.models import Category, Event, Source
from app.utils import dig, parse_ts

log = logging.getLogger(__name__)

EVENT_FIELDS = list(Event.model_fields.keys())

AUTH_CLOUDTRAIL_ACTIONS = {"ConsoleLogin", "AssumeRoleWithSAML", "GetSessionToken"}


def canonical_identity(value: str | None) -> str:
    """Canonicalize identity: lowercase, email local part, ARN last segment, None -> 'unknown'."""
    if not value or not str(value).strip():
        return "unknown"
    val = str(value).strip().lower()
    if "@" in val:
        val = val.split("@")[0]
    if "/" in val:
        val = val.split("/")[-1]
    return val if val else "unknown"


def _extract_ct_resource(rec: dict) -> str | None:
    resources = dig(rec, "resources")
    if isinstance(resources, list) and resources:
        first = resources[0]
        if isinstance(first, dict) and "ARN" in first and first["ARN"]:
            return str(first["ARN"])

    # Fallback to key requestParameters
    for param in ("policyArn", "roleArn", "bucketName", "userName", "secretId", "name"):
        val = dig(rec, f"requestParameters.{param}")
        if val:
            return str(val)

    return None


def normalize_cloudtrail(rec: dict, idx: int) -> Event | None:
    """Map one CloudTrail record into Event contract. Returns None if timestamp missing/bad."""
    ts = parse_ts(dig(rec, "eventTime"))
    if ts is None:
        return None

    raw_id = (
        dig(rec, "userIdentity.userName")
        or dig(rec, "userIdentity.sessionContext.sessionIssuer.userName")
        or dig(rec, "userIdentity.arn")
    )
    ident = canonical_identity(raw_id)
    action = str(dig(rec, "eventName", "Unknown"))
    category = Category.auth if action in AUTH_CLOUDTRAIL_ACTIONS else Category.api

    has_error = bool(dig(rec, "errorCode"))
    outcome = "failure" if has_error else "success"

    event_id = str(dig(rec, "eventID") or f"ct-{idx}")
    src_ip = dig(rec, "sourceIPAddress")
    user_agent = dig(rec, "userAgent")
    token_id = dig(rec, "userIdentity.accessKeyId")
    region = dig(rec, "awsRegion")
    resource = _extract_ct_resource(rec)
    label = rec.get("label")

    return Event(
        event_id=event_id,
        source=Source.cloudtrail,
        timestamp=ts,
        identity_id=ident,
        session_id=None,
        action=action,
        category=category,
        outcome=outcome,
        src_ip=src_ip,
        country=None,
        city=None,
        lat=None,
        lon=None,
        asn=None,
        user_agent=user_agent,
        device_id=None,
        token_id=token_id,
        region=region,
        resource=resource,
        resource_sensitivity=1,
        privilege_level=1,
        label=label,
    )


def normalize_okta(rec: dict, idx: int) -> Event | None:
    """Map one Okta log record into Event contract. Returns None if timestamp missing/bad."""
    ts = parse_ts(dig(rec, "published"))
    if ts is None:
        return None

    raw_id = dig(rec, "actor.alternateId") or dig(rec, "actor.id")
    ident = canonical_identity(raw_id)
    session_id = dig(rec, "authenticationContext.externalSessionId")
    action = str(dig(rec, "eventType", "unknown"))

    # Category determination
    if action in {"user.session.start", "user.authentication.verify"} or action.startswith("user.authentication."):
        category = Category.auth
    elif action.startswith("user.session."):
        category = Category.session
    else:
        category = Category.api

    raw_outcome = str(dig(rec, "outcome.result", "SUCCESS")).strip().lower()
    outcome = "success" if raw_outcome == "success" else "failure"

    event_id = str(dig(rec, "uuid") or f"okta-{idx}")
    src_ip = dig(rec, "client.ipAddress")
    country = dig(rec, "client.geographicalContext.country")
    city = dig(rec, "client.geographicalContext.city")

    raw_lat = dig(rec, "client.geographicalContext.geolocation.lat")
    raw_lon = dig(rec, "client.geographicalContext.geolocation.lon")
    lat = float(raw_lat) if raw_lat is not None else None
    lon = float(raw_lon) if raw_lon is not None else None

    raw_asn = dig(rec, "securityContext.asNumber")
    asn = str(raw_asn) if raw_asn is not None else None

    user_agent = dig(rec, "client.userAgent.rawUserAgent")
    device_id = dig(rec, "client.device") or dig(rec, "debugContext.debugData.deviceFingerprint")
    label = rec.get("label")

    return Event(
        event_id=event_id,
        source=Source.okta,
        timestamp=ts,
        identity_id=ident,
        session_id=session_id,
        action=action,
        category=category,
        outcome=outcome,
        src_ip=src_ip,
        country=country,
        city=city,
        lat=lat,
        lon=lon,
        asn=asn,
        user_agent=user_agent,
        device_id=device_id,
        token_id=None,
        region=None,
        resource=None,
        resource_sensitivity=1,
        privilege_level=1,
        label=label,
    )


def normalize_all(ct: list[dict], okta: list[dict]) -> tuple[pd.DataFrame, int]:
    """Normalize lists of raw CloudTrail and Okta records into an Event DataFrame sorted by timestamp."""
    rows: list[dict] = []
    skipped = 0

    for idx, rec in enumerate(ct, start=1):
        evt = normalize_cloudtrail(rec, idx)
        if evt is None:
            skipped += 1
        else:
            d = evt.model_dump()
            # Ensure source and category are standard strings for DataFrame operations
            d["source"] = evt.source.value
            d["category"] = evt.category.value
            rows.append(d)

    for idx, rec in enumerate(okta, start=1):
        evt = normalize_okta(rec, idx)
        if evt is None:
            skipped += 1
        else:
            d = evt.model_dump()
            d["source"] = evt.source.value
            d["category"] = evt.category.value
            rows.append(d)

    if not rows:
        empty_df = pd.DataFrame(columns=EVENT_FIELDS)
        return empty_df, skipped

    df = pd.DataFrame(rows)
    # Ensure exact model field order
    df = df[EVENT_FIELDS]
    # Sort chronologically and reset index
    df = df.sort_values(by="timestamp").reset_index(drop=True)

    return df, skipped
