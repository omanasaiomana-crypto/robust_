import logging
import math
from datetime import datetime, timezone
from typing import Any

from app.config import BAND_RESTRICT, BAND_REVOKE, BAND_STEP_UP

log = logging.getLogger(__name__)


def dig(obj: Any, path: str, default: Any = None) -> Any:
    """Safely read nested keys: dig(evt, 'client.ipAddress')."""
    cur = obj
    for key in path.split("."):
        if isinstance(cur, dict) and key in cur:
            cur = cur[key]
        else:
            return default
    return default if cur is None else cur


def parse_ts(value: Any) -> datetime | None:
    """Parse ISO-8601 strings (Z or offset) or epoch seconds to timezone-aware UTC."""
    if value is None or value == "":
        return None
    try:
        if isinstance(value, datetime):
            dt = value
        elif isinstance(value, (int, float)):
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        else:
            text = str(value).strip().replace("Z", "+00:00")
            dt = datetime.fromisoformat(text)
        return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (ValueError, OSError, OverflowError, TypeError):
        log.warning("Bad timestamp skipped: %r", value)
        return None


def safe_div(a: float, b: float, default: float = 0.0) -> float:
    return a / b if b else default


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = p2 - p1
    dl = math.radians(lon2 - lon1)
    h = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(min(1.0, h)))


def clean_json(value: Any) -> Any:
    """Recursively make a value JSON-safe: NaN/inf -> None, numpy scalars -> Python, datetimes -> ISO."""
    if isinstance(value, dict):
        return {str(k): clean_json(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [clean_json(v) for v in value]
    if hasattr(value, "model_dump"):
        return clean_json(value.model_dump(mode="json"))
    if hasattr(value, "item") and callable(value.item):
        try:
            value = value.item()
        except (ValueError, TypeError):
            pass
    if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def to_band(risk: float) -> str:
    if risk < BAND_STEP_UP:
        return "monitor"
    if risk < BAND_RESTRICT:
        return "step_up"
    if risk < BAND_REVOKE:
        return "restrict"
    return "revoke"
