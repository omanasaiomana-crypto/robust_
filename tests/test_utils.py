"""Unit tests for utility functions in app/utils.py."""
import math
from datetime import datetime, timezone
import numpy as np

from app.utils import clean_json, dig, haversine_km, parse_ts, safe_div, to_band


def test_dig():
    data = {"user": {"details": {"name": "Alice", "age": 30}, "tags": ["admin"]}}
    assert dig(data, "user.details.name") == "Alice"
    assert dig(data, "user.details.age") == 30
    assert dig(data, "user.details.missing", "default") == "default"
    assert dig(data, "nonexistent.key", None) is None
    assert dig(None, "any.path", "fallback") == "fallback"
    assert dig({"a": None}, "a.b", "default") == "default"


def test_parse_ts():
    # ISO-8601 with Z
    dt_z = parse_ts("2026-10-28T09:00:00Z")
    assert dt_z is not None
    assert dt_z.tzinfo == timezone.utc
    assert dt_z.hour == 9

    # ISO-8601 with offset (+05:30)
    dt_offset = parse_ts("2026-10-28T14:30:00+05:30")
    assert dt_offset is not None
    assert dt_offset.tzinfo == timezone.utc
    assert dt_offset.hour == 9  # 14:30 - 5:30 = 09:00 UTC

    # Epoch timestamp (int and float)
    epoch = 1761642000
    dt_epoch = parse_ts(epoch)
    assert dt_epoch is not None
    assert dt_epoch.tzinfo == timezone.utc

    # Already datetime
    now_utc = datetime.now(timezone.utc)
    assert parse_ts(now_utc) == now_utc

    # Invalid and empty inputs
    assert parse_ts(None) is None
    assert parse_ts("") is None
    assert parse_ts("not-a-timestamp") is None


def test_haversine_km():
    # Same point
    assert haversine_km(12.9716, 77.5946, 12.9716, 77.5946) == 0.0

    # Known distance: London (51.5074, -0.1278) to Paris (48.8566, 2.3522) ~ 343 km
    dist = haversine_km(51.5074, -0.1278, 48.8566, 2.3522)
    assert 330.0 < dist < 360.0

    # Bengaluru to Frankfurt ~ 7,400 km
    blr_fra = haversine_km(12.9716, 77.5946, 50.1109, 8.6821)
    assert 7200.0 < blr_fra < 7600.0


def test_clean_json():
    # NaN and Inf handling
    raw = {
        "nan_val": float("nan"),
        "inf_val": float("inf"),
        "neg_inf": float("-inf"),
        "num": np.int64(42),
        "float_np": np.float64(3.14159),
        "dt": datetime(2026, 10, 28, 12, 0, 0, tzinfo=timezone.utc),
        "nested": [float("nan"), np.int32(10), "text"],
    }
    cleaned = clean_json(raw)
    assert cleaned["nan_val"] is None
    assert cleaned["inf_val"] is None
    assert cleaned["neg_inf"] is None
    assert cleaned["num"] == 42
    assert isinstance(cleaned["num"], int)
    assert math.isclose(cleaned["float_np"], 3.14159, rel_tol=1e-4)
    assert isinstance(cleaned["float_np"], float)
    assert cleaned["dt"] == "2026-10-28T12:00:00+00:00"
    assert cleaned["nested"] == [None, 10, "text"]


def test_safe_div():
    assert safe_div(10.0, 2.0) == 5.0
    assert safe_div(10.0, 0.0, default=99.0) == 99.0


def test_to_band():
    assert to_band(0.0) == "monitor"
    assert to_band(39.9) == "monitor"
    assert to_band(40.0) == "step_up"
    assert to_band(69.9) == "step_up"
    assert to_band(70.0) == "restrict"
    assert to_band(89.9) == "restrict"
    assert to_band(90.0) == "revoke"
    assert to_band(100.0) == "revoke"
