"""Configuration for the 30-day memory. Every value can be overridden with an environment variable MEM30_<NAME>."""
from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT / "data"


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(f"MEM30_{name}")
    try:
        return int(raw) if raw not in (None, "") else default
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(f"MEM30_{name}")
    try:
        return float(raw) if raw not in (None, "") else default
    except ValueError:
        return default


DB_PATH = Path(os.environ.get("MEM30_DB_PATH") or (DATA_DIR / "memory30.sqlite"))

# Tiered retention
RAW_EVENT_RETENTION_DAYS = _env_int("RAW_EVENT_RETENTION_DAYS", 7)     # raw events (non-evidence)
MEMORY_RETENTION_DAYS = _env_int("MEMORY_RETENTION_DAYS", 30)          # daily summaries, hits, networks

# Chain linking
CHAIN_MAX_GAP_DAYS = _env_int("CHAIN_MAX_GAP_DAYS", 14)                # max gap between two linked steps
CHAIN_MAX_SPAN_DAYS = _env_int("CHAIN_MAX_SPAN_DAYS", 30)              # max length of one chain
FINDING_MIN_STAGES = _env_int("FINDING_MIN_STAGES", 3)                 # distinct kill-chain stages for a finding
FINDING_MIN_RISK = _env_float("FINDING_MIN_RISK", 70.0)                # or a risk at least this high
SINGLE_STEP_MIN_SEVERITY = _env_float("SINGLE_STEP_MIN_SEVERITY", 0.8)  # one step alone must be critical
SHARED_TARGET_MIN_WRITERS = _env_int("SHARED_TARGET_MIN_WRITERS", 3)   # team resource if >= N other writers
CHAIN_STEP_BONUS = 0.15
CHAIN_FACTOR_CAP = 1.6

# Baselines
MIN_HISTORY_DAYS = _env_int("MIN_HISTORY_DAYS", 3)                     # before "new network" can fire
DISCOVERY_DAILY_MIN = _env_int("DISCOVERY_DAILY_MIN", 5)               # discovery calls per day
DISCOVERY_SERVICES_MIN = _env_int("DISCOVERY_SERVICES_MIN", 3)         # distinct services per day
STAIRCASE_WEEKS = 3                                                    # consecutive week-over-week increases
STAIRCASE_GROWTH = _env_float("STAIRCASE_GROWTH", 0.4)                 # +40 % per week
STAIRCASE_MIN_LAST_WEEK = _env_int("STAIRCASE_MIN_LAST_WEEK", 20)      # ignore tiny volumes
PEER_PERCENTILE = 0.9
PEER_MIN_IDENTITIES = 5

# Identity risk decay
HALF_LIFE_HOURS = _env_float("HALF_LIFE_HOURS", 24.0)

SENSITIVE_MARKERS = tuple(
    m.strip().lower()
    for m in os.environ.get(
        "MEM30_SENSITIVE_MARKERS",
        "prod,finance,secret,pii,payroll,kms,signing,customer,ledger,wallet",
    ).split(",")
    if m.strip()
)

RAW_MAX_CHARS = 4000            # raw JSON kept per event (truncated)
EVIDENCE_MAX_IDS = 60           # evidence ids kept per finding
HIT_MAX_IDS = 10                # event ids kept per hit

DEFAULT_SOURCES = [DATA_DIR / "raw" / "okta", DATA_DIR / "raw" / "cloudtrail", DATA_DIR / "input"]
SYNTH_DIR = DATA_DIR / "synth"


def analyst_token() -> str:
    """Read at call time so tests and .env changes apply without restart."""
    return os.environ.get("ANALYST_TOKEN", "")
