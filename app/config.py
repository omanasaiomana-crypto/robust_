from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
RAW_CLOUDTRAIL = DATA_DIR / "raw" / "cloudtrail"
RAW_OKTA = DATA_DIR / "raw" / "okta"
METADATA_DIR = DATA_DIR / "metadata"
LABELS_DIR = DATA_DIR / "labels"
SAMPLE_DIR = DATA_DIR / "sample"
DB_PATH = DATA_DIR / "identityshield.db"
STATIC_DIR = ROOT / "static"

USE_SAMPLE_IF_NO_DATA = True
SIMULATOR_MODE = "mock"            # "mock" or "supplied"

# Detection thresholds
IMPOSSIBLE_TRAVEL_KMH = 900.0
DORMANT_DAYS = 30
ESCALATION_WINDOW_HOURS = 6
API_RARITY_THRESHOLD = 0.98
PEER_RARITY_THRESHOLD = 0.95

# Scoring
PRIVILEGE_MULTIPLIER = {1: 1.0, 2: 1.0, 3: 1.3, 4: 1.6, 5: 2.0}
SENSITIVITY_MULTIPLIER = {1: 1.0, 2: 1.0, 3: 1.2, 4: 1.35, 5: 1.5}
SIGNAL_WEIGHTS = {"P1": 25.0, "P2": 20.0, "P3": 35.0, "P4": 15.0, "P5": 30.0, "ML": 20.0}
COMBO_BONUS_PER_PATTERN = 0.25
RISK_HALF_LIFE_HOURS = 6.0

# Response bands
BAND_STEP_UP = 40
BAND_RESTRICT = 70
BAND_REVOKE = 90
FRICTION_BUDGET_PER_DAY = 2
REQUIRE_APPROVAL_FOR_REVOKE = True

# Feedback
FEEDBACK_LEARNING_RATE = 0.1
WEIGHT_MIN, WEIGHT_MAX = 5.0, 60.0

# Sensitive resources and actions
SENSITIVE_ACTIONS = {
    "StopLogging", "DeleteTrail", "PutBucketPolicy", "GetSecretValue",
    "CreateAccessKey", "AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy",
    "UpdateAssumeRolePolicy", "CreateLoginProfile", "UpdateLoginProfile",
}

PATTERN_NAMES = {
    "P1": "Impossible travel",
    "P2": "Dormant account",
    "P3": "Privilege escalation",
    "P4": "Unusual API",
    "P5": "Token abuse",
    "ML": "Behavior anomaly",
}
MITRE_BY_PATTERN = {
    "P1": ["T1078"],
    "P2": ["T1078.004"],
    "P3": ["T1098", "T1548"],
    "P4": ["T1526", "T1562"],
    "P5": ["T1550", "T1539"],
    "ML": [],
}

# Session correlation & clustering
SESSION_LINK_WINDOW_HOURS = 12
CLOUDTRAIL_SESSION_GAP_HOURS = 1

# Additional detection & scoring thresholds
IMPOSSIBLE_TRAVEL_MAX_SPEED_KMH = 3000.0
DORMANT_PRIVILEGE_THRESHOLD = 4
DORMANT_HIGH_SEVERITY = 0.9
DORMANT_LOW_SEVERITY = 0.6
ESCALATION_BASE_SEVERITY = 0.4
ESCALATION_STEP_SEVERITY = 0.15
API_MIN_EVENTS_BASELINE = 5
API_ANOMALY_BASE_SEV = 0.5
API_ANOMALY_SENSITIVE_BOOST = 0.3
API_ANOMALY_REGION_BOOST = 0.2
TOKEN_CONCURRENT_WINDOW_MINUTES = 5
TOKEN_CRITICAL_SEVERITY = 0.9
TOKEN_MODERATE_SEVERITY = 0.6
ML_MIN_TRAIN_SESSIONS = 20
ML_ANOMALY_THRESHOLD = 0.6
GRAPH_ESCALATION_CUTOFF = 6
GRAPH_MAX_ESCALATION_PATHS = 20
BLAST_RADIUS_MIN_SENSITIVITY = 4
GRAPH_NEIGHBORHOOD_CUTOFF = 3
GRAPH_MAX_SUBGRAPH_NODES = 150
CONFIDENCE_EVENTS_SATURATION = 10.0
MAX_EVIDENCE_EVENTS = 5

# ---------------------------------------------------------------------------
# v2 additions (append-only block: analytics, email alerts, background runs)
# ---------------------------------------------------------------------------
import os


def _load_dotenv(path: Path) -> None:
    """Minimal .env reader (no extra dependency). Existing environment variables win."""
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


_load_dotenv(ROOT / ".env")

# Analytics
DISPLAY_UTC_OFFSET_MINUTES = _env_int("DISPLAY_UTC_OFFSET_MINUTES", 330)   # IST; fixed offset, no tz database needed
HEATMAP_DAYS = 14
ANALYTICS_HYBRID_MIN_RISK = BAND_STEP_UP

# Email alerts
EMAIL_MODE = os.environ.get("EMAIL_MODE", "outbox").strip().lower()       # off | outbox | smtp
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = _env_int("SMTP_PORT", 587)
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SMTP_STARTTLS = _env_bool("SMTP_STARTTLS", True)
SMTP_SSL = _env_bool("SMTP_SSL", False)
SMTP_TIMEOUT_SECONDS = _env_int("SMTP_TIMEOUT_SECONDS", 10)
ALERT_EMAIL_FROM = os.environ.get("ALERT_EMAIL_FROM", "identityshield@localhost")
ALERT_EMAIL_TO = [a.strip() for a in os.environ.get("ALERT_EMAIL_TO", "").split(",") if a.strip()]
EMAIL_MIN_RISK = _env_int("EMAIL_MIN_RISK", BAND_RESTRICT)
EMAIL_MAX_PER_HOUR = _env_int("EMAIL_MAX_PER_HOUR", 10)
CONSOLE_BASE_URL = os.environ.get("CONSOLE_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
OUTBOX_DIR = DATA_DIR / "outbox"

# Export settings (Phase 21)
EXPORT_MIN_RISK = BAND_STEP_UP
OUTPUT_DIR = DATA_DIR / "output"

# ---------------------------------------------------------------------------
# v2.1 additions (append-only block: agent trace, threat audit, data input)
# ---------------------------------------------------------------------------
TRACE_MAX_EVENTS = 5000                    # in-memory ring buffer of scan trace events
TRACE_MAX_DATA_CHARS = 20000               # larger JSON payloads are truncated with a preview
THREAT_AUDIT_MIN_RISK = BAND_STEP_UP       # every alert at/above this risk gets its own audit entry
INPUT_DIR = DATA_DIR / "input"             # data/input/cloudtrail, data/input/okta
INPUT_MAX_BYTES = _env_int("INPUT_MAX_BYTES", 5_000_000)
INPUT_MAX_RECORDS = _env_int("INPUT_MAX_RECORDS", 50_000)

