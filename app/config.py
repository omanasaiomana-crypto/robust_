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
