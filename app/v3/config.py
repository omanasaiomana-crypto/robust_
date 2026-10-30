"""IdentityShield v3 configuration module.

All thresholds and defaults are typed constants matching context.md Section 12.
Secrets are read from environment / .env and never leaked in repr.
"""
import os
from dataclasses import dataclass
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent

# --- Defaults from context.md Section 12 ---
V3_ENABLED: bool = True
SEED: int = 42
QUEUE_MAX: int = 10000
WATERMARK_SECONDS: int = 120
SESSION_IDLE_MINUTES: int = 15
GRAPH_RETENTION_DAYS: int = 30
GRAPH_MAX_NODES: int = 50000
MAX_SPEED_KMH: float = 900.0
MIN_DISTANCE_KM: float = 500.0
MIN_HISTORY_LOGINS: int = 5
MFA_FATIGUE_DENIES: int = 5
MFA_WINDOW_MINUTES: int = 10
DORMANT_DAYS: int = 30
NEW_KEY_WINDOW_MINUTES: int = 60
PRIVESC_MAX_STEP_GAP_HOURS: int = 168
SPRAY_MIN_USERS: int = 10
SPRAY_WINDOW_MINUTES: int = 10
SHARED_INFRA_MIN_IDENTITIES: int = 3
MASS_DELETE_COUNT: int = 50
MASS_DELETE_WINDOW_MIN: int = 5
SECRET_HARVEST_COUNT: int = 5
SECRET_HARVEST_WINDOW_MIN: int = 10
ML_CONTAMINATION: float = 0.02
PRIVILEGE_MULT: list[float] = [0.8, 1.0, 1.15, 1.3, 1.5]
SENSITIVITY_MULT: list[float] = [0.9, 1.0, 1.1, 1.25, 1.4]
ACTION_MULT: dict[str, float] = {
    "read": 1.0,
    "write": 1.1,
    "permission_change": 1.25,
    "credential_change": 1.25,
    "destructive": 1.4,
    "defense_evasion": 1.4,
}
CHAIN_STEP: float = 0.15
CHAIN_CAP: float = 1.6
IDENTITY_HALF_LIFE_HOURS: float = 24.0

# Risk bands
BAND_STEP_UP: float = 40.0
BAND_RESTRICT: float = 70.0
BAND_REVOKE: float = 90.0
BANDS: tuple[float, float, float] = (40.0, 70.0, 90.0)

# Friction budget and timeouts
FRICTION_UNITS: int = 2
FRICTION_WINDOW_HOURS: int = 8
APPROVAL_TIMEOUT_MINUTES: int = 30
RESTRICT_TTL_MINUTES: int = 240
WARM_TICK_SECONDS: float = 30.0
DRY_RUN: bool = False


# Investigation bounds
INVESTIGATION_MAX_DEPTH: int = 2
INVESTIGATION_MAX_ENTITIES: int = 50
INVESTIGATION_TIMEOUT_SECONDS: float = 2.0
NEXT_STEP_MIN_PROB: float = 0.3

# Feedback learning
LEARNING_RATE: float = 0.05
WEIGHT_FLOORS: dict[str, float] = {"D-PE": 0.6, "D-DEF": 0.6}

# Ingest service
INGEST_PORT: int = 8001
INGEST_MAX_BODY_BYTES: int = 1048576  # 1 MB
INGEST_MAX_EVENTS: int = 500
INGEST_RATE_RPS: int = 20
INGEST_RATE_EVENTS_PER_MIN: int = 2000
INGEST_SKEW_SECONDS: int = 60
INGEST_NONCE_TTL_SECONDS: int = 300

# Email & LLM & Enrichment defaults
EMAIL_MIN_BAND: str = "restrict"
LLM_ENABLED: bool = False
ENRICH_PROVIDERS: list[str] = []


def _parse_ingest_keys(val: str) -> dict[str, str]:
    """Parse format keyid:secret,keyid2:secret2 into dict."""
    keys: dict[str, str] = {}
    if not val:
        return keys
    for pair in val.split(","):
        pair = pair.strip()
        if not pair:
            continue
        if ":" in pair:
            kid, secret = pair.split(":", 1)
            kid = kid.strip()
            secret = secret.strip()
            if kid and secret:
                keys[kid] = secret
    return keys


def _parse_csv_list(val: str) -> list[str]:
    """Parse comma-separated values into stripped string list."""
    if not val:
        return []
    return [item.strip() for item in val.split(",") if item.strip()]


def _parse_bool(val: str | None, default: bool = False) -> bool:
    if val is None:
        return default
    v = str(val).strip().lower()
    return v in ("true", "1", "yes", "on")


def _read_env_file(path: Path) -> dict[str, str]:
    """Read a .env file without external dependencies."""
    env: dict[str, str] = {}
    if not path.is_file():
        return env
    try:
        content = path.read_text(encoding="utf-8")
    except OSError:
        return env
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, val = line.split("=", 1)
            key = key.strip()
            val = val.strip()
            if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                val = val[1:-1]
            env[key] = val
    return env


@dataclass(frozen=True)
class Settings:
    """Frozen dataclass containing runtime configuration and loaded settings.

    Secrets are masked in __repr__ to prevent accidental leaks.
    """

    # Core & v3 flags
    v3_enabled: bool
    analyst_token: str
    dry_run: bool
    console_base_url: str

    # Ingest keys (dict of key_id -> secret)
    ingest_keys: dict[str, str]
    ingest_allowed_origins: list[str]

    # Enrichment
    enrich_providers: list[str]
    ipinfo_token: str
    abuseipdb_key: str
    greynoise_key: str
    otx_key: str
    vt_key: str
    maxmind_license_key: str

    # LLM
    llm_enabled: bool
    llm_provider: str
    gemini_api_key: str
    groq_api_key: str
    ollama_url: str
    openrouter_api_key: str

    # Email
    email_mode: str
    admin_email: str
    alert_email_to: list[str]
    alert_email_from: str
    email_min_risk: float
    email_max_per_hour: int

    # SMTP
    smtp_host: str
    smtp_port: int
    smtp_user: str
    smtp_password: str
    smtp_starttls: bool
    smtp_ssl: bool
    smtp_timeout_seconds: int

    # ngrok
    ngrok_authtoken: str

    def __repr__(self) -> str:
        """Mask all sensitive secrets."""
        masked_keys = {k: "***" for k in self.ingest_keys}
        return (
            f"Settings("
            f"v3_enabled={self.v3_enabled}, "
            f"analyst_token={'***' if self.analyst_token else ''!r}, "
            f"dry_run={self.dry_run}, "
            f"console_base_url={self.console_base_url!r}, "
            f"ingest_keys={masked_keys}, "
            f"ingest_allowed_origins={self.ingest_allowed_origins}, "
            f"enrich_providers={self.enrich_providers}, "
            f"ipinfo_token={'***' if self.ipinfo_token else ''!r}, "
            f"abuseipdb_key={'***' if self.abuseipdb_key else ''!r}, "
            f"greynoise_key={'***' if self.greynoise_key else ''!r}, "
            f"otx_key={'***' if self.otx_key else ''!r}, "
            f"vt_key={'***' if self.vt_key else ''!r}, "
            f"maxmind_license_key={'***' if self.maxmind_license_key else ''!r}, "
            f"llm_enabled={self.llm_enabled}, "
            f"llm_provider={self.llm_provider!r}, "
            f"gemini_api_key={'***' if self.gemini_api_key else ''!r}, "
            f"groq_api_key={'***' if self.groq_api_key else ''!r}, "
            f"ollama_url={self.ollama_url!r}, "
            f"openrouter_api_key={'***' if self.openrouter_api_key else ''!r}, "
            f"email_mode={self.email_mode!r}, "
            f"admin_email={self.admin_email!r}, "
            f"alert_email_to={self.alert_email_to}, "
            f"alert_email_from={self.alert_email_from!r}, "
            f"email_min_risk={self.email_min_risk}, "
            f"email_max_per_hour={self.email_max_per_hour}, "
            f"smtp_host={self.smtp_host!r}, "
            f"smtp_port={self.smtp_port}, "
            f"smtp_user={self.smtp_user!r}, "
            f"smtp_password={'***' if self.smtp_password else ''!r}, "
            f"smtp_starttls={self.smtp_starttls}, "
            f"smtp_ssl={self.smtp_ssl}, "
            f"smtp_timeout_seconds={self.smtp_timeout_seconds}, "
            f"ngrok_authtoken={'***' if self.ngrok_authtoken else ''!r})"
        )


_settings_cache: Settings | None = None


def load_env(env_path: Path | str | None = None) -> Settings:
    """Read .env file and environment variables without printing them."""
    global _settings_cache
    target = Path(env_path) if env_path else (ROOT_DIR / ".env")
    file_vars = _read_env_file(target)

    def get_val(key: str, default: str = "") -> str:
        return os.environ.get(key, file_vars.get(key, default))

    settings = Settings(
        v3_enabled=_parse_bool(get_val("V3_ENABLED", "true"), default=True),
        analyst_token=get_val("ANALYST_TOKEN", ""),
        dry_run=_parse_bool(get_val("DRY_RUN", "false"), default=False),
        console_base_url=get_val("CONSOLE_BASE_URL", "http://127.0.0.1:8000"),
        ingest_keys=_parse_ingest_keys(get_val("INGEST_KEYS", "")),
        ingest_allowed_origins=[
            origin for origin in _parse_csv_list(get_val("INGEST_ALLOWED_ORIGINS", "null,http://localhost:5500"))
            if origin != "*"
        ],
        enrich_providers=_parse_csv_list(get_val("ENRICH_PROVIDERS", "")),
        ipinfo_token=get_val("IPINFO_TOKEN", ""),
        abuseipdb_key=get_val("ABUSEIPDB_KEY", ""),
        greynoise_key=get_val("GREYNOISE_KEY", ""),
        otx_key=get_val("OTX_KEY", ""),
        vt_key=get_val("VT_KEY", ""),
        maxmind_license_key=get_val("MAXMIND_LICENSE_KEY", ""),
        llm_enabled=_parse_bool(get_val("LLM_ENABLED", "false"), default=False),
        llm_provider=get_val("LLM_PROVIDER", ""),
        gemini_api_key=get_val("GEMINI_API_KEY", ""),
        groq_api_key=get_val("GROQ_API_KEY", ""),
        ollama_url=get_val("OLLAMA_URL", "http://127.0.0.1:11434"),
        openrouter_api_key=get_val("OPENROUTER_API_KEY", ""),
        email_mode=get_val("EMAIL_MODE", "outbox"),
        admin_email=get_val("ADMIN_EMAIL", ""),
        alert_email_to=_parse_csv_list(get_val("ALERT_EMAIL_TO", "")),
        alert_email_from=get_val("ALERT_EMAIL_FROM", "identityshield@yourcompany.com"),
        email_min_risk=float(get_val("EMAIL_MIN_RISK", "70")),
        email_max_per_hour=int(get_val("EMAIL_MAX_PER_HOUR", "10")),
        smtp_host=get_val("SMTP_HOST", ""),
        smtp_port=int(get_val("SMTP_PORT", "587")),
        smtp_user=get_val("SMTP_USER", ""),
        smtp_password=get_val("SMTP_PASSWORD", ""),
        smtp_starttls=_parse_bool(get_val("SMTP_STARTTLS", "true"), default=True),
        smtp_ssl=_parse_bool(get_val("SMTP_SSL", "false"), default=False),
        smtp_timeout_seconds=int(get_val("SMTP_TIMEOUT_SECONDS", "10")),
        ngrok_authtoken=get_val("NGROK_AUTHTOKEN", ""),
    )
    _settings_cache = settings
    return settings


def get_settings() -> Settings:
    """Return cached frozen Settings instance (loads from default environment if not cached)."""
    global _settings_cache
    if _settings_cache is None:
        _settings_cache = load_env()
    return _settings_cache
