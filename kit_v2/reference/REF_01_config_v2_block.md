# Config v2 block

**Target file:** `app/config.py (APPEND to the end; do not change existing lines)`

Adds .env loading (no extra dependency), analytics settings and email settings. Existing constants are untouched.

**Status:** written and tested before shipping this kit (all 23 Python reference tests pass).
Copy the code block EXACTLY. Do not rename functions; other phases call them by these names.

```python
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
```
