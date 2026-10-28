"""Admin email alerts.

Modes (config.EMAIL_MODE):
  off    -> nothing is sent or written
  outbox -> email is written to data/outbox/ (.eml + .txt) and shown in the console (default; works offline)
  smtp   -> email is sent through SMTP; on failure it is still written to the outbox

Guarantees: never raises to the caller, never blocks the pipeline (async by default),
one email per new alert fingerprint, rate-limited, every attempt is audited.
"""
import html
import json
import logging
import re
import smtplib
import ssl
import threading
import uuid
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

from app import audit, config, store
from app.models import Alert

log = logging.getLogger(__name__)

_send_lock = threading.Lock()
_EMAIL_RE = re.compile(r"^[^@\s,;<>]+@[^@\s,;<>]+\.[^@\s,;<>]+$")
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")

ACTION_TEXT = {"monitor": "Monitor", "step_up": "Step-up MFA", "restrict": "Restrict access",
               "revoke": "Revoke session (needs analyst approval)", "dismiss": "Dismissed"}

SCHEMA = """
CREATE TABLE IF NOT EXISTS notifications (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    kind TEXT NOT NULL,
    subject TEXT NOT NULL,
    recipients TEXT NOT NULL,
    alert_ids TEXT NOT NULL,
    fingerprints TEXT NOT NULL,
    mode TEXT NOT NULL,
    status TEXT NOT NULL,
    detail TEXT NOT NULL,
    body_text TEXT NOT NULL
);
"""


def init_tables() -> None:
    with store._lock:
        store.conn().executescript(SCHEMA)
        store.conn().commit()


def clean_header(value: object, limit: int = 180) -> str:
    """Remove CR/LF/control characters so log-controlled text cannot inject email headers."""
    text = _CTRL_RE.sub(" ", str(value if value is not None else ""))
    return re.sub(r"\s+", " ", text).strip()[:limit]


def valid_recipients() -> list[str]:
    return [a for a in config.ALERT_EMAIL_TO if _EMAIL_RE.match(a)]


def fingerprint(alert: Alert) -> str:
    return f"{alert.identity_id}|{alert.session_id or '-'}|{alert.band}"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _already_notified(fps: list[str]) -> set[str]:
    done: set[str] = set()
    for r in store.execute("SELECT fingerprints FROM notifications WHERE status IN ('sent', 'outbox')"):
        try:
            done.update(json.loads(r["fingerprints"]))
        except (ValueError, TypeError):
            continue
    return done & set(fps)


def _sent_last_hour() -> int:
    since = (_now() - timedelta(hours=1)).isoformat()
    rows = store.execute(
        "SELECT COUNT(*) AS n FROM notifications WHERE created_at >= ? AND status IN ('sent', 'outbox')",
        (since,))
    return int(rows[0]["n"]) if rows else 0


def _pattern_text(codes: list[str]) -> str:
    return ", ".join(config.PATTERN_NAMES.get(c, c) for c in codes) or "-"


def build_digest(alerts: list[Alert], total_open: int | None = None) -> tuple[EmailMessage, str]:
    """Return (message, plain-text body). All dynamic text is sanitized/escaped."""
    alerts = sorted(alerts, key=lambda a: a.risk, reverse=True)
    top = alerts[0]
    critical = sum(1 for a in alerts if a.band == "revoke")
    level = "CRITICAL" if critical else "HIGH"
    subject = clean_header(
        f"[IdentityShield] {level}: {len(alerts)} identit{'y' if len(alerts) == 1 else 'ies'} need attention"
        f" - {top.identity_id} (risk {top.risk:.0f})")

    lines = [
        "IdentityShield detected suspicious identity activity.",
        "",
        f"New high-risk alerts: {len(alerts)}  (critical: {critical})",
    ]
    if total_open is not None:
        lines.append(f"Open alerts in console: {total_open}")
    lines.append("")
    for a in alerts[:5]:
        lines += [
            f"- {clean_header(a.identity_id, 60)} | risk {a.risk:.0f} ({a.band}) | {_pattern_text(a.patterns)}",
            f"  Why: {clean_header(a.reasons[0] if a.reasons else 'See console', 220)}",
            f"  Recommended: {ACTION_TEXT.get(a.recommended_action, a.recommended_action)}",
            f"  Open: {config.CONSOLE_BASE_URL}/alert.html?id={clean_header(a.alert_id, 40)}",
            "",
        ]
    if len(alerts) > 5:
        lines.append(f"...and {len(alerts) - 5} more in the console: {config.CONSOLE_BASE_URL}/alerts.html")
        lines.append("")
    lines += [
        "No session was revoked automatically. Revocation always requires analyst approval.",
        "This is an automated message from IdentityShield.",
    ]
    text = "\n".join(lines)

    rows_html = "".join(
        "<tr>"
        f"<td style='padding:6px 10px;border-bottom:1px solid #e5e7eb'>{html.escape(a.identity_id)}</td>"
        f"<td style='padding:6px 10px;border-bottom:1px solid #e5e7eb;text-align:right'><b>{a.risk:.0f}</b></td>"
        f"<td style='padding:6px 10px;border-bottom:1px solid #e5e7eb'>{html.escape(a.band)}</td>"
        f"<td style='padding:6px 10px;border-bottom:1px solid #e5e7eb'>{html.escape(_pattern_text(a.patterns))}</td>"
        f"<td style='padding:6px 10px;border-bottom:1px solid #e5e7eb'>"
        f"{html.escape(ACTION_TEXT.get(a.recommended_action, a.recommended_action))}</td>"
        f"<td style='padding:6px 10px;border-bottom:1px solid #e5e7eb'>"
        f"<a href='{html.escape(config.CONSOLE_BASE_URL)}/alert.html?id={html.escape(a.alert_id)}'>Open</a></td>"
        "</tr>"
        for a in alerts[:5])
    html_body = (
        "<div style='font-family:Arial,sans-serif;color:#111827'>"
        f"<h2 style='margin:0 0 8px'>{html.escape(level)}: suspicious identity activity</h2>"
        f"<p>{len(alerts)} new high-risk alert(s), {critical} critical.</p>"
        "<table style='border-collapse:collapse;font-size:14px'>"
        "<tr><th align='left'>Identity</th><th>Risk</th><th align='left'>Band</th>"
        "<th align='left'>Patterns</th><th align='left'>Recommended</th><th></th></tr>"
        f"{rows_html}</table>"
        f"<p><b>Top reason:</b> {html.escape(top.reasons[0] if top.reasons else 'See console')}</p>"
        "<p style='color:#6b7280;font-size:12px'>No session was revoked automatically. "
        "Revocation always requires analyst approval.</p></div>")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = clean_header(config.ALERT_EMAIL_FROM)
    msg["To"] = ", ".join(valid_recipients()) or "admin@localhost"
    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = make_msgid(domain="identityshield.local")
    msg.set_content(text)
    msg.add_alternative(html_body, subtype="html")
    return msg, text


def _smtp_send(msg: EmailMessage) -> None:
    ctx = ssl.create_default_context()
    if config.SMTP_SSL:
        with smtplib.SMTP_SSL(config.SMTP_HOST, config.SMTP_PORT, timeout=config.SMTP_TIMEOUT_SECONDS,
                              context=ctx) as s:
            if config.SMTP_USER:
                s.login(config.SMTP_USER, config.SMTP_PASSWORD)
            s.send_message(msg)
        return
    with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=config.SMTP_TIMEOUT_SECONDS) as s:
        s.ehlo()
        if config.SMTP_STARTTLS:
            s.starttls(context=ctx)
            s.ehlo()
        if config.SMTP_USER:
            s.login(config.SMTP_USER, config.SMTP_PASSWORD)
        s.send_message(msg)


def _write_outbox(nid: str, msg: EmailMessage, text: str) -> None:
    config.OUTBOX_DIR.mkdir(parents=True, exist_ok=True)
    (config.OUTBOX_DIR / f"{nid}.eml").write_bytes(bytes(msg))
    (config.OUTBOX_DIR / f"{nid}.txt").write_text(text, encoding="utf-8")


def _record(nid: str, kind: str, msg: EmailMessage, alert_ids: list[str], fps: list[str],
            status: str, detail: str, text: str) -> dict:
    row = {"id": nid, "created_at": _now().isoformat(), "kind": kind, "subject": str(msg["Subject"]),
           "recipients": str(msg["To"]), "alert_ids": alert_ids, "fingerprints": fps,
           "mode": config.EMAIL_MODE, "status": status, "detail": detail[:300], "body_text": text}
    store.execute(
        "INSERT INTO notifications (id, created_at, kind, subject, recipients, alert_ids, fingerprints, mode, "
        "status, detail, body_text) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (nid, row["created_at"], kind, row["subject"], row["recipients"], json.dumps(alert_ids),
         json.dumps(fps), row["mode"], status, row["detail"], text))
    audit.append("notifier", f"email_{status}", f"{kind}: {row['subject']} -> {row['recipients']}")
    return row


def deliver(msg: EmailMessage, text: str, kind: str, alert_ids: list[str], fps: list[str]) -> dict | None:
    """Send or store one message according to EMAIL_MODE. Returns the notification record."""
    if config.EMAIL_MODE == "off":
        return None
    nid = uuid.uuid4().hex[:12]
    try:
        if _sent_last_hour() >= config.EMAIL_MAX_PER_HOUR:
            return _record(nid, kind, msg, alert_ids, fps, "rate_limited",
                           f"More than {config.EMAIL_MAX_PER_HOUR} emails in the last hour", text)
        _write_outbox(nid, msg, text)
        if config.EMAIL_MODE != "smtp":
            return _record(nid, kind, msg, alert_ids, fps, "outbox", f"Saved to {config.OUTBOX_DIR.name}/", text)
        if not config.SMTP_HOST or not valid_recipients():
            return _record(nid, kind, msg, alert_ids, fps, "failed",
                           "SMTP_HOST or ALERT_EMAIL_TO not configured; saved to outbox", text)
        _smtp_send(msg)
        return _record(nid, kind, msg, alert_ids, fps, "sent", f"Sent via {config.SMTP_HOST}", text)
    except (smtplib.SMTPException, OSError, ssl.SSLError) as exc:
        log.warning("Email delivery failed: %s", exc)
        return _record(nid, kind, msg, alert_ids, fps, "failed",
                       f"{type(exc).__name__}: {exc}; saved to outbox", text)
    except Exception as exc:  # noqa: BLE001 - notifications must never crash the caller
        log.exception("Unexpected notifier error")
        try:
            return _record(nid, kind, msg, alert_ids, fps, "failed", f"{type(exc).__name__}", text)
        except Exception:  # noqa: BLE001
            return None


def notify_new_alerts(alerts: list[Alert], total_open: int | None = None, async_: bool = True) -> None:
    """Send ONE digest for alerts at/above EMAIL_MIN_RISK that were not emailed before."""
    def _job() -> None:
        try:
            with _send_lock:
                candidates = [a for a in alerts or [] if a.risk >= config.EMAIL_MIN_RISK]
                if not candidates:
                    return
                fps = [fingerprint(a) for a in candidates]
                done = _already_notified(fps)
                fresh = [a for a, fp in zip(candidates, fps) if fp not in done]
                if not fresh:
                    return
                msg, text = build_digest(fresh, total_open)
                deliver(msg, text, "digest", [a.alert_id for a in fresh], [fingerprint(a) for a in fresh])
        except Exception:  # noqa: BLE001
            log.exception("notify_new_alerts failed")

    if config.EMAIL_MODE == "off":
        return
    if async_:
        threading.Thread(target=_job, name="notifier", daemon=True).start()
    else:
        _job()


def notify_alert(alert: Alert) -> dict | None:
    """Manual 'Email admin' for one alert. Not deduplicated (the analyst asked for it)."""
    msg, text = build_digest([alert])
    with _send_lock:
        return deliver(msg, text, "manual", [alert.alert_id], [])


def send_test() -> dict | None:
    msg = EmailMessage()
    msg["Subject"] = "[IdentityShield] Test email"
    msg["From"] = clean_header(config.ALERT_EMAIL_FROM)
    msg["To"] = ", ".join(valid_recipients()) or "admin@localhost"
    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = make_msgid(domain="identityshield.local")
    text = "This is a test email from IdentityShield. Email alerts are configured correctly."
    msg.set_content(text)
    with _send_lock:
        return deliver(msg, text, "test", [], [])


def list_notifications(limit: int = 50) -> list[dict]:
    limit = max(1, min(int(limit), 500))
    out = []
    for r in store.execute("SELECT * FROM notifications ORDER BY created_at DESC LIMIT ?", (limit,)):
        out.append({"id": r["id"], "created_at": r["created_at"], "kind": r["kind"], "subject": r["subject"],
                    "recipients": r["recipients"], "alert_ids": json.loads(r["alert_ids"] or "[]"),
                    "mode": r["mode"], "status": r["status"], "detail": r["detail"], "body_text": r["body_text"]})
    return out


def status() -> dict:
    recipients = valid_recipients()
    return {"mode": config.EMAIL_MODE, "recipients": recipients,
            "recipients_configured": bool(recipients), "smtp_host": config.SMTP_HOST or None,
            "min_risk": config.EMAIL_MIN_RISK, "max_per_hour": config.EMAIL_MAX_PER_HOUR,
            "sent_last_hour": _sent_last_hour()}
