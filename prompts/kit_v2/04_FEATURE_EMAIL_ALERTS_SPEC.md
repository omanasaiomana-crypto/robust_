# 04 · Feature spec: admin email alerts

## 1. What the user asked for

> "Once it detects an anomaly or suspicious behavior, it should email the company admin a brief summary of what is happening on the server."

## 2. Behavior

| Trigger | What is sent | Dedupe |
|---|---|---|
| **After every pipeline run** (startup and re-run) | **One digest email** covering all *new* alerts with risk ≥ `EMAIL_MIN_RISK` (default 70 = restrict band and above) | Yes. Fingerprint = `identity | session | band`; an alert already emailed is never emailed again. A higher band produces a new fingerprint, so an escalation is emailed again. |
| **"Email admin" button** on an alert | Email about that one alert | No (the analyst asked for it explicitly) |
| **"Send test email"** on the Notifications page | Test message | No |

**Why a digest:** 30 alerts must not produce 30 emails. Admins ignore noisy alerting (alert fatigue, the same idea as the friction budget).

**Rate limit:** at most `EMAIL_MAX_PER_HOUR` (default 10) delivered emails per hour. Extra emails are recorded as `rate_limited` and are not sent.

### 2.1 Delivery modes (`EMAIL_MODE`)

| Mode | Behavior | When to use |
|---|---|---|
| `outbox` (default) | Writes `.eml` + `.txt` to `data/outbox/`; the console shows them | Demo without internet, development, tests |
| `smtp` | Sends through SMTP and **also** writes the outbox copy. On any failure, status is `failed` and the copy stays in the outbox. | Real email to the admin |
| `off` | Nothing is sent or written | Disable completely |

**Never blocks, never crashes:** sending runs in a background thread with a 10-second SMTP timeout. Every exception is caught, recorded and logged, and the pipeline and API are unaffected.

**Every attempt is audited:** the notifier appends a `notifier` entry (`email_sent`, `email_outbox`, `email_failed` or `email_rate_limited`) to the hash-chained audit log.

## 3. Email content (brief summary)

**Subject:** `[IdentityShield] CRITICAL: 3 identities need attention - svc-report (risk 94)`
(CRITICAL if any alert is in the revoke band, else HIGH.)

**Body (plain text + simple HTML version):**

```text
IdentityShield detected suspicious identity activity.

New high-risk alerts: 3  (critical: 1)
Open alerts in console: 7

- svc-report | risk 94 (revoke) | Privilege escalation, Dormant account
  Why: Escalation chain: CreateAccessKey -> AttachUserPolicy -> AssumeRole within 11 min.
  Recommended: Revoke session (needs analyst approval)
  Open: http://127.0.0.1:8000/alert.html?id=AL-0001
...
No session was revoked automatically. Revocation always requires analyst approval.
This is an automated message from IdentityShield.
```

At most the top 5 alerts are listed in detail, followed by "...and N more" with a link to the console.

## 4. Security design (tell the judges)

| Threat | Control |
|---|---|
| **Email header injection**: an attacker sets an Okta username like `x\r\nBcc: attacker@evil.com` | `clean_header()` strips CR/LF/control characters from all header text (tested) |
| **HTML injection** in the HTML email body via log fields | `html.escape()` on every dynamic value (tested) |
| Leaking secrets | SMTP password only in `.env` (git-ignored) or environment variables; never logged or shown in the UI or API |
| Leaking sensitive data | The email has a summary only: no raw logs, IPs or tokens; details stay in the console |
| Email flooding | Digest + dedupe + hourly rate limit |
| Plain-text transport | STARTTLS by default (`SMTP_STARTTLS=true`) or implicit TLS (`SMTP_SSL=true`) with certificate verification (`ssl.create_default_context()`) |
| Notifier failure takes down detection | Background thread, catch-all, outbox fallback |

## 5. Configuration (`.env` at the project root; never commit it)

`.env.example` (commit this one):

```dotenv
# off | outbox | smtp
EMAIL_MODE=outbox
ALERT_EMAIL_TO=admin@yourcompany.com
ALERT_EMAIL_FROM=identityshield@yourcompany.com
EMAIL_MIN_RISK=70
EMAIL_MAX_PER_HOUR=10
CONSOLE_BASE_URL=http://127.0.0.1:8000

# SMTP (only used when EMAIL_MODE=smtp)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_STARTTLS=true
SMTP_SSL=false
SMTP_USER=your.address@gmail.com
SMTP_PASSWORD=your-16-character-app-password
SMTP_TIMEOUT_SECONDS=10
```

Add `.env` and `data/outbox/` to `.gitignore`.

### 5.1 Gmail quick setup (if you want real email in the demo)

1. Turn on 2-Step Verification for the sending Google account.
2. Create an **App Password** in the Google Account security settings (search "App passwords"). Use those 16 characters as `SMTP_PASSWORD`; your normal password will not work.
3. `SMTP_HOST=smtp.gmail.com`, `SMTP_PORT=587`, `SMTP_STARTTLS=true`, `SMTP_USER` = the Gmail address, `ALERT_EMAIL_FROM` = the same address.
4. Restart the server, open Notifications, and click **Send test email**.

Venue Wi-Fi often blocks SMTP ports. If the test fails with a timeout, use a phone hotspot or present in `outbox` mode; the console shows the exact email that would be sent.

## 6. Backend

**Files:**
- `app/notify.py`: copy exactly from `reference/REF_03_notify.md` (tested).
- Config: the v2 block in `reference/REF_01_config_v2_block.md` (appended in Phase 20).
- `app/api/notifications.py`: new router.

| Method | Path | Body | Response |
|---|---|---|---|
| GET | `/api/notifications` | `?limit=50` | `list[notification]` |
| GET | `/api/notifications/status` | none | `{mode, recipients, recipients_configured, smtp_host, min_risk, max_per_hour, sent_last_hour}` |
| POST | `/api/notifications/test` | none | notification record, or `{"status":"off"}` when `EMAIL_MODE=off` |
| POST | `/api/alerts/{id}/notify` | none | notification record (404 if the alert is unknown) |

A notification record has: `id, created_at, kind (digest|manual|test), subject, recipients, alert_ids, mode, status (sent|outbox|failed|rate_limited), detail, body_text`.

**Wiring:**
- In the `main.py` lifespan, call `notify.init_tables()` right after `store.init_db()`, and after the startup pipeline call `notify.notify_new_alerts(result.alerts, total_open=len(result.alerts))` (async).
- Do the same after `POST /api/pipeline/run`. (Phase 26 moves both into `app/runner.py`.)

## 7. Frontend

### 7.1 `notifications.html` + `static/js/notifications.js` (sidebar item "Notifications", envelope icon, after Audit)

| Block | Details |
|---|---|
| **Status card** | Mode pill (`outbox` = brand2 "Outbox (demo)", `smtp` = ok "SMTP", `off` = muted "Off"), recipients (or a warning "No recipients configured" in warn color), SMTP host, threshold "Emails for risk ≥ 70", "Sent this hour 1 / 10". Primary button **Send test email** → POST, then a toast with the resulting status and a refresh. |
| **History table** | Time, Kind chip (Digest/Manual/Test), Status badge (sent = ok, outbox = brand2, failed = crit, rate_limited = warn), Subject (truncated), Recipients, Alerts (links to `alert.html?id=`). Clicking a row expands a preview below it: `detail` in muted text and `body_text` in a `<pre class="whitespace-pre-wrap font-mono text-xs">` inserted with `esc()`. Never render email HTML. |
| **Help note** | One line: "Configure email in `.env` (see `.env.example`). Outbox mode works offline." |

States: skeleton, empty ("No emails yet. Emails are sent when an alert reaches risk 70."), error.

### 7.2 Alert detail page

Add a secondary button **"Email admin"** (envelope icon) next to the existing action buttons. It POSTs `/api/alerts/{id}/notify`, then shows a toast, for example "Email saved to outbox" / "Email sent to admin@…" / "Email failed: …" (from `status`/`detail`). Disable it while the request runs.

### 7.3 Mock mode

Add `/notifications` → `notifications`, `/notifications/status` → `notifications_status` to the `api.js` mock map (`GET`). Mock `POST` already returns `{status:"mocked"}`. Fixtures are in `reference/REF_07_mock_json.md`.

## 8. Demo talking point

"When risk crosses 70, the admin gets one short digest, not 30 emails. It says who, how risky, why and what to do, with a link to the evidence. Usernames come from attacker-controlled logs, so we strip header-injection characters. Revocation still needs a human."
