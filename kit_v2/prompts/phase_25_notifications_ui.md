# PHASE 25: Notifications page + "Email admin" button (≈35 min) · Person D

Spec: `kit_v2/04_FEATURE_EMAIL_ALERTS_SPEC.md` §7. Can be built in mock mode before Phase 24 is live.

## Part A: page, mocks, sidebar (≈20 min)

```text
Read context.md Section 10 and Sections 16.7–16.8, then kit_v2/04_FEATURE_EMAIL_ALERTS_SPEC.md Section 7.

DO:
1. Create static/mock/notifications.json and static/mock/notifications_status.json by copying EXACTLY the
   blocks in kit_v2/reference/REF_07_mock_json.md.
2. static/js/api.js: extend the mock table (GET): /notifications → notifications,
   /notifications/status → notifications_status. Order matters: match /notifications/status before
   /notifications. Change nothing else.
3. static/js/layout.js: add a sidebar item "Notifications" (inline SVG envelope icon) after Audit.
4. static/notifications.html: same head/body structure as static/audit.html, title
   "IdentityShield · Notifications", module script /js/notifications.js.
5. static/js/notifications.js: renderLayout("notifications", "Notifications",
   "Email alerts sent to the security admin"), then:

   Status card (load /notifications/status):
   - left: mode pill (outbox → "Outbox (demo)" brand2 tint; smtp → "SMTP" ok tint; off → "Off" muted),
     then a definition list: Recipients (comma list, or warn-colored "No recipients configured"),
     SMTP server (smtp_host or "—"), Threshold "Risk ≥ {min_risk}", Sent this hour "{sent_last_hour} / {max_per_hour}".
   - right: primary button "Send test email" (envelope icon). On click: disable, POST /notifications/test,
     toast by status: sent → success "Test email sent"; outbox → success "Saved to outbox (demo mode)";
     off → error "Email is turned off (EMAIL_MODE=off)"; failed/rate_limited → error with the detail text.
     Re-enable, then reload status and history.
   - footer note (text-xs text-muted): "Configure in .env (see .env.example). Outbox mode works offline."

   History card (load /notifications?limit=50): table with columns Time (fmtTime), Kind chip
   (Digest/Manual/Test), Status badge (sent ok, outbox brand2, failed crit, rate_limited warn; label text
   always shown), Subject (truncate max-w-md with title), Recipients, Alerts (links alert.html?id=, keep
   ?mock=1). Rows are buttons (keyboard accessible): clicking toggles a detail row directly under it showing
   detail (text-muted text-xs) and body_text inside <pre class="whitespace-pre-wrap font-mono text-xs
   bg-panel2 border border-line rounded-lg p-4 max-h-80 overflow-auto"> inserted via esc().
   NEVER render email HTML. Only one detail row is open at a time.
   Empty: emptyState("No emails yet. A digest is sent when an alert reaches the risk threshold.")
   Skeleton and errorState as usual.
FILES: static/mock/notifications*.json, static/js/api.js, static/js/layout.js, static/notifications.html,
static/js/notifications.js
```

CHECK: `notifications.html?mock=1` shows the status card, two history rows (the digest with an `outbox` badge, the test with `failed`); clicking a row opens the preview; works at 375 px; no console errors.

## Part B: "Email admin" on the alert page (≈10 min)

```text
In static/js/alert.js, add a secondary button "Email admin" (envelope icon, aria-label "Email the admin
about this alert") next to the existing action buttons in the header card. On click: disable it, show
"Sending…", POST /alerts/{id}/notify, then toast:
- status sent → "Email sent to {recipients}"
- status outbox → "Email saved to outbox (demo mode)"
- status off → "Email is turned off"
- failed / rate_limited → error toast with detail
Re-enable afterwards. Do not change any other behavior on the page.
FILES: static/js/alert.js
```

CHECK: on the live server, open the top alert → **Email admin** → toast → the Notifications page shows a new `Manual` record whose preview contains that alert.

---

**After the CHECKs pass:** `git commit -m "phase 25 ok"`, then update context.md Section 20.
