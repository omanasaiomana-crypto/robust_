# PHASE 35: Input page UI (≈40 min) · Person D

Spec: `kit_v2/08_FEATURE_AGENTS_SCAN_INPUT_GRAPH_SPEC.md` §5.4. Works in `?mock=1` first.

## Prompt

```text
Read context.md Section 10 and 16.8, then kit_v2/08_FEATURE_AGENTS_SCAN_INPUT_GRAPH_SPEC.md Section 5.

DO:
1. static/mock/inputs.json exactly from kit_v2/reference/REF_18_mock_json_v21.md; api.js mock table (GET): /inputs → inputs.
2. static/js/layout.js: sidebar item "Input data" (inline SVG upload/tray icon) after Live scan.
3. static/input.html: same head/body as alerts.html, title "IdentityShield · Input data", module /js/input.js.
4. static/js/input.js: renderLayout("input", "Input data", "Add your own logs or single events, then scan only them").
   Use escHtml from ./jsonview.js for every dynamic value.

   Layout (lg: 2 columns, left 2/3, right 1/3; single column on mobile):

   LEFT · Card "Add logs" with two tabs (buttons, not hidden-until-JS content: render both panels, show one):
   a) "Paste or upload":
      - source select: Auto-detect / AWS CloudTrail / Okta System Log
      - a drop zone (dashed border-line, rounded-xl, p-8, centered icon + "Drop .json / .jsonl files here or
        click to choose") backed by <input type="file" accept=".json,.jsonl,.txt" multiple>. Files are read in the
        browser with file.text() and each file is POSTed separately to /inputs/upload as
        {content, source, filename}. Reject files larger than limits.max_bytes (from GET /inputs) client-side
        with an error toast before sending.
      - a textarea (font-mono text-xs, h-56, bg #05070C, placeholder showing a 1-line CloudTrail example) +
        button "Add pasted records".
      - result box after each upload: "Accepted: 120 CloudTrail · 0 Okta · Rejected: 1" + the first errors as a list
        (crit text). Never echo the uploaded content back.
   b) "Single event" form:
      - kind select: "Okta login" (okta_login) / "Okta logout" (okta_logout) / "AWS API call" (cloudtrail_api).
        Fields shown depend on kind:
        Okta: user*, ip*, time (datetime-local; convert to ISO UTC "Z"), outcome (SUCCESS/FAILURE), city, country,
              lat, lon, session_id, label (optional, e.g. impossible_travel)
        AWS:  user*, ip*, time, event_name* (datalist of common names: ConsoleLogin, CreateAccessKey,
              AttachUserPolicy, PutUserPolicy, AssumeRole, GetSecretValue, StopLogging, DeleteTrail, ListBuckets),
              event_source (default iam.amazonaws.com), region (default ap-south-1), access_key_id, resource, label
      - "Presets" row of small secondary buttons that fill the form (do not submit):
        "Login · Bengaluru" (anita.rao, 49.207.12.8, Bengaluru, India, 12.97, 77.59),
        "Login · Frankfurt +30 min" (anita.rao, 91.64.18.2, Frankfurt, Germany, 50.11, 8.68, time = previous preset + 30 min,
          label impossible_travel),
        "Attach AdministratorAccess" (svc-report, 185.220.101.4, AttachUserPolicy,
          resource arn:aws:iam::aws:policy/AdministratorAccess, label privilege_escalation),
        "Stop CloudTrail logging" (dev.kumar, 177.71.200.9, StopLogging, region sa-east-1, event_source
          cloudtrail.amazonaws.com, label unusual_api).
      - Submit → POST /inputs/manual {kind, fields}. On 422 show the server message under the form (crit) and
        keep the values. On success toast "Event added" and show the stored record with highlightJson in a dark <pre>.

   RIGHT · Card "Your input data": totals (CloudTrail / Okta / total records), file list (name mono truncated,
      source chip, records, size in KB, modified fmtTime), "Clear all" (danger, confirmModal first, DELETE /inputs).
      Below: Card "Scan it":
        primary button "Scan input only" → navigate to scan.html?autostart=1&mode=only (keep ?mock=1).
          Do NOT POST from this page: the Live scan page starts the run itself and attaches to the new run id.
        secondary button "Scan dataset + input" → scan.html?autostart=1&mode=merge (keep ?mock=1).
        Both disabled when total_records is 0, with a hint "Add data first".
        Note (text-xs text-muted): "Input-only scans look at nothing else. Detectors that need history (dormant
        accounts, ML baseline) may report nothing on very small inputs; use Dataset + input for those."

   After every successful add/clear, reload GET /inputs.
   States: skeleton, empty ("No input yet. Paste logs, drop files or add a single event."), errorState.
5. static/js/scan.js must NOT be modified. It already supports ?autostart=1&mode=only|merge|dataset.
FILES: static/mock/inputs.json, static/js/api.js, static/js/layout.js, static/input.html, static/js/input.js
```

## CHECK (human)

1. `input.html?mock=1`: both tabs render, presets fill the form, the file list shows 3 files; no console errors; works at 375 px.
2. Live:
   - Click the preset **Login · Bengaluru**, then **Add**.
   - Click the preset **Login · Frankfurt +30 min**, then **Add**.
   - Click **Scan input only**. The live scan shows *Impossible Travel Agent* flagging `anita.rao`, a THREAT line, and a new audit entry.
3. Paste `{"foo": 1}` → a clear error ("No valid CloudTrail or Okta records found…"). Paste an invalid IP in the form → the field error from the server.
4. **Clear all** → totals go back to 0.

---

**After the CHECK passes:** `git commit -m "phase 35 ok"`, then update context.md Section 24.
