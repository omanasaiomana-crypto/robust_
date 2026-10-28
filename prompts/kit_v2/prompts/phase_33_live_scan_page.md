# PHASE 33: Live scan page (full-color console + full JSON) (≈20 min) · Person D

**Why:** when the system checks for malicious activity, the judges see every agent step in a colored console, the **current step** and its **full JSON**, the threats as they are found, and a note that each threat was written to the audit log.

The page code is **pre-built and tested** (headless Chromium, mock and live modes: 32/32 events, 4 threats, 0 browser errors). This phase copies it and wires it in.

Spec: `kit_v2/08_FEATURE_AGENTS_SCAN_INPUT_GRAPH_SPEC.md` §4.

## Prompt

```text
Read context.md Section 10, 16.5, 16.8 and kit_v2/08_FEATURE_AGENTS_SCAN_INPUT_GRAPH_SPEC.md Section 4.

DO:
1. Create static/js/jsonview.js exactly from kit_v2/reference/REF_14_jsonview_js.md (skip if it already MATCHES).
2. Create static/js/scan.js exactly from kit_v2/reference/REF_16_scan_page_js.md.
3. Create static/mock/scan_trace.json exactly from kit_v2/reference/REF_18_mock_json_v21.md (and scan_status.json /
   agents.json if missing). Add to the api.js mock table (GET): /scan/trace → scan_trace. Query strings must be
   ignored when matching.
4. static/scan.html: same head/body as static/alerts.html, title "IdentityShield · Live scan",
   module script /js/scan.js.
5. static/js/layout.js: add a sidebar item "Live scan" (inline SVG radar/pulse icon) directly after Overview.
   The renderLayout id is "scan".
6. Compatibility check (report, then fix only in api.js/ui.js/layout.js if needed, minimal change):
   scan.js imports { api } from ./api.js, { toast } from ./ui.js, { renderLayout } from ./layout.js.
   - api(path, { method: "POST", body: {...} }) must JSON-encode body and throw Error("<error>: <detail>")
     on non-2xx (Phase 12 contract). In mock mode a POST must resolve to {status:"mocked"}.
   - toast(message, type) must accept "success" and "error".
   - renderLayout(active, title, subtitle) must return the content element.
   If one of these differs, adapt api.js/ui.js/layout.js (NOT scan.js) and tell me what changed.
7. On the Overview page add a primary button "Run live scan" in the header area linking to scan.html?autostart=1
   (keep ?mock=1 → scan.html?mock=1&autostart=replay).
FILES: static/js/jsonview.js, static/js/scan.js, static/mock/scan_trace.json (+ scan_status.json, agents.json if missing),
static/js/api.js, static/scan.html, static/js/layout.js, static/js/overview.js, (ui.js only if step 6 requires)
```

## CHECK (human)

```bash
python tools/check_ref.py static/js/scan.js kit_v2/reference/REF_16_scan_page_js.md
python tools/check_ref.py static/js/jsonview.js kit_v2/reference/REF_14_jsonview_js.md
```

1. `scan.html?mock=1` → **Replay last scan**: lines stream in color; header shows "Step k / 13 · <agent>"; the JSON panel follows the current step; 4 threats appear on the right; the green banner reads "Scan complete · 4 threat(s), each written to the audit log".
2. Live, without `?mock=1`: pick **Dataset**, press **Start scan** at 1×. The real run takes about 2 s; the page replays it at a watchable pace and the banner shows the actual time.
3. Toggle **Inline JSON**, set the filter to **Threats**, use **Download JSON**, click a line to inspect it.
4. Open **Audit**: the new `threat_detected` entries are there (one per threat).

---

**After the CHECK passes:** `git commit -m "phase 33 ok"`, then update context.md Section 24.
