# PHASE 36: Identity Graph upgrade: Attack Path Explorer (≈40 min) · Persons A + D

**Why:** this is the "wow" screen for judges. The attack path glows red, with particles flowing along it and numbered steps. **Play attack** walks the camera through the escalation one step at a time. Focus mode dims everything else, and the blast-radius halo shows what the attacker could reach next.

The page code is **pre-built** (REF_17) and was logic-tested in headless Chromium against a vis-network stand-in (path, playback, focus, blast radius, layouts, inspector, global view, PNG export: 0 browser errors). The real vis-network rendering is checked by you in this phase's CHECK.

Spec: `kit_v2/08_FEATURE_AGENTS_SCAN_INPUT_GRAPH_SPEC.md` §6.

## Part A: backend, 2 endpoints (≈15 min) · Person A

```text
Read context.md Sections 9, 16 and kit_v2/08_FEATURE_AGENTS_SCAN_INPUT_GRAPH_SPEC.md Section 6.2.

In app/api/identities.py add (plain def, clean_json, 503 if no pipeline result, reuse app/correlate/graph.py functions):
1. GET /identities/{identity_id}/attack →
   {"identity_id", "identity": <the row from get_identity_rows(result) for this id, or null>,
    "graph": identity_subgraph(result.graph, identity_id, suspicious_ids).model_dump(mode="json"),
    "alert": <this identity's highest-risk Alert as model_dump(mode="json"), or null>,
    "blast_radius": blast_radius(result.graph, identity_id)}
   suspicious_ids = the evidence_event_ids of that alert (so path edges are marked suspicious).
   404 not_found if the identity has no events and no alerts.
   The graph must contain the edges whose event_id is in the alert's evidence_event_ids (so the attack path can be drawn).
   If identity_subgraph's 150-node cap could drop them, keep evidence edges first when trimming (smallest change in
   identity_subgraph, behavior otherwise unchanged).
2. GET /graph/global?top=8 (clamp 1..15) → merge identity_subgraph(...) of the top-N identities by max alert risk:
   {"identities": [ids], "nodes": [...unique by id...], "edges": [...unique by (source,target,label,event_id)...],
    "truncated": bool}. Cap at 300 nodes (truncated=true if capped). Edges whose event_id is in ANY of those identities'
   top alert evidence get suspicious=true.
3. tests/test_v2_api.py: on sample data, GET /api/identities/svc-report/attack → 200, alert.alert_id present, at least one
   graph edge has an event_id contained in alert.evidence_event_ids; GET /api/identities/nobody-xyz/attack → 404;
   GET /api/graph/global → 200 with "nodes" and "edges", and len(nodes) <= 300.
FILES: app/api/identities.py, app/correlate/graph.py (only the trimming order, if needed), tests/test_v2_api.py
```

## Part B: frontend (≈15 min) · Person D

```text
Read context.md Section 10, 16.5, 16.8 and kit_v2/08_FEATURE_AGENTS_SCAN_INPUT_GRAPH_SPEC.md Section 6.

DO:
1. Create static/js/graphfx.js exactly from kit_v2/reference/REF_15_graphfx_js.md.
2. REPLACE static/js/graph.js with exactly the code in kit_v2/reference/REF_17_graph_page_js.md.
   (jsonview.js must exist from Phase 33.)
3. static/graph.html: keep the head; make sure the vis-network script (CDN or /vendor/vis-network.min.js from Phase 27)
   comes BEFORE <script type="module" src="/js/graph.js">. Title "IdentityShield · Attack path explorer".
4. Mocks: create static/mock/graph_attack.json, graph_global.json (and events_AL-0001.json) exactly from
   kit_v2/reference/REF_18_mock_json_v21.md. api.js mock table (GET, ignore query strings):
   /identities/{id}/attack → graph_attack, /graph/global → graph_global. If the existing static/mock/identities.json lacks
   "risk" or "identity_id", replace it with the REF_18 version. Map /alerts/{id}/events → events only if no mapping exists.
5. graph.js calls renderLayout("graph", …). If layout.js has no sidebar item with id "graph", make the Identities item
   active for "graph" too (change layout.js, not graph.js).
6. Identities page and alert page links to graph.html?identity=… keep working. On the alert detail page, change the
   "Open identity graph" link to graph.html?identity=<id>&play=1 so it opens and plays the attack.
FILES: static/js/graphfx.js, static/js/graph.js, static/graph.html, static/mock/graph_attack.json,
static/mock/graph_global.json, static/mock/events_AL-0001.json, static/mock/identities.json (only if needed),
static/js/api.js, static/js/layout.js (only if needed), static/js/alert.js (link only)
```

## CHECK (human, in a real browser)

```bash
python tools/check_ref.py static/js/graph.js kit_v2/reference/REF_17_graph_page_js.md
python tools/check_ref.py static/js/graphfx.js kit_v2/reference/REF_15_graphfx_js.md
```

Open `graph.html?mock=1`, then the live page for `svc-report`:
1. The red path is visible, with **moving particles** and **numbered badges 1…6**. The stats read "Path steps 5 · Time to impact 11 min".
2. **▶ Play attack**: the camera moves step by step and the caption reads "STEP 2/5 · CreateAccessKey · CredCreate".
3. **Focus attack path** dims everything else. **Blast radius** shows an orange dashed halo and glowing resources.
4. **Left → right** gives a clean hierarchical layout; **Force** returns to the organic layout.
5. Click a node: the inspector lists its connections; clicking an event id shows the evidence JSON.
6. **All risky identities** shows several identities with their suspicious edges in red. **Export PNG** downloads an image. **Fullscreen** works.
7. No console errors.

If something looks off visually (for example particles not exactly on curved edges), tell the agent which item failed. Only `graph.js` styling constants may be adjusted; keep `graphfx.js` unchanged.

---

**After the CHECK passes:** `git commit -m "phase 36 ok"`, then update context.md Section 24.
