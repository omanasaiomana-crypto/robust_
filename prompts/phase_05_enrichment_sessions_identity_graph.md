# PHASE 5: Enrichment, sessions, identity graph (≈25 min) · Person B

```text
Read context.md fully. Then read docs/TECH_PRD.md Sections 9.6, 10.1, 10.2, 10.3.

GOAL: Add context to events, link Okta sessions to AWS activity, and build the identity graph.

DO:
1. app/ingest/enrich.py: enrich(df: pd.DataFrame, metadata: dict) -> pd.DataFrame
   - privilege_level from metadata, else inferred (admin → 5, power/ops → 3, else 1).
   - resource_sensitivity rules from TECH_PRD 9.6.
   - For CloudTrail rows missing lat/lon/country: copy from the most recent Okta login of the same
     identity with the same src_ip (use pandas merge_asof by timestamp, grouped by identity_id).
     Both frames must be sorted by timestamp before merge_asof. If it fails, leave values None.
   - Never drop rows.
2. app/correlate/sessions.py: assign_sessions(df) -> pd.DataFrame following TECH_PRD 10.1
   (okta:<externalSessionId>; CloudTrail linked to an Okta session of the same identity started
   within 12 h with matching IP; else aws:<identity>:<n> using 1-hour inactivity gaps per
   identity+token). Every row ends with a non-empty session_id.
3. app/correlate/graph.py with the 4 functions in TECH_PRD 10.3, returning models from app.models.
   Node and edge naming exactly as TECH_PRD 10.2. Use nx.MultiDiGraph. Path searches use cutoff=6.
   identity_subgraph keeps at most 150 nodes (most recent first) so the browser stays fast.
   blast_radius counts reachable resource nodes with sensitivity >= 4.

FILES: app/ingest/enrich.py, app/correlate/sessions.py, app/correlate/graph.py

CHECK: write and run a short script scratch_phase5.py (do not commit it) that loads sample data,
normalizes, enriches, assigns sessions, builds the graph and prints:
number of sessions, graph node and edge counts, blast_radius('svc-report'),
and len(identity_subgraph(g,'svc-report',set()).nodes).
Expected: no errors; svc-report blast radius > 0 after escalation.
Then update context.md Section 12: Phase 5 = ☑.
```

---

**After the CHECK passes:** `git add . && git commit -m "phase 5 ok"`, then open the next file.
**If the CHECK fails:** use template T2 in `prompts/00_templates.md` with the exact error.
