# P05: Agents 3–4: Context + Threat Intel, Correlation + Graph (MUST)

> **Before pasting:** open a NEW Antigravity chat and paste T1 from `00_TEMPLATES.md` first. Then paste only the text block below. Run the CHECK yourself.

```text
Read context.md Sections 5, 7, 8, 12, 15 and PRD §8, §12 (Agents 3, 4). Phase P5.
DO:
1. app/v3/data/: create tor_exits.txt (a small sample list with a header comment saying how to refresh it from the
   Tor bulk exit list), hosting_asns.txt (common cloud/hosting ASNs: AWS 16509 and 14618, Google 15169 and 396982,
   Microsoft 8075, DigitalOcean 14061, OVH 16276, Hetzner 24940, Linode 63949, Vultr 20473), trusted_ips.txt
   (empty with comment), geo_seed.csv (columns cidr,country,city,lat,lon,asn,as_org covering every IP used in the
   official dataset and fixtures; generate it from the dataset IPs with plausible values if the dataset has
   geo fields, otherwise create entries for the fixture IPs), privilege and sensitivity rules in
   app/v3/data/context_rules.yaml (privilege by attached policy names/patterns, sensitivity by resource ARN patterns:
   secretsmanager, kms, s3 buckets with prod/finance/pii in the name = 5).
2. app/v3/enrich/offline.py: loads the files once; lookup_ip(ip) -> geo/asn/flags using Okta securityContext
   values when present in event attrs (prefer them), else geo_seed CIDR match, else unknown (context_complete=False).
3. app/v3/enrich/providers.py: OPTIONAL providers (ipinfo_lite, ipapi, abuseipdb, greynoise, otx) disabled unless
   listed in ENRICH_PROVIDERS; each with httpx timeout 2 s, per-provider rate limit, results cached in
   enrich_cache_v3 for 24 h; a background prefetch queue (thread) for cache misses; send only the IP; never block
   Agent 3; all exceptions swallowed with a warning counter. Unit tests mock httpx; no network in tests.
4. app/v3/agents/a03_context.py (Agent 3, hot): subscribes events.normalized → events.enriched with Context per
   context.md Section 8 (privilege from identity's attached policies seen in the dataset or context_rules; sensitivity
   from resource ARN; action_type from catalog; is_tor/is_hosting/is_proxy/trusted_ip flags).
5. app/v3/agents/a04_correlation.py (Agent 4): subscribes events.enriched; maintains sessions: Okta
   external_session_id defines a session; AWS events whose credentials derive from that identity's SAML login
   within the session window join it; standalone AWS sessions keyed by (identity, access key, 15-min idle gap);
   publishes `sessions` messages on open, update (at most every 5 events or 10 s) and close (idle
   SESSION_IDLE_MINUTES via on_tick; drain mode closes all at final tick). Maintains a NetworkX MultiDiGraph with
   node kinds identity, session, ip, asn, device, access_key, role, resource; edges logged_in_from, assumed,
   created_key, used_key, called, touched with event_id and time; publishes graph.updates deltas; prunes by
   GRAPH_RETENTION_DAYS and GRAPH_MAX_NODES; provides blast_radius(identity_id) counting sensitivity ≥ 4 resources
   reachable within 3 hops via role/key edges; exposes get_graph() for the API (read-only copy or view).
6. Tests tests/v3/test_agents_data_3_4.py: securityContext preferred, hosting ASN flag, unknown IP →
   context_complete False, sensitivity rules, providers disabled by default and mocked when enabled, cross-provider
   session (Okta login + SAML + AWS calls) forms ONE session, idle close, graph edges and blast radius on fixture.
FILES: app/v3/data/*, app/v3/enrich/__init__.py, app/v3/enrich/offline.py, app/v3/enrich/providers.py,
app/v3/agents/a03_context.py, app/v3/agents/a04_correlation.py, tests/v3/test_agents_data_3_4.py
```

**CHECK**
```bash
pytest -q tests/v3
ruff check app/v3 tests/v3
```

---
**After the CHECK passes:** paste template T5 (in `00_TEMPLATES.md`), then commit: `git add -A && git commit -m "v3 P05: Agents 3–4: Context + Threat Intel, Correlation + Graph"`. Next file: `P06_agents_5_6_access_anomaly_session_token_integ.md`.
