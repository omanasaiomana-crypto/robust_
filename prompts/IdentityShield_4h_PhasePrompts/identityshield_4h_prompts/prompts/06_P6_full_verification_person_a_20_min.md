# P6 · Full verification (Person A, 20 min)

Start the server (`python -m uvicorn app.main:app --port 8000`), then:

```text
Do NOT edit files. Write and run scratch_verify.py (do not commit it) that uses fastapi.testclient.TestClient(app.main.app)
inside `with TestClient(app) as c:` and prints status code + top-level keys for:
GET /api/agents, POST /api/scan/start (body {}), then poll GET /api/scan/status every 0.5 s until state != "running"
(max 60 s), GET /api/scan/trace?after=0 (print number of events and the distinct agent_id values),
GET /api/audit (count entries with action "threat_detected"), GET /api/audit/verify,
GET /api/identities/svc-report/attack (print number of nodes/edges and alert id),
GET /api/graph/global, GET /api/analytics/detectors (print winner), GET /api/analytics/heatmap/time (print total),
GET /api/inputs, GET /api/notifications/status, POST /api/notifications/test,
GET /scan.html, /agents.html, /input.html, /explorer.html, /analytics.html, /notifications.html.
Report a table: endpoint | status | key facts. Mark anything that is not 2xx.
```

**Expected:** all 2xx (or 202); 14+ distinct agent ids in the trace; at least one `threat_detected` entry; audit `valid: true`; the explorer for svc-report has edges and an alert id.

Then **click through in the browser** (10 min):

| Page | Must see |
|---|---|
| Live scan | Start scan at 1×: steps stream, "Step k/13", JSON panel, THREAT cards, banner with the actual time |
| Agents | 15 cards, all Done; click one to see its JSON |
| Attack paths | svc-report: red path with particles, numbered badges, ▶ Play attack, Focus, Blast radius |
| Input data | Presets Bengaluru + Frankfurt → Add → Scan input only → THREAT anita.rao |
| Analytics | Winner, 3 cards, chart, heatmaps |
| Notifications | Send test email → outbox row with a preview |
| Audit | `threat_detected` entries; chain intact |

Write every problem into a list for P7.


---
**If the CHECK fails:** use `prompts/99_FIX_template.md`. **Next:** the next numbered file.
