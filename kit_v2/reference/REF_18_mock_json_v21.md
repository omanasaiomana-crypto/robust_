# Mock JSON fixtures for v2.1

Save each block as `static/mock/<name>.json`. They were produced by the reference code (trace, inputs) or written to match it exactly, and the Live scan and Graph pages were tested against them.

| Mock file | Endpoint |
|---|---|
| agents.json | GET /api/agents |
| scan_status.json | GET /api/scan/status |
| scan_trace.json | GET /api/scan/trace |
| inputs.json | GET /api/inputs |
| identities.json | GET /api/identities (only if your existing mock lacks risk/blast_radius) |
| graph_attack.json | GET /api/identities/{id}/attack |
| graph_global.json | GET /api/graph/global |
| events_AL-0001.json | GET /api/alerts/{id}/events (graph inspector; optional) |

## static/mock/agents.json

```json
{
  "agents": [
    {
      "id": "ingestion",
      "num": 1,
      "name": "Log Ingestion Agent",
      "layer": "data",
      "pattern": null,
      "role": "Reads CloudTrail and Okta files and replays events in time order",
      "permissions": [
        "read:raw_logs"
      ],
      "state": "done",
      "runs": 1,
      "last_started": "2026-10-28T16:11:21.249359+00:00",
      "last_finished": "2026-10-28T16:11:21.249395+00:00",
      "last_duration_ms": 0.0,
      "last_message": "Loaded 2,967 records from 2 files",
      "last_output": {
        "files": {
          "cloudtrail": [
            "cloudtrail.json"
          ],
          "okta": [
            "okta.json"
          ]
        },
        "records": {
          "cloudtrail": 2214,
          "okta": 753
        },
        "skipped": 0
      },
      "last_error": "",
      "signals": null
    },
    {
      "id": "normalization",
      "num": 2,
      "name": "Normalization Agent",
      "layer": "data",
      "pattern": null,
      "role": "Maps both log formats into one event schema",
      "permissions": [
        "read:raw_logs",
        "write:events"
      ],
      "state": "done",
      "runs": 1,
      "last_started": "2026-10-28T16:11:21.249537+00:00",
      "last_finished": "2026-10-28T16:11:21.249577+00:00",
      "last_duration_ms": 0.0,
      "last_message": "2,967 events normalized for 21 identities",
      "last_output": {
        "events": 2967,
        "skipped": 0,
        "sources": {
          "cloudtrail": 2214,
          "okta": 753
        },
        "identities": 21,
        "sample_event": {
          "event_id": "ct-1a7f",
          "source": "cloudtrail",
          "timestamp": "2026-10-28T04:21:12+00:00",
          "identity_id": "svc-report",
          "action": "AttachUserPolicy",
          "category": "api",
          "src_ip": "185.220.101.4",
          "resource": "arn:aws:iam::aws:policy/AdministratorAccess"
        }
      },
      "last_error": "",
      "signals": null
    },
    {
      "id": "enrichment",
      "num": 3,
      "name": "Enrichment Agent",
      "layer": "data",
      "pattern": null,
      "role": "Adds geo, privilege level and resource sensitivity",
      "permissions": [
        "read:metadata",
        "write:events"
      ],
      "state": "done",
      "runs": 1,
      "last_started": "2026-10-28T16:11:21.249635+00:00",
      "last_finished": "2026-10-28T16:11:21.249652+00:00",
      "last_duration_ms": 0.0,
      "last_message": "Enriched 2,967 events · 61 touch sensitive resources",
      "last_output": {
        "geo_filled": 2140,
        "privileged_identities": 3,
        "sensitive_events": 61
      },
      "last_error": "",
      "signals": null
    },
    {
      "id": "correlation",
      "num": 4,
      "name": "Session Correlation Agent",
      "layer": "data",
      "pattern": null,
      "role": "Links Okta sessions to AWS activity and builds the identity graph",
      "permissions": [
        "read:events",
        "write:graph"
      ],
      "state": "done",
      "runs": 1,
      "last_started": "2026-10-28T16:11:21.249680+00:00",
      "last_finished": "2026-10-28T16:11:21.249696+00:00",
      "last_duration_ms": 0.0,
      "last_message": "412 sessions · identity graph 964 nodes / 3,311 edges",
      "last_output": {
        "sessions": 412,
        "okta_linked": 388,
        "aws_only": 24,
        "graph": {
          "nodes": 964,
          "edges": 3311
        }
      },
      "last_error": "",
      "signals": null
    },
    {
      "id": "impossible_travel",
      "num": 5,
      "name": "Impossible Travel Agent",
      "layer": "detection",
      "pattern": "P1",
      "role": "Flags logins too far apart for the time between them",
      "permissions": [
        "read:events"
      ],
      "state": "done",
      "runs": 1,
      "last_started": "2026-10-28T16:11:21.249725+00:00",
      "last_finished": "2026-10-28T16:11:21.249738+00:00",
      "last_duration_ms": 0.0,
      "last_message": "1 signal · anita.rao 14,812 km/h",
      "last_output": {
        "signals": 1,
        "pairs_checked": 731,
        "examples": [
          {
            "identity_id": "anita.rao",
            "from": "Bengaluru",
            "to": "Frankfurt",
            "km": 7406,
            "minutes": 30,
            "kmh": 14812
          }
        ]
      },
      "last_error": "",
      "signals": 1
    },
    {
      "id": "dormant",
      "num": 6,
      "name": "Dormant Account Agent",
      "layer": "detection",
      "pattern": "P2",
      "role": "Flags accounts that wake up after a long silence",
      "permissions": [
        "read:events"
      ],
      "state": "done",
      "runs": 1,
      "last_started": "2026-10-28T16:11:21.249769+00:00",
      "last_finished": "2026-10-28T16:11:21.249786+00:00",
      "last_duration_ms": 0.0,
      "last_message": "1 signal · svc-report idle 47 days",
      "last_output": {
        "signals": 1,
        "examples": [
          {
            "identity_id": "svc-report",
            "idle_days": 47,
            "privilege_level": 5
          }
        ]
      },
      "last_error": "",
      "signals": 1
    },
    {
      "id": "priv_escalation",
      "num": 7,
      "name": "Privilege Escalation Agent",
      "layer": "detection",
      "pattern": "P3",
      "role": "Reconstructs multi-step escalation chains",
      "permissions": [
        "read:events",
        "read:graph"
      ],
      "state": "done",
      "runs": 1,
      "last_started": "2026-10-28T16:11:21.249811+00:00",
      "last_finished": "2026-10-28T16:11:21.249824+00:00",
      "last_duration_ms": 0.0,
      "last_message": "1 chain · 4 steps in 11 min",
      "last_output": {
        "signals": 1,
        "chains": [
          {
            "session_id": "okta:102svcR7",
            "steps": [
              "CredCreate",
              "PermGrant",
              "RoleAssume",
              "Impact"
            ],
            "minutes": 11
          }
        ]
      },
      "last_error": "",
      "signals": 1
    },
    {
      "id": "api_anomaly",
      "num": 8,
      "name": "API Anomaly Agent",
      "layer": "detection",
      "pattern": "P4",
      "role": "Flags rare, sensitive or new-region API calls",
      "permissions": [
        "read:events"
      ],
      "state": "done",
      "runs": 1,
      "last_started": "2026-10-28T16:11:21.249852+00:00",
      "last_finished": "2026-10-28T16:11:21.249865+00:00",
      "last_duration_ms": 0.0,
      "last_message": "2 signals · StopLogging in a new region",
      "last_output": {
        "signals": 2,
        "examples": [
          {
            "identity_id": "dev.kumar",
            "action": "StopLogging",
            "region": "sa-east-1",
            "new_region": true
          }
        ]
      },
      "last_error": "",
      "signals": 2
    },
    {
      "id": "token_abuse",
      "num": 9,
      "name": "Token Abuse Agent",
      "layer": "detection",
      "pattern": "P5",
      "role": "Flags session or token reuse from new places or after logout",
      "permissions": [
        "read:events"
      ],
      "state": "done",
      "runs": 1,
      "last_started": "2026-10-28T16:11:21.249889+00:00",
      "last_finished": "2026-10-28T16:11:21.249902+00:00",
      "last_duration_ms": 0.0,
      "last_message": "1 signal · same key in IN and BR within 3 min",
      "last_output": {
        "signals": 1,
        "examples": [
          {
            "identity_id": "meera.n",
            "token": "AKIA...Q7",
            "countries": [
              "IN",
              "BR"
            ],
            "minutes": 3
          }
        ]
      },
      "last_error": "",
      "signals": 1
    },
    {
      "id": "baseline_ml",
      "num": 10,
      "name": "Behavior Baseline Agent (ML)",
      "layer": "detection",
      "pattern": "ML",
      "role": "Isolation Forest anomaly score per session",
      "permissions": [
        "read:features"
      ],
      "state": "done",
      "runs": 1,
      "last_started": "2026-10-28T16:11:21.249928+00:00",
      "last_finished": "2026-10-28T16:11:21.249942+00:00",
      "last_duration_ms": 0.0,
      "last_message": "2 sessions above anomaly threshold 0.60",
      "last_output": {
        "signals": 2,
        "trained_on": 398,
        "features": 13,
        "top_scores": [
          {
            "session_id": "okta:55aniK9",
            "score": 0.91
          },
          {
            "session_id": "okta:102svcR7",
            "score": 0.84
          }
        ]
      },
      "last_error": "",
      "signals": 2
    },
    {
      "id": "risk_scoring",
      "num": 11,
      "name": "Risk Scoring Agent",
      "layer": "decision",
      "pattern": null,
      "role": "Combines signals x privilege x sensitivity into a 0-100 risk",
      "permissions": [
        "read:signals",
        "write:scores"
      ],
      "state": "done",
      "runs": 1,
      "last_started": "2026-10-28T16:11:21.249976+00:00",
      "last_finished": "2026-10-28T16:11:21.249992+00:00",
      "last_duration_ms": 0.0,
      "last_message": "4 alerts · top risk 94 (svc-report)",
      "last_output": {
        "sessions_scored": 7,
        "alerts": 4,
        "bands": {
          "revoke": 1,
          "restrict": 2,
          "step_up": 1,
          "monitor": 0
        },
        "top": {
          "alert_id": "AL-0001",
          "risk": 94.0
        }
      },
      "last_error": "",
      "signals": null
    },
    {
      "id": "explanation",
      "num": 12,
      "name": "Explanation Agent",
      "layer": "decision",
      "pattern": null,
      "role": "Writes reasons, counterfactuals and MITRE tags with evidence",
      "permissions": [
        "read:signals"
      ],
      "state": "done",
      "runs": 1,
      "last_started": "2026-10-28T16:11:21.250021+00:00",
      "last_finished": "2026-10-28T16:11:21.250035+00:00",
      "last_duration_ms": 0.0,
      "last_message": "4 alerts explained with evidence",
      "last_output": {
        "alerts_explained": 4,
        "counterfactuals": {
          "AL-0001": {
            "without P3": 44.0,
            "without P2": 61.0
          }
        },
        "mitre": [
          "T1078",
          "T1078.004",
          "T1098",
          "T1526",
          "T1539",
          "T1548",
          "T1550",
          "T1562"
        ]
      },
      "last_error": "",
      "signals": null
    },
    {
      "id": "response",
      "num": 13,
      "name": "Response Agent",
      "layer": "decision",
      "pattern": null,
      "role": "Recommends and applies actions through the simulator only",
      "permissions": [
        "call:simulator"
      ],
      "state": "done",
      "runs": 1,
      "last_started": "2026-10-28T16:11:21.250064+00:00",
      "last_finished": "2026-10-28T16:11:21.250075+00:00",
      "last_duration_ms": 0.0,
      "last_message": "3 actions applied · 1 revoke awaiting analyst approval",
      "last_output": {
        "applied": [
          {
            "alert_id": "AL-0002",
            "action": "restrict",
            "result": "simulated:restrict:ok"
          },
          {
            "alert_id": "AL-0003",
            "action": "restrict",
            "result": "simulated:restrict:ok"
          },
          {
            "alert_id": "AL-0004",
            "action": "step_up",
            "result": "simulated:step_up:ok"
          }
        ],
        "pending_approval": [
          {
            "alert_id": "AL-0001",
            "action": "revoke"
          }
        ]
      },
      "last_error": "",
      "signals": null
    },
    {
      "id": "feedback",
      "num": 14,
      "name": "Feedback Learning Agent",
      "layer": "learning",
      "pattern": null,
      "role": "Tunes detector weights from analyst labels",
      "permissions": [
        "write:weights"
      ],
      "state": "idle",
      "runs": 0,
      "last_started": null,
      "last_finished": null,
      "last_duration_ms": null,
      "last_message": "",
      "last_output": null,
      "last_error": "",
      "signals": null
    },
    {
      "id": "orchestrator",
      "num": 15,
      "name": "Orchestrator & Supervisor Agent",
      "layer": "oversight",
      "pattern": null,
      "role": "Runs the agents in order, deduplicates, guards safety, logs threats",
      "permissions": [
        "coordinate",
        "write:audit"
      ],
      "state": "done",
      "runs": 1,
      "last_started": "2026-10-28T16:11:21.249224+00:00",
      "last_finished": "2026-10-28T16:11:21.257797+00:00",
      "last_duration_ms": 8.6,
      "last_message": "Scan complete · 4 threat(s) logged",
      "last_output": {
        "status": "ok",
        "alerts": 4,
        "threats_logged": 4,
        "detail": ""
      },
      "last_error": "",
      "signals": null
    }
  ],
  "run": {
    "run_id": "scan-20261028-161121-43d1",
    "mode": "dataset",
    "state": "done",
    "started_at": "2026-10-28T16:11:21.249206+00:00",
    "finished_at": "2026-10-28T16:11:21.257774+00:00",
    "duration_ms": 8.6,
    "current": null,
    "completed": [
      "ingestion",
      "normalization",
      "enrichment",
      "correlation",
      "impossible_travel",
      "dormant",
      "priv_escalation",
      "api_anomaly",
      "token_abuse",
      "baseline_ml",
      "risk_scoring",
      "explanation",
      "response"
    ],
    "failed": [],
    "threats": 4,
    "summary": {
      "status": "ok",
      "alerts": 4,
      "threats_logged": 4,
      "detail": ""
    },
    "total_steps": 13,
    "progress": 1.0,
    "last_seq": 32
  }
}
```

## static/mock/scan_status.json

```json
{
  "run_id": "scan-20261028-161121-43d1",
  "mode": "dataset",
  "state": "done",
  "started_at": "2026-10-28T16:11:21.249206+00:00",
  "finished_at": "2026-10-28T16:11:21.257774+00:00",
  "duration_ms": 8.6,
  "current": null,
  "completed": [
    "ingestion",
    "normalization",
    "enrichment",
    "correlation",
    "impossible_travel",
    "dormant",
    "priv_escalation",
    "api_anomaly",
    "token_abuse",
    "baseline_ml",
    "risk_scoring",
    "explanation",
    "response"
  ],
  "failed": [],
  "threats": 4,
  "summary": {
    "status": "ok",
    "alerts": 4,
    "threats_logged": 4,
    "detail": ""
  },
  "total_steps": 13,
  "progress": 1.0,
  "last_seq": 32
}
```

## static/mock/scan_trace.json

```json
{
  "run_id": "scan-20261028-161121-43d1",
  "state": "done",
  "last_seq": 32,
  "events": [
    {
      "seq": 1,
      "run_id": "scan-20261028-161121-43d1",
      "ts": "2026-10-28T16:11:21.249224+00:00",
      "agent_id": "orchestrator",
      "agent_num": 15,
      "agent_name": "Orchestrator & Supervisor Agent",
      "layer": "oversight",
      "state": "started",
      "level": "info",
      "message": "Scan started · mode dataset · 15 agents on duty",
      "duration_ms": null,
      "data": {
        "run_id": "scan-20261028-161121-43d1",
        "mode": "dataset",
        "agents": [
          "Log Ingestion Agent",
          "Normalization Agent",
          "Enrichment Agent",
          "Session Correlation Agent",
          "Impossible Travel Agent",
          "Dormant Account Agent",
          "Privilege Escalation Agent",
          "API Anomaly Agent",
          "Token Abuse Agent",
          "Behavior Baseline Agent (ML)",
          "Risk Scoring Agent",
          "Explanation Agent",
          "Response Agent",
          "Feedback Learning Agent",
          "Orchestrator & Supervisor Agent"
        ]
      }
    },
    {
      "seq": 2,
      "run_id": "scan-20261028-161121-43d1",
      "ts": "2026-10-28T16:11:21.249359+00:00",
      "agent_id": "ingestion",
      "agent_num": 1,
      "agent_name": "Log Ingestion Agent",
      "layer": "data",
      "state": "started",
      "level": "info",
      "message": "Loading CloudTrail and Okta files",
      "duration_ms": null,
      "data": null
    },
    {
      "seq": 3,
      "run_id": "scan-20261028-161121-43d1",
      "ts": "2026-10-28T16:11:21.249395+00:00",
      "agent_id": "ingestion",
      "agent_num": 1,
      "agent_name": "Log Ingestion Agent",
      "layer": "data",
      "state": "done",
      "level": "ok",
      "message": "Loaded 2,967 records from 2 files",
      "duration_ms": 0.0,
      "data": {
        "files": {
          "cloudtrail": [
            "cloudtrail.json"
          ],
          "okta": [
            "okta.json"
          ]
        },
        "records": {
          "cloudtrail": 2214,
          "okta": 753
        },
        "skipped": 0
      }
    },
    {
      "seq": 4,
      "run_id": "scan-20261028-161121-43d1",
      "ts": "2026-10-28T16:11:21.249537+00:00",
      "agent_id": "normalization",
      "agent_num": 2,
      "agent_name": "Normalization Agent",
      "layer": "data",
      "state": "started",
      "level": "info",
      "message": "Mapping both formats to the unified event schema",
      "duration_ms": null,
      "data": null
    },
    {
      "seq": 5,
      "run_id": "scan-20261028-161121-43d1",
      "ts": "2026-10-28T16:11:21.249577+00:00",
      "agent_id": "normalization",
      "agent_num": 2,
      "agent_name": "Normalization Agent",
      "layer": "data",
      "state": "done",
      "level": "ok",
      "message": "2,967 events normalized for 21 identities",
      "duration_ms": 0.0,
      "data": {
        "events": 2967,
        "skipped": 0,
        "sources": {
          "cloudtrail": 2214,
          "okta": 753
        },
        "identities": 21,
        "sample_event": {
          "event_id": "ct-1a7f",
          "source": "cloudtrail",
          "timestamp": "2026-10-28T04:21:12+00:00",
          "identity_id": "svc-report",
          "action": "AttachUserPolicy",
          "category": "api",
          "src_ip": "185.220.101.4",
          "resource": "arn:aws:iam::aws:policy/AdministratorAccess"
        }
      }
    },
    {
      "seq": 6,
      "run_id": "scan-20261028-161121-43d1",
      "ts": "2026-10-28T16:11:21.249635+00:00",
      "agent_id": "enrichment",
      "agent_num": 3,
      "agent_name": "Enrichment Agent",
      "layer": "data",
      "state": "started",
      "level": "info",
      "message": "Adding geo, privilege level and resource sensitivity",
      "duration_ms": null,
      "data": null
    },
    {
      "seq": 7,
      "run_id": "scan-20261028-161121-43d1",
      "ts": "2026-10-28T16:11:21.249652+00:00",
      "agent_id": "enrichment",
      "agent_num": 3,
      "agent_name": "Enrichment Agent",
      "layer": "data",
      "state": "done",
      "level": "ok",
      "message": "Enriched 2,967 events · 61 touch sensitive resources",
      "duration_ms": 0.0,
      "data": {
        "geo_filled": 2140,
        "privileged_identities": 3,
        "sensitive_events": 61
      }
    },
    {
      "seq": 8,
      "run_id": "scan-20261028-161121-43d1",
      "ts": "2026-10-28T16:11:21.249680+00:00",
      "agent_id": "correlation",
      "agent_num": 4,
      "agent_name": "Session Correlation Agent",
      "layer": "data",
      "state": "started",
      "level": "info",
      "message": "Linking Okta sessions to AWS activity",
      "duration_ms": null,
      "data": null
    },
    {
      "seq": 9,
      "run_id": "scan-20261028-161121-43d1",
      "ts": "2026-10-28T16:11:21.249696+00:00",
      "agent_id": "correlation",
      "agent_num": 4,
      "agent_name": "Session Correlation Agent",
      "layer": "data",
      "state": "done",
      "level": "ok",
      "message": "412 sessions · identity graph 964 nodes / 3,311 edges",
      "duration_ms": 0.0,
      "data": {
        "sessions": 412,
        "okta_linked": 388,
        "aws_only": 24,
        "graph": {
          "nodes": 964,
          "edges": 3311
        }
      }
    },
    {
      "seq": 10,
      "run_id": "scan-20261028-161121-43d1",
      "ts": "2026-10-28T16:11:21.249725+00:00",
      "agent_id": "impossible_travel",
      "agent_num": 5,
      "agent_name": "Impossible Travel Agent",
      "layer": "detection",
      "state": "started",
      "level": "info",
      "message": "Checking login pairs for impossible travel",
      "duration_ms": null,
      "data": null
    },
    {
      "seq": 11,
      "run_id": "scan-20261028-161121-43d1",
      "ts": "2026-10-28T16:11:21.249738+00:00",
      "agent_id": "impossible_travel",
      "agent_num": 5,
      "agent_name": "Impossible Travel Agent",
      "layer": "detection",
      "state": "done",
      "level": "ok",
      "message": "1 signal · anita.rao 14,812 km/h",
      "duration_ms": 0.0,
      "data": {
        "signals": 1,
        "pairs_checked": 731,
        "examples": [
          {
            "identity_id": "anita.rao",
            "from": "Bengaluru",
            "to": "Frankfurt",
            "km": 7406,
            "minutes": 30,
            "kmh": 14812
          }
        ]
      }
    },
    {
      "seq": 12,
      "run_id": "scan-20261028-161121-43d1",
      "ts": "2026-10-28T16:11:21.249769+00:00",
      "agent_id": "dormant",
      "agent_num": 6,
      "agent_name": "Dormant Account Agent",
      "layer": "detection",
      "state": "started",
      "level": "info",
      "message": "Looking for dormant accounts that woke up",
      "duration_ms": null,
      "data": null
    },
    {
      "seq": 13,
      "run_id": "scan-20261028-161121-43d1",
      "ts": "2026-10-28T16:11:21.249786+00:00",
      "agent_id": "dormant",
      "agent_num": 6,
      "agent_name": "Dormant Account Agent",
      "layer": "detection",
      "state": "done",
      "level": "ok",
      "message": "1 signal · svc-report idle 47 days",
      "duration_ms": 0.0,
      "data": {
        "signals": 1,
        "examples": [
          {
            "identity_id": "svc-report",
            "idle_days": 47,
            "privilege_level": 5
          }
        ]
      }
    },
    {
      "seq": 14,
      "run_id": "scan-20261028-161121-43d1",
      "ts": "2026-10-28T16:11:21.249811+00:00",
      "agent_id": "priv_escalation",
      "agent_num": 7,
      "agent_name": "Privilege Escalation Agent",
      "layer": "detection",
      "state": "started",
      "level": "info",
      "message": "Reconstructing privilege-escalation chains",
      "duration_ms": null,
      "data": null
    },
    {
      "seq": 15,
      "run_id": "scan-20261028-161121-43d1",
      "ts": "2026-10-28T16:11:21.249824+00:00",
      "agent_id": "priv_escalation",
      "agent_num": 7,
      "agent_name": "Privilege Escalation Agent",
      "layer": "detection",
      "state": "done",
      "level": "ok",
      "message": "1 chain · 4 steps in 11 min",
      "duration_ms": 0.0,
      "data": {
        "signals": 1,
        "chains": [
          {
            "session_id": "okta:102svcR7",
            "steps": [
              "CredCreate",
              "PermGrant",
              "RoleAssume",
              "Impact"
            ],
            "minutes": 11
          }
        ]
      }
    },
    {
      "seq": 16,
      "run_id": "scan-20261028-161121-43d1",
      "ts": "2026-10-28T16:11:21.249852+00:00",
      "agent_id": "api_anomaly",
      "agent_num": 8,
      "agent_name": "API Anomaly Agent",
      "layer": "detection",
      "state": "started",
      "level": "info",
      "message": "Scoring API calls for rarity and sensitivity",
      "duration_ms": null,
      "data": null
    },
    {
      "seq": 17,
      "run_id": "scan-20261028-161121-43d1",
      "ts": "2026-10-28T16:11:21.249865+00:00",
      "agent_id": "api_anomaly",
      "agent_num": 8,
      "agent_name": "API Anomaly Agent",
      "layer": "detection",
      "state": "done",
      "level": "ok",
      "message": "2 signals · StopLogging in a new region",
      "duration_ms": 0.0,
      "data": {
        "signals": 2,
        "examples": [
          {
            "identity_id": "dev.kumar",
            "action": "StopLogging",
            "region": "sa-east-1",
            "new_region": true
          }
        ]
      }
    },
    {
      "seq": 18,
      "run_id": "scan-20261028-161121-43d1",
      "ts": "2026-10-28T16:11:21.249889+00:00",
      "agent_id": "token_abuse",
      "agent_num": 9,
      "agent_name": "Token Abuse Agent",
      "layer": "detection",
      "state": "started",
      "level": "info",
      "message": "Checking token and session reuse",
      "duration_ms": null,
      "data": null
    },
    {
      "seq": 19,
      "run_id": "scan-20261028-161121-43d1",
      "ts": "2026-10-28T16:11:21.249902+00:00",
      "agent_id": "token_abuse",
      "agent_num": 9,
      "agent_name": "Token Abuse Agent",
      "layer": "detection",
      "state": "done",
      "level": "ok",
      "message": "1 signal · same key in IN and BR within 3 min",
      "duration_ms": 0.0,
      "data": {
        "signals": 1,
        "examples": [
          {
            "identity_id": "meera.n",
            "token": "AKIA...Q7",
            "countries": [
              "IN",
              "BR"
            ],
            "minutes": 3
          }
        ]
      }
    },
    {
      "seq": 20,
      "run_id": "scan-20261028-161121-43d1",
      "ts": "2026-10-28T16:11:21.249928+00:00",
      "agent_id": "baseline_ml",
      "agent_num": 10,
      "agent_name": "Behavior Baseline Agent (ML)",
      "layer": "detection",
      "state": "started",
      "level": "info",
      "message": "Isolation Forest over 412 session feature vectors",
      "duration_ms": null,
      "data": null
    },
    {
      "seq": 21,
      "run_id": "scan-20261028-161121-43d1",
      "ts": "2026-10-28T16:11:21.249942+00:00",
      "agent_id": "baseline_ml",
      "agent_num": 10,
      "agent_name": "Behavior Baseline Agent (ML)",
      "layer": "detection",
      "state": "done",
      "level": "ok",
      "message": "2 sessions above anomaly threshold 0.60",
      "duration_ms": 0.0,
      "data": {
        "signals": 2,
        "trained_on": 398,
        "features": 13,
        "top_scores": [
          {
            "session_id": "okta:55aniK9",
            "score": 0.91
          },
          {
            "session_id": "okta:102svcR7",
            "score": 0.84
          }
        ]
      }
    },
    {
      "seq": 22,
      "run_id": "scan-20261028-161121-43d1",
      "ts": "2026-10-28T16:11:21.249976+00:00",
      "agent_id": "risk_scoring",
      "agent_num": 11,
      "agent_name": "Risk Scoring Agent",
      "layer": "decision",
      "state": "started",
      "level": "info",
      "message": "Combining signals x privilege x sensitivity",
      "duration_ms": null,
      "data": null
    },
    {
      "seq": 23,
      "run_id": "scan-20261028-161121-43d1",
      "ts": "2026-10-28T16:11:21.249992+00:00",
      "agent_id": "risk_scoring",
      "agent_num": 11,
      "agent_name": "Risk Scoring Agent",
      "layer": "decision",
      "state": "done",
      "level": "ok",
      "message": "4 alerts · top risk 94 (svc-report)",
      "duration_ms": 0.0,
      "data": {
        "sessions_scored": 7,
        "alerts": 4,
        "bands": {
          "revoke": 1,
          "restrict": 2,
          "step_up": 1,
          "monitor": 0
        },
        "top": {
          "alert_id": "AL-0001",
          "risk": 94.0
        }
      }
    },
    {
      "seq": 24,
      "run_id": "scan-20261028-161121-43d1",
      "ts": "2026-10-28T16:11:21.250021+00:00",
      "agent_id": "explanation",
      "agent_num": 12,
      "agent_name": "Explanation Agent",
      "layer": "decision",
      "state": "started",
      "level": "info",
      "message": "Writing reasons, counterfactuals and MITRE tags",
      "duration_ms": null,
      "data": null
    },
    {
      "seq": 25,
      "run_id": "scan-20261028-161121-43d1",
      "ts": "2026-10-28T16:11:21.250035+00:00",
      "agent_id": "explanation",
      "agent_num": 12,
      "agent_name": "Explanation Agent",
      "layer": "decision",
      "state": "done",
      "level": "ok",
      "message": "4 alerts explained with evidence",
      "duration_ms": 0.0,
      "data": {
        "alerts_explained": 4,
        "counterfactuals": {
          "AL-0001": {
            "without P3": 44.0,
            "without P2": 61.0
          }
        },
        "mitre": [
          "T1078",
          "T1078.004",
          "T1098",
          "T1526",
          "T1539",
          "T1548",
          "T1550",
          "T1562"
        ]
      }
    },
    {
      "seq": 26,
      "run_id": "scan-20261028-161121-43d1",
      "ts": "2026-10-28T16:11:21.250064+00:00",
      "agent_id": "response",
      "agent_num": 13,
      "agent_name": "Response Agent",
      "layer": "decision",
      "state": "started",
      "level": "info",
      "message": "Choosing actions (simulator only)",
      "duration_ms": null,
      "data": null
    },
    {
      "seq": 27,
      "run_id": "scan-20261028-161121-43d1",
      "ts": "2026-10-28T16:11:21.250075+00:00",
      "agent_id": "response",
      "agent_num": 13,
      "agent_name": "Response Agent",
      "layer": "decision",
      "state": "done",
      "level": "ok",
      "message": "3 actions applied · 1 revoke awaiting analyst approval",
      "duration_ms": 0.0,
      "data": {
        "applied": [
          {
            "alert_id": "AL-0002",
            "action": "restrict",
            "result": "simulated:restrict:ok"
          },
          {
            "alert_id": "AL-0003",
            "action": "restrict",
            "result": "simulated:restrict:ok"
          },
          {
            "alert_id": "AL-0004",
            "action": "step_up",
            "result": "simulated:step_up:ok"
          }
        ],
        "pending_approval": [
          {
            "alert_id": "AL-0001",
            "action": "revoke"
          }
        ]
      }
    },
    {
      "seq": 28,
      "run_id": "scan-20261028-161121-43d1",
      "ts": "2026-10-28T16:11:21.251964+00:00",
      "agent_id": "priv_escalation",
      "agent_num": 7,
      "agent_name": "Privilege Escalation Agent",
      "layer": "detection",
      "state": "threat",
      "level": "crit",
      "message": "THREAT DETECTED · svc-report · risk 94 (revoke) · Privilege escalation, Dormant account",
      "duration_ms": null,
      "data": {
        "fingerprint": "svc-report|okta:102svcR7|revoke",
        "alert_id": "AL-0001",
        "identity_id": "svc-report",
        "session_id": "okta:102svcR7",
        "risk": 94.0,
        "band": "revoke",
        "patterns": [
          "P3",
          "P2"
        ],
        "mitre": [
          "T1098",
          "T1548",
          "T1078.004"
        ],
        "detectors": [
          "dormant",
          "priv_escalation"
        ],
        "evidence_count": 5,
        "evidence_sample": [
          "okta-8f1d",
          "ct-1a2c",
          "ct-1a7f",
          "ct-1b03",
          "ct-1b19"
        ],
        "recommended_action": "revoke",
        "reason": "Escalation chain: CreateAccessKey -> AttachUserPolicy -> AssumeRole -> GetSecretValue within 11 min.",
        "run_id": "scan-20261028-161121-43d1"
      }
    },
    {
      "seq": 29,
      "run_id": "scan-20261028-161121-43d1",
      "ts": "2026-10-28T16:11:21.254228+00:00",
      "agent_id": "token_abuse",
      "agent_num": 9,
      "agent_name": "Token Abuse Agent",
      "layer": "detection",
      "state": "threat",
      "level": "crit",
      "message": "THREAT DETECTED · meera.n · risk 88 (restrict) · Token abuse",
      "duration_ms": null,
      "data": {
        "fingerprint": "meera.n|okta:77meeQ2|restrict",
        "alert_id": "AL-0002",
        "identity_id": "meera.n",
        "session_id": "okta:77meeQ2",
        "risk": 88.0,
        "band": "restrict",
        "patterns": [
          "P5"
        ],
        "mitre": [
          "T1550",
          "T1539"
        ],
        "detectors": [
          "token_abuse"
        ],
        "evidence_count": 2,
        "evidence_sample": [
          "ct-2c11",
          "ct-2c19"
        ],
        "recommended_action": "restrict",
        "reason": "Access key AKIA...Q7 used from India and Brazil within 3 minutes.",
        "run_id": "scan-20261028-161121-43d1"
      }
    },
    {
      "seq": 30,
      "run_id": "scan-20261028-161121-43d1",
      "ts": "2026-10-28T16:11:21.256105+00:00",
      "agent_id": "impossible_travel",
      "agent_num": 5,
      "agent_name": "Impossible Travel Agent",
      "layer": "detection",
      "state": "threat",
      "level": "crit",
      "message": "THREAT DETECTED · anita.rao · risk 78 (restrict) · Impossible travel, Behavior anomaly",
      "duration_ms": null,
      "data": {
        "fingerprint": "anita.rao|okta:55aniK9|restrict",
        "alert_id": "AL-0003",
        "identity_id": "anita.rao",
        "session_id": "okta:55aniK9",
        "risk": 78.0,
        "band": "restrict",
        "patterns": [
          "P1",
          "ML"
        ],
        "mitre": [
          "T1078"
        ],
        "detectors": [
          "baseline_ml",
          "impossible_travel"
        ],
        "evidence_count": 2,
        "evidence_sample": [
          "okta-3e02",
          "okta-3e09"
        ],
        "recommended_action": "restrict",
        "reason": "Login from Frankfurt, 7,406 km from Bengaluru, 30 min after previous login (14,812 km/h).",
        "run_id": "scan-20261028-161121-43d1"
      }
    },
    {
      "seq": 31,
      "run_id": "scan-20261028-161121-43d1",
      "ts": "2026-10-28T16:11:21.257675+00:00",
      "agent_id": "api_anomaly",
      "agent_num": 8,
      "agent_name": "API Anomaly Agent",
      "layer": "detection",
      "state": "threat",
      "level": "crit",
      "message": "THREAT DETECTED · dev.kumar · risk 62 (step_up) · Unusual API",
      "duration_ms": null,
      "data": {
        "fingerprint": "dev.kumar|aws:dev.kumar:7|step_up",
        "alert_id": "AL-0004",
        "identity_id": "dev.kumar",
        "session_id": "aws:dev.kumar:7",
        "risk": 62.0,
        "band": "step_up",
        "patterns": [
          "P4"
        ],
        "mitre": [
          "T1526",
          "T1562"
        ],
        "detectors": [
          "api_anomaly"
        ],
        "evidence_count": 1,
        "evidence_sample": [
          "ct-4d70"
        ],
        "recommended_action": "step_up",
        "reason": "StopLogging called in sa-east-1, a region this identity never used.",
        "run_id": "scan-20261028-161121-43d1"
      }
    },
    {
      "seq": 32,
      "run_id": "scan-20261028-161121-43d1",
      "ts": "2026-10-28T16:11:21.257797+00:00",
      "agent_id": "orchestrator",
      "agent_num": 15,
      "agent_name": "Orchestrator & Supervisor Agent",
      "layer": "oversight",
      "state": "done",
      "level": "ok",
      "message": "Scan complete · 4 threat(s) logged",
      "duration_ms": 8.6,
      "data": {
        "status": "ok",
        "alerts": 4,
        "threats_logged": 4,
        "detail": ""
      }
    }
  ]
}
```

## static/mock/inputs.json

```json
{
  "files": [
    {
      "source": "cloudtrail",
      "file": "cloudtrail_20261028T162032389684_trail-export.jsonl",
      "records": 120,
      "bytes": 14290,
      "modified": "2026-10-28T10:05:00+00:00"
    },
    {
      "source": "cloudtrail",
      "file": "cloudtrail_manual.jsonl",
      "records": 1,
      "bytes": 586,
      "modified": "2026-10-28T10:05:00+00:00"
    },
    {
      "source": "okta",
      "file": "okta_manual.jsonl",
      "records": 1,
      "bytes": 580,
      "modified": "2026-10-28T10:05:00+00:00"
    }
  ],
  "totals": {
    "cloudtrail": 121,
    "okta": 1
  },
  "total_records": 122,
  "limits": {
    "max_bytes": 5000000,
    "max_records": 50000
  }
}
```

## static/mock/identities.json

```json
[
  {
    "identity_id": "svc-report",
    "risk": 94.0,
    "alerts": 2,
    "privilege_level": 5,
    "blast_radius": 4
  },
  {
    "identity_id": "meera.n",
    "risk": 88.0,
    "alerts": 1,
    "privilege_level": 2,
    "blast_radius": 1
  },
  {
    "identity_id": "anita.rao",
    "risk": 78.0,
    "alerts": 1,
    "privilege_level": 1,
    "blast_radius": 0
  }
]
```

## static/mock/graph_attack.json

```json
{
  "identity_id": "svc-report",
  "identity": {
    "identity_id": "svc-report",
    "risk": 94.0,
    "alerts": 2,
    "privilege_level": 5,
    "blast_radius": 4
  },
  "graph": {
    "identity_id": "svc-report",
    "nodes": [
      {
        "id": "user:svc-report",
        "label": "svc-report",
        "kind": "user",
        "risk": 94.0
      },
      {
        "id": "session:okta:102svcR7",
        "label": "okta:102svcR7",
        "kind": "session",
        "risk": 94.0
      },
      {
        "id": "session:okta:88svcA1",
        "label": "okta:88svcA1",
        "kind": "session",
        "risk": 0.0
      },
      {
        "id": "ip:185.220.101.4",
        "label": "185.220.101.4",
        "kind": "ip",
        "risk": 0.0
      },
      {
        "id": "ip:49.207.12.8",
        "label": "49.207.12.8",
        "kind": "ip",
        "risk": 0.0
      },
      {
        "id": "key:AKIA...R7Q2",
        "label": "AKIA…R7Q2",
        "kind": "key",
        "risk": 0.0
      },
      {
        "id": "policy:AdministratorAccess",
        "label": "AdministratorAccess",
        "kind": "policy",
        "risk": 0.0
      },
      {
        "id": "role:AdminRole",
        "label": "AdminRole",
        "kind": "role",
        "risk": 0.0
      },
      {
        "id": "role:ReportReader",
        "label": "ReportReader",
        "kind": "role",
        "risk": 0.0
      },
      {
        "id": "res:arn:aws:secretsmanager:ap-south-1:123456789012:secret:prod/db",
        "label": "secret:prod/db",
        "kind": "resource",
        "risk": 0.0
      },
      {
        "id": "res:s3://finance-backup",
        "label": "s3://finance-backup",
        "kind": "resource",
        "risk": 0.0
      },
      {
        "id": "res:s3://reports-public",
        "label": "s3://reports-public",
        "kind": "resource",
        "risk": 0.0
      },
      {
        "id": "res:arn:aws:kms:ap-south-1:123456789012:key/7f1c",
        "label": "kms:key/7f1c",
        "kind": "resource",
        "risk": 0.0
      },
      {
        "id": "res:cloudtrail:org-trail",
        "label": "cloudtrail:org-trail",
        "kind": "resource",
        "risk": 0.0
      }
    ],
    "edges": [
      {
        "source": "user:svc-report",
        "target": "session:okta:88svcA1",
        "label": "login",
        "event_id": "okta-0a11",
        "suspicious": false
      },
      {
        "source": "session:okta:88svcA1",
        "target": "ip:49.207.12.8",
        "label": "from_ip",
        "event_id": "okta-0a11",
        "suspicious": false
      },
      {
        "source": "session:okta:88svcA1",
        "target": "role:ReportReader",
        "label": "assumed",
        "event_id": "ct-0b20",
        "suspicious": false
      },
      {
        "source": "role:ReportReader",
        "target": "res:s3://reports-public",
        "label": "accessed",
        "event_id": "ct-0b21",
        "suspicious": false
      },
      {
        "source": "user:svc-report",
        "target": "session:okta:102svcR7",
        "label": "login",
        "event_id": "okta-8f1d",
        "suspicious": true
      },
      {
        "source": "session:okta:102svcR7",
        "target": "ip:185.220.101.4",
        "label": "from_ip",
        "event_id": "okta-8f1d",
        "suspicious": true
      },
      {
        "source": "user:svc-report",
        "target": "key:AKIA...R7Q2",
        "label": "created_key",
        "event_id": "ct-1a2c",
        "suspicious": true
      },
      {
        "source": "user:svc-report",
        "target": "policy:AdministratorAccess",
        "label": "attached",
        "event_id": "ct-1a7f",
        "suspicious": true
      },
      {
        "source": "session:okta:102svcR7",
        "target": "role:AdminRole",
        "label": "assumed",
        "event_id": "ct-1b03",
        "suspicious": true
      },
      {
        "source": "role:AdminRole",
        "target": "res:arn:aws:secretsmanager:ap-south-1:123456789012:secret:prod/db",
        "label": "accessed",
        "event_id": "ct-1b19",
        "suspicious": true
      },
      {
        "source": "role:AdminRole",
        "target": "res:s3://finance-backup",
        "label": "can_access",
        "event_id": null,
        "suspicious": false
      },
      {
        "source": "role:AdminRole",
        "target": "res:arn:aws:kms:ap-south-1:123456789012:key/7f1c",
        "label": "can_access",
        "event_id": null,
        "suspicious": false
      },
      {
        "source": "role:AdminRole",
        "target": "res:cloudtrail:org-trail",
        "label": "can_access",
        "event_id": null,
        "suspicious": false
      }
    ],
    "escalation_paths": [
      [
        "user:svc-report",
        "policy:AdministratorAccess"
      ],
      [
        "user:svc-report",
        "session:okta:102svcR7",
        "role:AdminRole"
      ]
    ]
  },
  "alert": {
    "alert_id": "AL-0001",
    "level": "session",
    "identity_id": "svc-report",
    "session_id": "okta:102svcR7",
    "risk": 94.0,
    "confidence": 0.9,
    "blast_radius": 4,
    "band": "revoke",
    "patterns": [
      "P3",
      "P2",
      "P1"
    ],
    "mitre": [
      "T1098",
      "T1548",
      "T1078.004"
    ],
    "reasons": [
      "Escalation chain: CreateAccessKey -> AttachUserPolicy -> AssumeRole -> GetSecretValue within 11 min.",
      "Account inactive for 47 days before this activity."
    ],
    "evidence_event_ids": [
      "okta-8f1d",
      "ct-1a2c",
      "ct-1a7f",
      "ct-1b03",
      "ct-1b19"
    ],
    "chain": [
      {
        "event_id": "ct-1a2c",
        "action": "CreateAccessKey",
        "state": "CredCreate",
        "timestamp": "2026-10-28T04:12:40Z"
      },
      {
        "event_id": "ct-1a7f",
        "action": "AttachUserPolicy",
        "state": "PermGrant",
        "timestamp": "2026-10-28T04:16:02Z"
      },
      {
        "event_id": "ct-1b03",
        "action": "AssumeRole",
        "state": "RoleAssume",
        "timestamp": "2026-10-28T04:19:31Z"
      },
      {
        "event_id": "ct-1b19",
        "action": "GetSecretValue",
        "state": "Impact",
        "timestamp": "2026-10-28T04:23:55Z"
      }
    ],
    "prediction": {
      "next_state": "Impact",
      "probability": 0.71
    },
    "counterfactuals": [
      {
        "without": "P3",
        "risk": 44.0
      },
      {
        "without": "P2",
        "risk": 61.0
      }
    ],
    "recommended_action": "revoke",
    "action_status": "pending",
    "feedback": null,
    "first_seen": "2026-10-28T04:10:11Z",
    "last_seen": "2026-10-28T04:23:55Z"
  },
  "blast_radius": 4
}
```

## static/mock/graph_global.json

```json
{
  "identities": [
    "svc-report",
    "meera.n",
    "anita.rao"
  ],
  "nodes": [
    {
      "id": "user:svc-report",
      "label": "svc-report",
      "kind": "user",
      "risk": 94.0
    },
    {
      "id": "user:meera.n",
      "label": "meera.n",
      "kind": "user",
      "risk": 88.0
    },
    {
      "id": "user:anita.rao",
      "label": "anita.rao",
      "kind": "user",
      "risk": 78.0
    },
    {
      "id": "session:okta:102svcR7",
      "label": "okta:102svcR7",
      "kind": "session",
      "risk": 94.0
    },
    {
      "id": "session:okta:77meeQ2",
      "label": "okta:77meeQ2",
      "kind": "session",
      "risk": 88.0
    },
    {
      "id": "session:okta:55aniK9",
      "label": "okta:55aniK9",
      "kind": "session",
      "risk": 78.0
    },
    {
      "id": "key:AKIA...R7Q2",
      "label": "AKIA…R7Q2",
      "kind": "key",
      "risk": 0.0
    },
    {
      "id": "key:AKIA...Q7",
      "label": "AKIA…Q7",
      "kind": "key",
      "risk": 0.0
    },
    {
      "id": "policy:AdministratorAccess",
      "label": "AdministratorAccess",
      "kind": "policy",
      "risk": 0.0
    },
    {
      "id": "role:AdminRole",
      "label": "AdminRole",
      "kind": "role",
      "risk": 0.0
    },
    {
      "id": "ip:185.220.101.4",
      "label": "185.220.101.4",
      "kind": "ip",
      "risk": 0.0
    },
    {
      "id": "ip:177.71.200.9",
      "label": "177.71.200.9",
      "kind": "ip",
      "risk": 0.0
    },
    {
      "id": "ip:49.207.12.8",
      "label": "49.207.12.8",
      "kind": "ip",
      "risk": 0.0
    },
    {
      "id": "ip:91.64.18.2",
      "label": "91.64.18.2",
      "kind": "ip",
      "risk": 0.0
    },
    {
      "id": "res:secret:prod/db",
      "label": "secret:prod/db",
      "kind": "resource",
      "risk": 0.0
    },
    {
      "id": "res:s3://finance-backup",
      "label": "s3://finance-backup",
      "kind": "resource",
      "risk": 0.0
    }
  ],
  "edges": [
    {
      "source": "user:svc-report",
      "target": "session:okta:102svcR7",
      "label": "login",
      "event_id": "okta-8f1d",
      "suspicious": true
    },
    {
      "source": "user:svc-report",
      "target": "key:AKIA...R7Q2",
      "label": "created_key",
      "event_id": "ct-1a2c",
      "suspicious": true
    },
    {
      "source": "user:svc-report",
      "target": "policy:AdministratorAccess",
      "label": "attached",
      "event_id": "ct-1a7f",
      "suspicious": true
    },
    {
      "source": "session:okta:102svcR7",
      "target": "role:AdminRole",
      "label": "assumed",
      "event_id": "ct-1b03",
      "suspicious": true
    },
    {
      "source": "role:AdminRole",
      "target": "res:secret:prod/db",
      "label": "accessed",
      "event_id": "ct-1b19",
      "suspicious": true
    },
    {
      "source": "role:AdminRole",
      "target": "res:s3://finance-backup",
      "label": "can_access",
      "event_id": null,
      "suspicious": false
    },
    {
      "source": "session:okta:102svcR7",
      "target": "ip:185.220.101.4",
      "label": "from_ip",
      "event_id": "okta-8f1d",
      "suspicious": true
    },
    {
      "source": "user:meera.n",
      "target": "session:okta:77meeQ2",
      "label": "login",
      "event_id": "okta-77a1",
      "suspicious": false
    },
    {
      "source": "user:meera.n",
      "target": "key:AKIA...Q7",
      "label": "uses_key",
      "event_id": "ct-2c11",
      "suspicious": true
    },
    {
      "source": "key:AKIA...Q7",
      "target": "ip:49.207.12.8",
      "label": "from_ip",
      "event_id": "ct-2c11",
      "suspicious": false
    },
    {
      "source": "key:AKIA...Q7",
      "target": "ip:177.71.200.9",
      "label": "from_ip",
      "event_id": "ct-2c19",
      "suspicious": true
    },
    {
      "source": "user:anita.rao",
      "target": "session:okta:55aniK9",
      "label": "login",
      "event_id": "okta-3e09",
      "suspicious": true
    },
    {
      "source": "session:okta:55aniK9",
      "target": "ip:91.64.18.2",
      "label": "from_ip",
      "event_id": "okta-3e09",
      "suspicious": true
    },
    {
      "source": "session:okta:77meeQ2",
      "target": "ip:49.207.12.8",
      "label": "from_ip",
      "event_id": "okta-77a1",
      "suspicious": false
    }
  ],
  "truncated": false
}
```

## static/mock/events_AL-0001.json

```json
[
  {
    "event_id": "ct-1a7f",
    "source": "cloudtrail",
    "timestamp": "2026-10-28T04:16:02Z",
    "identity_id": "svc-report",
    "session_id": "okta:102svcR7",
    "action": "AttachUserPolicy",
    "category": "api",
    "outcome": "success",
    "src_ip": "185.220.101.4",
    "country": "NL",
    "city": "Amsterdam",
    "region": "ap-south-1",
    "resource": "arn:aws:iam::aws:policy/AdministratorAccess",
    "resource_sensitivity": 5,
    "privilege_level": 5,
    "label": "privilege_escalation"
  }
]
```
