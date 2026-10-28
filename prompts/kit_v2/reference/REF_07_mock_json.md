# Mock JSON fixtures for the new endpoints

Save each block as `static/mock/<name>.json`. They were generated from the reference code, so their shape matches the live API exactly.

| Mock file | Endpoint |
|---|---|
| analytics_detectors.json | GET /api/analytics/detectors |
| analytics_heatmap_time.json | GET /api/analytics/heatmap/time |
| analytics_heatmap_identities.json | GET /api/analytics/heatmap/identities |
| notifications.json | GET /api/notifications |
| notifications_status.json | GET /api/notifications/status |
| pipeline_status.json | GET /api/pipeline/status |

## static/mock/analytics_detectors.json

```json
{
  "labeled": true,
  "level": "session",
  "scenarios": [
    "dormant_reactivation",
    "impossible_travel",
    "privilege_escalation",
    "token_abuse",
    "unusual_api"
  ],
  "rows": [
    {
      "id": "rules",
      "label": "Rules (P1–P5)",
      "kind": "summary",
      "flagged": 6,
      "tp": 5,
      "fp": 1,
      "fn": 2,
      "precision": 0.833,
      "recall": 0.714,
      "f1": 0.769
    },
    {
      "id": "ml",
      "label": "ML (Isolation Forest)",
      "kind": "summary",
      "flagged": 4,
      "tp": 2,
      "fp": 2,
      "fn": 5,
      "precision": 0.5,
      "recall": 0.286,
      "f1": 0.364
    },
    {
      "id": "hybrid",
      "label": "Hybrid (final alerts)",
      "kind": "summary",
      "flagged": 7,
      "tp": 6,
      "fp": 1,
      "fn": 1,
      "precision": 0.857,
      "recall": 0.857,
      "f1": 0.857
    },
    {
      "id": "P1",
      "label": "P1 Impossible travel",
      "kind": "detector",
      "flagged": 1,
      "tp": 1,
      "fp": 0,
      "fn": 6,
      "precision": 1.0,
      "recall": 0.143,
      "f1": 0.25
    },
    {
      "id": "P2",
      "label": "P2 Dormant account",
      "kind": "detector",
      "flagged": 2,
      "tp": 2,
      "fp": 0,
      "fn": 5,
      "precision": 1.0,
      "recall": 0.286,
      "f1": 0.444
    },
    {
      "id": "P3",
      "label": "P3 Privilege escalation",
      "kind": "detector",
      "flagged": 1,
      "tp": 1,
      "fp": 0,
      "fn": 6,
      "precision": 1.0,
      "recall": 0.143,
      "f1": 0.25
    },
    {
      "id": "P4",
      "label": "P4 Unusual API",
      "kind": "detector",
      "flagged": 2,
      "tp": 1,
      "fp": 1,
      "fn": 6,
      "precision": 0.5,
      "recall": 0.143,
      "f1": 0.222
    },
    {
      "id": "P5",
      "label": "P5 Token abuse",
      "kind": "detector",
      "flagged": 1,
      "tp": 1,
      "fp": 0,
      "fn": 6,
      "precision": 1.0,
      "recall": 0.143,
      "f1": 0.25
    },
    {
      "id": "ML",
      "label": "ML Behavior anomaly",
      "kind": "detector",
      "flagged": 4,
      "tp": 2,
      "fp": 2,
      "fn": 5,
      "precision": 0.5,
      "recall": 0.286,
      "f1": 0.364
    }
  ],
  "matrix": [
    {
      "id": "rules",
      "label": "Rules (P1–P5)",
      "kind": "summary",
      "cells": [
        {
          "scenario": "dormant_reactivation",
          "caught": 1,
          "total": 1,
          "recall": 1.0
        },
        {
          "scenario": "impossible_travel",
          "caught": 1,
          "total": 1,
          "recall": 1.0
        },
        {
          "scenario": "privilege_escalation",
          "caught": 1,
          "total": 1,
          "recall": 1.0
        },
        {
          "scenario": "token_abuse",
          "caught": 1,
          "total": 2,
          "recall": 0.5
        },
        {
          "scenario": "unusual_api",
          "caught": 1,
          "total": 2,
          "recall": 0.5
        }
      ],
      "false_alarms": 1
    },
    {
      "id": "ml",
      "label": "ML (Isolation Forest)",
      "kind": "summary",
      "cells": [
        {
          "scenario": "dormant_reactivation",
          "caught": 0,
          "total": 1,
          "recall": 0.0
        },
        {
          "scenario": "impossible_travel",
          "caught": 1,
          "total": 1,
          "recall": 1.0
        },
        {
          "scenario": "privilege_escalation",
          "caught": 0,
          "total": 1,
          "recall": 0.0
        },
        {
          "scenario": "token_abuse",
          "caught": 0,
          "total": 2,
          "recall": 0.0
        },
        {
          "scenario": "unusual_api",
          "caught": 1,
          "total": 2,
          "recall": 0.5
        }
      ],
      "false_alarms": 2
    },
    {
      "id": "hybrid",
      "label": "Hybrid (final alerts)",
      "kind": "summary",
      "cells": [
        {
          "scenario": "dormant_reactivation",
          "caught": 1,
          "total": 1,
          "recall": 1.0
        },
        {
          "scenario": "impossible_travel",
          "caught": 1,
          "total": 1,
          "recall": 1.0
        },
        {
          "scenario": "privilege_escalation",
          "caught": 1,
          "total": 1,
          "recall": 1.0
        },
        {
          "scenario": "token_abuse",
          "caught": 1,
          "total": 2,
          "recall": 0.5
        },
        {
          "scenario": "unusual_api",
          "caught": 2,
          "total": 2,
          "recall": 1.0
        }
      ],
      "false_alarms": 1
    },
    {
      "id": "P1",
      "label": "P1 Impossible travel",
      "kind": "detector",
      "cells": [
        {
          "scenario": "dormant_reactivation",
          "caught": 0,
          "total": 1,
          "recall": 0.0
        },
        {
          "scenario": "impossible_travel",
          "caught": 1,
          "total": 1,
          "recall": 1.0
        },
        {
          "scenario": "privilege_escalation",
          "caught": 0,
          "total": 1,
          "recall": 0.0
        },
        {
          "scenario": "token_abuse",
          "caught": 0,
          "total": 2,
          "recall": 0.0
        },
        {
          "scenario": "unusual_api",
          "caught": 0,
          "total": 2,
          "recall": 0.0
        }
      ],
      "false_alarms": 0
    },
    {
      "id": "P2",
      "label": "P2 Dormant account",
      "kind": "detector",
      "cells": [
        {
          "scenario": "dormant_reactivation",
          "caught": 1,
          "total": 1,
          "recall": 1.0
        },
        {
          "scenario": "impossible_travel",
          "caught": 0,
          "total": 1,
          "recall": 0.0
        },
        {
          "scenario": "privilege_escalation",
          "caught": 1,
          "total": 1,
          "recall": 1.0
        },
        {
          "scenario": "token_abuse",
          "caught": 0,
          "total": 2,
          "recall": 0.0
        },
        {
          "scenario": "unusual_api",
          "caught": 0,
          "total": 2,
          "recall": 0.0
        }
      ],
      "false_alarms": 0
    },
    {
      "id": "P3",
      "label": "P3 Privilege escalation",
      "kind": "detector",
      "cells": [
        {
          "scenario": "dormant_reactivation",
          "caught": 0,
          "total": 1,
          "recall": 0.0
        },
        {
          "scenario": "impossible_travel",
          "caught": 0,
          "total": 1,
          "recall": 0.0
        },
        {
          "scenario": "privilege_escalation",
          "caught": 1,
          "total": 1,
          "recall": 1.0
        },
        {
          "scenario": "token_abuse",
          "caught": 0,
          "total": 2,
          "recall": 0.0
        },
        {
          "scenario": "unusual_api",
          "caught": 0,
          "total": 2,
          "recall": 0.0
        }
      ],
      "false_alarms": 0
    },
    {
      "id": "P4",
      "label": "P4 Unusual API",
      "kind": "detector",
      "cells": [
        {
          "scenario": "dormant_reactivation",
          "caught": 0,
          "total": 1,
          "recall": 0.0
        },
        {
          "scenario": "impossible_travel",
          "caught": 0,
          "total": 1,
          "recall": 0.0
        },
        {
          "scenario": "privilege_escalation",
          "caught": 0,
          "total": 1,
          "recall": 0.0
        },
        {
          "scenario": "token_abuse",
          "caught": 0,
          "total": 2,
          "recall": 0.0
        },
        {
          "scenario": "unusual_api",
          "caught": 1,
          "total": 2,
          "recall": 0.5
        }
      ],
      "false_alarms": 1
    },
    {
      "id": "P5",
      "label": "P5 Token abuse",
      "kind": "detector",
      "cells": [
        {
          "scenario": "dormant_reactivation",
          "caught": 0,
          "total": 1,
          "recall": 0.0
        },
        {
          "scenario": "impossible_travel",
          "caught": 0,
          "total": 1,
          "recall": 0.0
        },
        {
          "scenario": "privilege_escalation",
          "caught": 0,
          "total": 1,
          "recall": 0.0
        },
        {
          "scenario": "token_abuse",
          "caught": 1,
          "total": 2,
          "recall": 0.5
        },
        {
          "scenario": "unusual_api",
          "caught": 0,
          "total": 2,
          "recall": 0.0
        }
      ],
      "false_alarms": 0
    },
    {
      "id": "ML",
      "label": "ML Behavior anomaly",
      "kind": "detector",
      "cells": [
        {
          "scenario": "dormant_reactivation",
          "caught": 0,
          "total": 1,
          "recall": 0.0
        },
        {
          "scenario": "impossible_travel",
          "caught": 1,
          "total": 1,
          "recall": 1.0
        },
        {
          "scenario": "privilege_escalation",
          "caught": 0,
          "total": 1,
          "recall": 0.0
        },
        {
          "scenario": "token_abuse",
          "caught": 0,
          "total": 2,
          "recall": 0.0
        },
        {
          "scenario": "unusual_api",
          "caught": 1,
          "total": 2,
          "recall": 0.5
        }
      ],
      "false_alarms": 2
    }
  ],
  "agreement": {
    "both": 2,
    "rules_only": 4,
    "ml_only": 2,
    "missed_by_both": 1,
    "both_true": 1,
    "rules_only_true": 4,
    "ml_only_true": 1
  },
  "winner": {
    "id": "hybrid",
    "label": "Hybrid (final alerts)",
    "f1": 0.857,
    "text": "Hybrid (final alerts) performs best (F1 0.86 vs Rules (P1–P5) 0.77, ML (Isolation Forest) 0.36)"
  },
  "malicious_sessions": 7,
  "note": null
}
```

## static/mock/analytics_heatmap_time.json

```json
{
  "days": [
    "2026-10-14",
    "2026-10-15",
    "2026-10-16",
    "2026-10-17",
    "2026-10-18",
    "2026-10-19",
    "2026-10-20",
    "2026-10-21",
    "2026-10-22",
    "2026-10-23",
    "2026-10-24",
    "2026-10-25",
    "2026-10-26",
    "2026-10-27"
  ],
  "hours": [
    0,
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    12,
    13,
    14,
    15,
    16,
    17,
    18,
    19,
    20,
    21,
    22,
    23
  ],
  "cells": [
    [
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0
    ],
    [
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0
    ],
    [
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0
    ],
    [
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0
    ],
    [
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0
    ],
    [
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0
    ],
    [
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      1
    ],
    [
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0
    ],
    [
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0
    ],
    [
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0
    ],
    [
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0
    ],
    [
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      4,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0
    ],
    [
      4,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      4,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      4,
      0,
      0
    ],
    [
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      4,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      4,
      0,
      0,
      0,
      0,
      0
    ]
  ],
  "max": 4,
  "total": 25,
  "tz": "UTC+05:30"
}
```

## static/mock/analytics_heatmap_identities.json

```json
{
  "identities": [
    "svc-report",
    "meera.n",
    "anita.rao",
    "dev.kumar",
    "rahul.s"
  ],
  "risk": [
    94.0,
    88.0,
    78.0,
    55.0,
    44.0
  ],
  "patterns": [
    "P1",
    "P2",
    "P3",
    "P4",
    "P5",
    "ML"
  ],
  "pattern_names": [
    "Impossible travel",
    "Dormant account",
    "Privilege escalation",
    "Unusual API",
    "Token abuse",
    "Behavior anomaly"
  ],
  "cells": [
    [
      0,
      2,
      1,
      0,
      0,
      0
    ],
    [
      0,
      0,
      0,
      0,
      1,
      0
    ],
    [
      1,
      0,
      0,
      0,
      0,
      1
    ],
    [
      0,
      0,
      0,
      1,
      0,
      1
    ],
    [
      0,
      0,
      0,
      1,
      0,
      1
    ]
  ],
  "max": 2
}
```

## static/mock/notifications.json

```json
[
  {
    "id": "a1b2c3d4e5f6",
    "created_at": "2026-10-28T09:56:10+00:00",
    "kind": "digest",
    "subject": "[IdentityShield] CRITICAL: 3 identities need attention - svc-report (risk 94)",
    "recipients": "admin@corp.example",
    "alert_ids": [
      "AL-0001",
      "AL-0002",
      "AL-0003"
    ],
    "mode": "outbox",
    "status": "outbox",
    "detail": "Saved to outbox/",
    "body_text": "IdentityShield detected suspicious identity activity.\n\nNew high-risk alerts: 3  (critical: 1)\nOpen alerts in console: 7\n\n- svc-report | risk 94 (revoke) | Privilege escalation, Dormant account\n  Why: Escalation chain: CreateAccessKey -> AttachUserPolicy -> AssumeRole within 11 min.\n  Recommended: Revoke session (needs analyst approval)\n  Open: http://127.0.0.1:8000/alert.html?id=AL-0001\n\n- meera.n | risk 88 (restrict) | Token abuse\n  Why: Access key used from India and Brazil within 3 minutes.\n  Recommended: Restrict access\n  Open: http://127.0.0.1:8000/alert.html?id=AL-0002\n\n- anita.rao | risk 78 (restrict) | Impossible travel, Behavior anomaly\n  Why: Login from Frankfurt, 7,406 km from Bengaluru, 30 min after previous login (14,812 km/h).\n  Recommended: Restrict access\n  Open: http://127.0.0.1:8000/alert.html?id=AL-0003\n\nNo session was revoked automatically. Revocation always requires analyst approval.\nThis is an automated message from IdentityShield."
  },
  {
    "id": "f6e5d4c3b2a1",
    "created_at": "2026-10-28T09:40:02+00:00",
    "kind": "test",
    "subject": "[IdentityShield] Test email",
    "recipients": "admin@corp.example",
    "alert_ids": [],
    "mode": "smtp",
    "status": "failed",
    "detail": "TimeoutError: timed out; saved to outbox",
    "body_text": "This is a test email from IdentityShield. Email alerts are configured correctly."
  }
]
```

## static/mock/notifications_status.json

```json
{
  "mode": "outbox",
  "recipients": [
    "admin@corp.example"
  ],
  "recipients_configured": true,
  "smtp_host": null,
  "min_risk": 70,
  "max_per_hour": 10,
  "sent_last_hour": 1
}
```

## static/mock/pipeline_status.json

```json
{
  "state": "done",
  "run_id": 2,
  "started_at": "2026-10-28T09:55:58+00:00",
  "finished_at": "2026-10-28T09:56:00+00:00",
  "duration_ms": 1843.2,
  "detail": "",
  "alerts": 7
}
```
