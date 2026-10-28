# 03 · Feature spec: detection analytics (heatmaps + rules vs ML)

## 1. What the user asked for

> "A heat map comparing the number of attacks on our server and indicating which detector performs better, the AI/ML model or the rules."

This becomes **one new page, Analytics**, answering three questions:

1. **When are we being attacked?** Attack-activity heatmap: date × hour of day, counting the events that appear as evidence in alerts.
2. **Which detector catches which attack?** Detection heatmap: rows are detectors (Rules, ML, Hybrid, then each of P1–P5 and ML), columns are attack scenarios, and each cell shows the share of attack sessions caught.
3. **Who performs better, rules or ML?** Precision, recall and F1 for Rules vs ML vs Hybrid, a "winner" banner, and an agreement breakdown (caught by both, only rules, only ML, missed by both).

A fourth, small heatmap (identity × detector) shows which accounts trigger which detectors.

---

## 2. Metric definitions (put these on the page in a short "How we measure" note)

**Level:** session. An attack is usually several events, and alerts are per session, so comparing at session level is fair to both rules and ML. (Event-level F1 stays on the Overview, as before.)

| Term | Definition |
|---|---|
| Attack session | A session containing at least one event whose label is not `benign` |
| Scenario | The attack label, e.g. `privilege_escalation`; a session can have more than one |
| Rules flagged | Sessions with at least one P1–P5 signal |
| ML flagged | Sessions with an ML signal (anomaly score ≥ 0.6) |
| Hybrid flagged | Sessions with a final alert at risk ≥ 40 (step-up band or higher) |
| Precision | Flagged attack sessions ÷ all flagged sessions |
| Recall | Flagged attack sessions ÷ all attack sessions |
| F1 | 2PR ÷ (P + R) |
| Recall per scenario (heatmap cell) | Sessions of that scenario that the detector flagged ÷ all sessions of that scenario |
| False alarms | Flagged sessions that are not attack sessions |
| Winner | Highest F1 among Rules, ML and Hybrid; ties go to precision, then recall |

**Without labels** (for example, hidden data without ground truth), the page still shows flagged counts, the agreement breakdown and both activity heatmaps, with the note *"No ground-truth labels: showing detection counts only."*

**Time zone:** buckets use a fixed offset (`DISPLAY_UTC_OFFSET_MINUTES = 330`, which is IST). A fixed offset needs no time-zone database, so it works on Windows without installing `tzdata`.

---

## 3. Backend

**File:** `app/analytics.py`. Copy it exactly from `reference/REF_02_analytics.md` (tested).

| Function | Purpose |
|---|---|
| `detector_comparison(events, signals, alerts)` | Rows (metrics per group), matrix (recall per scenario), agreement, winner |
| `attack_time_heatmap(events, alerts, days, offset_minutes)` | `days × 24` count grid |
| `identity_pattern_heatmap(signals, alerts, top)` | Top identities × detectors grid |

All three catch every exception and return an empty structure, so analytics can never break the API.

**Router:** `app/api/analytics.py`

| Method | Path | Query | Response |
|---|---|---|---|
| GET | `/api/analytics/detectors` | none | `detector_comparison(...)` |
| GET | `/api/analytics/heatmap/time` | `days` (1–60, default `HEATMAP_DAYS`) | `attack_time_heatmap(...)` |
| GET | `/api/analytics/heatmap/identities` | `top` (1–30, default 10) | `identity_pattern_heatmap(...)` |

The router returns **503** `pipeline_not_ready` when `app.state.result` is None, reusing the existing `_result()` helper pattern. Every response passes through `clean_json()`.

### 3.1 Response shapes

`GET /api/analytics/detectors` (abridged; the full example is in `reference/REF_07_mock_json.md`):

```json
{
  "labeled": true,
  "level": "session",
  "scenarios": ["dormant_reactivation", "impossible_travel", "privilege_escalation", "token_abuse", "unusual_api"],
  "rows": [
    {"id": "rules",  "label": "Rules (P1–P5)",         "kind": "summary",  "flagged": 6, "tp": 5, "fp": 1, "fn": 2, "precision": 0.833, "recall": 0.714, "f1": 0.769},
    {"id": "ml",     "label": "ML (Isolation Forest)", "kind": "summary",  "flagged": 4, "tp": 2, "fp": 2, "fn": 5, "precision": 0.5,   "recall": 0.286, "f1": 0.364},
    {"id": "hybrid", "label": "Hybrid (final alerts)", "kind": "summary",  "flagged": 7, "tp": 6, "fp": 1, "fn": 1, "precision": 0.857, "recall": 0.857, "f1": 0.857},
    {"id": "P1",     "label": "P1 Impossible travel",  "kind": "detector", "flagged": 1, "...": "..."}
  ],
  "matrix": [
    {"id": "rules", "label": "Rules (P1–P5)", "kind": "summary", "false_alarms": 1,
     "cells": [{"scenario": "dormant_reactivation", "caught": 1, "total": 1, "recall": 1.0}, "..."]}
  ],
  "agreement": {"both": 2, "rules_only": 4, "ml_only": 2, "missed_by_both": 1,
                "both_true": 2, "rules_only_true": 3, "ml_only_true": 1},
  "winner": {"id": "hybrid", "label": "Hybrid (final alerts)", "f1": 0.857,
             "text": "Hybrid (final alerts) performs best (F1 0.86 vs Rules (P1–P5) 0.77, ML (Isolation Forest) 0.36)"},
  "malicious_sessions": 7,
  "note": null
}
```

`GET /api/analytics/heatmap/time`:

```json
{"days": ["2026-10-14", "...", "2026-10-27"], "hours": [0, 1, "...", 23],
 "cells": [[0, 0, "...", 0], "..."], "max": 3, "total": 25, "tz": "UTC+05:30"}
```

`GET /api/analytics/heatmap/identities`:

```json
{"identities": ["svc-report", "meera.n", "anita.rao"], "risk": [94.0, 88.0, 78.0],
 "patterns": ["P1", "P2", "P3", "P4", "P5", "ML"],
 "pattern_names": ["Impossible travel", "Dormant account", "Privilege escalation", "Unusual API", "Token abuse", "Behavior anomaly"],
 "cells": [[0, 2, 1, 0, 0, 0], "..."], "max": 2}
```

---

## 4. Frontend: `analytics.html` + `static/js/analytics.js`

Uses the existing design system (context.md §10) and `ui.js` components. Add the sidebar item **"Analytics"** (bar-chart icon) between Identities and Hygiene.

### 4.1 Layout (top to bottom)

| # | Block | Details |
|---|---|---|
| 1 | **Winner banner** | Full-width card with a 2px `brand2` left border: trophy/check icon, `winner.text`, small muted line "Session-level · N attack sessions · labels from dataset". Unlabeled: neutral banner with `note`. |
| 2 | **Three comparison cards** | Rules / ML / Hybrid. Each shows the label, a large F1, a mini row of Precision · Recall · Flagged · False alarms, and a thin recall bar. The winner card gets a `ring-1 ring-brand2` and a "Best" pill. |
| 3 | **"Precision, recall, F1" chart** | Chart.js grouped bar: x = Rules, ML, Hybrid; 3 datasets (Precision `#3B82F6`, Recall `#22D3EE`, F1 `#10B981`); y from 0 to 1; dark grid `#1F2A3C`, ticks `#8A97AD`. Hidden when unlabeled. |
| 4 | **Detection heatmap "Which detector catches which attack"** | HTML grid (spec §4.2). Rows: the 3 summary rows, a thin divider, then P1–P5 and ML. Columns: scenarios (humanized: `privilege_escalation` → "Privilege escalation") plus a final "False alarms" column. |
| 5 | **Agreement card** | One 100%-width stacked horizontal bar (rules-only / both / ML-only / missed) made of divs, with a legend and counts, plus an auto sentence: "ML caught **1** attack session that rules missed; rules caught **3** that ML missed; **1** attack was missed by both." |
| 6 | **Attack activity heatmap "When are we attacked"** | Date rows × 24 hour columns; subtitle "Events cited as evidence in alerts · last 14 days · UTC+05:30"; total count on the right; a legend gradient (0 → max). |
| 7 | **Identity × detector heatmap** | Rows = top identities (with risk badge); columns = P1–P5, ML; each row links to `graph.html?identity=`. |
| 8 | **"How we measure" note** | A collapsible `<details>` with the definitions table from §2, in muted text. |

Two columns on large screens: blocks 4 and 5 side by side (4 is wider, `lg:col-span-2`); 6 and 7 stacked full width. Single column on mobile, with heatmaps scrolling horizontally inside their card.

### 4.2 Heatmap rendering (no plugin)

- Use a CSS grid: `grid-template-columns: <label col> repeat(N, minmax(28px, 1fr))`. Cells are `div`s with `rounded-[3px]`, height 28px (time heatmap: 18px), 2px gap.
- **Color (single hue, readable in the dark theme):** an empty or zero cell gets `bg-panel2`. Otherwise the background is `rgba(34, 211, 238, a)` (brand2 cyan) with `a = 0.15 + 0.80 * value / max` (recall matrix: `max = 1`). Text is `#0B0F17` when `a > 0.55`, else `#E6EBF2`.
- **False alarms column:** same formula with crit red `rgba(239, 68, 68, a)` scaled by the max false alarms.
- **Cell text:** the recall matrix shows `caught/total` and the time heatmap shows the count (blank for 0). Every cell has a `title` tooltip such as "ML · Privilege escalation: 1 of 1 sessions (100%)" or "Tue 27 Oct, 09:00–10:00 IST: 3 attack events".
- Numbers are always printed, so meaning never depends on color alone (accessibility).
- Time heatmap labels: rows as "Tue 27 Oct"; columns `00`…`23`, showing only every 3rd label under 640 px.
- All label text goes through `esc()`.

### 4.3 States

Skeleton while loading. Each block shows its own `errorState` on failure (use `Promise.allSettled`). Empty states: "No attack activity in this period" and "No alerts yet".

### 4.4 Mock mode

Add the three endpoints to the `api.js` mock map (`/analytics/detectors` → `analytics_detectors`, `/analytics/heatmap/time` → `analytics_heatmap_time`, `/analytics/heatmap/identities` → `analytics_heatmap_identities`) and save the fixtures from `reference/REF_07_mock_json.md`.

### 4.5 Overview tie-in (small)

On `index.html`, add a compact card "Rules vs ML" showing the winner text and three F1 numbers, with a link "Open analytics →". Hide it when unlabeled.

---

## 5. Demo talking points

- "Rules are precise and explainable; ML catches sessions the rules miss. The hybrid score combines both." Say this only if your official labeled run shows it, and quote the real numbers. If ML does not add value on the official data, say so honestly and show the agreement card; judges respect that.
- "The heatmap shows **when** attacks hit." Describe the pattern your heatmap actually shows, for example a burst outside business hours.
- "Each column is an attack type; you can see exactly which detector catches it."
