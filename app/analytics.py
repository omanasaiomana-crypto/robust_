"""Detection analytics: attack heatmaps and rules-vs-ML comparison.

Pure functions over the pipeline result. They never raise on bad or missing data;
they return empty structures instead.
"""
import logging
from datetime import timedelta, timezone

import pandas as pd

from app.config import (ANALYTICS_HYBRID_MIN_RISK, BAND_STEP_UP, DISPLAY_UTC_OFFSET_MINUTES,
                        HEATMAP_DAYS, PATTERN_NAMES)
from app.models import Alert, Signal

log = logging.getLogger(__name__)

RULE_PATTERNS = ("P1", "P2", "P3", "P4", "P5")
SUMMARY_GROUPS = ("rules", "ml", "hybrid")


def _has_value(value) -> bool:
    if value is None:
        return False
    try:
        if pd.isna(value):
            return False
    except (TypeError, ValueError):
        pass
    return str(value).strip() != ""


def _is_attack(label) -> bool:
    return _has_value(label) and str(label).strip().lower() not in {"benign", "none", "nan"}


def _tz_label(offset_minutes: int) -> str:
    sign = "+" if offset_minutes >= 0 else "-"
    h, m = divmod(abs(offset_minutes), 60)
    return f"UTC{sign}{h:02d}:{m:02d}"


def session_truth(events: pd.DataFrame) -> dict[str, set[str]] | None:
    """session_id -> set of attack labels in it (empty set = benign session). None if no labels exist."""
    if events is None or events.empty or "label" not in events.columns or "session_id" not in events.columns:
        return None
    if not events["label"].map(_has_value).any():
        return None
    truth: dict[str, set[str]] = {}
    for sid, label in zip(events["session_id"], events["label"]):
        if not _has_value(sid):
            continue
        labels = truth.setdefault(str(sid), set())
        if _is_attack(label):
            labels.add(str(label).strip())
    return truth


def detector_groups(signals: list[Signal], alerts: list[Alert]) -> list[dict]:
    """Each group: id, label, kind (summary|detector), sessions (set of flagged session ids)."""
    by_pattern: dict[str, set[str]] = {p: set() for p in RULE_PATTERNS + ("ML",)}
    for s in signals or []:
        if s.session_id and s.pattern in by_pattern:
            by_pattern[s.pattern].add(s.session_id)
    rules = set().union(*(by_pattern[p] for p in RULE_PATTERNS))
    hybrid = {a.session_id for a in alerts or [] if a.session_id and a.risk >= ANALYTICS_HYBRID_MIN_RISK}
    groups = [
        {"id": "rules", "label": "Rules (P1–P5)", "kind": "summary", "sessions": rules},
        {"id": "ml", "label": "ML (Isolation Forest)", "kind": "summary", "sessions": by_pattern["ML"]},
        {"id": "hybrid", "label": "Hybrid (final alerts)", "kind": "summary", "sessions": hybrid},
    ]
    for p in RULE_PATTERNS + ("ML",):
        groups.append({"id": p, "label": f"{p} {PATTERN_NAMES.get(p, p)}", "kind": "detector",
                       "sessions": by_pattern[p]})
    return groups


def _prf(flagged: set[str], malicious: set[str]) -> dict:
    tp = len(flagged & malicious)
    fp = len(flagged - malicious)
    fn = len(malicious - flagged)
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    f1 = (2 * precision * recall / (precision + recall)
          if precision is not None and recall is not None and (precision + recall) > 0 else
          (0.0 if precision is not None and recall is not None else None))
    r = lambda v: None if v is None else round(v, 3)  # noqa: E731
    return {"tp": tp, "fp": fp, "fn": fn, "precision": r(precision), "recall": r(recall), "f1": r(f1)}


def detector_comparison(events: pd.DataFrame, signals: list[Signal], alerts: list[Alert]) -> dict:
    """Session-level comparison of rules, ML and hybrid, plus a detector x scenario recall matrix."""
    try:
        groups = detector_groups(signals, alerts)
        truth = session_truth(events)
        labeled = truth is not None
        malicious = {s for s, labs in (truth or {}).items() if labs}
        scenarios = sorted({lab for labs in (truth or {}).values() for lab in labs})

        rows = []
        for g in groups:
            row = {"id": g["id"], "label": g["label"], "kind": g["kind"], "flagged": len(g["sessions"])}
            if labeled:
                row.update(_prf(g["sessions"], malicious))
            else:
                row.update({"tp": None, "fp": None, "fn": None, "precision": None, "recall": None, "f1": None})
            rows.append(row)

        matrix = []
        if labeled:
            sessions_by_scenario = {sc: {s for s, labs in truth.items() if sc in labs} for sc in scenarios}
            for g in groups:
                cells = []
                for sc in scenarios:
                    total = len(sessions_by_scenario[sc])
                    caught = len(g["sessions"] & sessions_by_scenario[sc])
                    cells.append({"scenario": sc, "caught": caught, "total": total,
                                  "recall": round(caught / total, 3) if total else None})
                matrix.append({"id": g["id"], "label": g["label"], "kind": g["kind"], "cells": cells,
                               "false_alarms": len(g["sessions"] - malicious)})

        rules = groups[0]["sessions"]
        ml = groups[1]["sessions"]
        agreement = {
            "both": len(rules & ml), "rules_only": len(rules - ml), "ml_only": len(ml - rules),
            "missed_by_both": len(malicious - rules - ml) if labeled else None,
            "both_true": len(rules & ml & malicious) if labeled else None,
            "rules_only_true": len((rules - ml) & malicious) if labeled else None,
            "ml_only_true": len((ml - rules) & malicious) if labeled else None,
        }

        winner = None
        if labeled:
            summary = [r for r in rows if r["kind"] == "summary" and r["f1"] is not None]
            if summary:
                best = max(summary, key=lambda r: (r["f1"], r["precision"] or 0.0, r["recall"] or 0.0))
                others = ", ".join(f"{r['label']} {r['f1']:.2f}" for r in summary if r is not best)
                winner = {"id": best["id"], "label": best["label"], "f1": best["f1"],
                          "text": f"{best['label']} performs best (F1 {best['f1']:.2f}"
                                  + (f" vs {others})" if others else ")")}

        return {"labeled": labeled, "level": "session", "scenarios": scenarios, "rows": rows,
                "matrix": matrix, "agreement": agreement, "winner": winner,
                "malicious_sessions": len(malicious) if labeled else None,
                "note": None if labeled else "No ground-truth labels: showing detection counts only."}
    except Exception:  # noqa: BLE001 - analytics must never break the API
        log.exception("detector_comparison failed")
        return {"labeled": False, "level": "session", "scenarios": [], "rows": [], "matrix": [],
                "agreement": {}, "winner": None, "malicious_sessions": None,
                "note": "Analytics unavailable; see server log."}


def attack_time_heatmap(events: pd.DataFrame, alerts: list[Alert], days: int = HEATMAP_DAYS,
                        offset_minutes: int = DISPLAY_UTC_OFFSET_MINUTES) -> dict:
    """Date x hour-of-day counts of events that are evidence in alerts (risk >= step-up)."""
    empty = {"days": [], "hours": list(range(24)), "cells": [], "max": 0, "total": 0,
             "tz": _tz_label(offset_minutes)}
    try:
        evidence = {eid for a in alerts or [] if a.risk >= BAND_STEP_UP for eid in a.evidence_event_ids}
        if events is None or events.empty or not evidence:
            return empty
        sub = events[events["event_id"].isin(evidence)]
        if sub.empty:
            return empty
        tz = timezone(timedelta(minutes=offset_minutes))
        ts = pd.to_datetime(sub["timestamp"], utc=True, errors="coerce").dropna().dt.tz_convert(tz)
        if ts.empty:
            return empty
        dates = ts.dt.strftime("%Y-%m-%d")
        counts: dict[tuple[str, int], int] = {}
        for d, h in zip(dates, ts.dt.hour):
            counts[(d, int(h))] = counts.get((d, int(h)), 0) + 1
        last = pd.Timestamp(dates.max())
        day_list = [(last - pd.Timedelta(days=i)).strftime("%Y-%m-%d") for i in range(max(1, days) - 1, -1, -1)]
        cells = [[counts.get((d, h), 0) for h in range(24)] for d in day_list]
        flat = [v for row in cells for v in row]
        return {"days": day_list, "hours": list(range(24)), "cells": cells, "max": max(flat) if flat else 0,
                "total": int(sum(flat)), "tz": _tz_label(offset_minutes)}
    except Exception:  # noqa: BLE001
        log.exception("attack_time_heatmap failed")
        return empty


def identity_pattern_heatmap(signals: list[Signal], alerts: list[Alert], top: int = 10) -> dict:
    """Top identities (by max alert risk) x detector: number of signals."""
    patterns = list(RULE_PATTERNS) + ["ML"]
    try:
        risk_by_id: dict[str, float] = {}
        for a in alerts or []:
            risk_by_id[a.identity_id] = max(risk_by_id.get(a.identity_id, 0.0), float(a.risk))
        identities = [i for i, _ in sorted(risk_by_id.items(), key=lambda kv: kv[1], reverse=True)[:top]]
        counts: dict[tuple[str, str], int] = {}
        for s in signals or []:
            if s.identity_id in risk_by_id and s.pattern in patterns:
                counts[(s.identity_id, s.pattern)] = counts.get((s.identity_id, s.pattern), 0) + 1
        cells = [[counts.get((i, p), 0) for p in patterns] for i in identities]
        flat = [v for row in cells for v in row]
        return {"identities": identities, "risk": [round(risk_by_id[i], 1) for i in identities],
                "patterns": patterns, "pattern_names": [PATTERN_NAMES.get(p, p) for p in patterns],
                "cells": cells, "max": max(flat) if flat else 0}
    except Exception:  # noqa: BLE001
        log.exception("identity_pattern_heatmap failed")
        return {"identities": [], "risk": [], "patterns": patterns,
                "pattern_names": [PATTERN_NAMES.get(p, p) for p in patterns], "cells": [], "max": 0}
