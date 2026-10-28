"""Explanation generators for alerts: human-readable reasons, MITRE mappings, and evidence."""
import pandas as pd

from app.models import Signal


def build_reasons(signals: list[Signal]) -> list[str]:
    """Return deduplicated list of reason strings ordered by signal severity descending."""
    if not signals:
        return []

    sorted_sigs = sorted(signals, key=lambda s: s.severity, reverse=True)
    reasons: list[str] = []
    seen: set[str] = set()

    for s in sorted_sigs:
        r = str(s.reason).strip()
        if r and r not in seen:
            seen.add(r)
            reasons.append(r)

    return reasons


def mitre_tags(signals: list[Signal]) -> list[str]:
    """Return sorted, unique MITRE technique IDs referenced across all signals."""
    if not signals:
        return []

    tags: set[str] = set()
    for s in signals:
        for t in s.mitre:
            t_str = str(t).strip()
            if t_str:
                tags.add(t_str)

    return sorted(tags)


def evidence_ids(signals: list[Signal], events: pd.DataFrame | None = None) -> list[str]:
    """Return deduplicated evidence event IDs, sorted chronologically if events DataFrame is supplied."""
    if not signals:
        return []

    raw_ids: set[str] = set()
    for s in signals:
        for eid in s.evidence_event_ids:
            if eid:
                raw_ids.add(str(eid))

    if not raw_ids:
        return []

    if events is not None and not events.empty and "timestamp" in events and "event_id" in events:
        sub = events[events["event_id"].isin(raw_ids)].sort_values(by="timestamp")
        ordered = list(sub["event_id"].unique())
        # Append any missing IDs preserving order
        missing = [eid for eid in raw_ids if eid not in ordered]
        return ordered + missing

    return sorted(raw_ids)
