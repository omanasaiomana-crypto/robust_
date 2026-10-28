"""Identity, graph, timeline, and hygiene endpoints."""
import logging
from typing import Any
from fastapi import APIRouter, HTTPException, Request
import pandas as pd

from app.config import DORMANT_DAYS
from app.correlate.graph import escalation_paths, identity_subgraph
from app.models import Event, IdentityGraph
from app.pipeline import get_identity_rows
from app.utils import clean_json

log = logging.getLogger(__name__)

router = APIRouter(tags=["identities"])


def _result(request: Request):
    res = getattr(request.app.state, "result", None)
    if res is None:
        raise HTTPException(status_code=503, detail="Pipeline has not produced results yet")
    return res


@router.get("/identities")
def list_identities(request: Request, min_risk: float = 0.0) -> list[dict[str, Any]]:
    res = _result(request)
    rows = get_identity_rows(res)
    filtered = [r for r in rows if r["risk"] >= min_risk]
    return clean_json(filtered)


@router.get("/identities/{identity_id}/graph", response_model=IdentityGraph)
def get_identity_graph(request: Request, identity_id: str) -> IdentityGraph:
    res = _result(request)
    if res.graph is None:
        return IdentityGraph(identity_id=identity_id, nodes=[], edges=[], escalation_paths=[])

    user_node = f"user:{identity_id}"
    has_user = res.graph.has_node(user_node) or (
        res.events is not None and not res.events.empty and (res.events["identity_id"] == identity_id).any()
    )
    if not has_user:
        raise HTTPException(status_code=404, detail=f"Identity {identity_id} not found")

    # Gather evidence event IDs from alerts for this identity to mark suspicious edges
    suspicious_ids: set[str] = set()
    if res.alerts:
        for a in res.alerts:
            if a.identity_id == identity_id:
                suspicious_ids.update(a.evidence_event_ids)

    return identity_subgraph(res.graph, identity_id, suspicious_ids=suspicious_ids)


@router.get("/sessions/{session_id}/timeline")
def get_session_timeline(request: Request, session_id: str) -> list[dict[str, Any]]:
    res = _result(request)
    if res.events is None or res.events.empty:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")

    sess_events = res.events[res.events["session_id"] == session_id]
    if sess_events.empty:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")

    sorted_events = sess_events.sort_values(by="timestamp")
    all_signals = res.signals or []

    timeline: list[dict[str, Any]] = []
    for _, row in sorted_events.iterrows():
        eid = str(row["event_id"])
        matching_sigs = [
            s.model_dump()
            for s in all_signals
            if eid in s.evidence_event_ids or s.session_id == session_id
        ]
        # Deduplicate signals by (pattern, reason)
        seen_sigs = set()
        deduped_sigs = []
        for ms in matching_sigs:
            key = (ms.get("pattern"), ms.get("reason"))
            if key not in seen_sigs:
                seen_sigs.add(key)
                deduped_sigs.append(ms)

        clean_d = {k: (None if pd.isna(v) else v) for k, v in row.items()}
        timeline.append({
            "event": Event.model_validate(clean_d).model_dump(mode="json"),
            "signals": deduped_sigs,
        })

    return clean_json(timeline)


@router.get("/hygiene")
def get_hygiene(request: Request) -> dict[str, Any]:
    res = _result(request)
    events_df = res.events
    dormant_admins: list[dict[str, Any]] = []

    if events_df is not None and not events_df.empty:
        admin_events = events_df[events_df["privilege_level"] >= 4].sort_values(by="timestamp")
        for uid, group in admin_events.groupby("identity_id"):
            if len(group) >= 2:
                prev_ts = group["timestamp"].iloc[0]
                for _, r in group.iloc[1:].iterrows():
                    curr_ts = r["timestamp"]
                    gap_days = (curr_ts - prev_ts).total_seconds() / 86400.0
                    if gap_days >= DORMANT_DAYS:
                        dormant_admins.append({
                            "identity_id": str(uid),
                            "privilege_level": int(r["privilege_level"]),
                            "gap_days": round(gap_days, 1),
                            "last_seen": curr_ts.isoformat(),
                            "action": str(r["action"]),
                        })
                        break
                    prev_ts = curr_ts

    paths_by_identity: list[dict[str, Any]] = []
    if res.graph is not None:
        id_rows = get_identity_rows(res)
        for r in id_rows[:10]:
            uid = r["identity_id"]
            paths = escalation_paths(res.graph, uid)
            if paths:
                paths_by_identity.append({
                    "identity_id": uid,
                    "risk": r["risk"],
                    "paths": paths,
                })

    out = {
        "dormant_admins": dormant_admins,
        "escalation_paths": paths_by_identity,
    }
    return clean_json(out)
