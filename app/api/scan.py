"""Scan and agent endpoints for Live Scan and Agents dashboard."""
from typing import Any
from fastapi import APIRouter

from app import trace
from app.utils import clean_json

router = APIRouter(tags=["scan"])


@router.get("/agents")
def get_agents() -> dict[str, Any]:
    return clean_json({"agents": trace.agents_status(), "run": trace.run_status()})


@router.get("/scan/status")
def get_scan_status() -> dict[str, Any]:
    return clean_json(trace.run_status())


@router.get("/scan/trace")
def get_scan_trace(after: int = 0, limit: int = 500, run_id: str | None = None) -> dict[str, Any]:
    current_run = trace.run_status()
    target_run_id = run_id if run_id else current_run.get("run_id")
    state = current_run.get("state") if target_run_id == current_run.get("run_id") else "done"

    after = max(0, int(after))
    limit = max(1, min(2000, int(limit)))

    evs = trace.events(after=after, limit=limit, run_id=target_run_id)
    return clean_json({
        "run_id": target_run_id,
        "state": state,
        "last_seq": current_run.get("last_seq", 0),
        "events": evs,
    })
