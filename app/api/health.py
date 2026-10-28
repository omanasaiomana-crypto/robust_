"""Health, pipeline runner, and summary endpoints."""
import logging
from typing import Any
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app import runner
from app.models import Health
from app.pipeline import get_identity_rows
from app.utils import clean_json

log = logging.getLogger(__name__)

router = APIRouter(tags=["health"])


class PipelineRunRequest(BaseModel):
    use_sample: bool | None = None


def _make_health(res: Any, startup_err: str = "") -> Health:
    if res is None:
        pipe_status = "failed" if startup_err else "not_run"
        return Health(
            status="degraded",
            pipeline=pipe_status,
            detail=startup_err or "Pipeline has not run yet",
            data_mode="sample",
            events=0,
            alerts=0,
        )

    pipe_status = "ok" if res.status in ("ok", "degraded") else "failed"
    return Health(
        status=res.status,
        pipeline=pipe_status,
        detail=res.detail,
        data_mode=res.data_mode,
        events=len(res.events) if res.events is not None else 0,
        alerts=len(res.alerts) if res.alerts is not None else 0,
    )


@router.get("/health", response_model=Health)
def get_health(request: Request) -> Health:
    res = getattr(request.app.state, "result", None)
    startup_err = getattr(request.app.state, "startup_error", "")
    h = _make_health(res, startup_err)
    if runner.is_running():
        h.pipeline = "running"
    return h


@router.post("/pipeline/run")
def trigger_pipeline(request: Request, body: PipelineRunRequest | None = None) -> JSONResponse:
    use_sample = body.use_sample if body is not None else None
    started, st = runner.start(request.app, use_sample)
    if not started:
        raise HTTPException(status_code=409, detail="A pipeline run is already in progress")
    return JSONResponse(status_code=202, content=clean_json(st))


@router.get("/pipeline/status")
def get_pipeline_status() -> dict[str, Any]:
    return clean_json(runner.status())


@router.get("/summary")
def get_summary(request: Request) -> dict[str, Any]:
    res = getattr(request.app.state, "result", None)
    if res is None:
        return clean_json({
            "by_band": {"monitor": 0, "step_up": 0, "restrict": 0, "revoke": 0},
            "by_pattern": {"P1": 0, "P2": 0, "P3": 0, "P4": 0, "P5": 0, "ML": 0},
            "top_identities": [],
            "totals": {"events": 0, "alerts": 0, "high_risk_alerts": 0, "identities": 0},
        })

    alerts = res.alerts or []
    by_band = {"monitor": 0, "step_up": 0, "restrict": 0, "revoke": 0}
    for a in alerts:
        by_band[a.band] = by_band.get(a.band, 0) + 1

    by_pattern = {"P1": 0, "P2": 0, "P3": 0, "P4": 0, "P5": 0, "ML": 0}
    for a in alerts:
        for p in a.patterns:
            by_pattern[p] = by_pattern.get(p, 0) + 1

    id_rows = get_identity_rows(res)
    top_identities = id_rows[:5]

    totals = {
        "events": len(res.events) if res.events is not None else 0,
        "alerts": len(alerts),
        "high_risk_alerts": sum(1 for a in alerts if a.risk >= 70.0),
        "identities": len(id_rows),
    }

    out = {
        "by_band": by_band,
        "by_pattern": by_pattern,
        "top_identities": top_identities,
        "totals": totals,
    }
    return clean_json(out)
