"""Analytics API router: detector comparison and attack heatmaps."""
import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request

from app import analytics
from app.config import HEATMAP_DAYS
from app.utils import clean_json

log = logging.getLogger(__name__)

router = APIRouter(tags=["analytics"])


def _result(request: Request):
    res = getattr(request.app.state, "result", None)
    if res is None:
        raise HTTPException(status_code=503, detail="Pipeline has not produced results yet")
    return res


@router.get("/analytics/detectors")
def get_detector_comparison(request: Request) -> dict[str, Any]:
    res = _result(request)
    signals = getattr(res, "signals", [])
    data = analytics.detector_comparison(res.events, signals, res.alerts)
    return clean_json(data)


@router.get("/analytics/heatmap/time")
def get_attack_time_heatmap(
    request: Request,
    days: int = Query(default=HEATMAP_DAYS),
) -> dict[str, Any]:
    res = _result(request)
    days = max(1, min(int(days), 60))
    data = analytics.attack_time_heatmap(res.events, res.alerts, days=days)
    return clean_json(data)


@router.get("/analytics/heatmap/identities")
def get_identity_pattern_heatmap(
    request: Request,
    top: int = Query(default=10),
) -> dict[str, Any]:
    res = _result(request)
    top = max(1, min(int(top), 30))
    signals = getattr(res, "signals", [])
    data = analytics.identity_pattern_heatmap(signals, res.alerts, top=top)
    return clean_json(data)
