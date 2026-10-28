"""Metrics and model weights endpoints."""
import logging
from typing import Any
from fastapi import APIRouter, HTTPException, Request

from app import store
from app.models import Metrics
from app.utils import clean_json

log = logging.getLogger(__name__)

router = APIRouter(tags=["metrics"])


def _result(request: Request):
    res = getattr(request.app.state, "result", None)
    if res is None:
        raise HTTPException(status_code=503, detail="Pipeline has not produced results yet")
    return res


@router.get("/metrics", response_model=Metrics)
def get_metrics(request: Request) -> Metrics:
    res = _result(request)
    return res.metrics if res.metrics is not None else Metrics()


@router.get("/weights")
def get_weights() -> dict[str, Any]:
    weights = store.get_weights()
    return clean_json(weights)
