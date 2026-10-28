"""Notifications API router: admin email notifications, status, and test delivery."""
import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request

from app import notify
from app.utils import clean_json

log = logging.getLogger(__name__)

router = APIRouter(tags=["notifications"])


@router.get("/notifications")
def get_notifications(limit: int = Query(default=50)) -> list[dict[str, Any]]:
    clamped = max(1, min(int(limit), 500))
    records = notify.list_notifications(limit=clamped)
    return clean_json(records)


@router.get("/notifications/status")
def get_notification_status() -> dict[str, Any]:
    stat = notify.status()
    return clean_json(stat)


@router.post("/notifications/test")
def send_test_notification() -> dict[str, Any]:
    rec = notify.send_test()
    if rec is None:
        rec = {"status": "off", "detail": "EMAIL_MODE=off"}
    return clean_json(rec)


@router.post("/alerts/{alert_id}/notify")
def notify_alert(request: Request, alert_id: str) -> dict[str, Any]:
    res = getattr(request.app.state, "result", None)
    if res is None:
        raise HTTPException(status_code=503, detail="Pipeline has not produced results yet")
    alert = next((a for a in (res.alerts or []) if a.alert_id == alert_id), None)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    rec = notify.notify_alert(alert)
    if rec is None:
        rec = {"status": "off", "detail": "EMAIL_MODE=off"}
    return clean_json(rec)
