"""v2.1 API: agents, live scan, threat trace, data input, attack-path graph, analytics, notifications.

Installed by install_v21.py and included in app/main.py BEFORE the static mount.
All handlers are plain `def`; logic lives in app/v21_service.py.
"""
import logging

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app import config, inputs, notify, store, trace
from app import v21_service as svc
from app.utils import clean_json

log = logging.getLogger(__name__)
router = APIRouter(tags=["v2.1"])

try:  # tables used by the notifier; safe to call repeatedly
    store.init_db()
    notify.init_tables()
except Exception:  # noqa: BLE001
    log.exception("v2.1 table init failed")


def _res(request: Request):
    res = getattr(request.app.state, "result", None)
    if res is None:
        raise HTTPException(status_code=503, detail="Pipeline has not produced results yet")
    return res


class ScanStart(BaseModel):
    use_sample: bool | None = None
    input_mode: str | None = None


class UploadBody(BaseModel):
    content: str
    source: str = "auto"
    filename: str | None = None


class ManualBody(BaseModel):
    kind: str
    fields: dict = {}


# ---------------------------------------------------------------- agents / scan
@router.get("/agents")
def get_agents():
    return clean_json(svc.agents_payload())


@router.get("/scan/status")
def scan_status():
    return clean_json(trace.run_status())


@router.get("/scan/trace")
def scan_trace(after: int = 0, limit: int = 500, run_id: str | None = None):
    return clean_json(svc.scan_trace(after, limit, run_id))


@router.post("/scan/start")
def scan_start(request: Request, body: ScanStart | None = None):
    body = body or ScanStart()
    outcome, payload = svc.start_scan(request.app, body.use_sample, body.input_mode)
    if outcome == "invalid":
        raise HTTPException(status_code=422, detail=str(payload))
    if outcome == "busy":
        raise HTTPException(status_code=409, detail="A scan is already running")
    return JSONResponse(status_code=202, content=clean_json(payload))


# ---------------------------------------------------------------- data input
@router.get("/inputs")
def list_inputs():
    return clean_json(inputs.list_inputs())


@router.post("/inputs/upload")
def upload_input(body: UploadBody):
    try:
        return clean_json(inputs.save_input(body.content, body.source, body.filename))
    except inputs.InputError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None


@router.post("/inputs/manual")
def manual_input(body: ManualBody):
    try:
        return clean_json(inputs.add_manual(body.kind, body.fields))
    except inputs.InputError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None


@router.delete("/inputs")
def clear_input():
    return {"removed": inputs.clear_inputs()}


# ---------------------------------------------------------------- attack-path graph
@router.get("/identities/{identity_id}/attack")
def identity_attack(identity_id: str, request: Request):
    out = svc.identity_attack(_res(request), identity_id)
    if out is None:
        raise HTTPException(status_code=404, detail=f"Identity {identity_id} not found")
    return clean_json(out)


@router.get("/graph/global")
def graph_global(request: Request, top: int = 8):
    return clean_json(svc.global_graph(_res(request), top))


# ---------------------------------------------------------------- analytics
@router.get("/analytics/detectors")
def analytics_detectors(request: Request):
    return clean_json(svc.analytics_detectors(_res(request)))


@router.get("/analytics/heatmap/time")
def analytics_time(request: Request, days: int = config.HEATMAP_DAYS):
    return clean_json(svc.analytics_time(_res(request), days))


@router.get("/analytics/heatmap/identities")
def analytics_identities(request: Request, top: int = 10):
    return clean_json(svc.analytics_identities(_res(request), top))


# ---------------------------------------------------------------- notifications
@router.get("/notifications")
def list_notifications(limit: int = 50):
    return clean_json(notify.list_notifications(limit))


@router.get("/notifications/status")
def notifications_status():
    return clean_json(notify.status())


@router.post("/notifications/test")
def notifications_test():
    rec = notify.send_test()
    return clean_json(rec if rec is not None else {"status": "off", "detail": "EMAIL_MODE=off"})


@router.post("/alerts/{alert_id}/notify")
def notify_alert(alert_id: str, request: Request):
    alert = svc.find_alert(_res(request), alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    rec = notify.notify_alert(alert)
    return clean_json(rec if rec is not None else {"status": "off", "detail": "EMAIL_MODE=off"})
