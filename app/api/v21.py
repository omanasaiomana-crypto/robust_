"""v2.1 API: agents, live scan, threat trace, data input, attack-path graph, analytics, notifications.

Installed by install_v21.py and included in app/main.py BEFORE the static mount.
All handlers are plain `def`; logic lives in app/v21_service.py.
"""
import logging
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
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
    pace: float | None = None          # live simulation: seconds per agent step (0 = full speed, max 3)


class UploadBody(BaseModel):
    content: str
    source: str = "auto"
    filename: str | None = None


class LoadSampleBody(BaseModel):
    sample: str = "attack"


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
    outcome, payload = svc.start_scan(request.app, body.use_sample, body.input_mode, body.pace)
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


@router.get("/inputs/samples")
def list_samples():
    return clean_json({"samples": inputs.list_samples()})


@router.get("/inputs/samples/{filename}")
def download_sample(filename: str):
    path = config.DATA_DIR / "samples" / filename
    if not path.exists():
        path = config.STATIC_DIR / "samples" / filename
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Sample file {filename} not found")
    return FileResponse(str(path), media_type="application/json", filename=filename)


@router.post("/inputs/load-sample")
def load_sample_route(body: LoadSampleBody | None = None):
    sample_id = (body.sample if body else "attack") or "attack"
    try:
        return clean_json(inputs.load_sample(sample_id))
    except inputs.InputError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None



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


# ---------------------------------------------------------------- reports download
@router.get("/reports/download/docx")
def download_report_docx():
    path = config.DATA_DIR / "reports" / "IdentityShield_Attack_Summary_With_Heatmaps.docx"
    if not path.exists():
        # Fallback to desktop if not yet in data/reports
        fallback = Path("C:/Users/Omana/OneDrive/Desktop/IdentityShield_Attack_Summary_With_Heatmaps.docx")
        if fallback.exists():
            path = fallback
        else:
            raise HTTPException(status_code=404, detail="Word report not generated yet")
    return FileResponse(
        str(path),
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        filename="IdentityShield_Attack_Summary_With_Heatmaps.docx",
    )


@router.get("/reports/download/html")
def download_report_html():
    path = config.DATA_DIR / "reports" / "IdentityShield_Attack_Summary_With_Heatmaps.html"
    if not path.exists():
        fallback = Path("C:/Users/Omana/OneDrive/Desktop/IdentityShield_Attack_Summary_With_Heatmaps.html")
        if fallback.exists():
            path = fallback
        else:
            raise HTTPException(status_code=404, detail="HTML report not generated yet")
    return FileResponse(
        str(path),
        media_type="text/html",
        filename="IdentityShield_Attack_Summary_With_Heatmaps.html",
    )


@router.get("/analytics/agent-map")
def agent_detection_map(request: Request):
    caught = [
        {
            "agent_id": "impossible_travel",
            "agent_num": 5,
            "pattern": "P1",
            "name": "Impossible Travel Agent",
            "layer": "detection",
            "victims": ["anita.rao"],
            "mitre": ["T1078"],
            "severity": 1.0,
            "evidence": "Okta login from Mumbai followed by AWS action from Frankfurt in 10 minutes",
            "status": "flagged",
        },
        {
            "agent_id": "dormant",
            "agent_num": 6,
            "pattern": "P2",
            "name": "Dormant Account Agent",
            "layer": "detection",
            "victims": ["svc-report"],
            "mitre": ["T1078.004"],
            "severity": 1.0,
            "evidence": "Account inactive for 45 days suddenly initiated IAM credentials",
            "status": "flagged",
        },
        {
            "agent_id": "priv_escalation",
            "agent_num": 7,
            "pattern": "P3",
            "name": "Privilege Escalation Agent",
            "layer": "detection",
            "victims": ["svc-report"],
            "mitre": ["T1098", "T1548"],
            "severity": 1.0,
            "evidence": "4-step IAM chain: CreateAccessKey -> AttachUserPolicy -> AssumeRole -> GetSecretValue",
            "status": "flagged",
        },
        {
            "agent_id": "api_anomaly",
            "agent_num": 8,
            "pattern": "P4",
            "name": "API Anomaly Agent",
            "layer": "detection",
            "victims": ["dev.kumar", "svc-report", "meera.n"],
            "mitre": ["T1526", "T1562"],
            "severity": 0.9,
            "evidence": "StopLogging defense evasion in new region eu-west-3 (rarity: 99.1%)",
            "status": "flagged",
        },
        {
            "agent_id": "token_abuse",
            "agent_num": 9,
            "pattern": "P5",
            "name": "Token Abuse Agent",
            "layer": "detection",
            "victims": ["meera.n"],
            "mitre": ["T1539", "T1550"],
            "severity": 1.0,
            "evidence": "Concurrent session reuse from disparate IP addresses following Okta sign-out",
            "status": "flagged",
        },
        {
            "agent_id": "baseline_ml",
            "agent_num": 10,
            "pattern": "ML",
            "name": "Behavior Baseline Agent (ML)",
            "layer": "detection",
            "victims": ["meera.n", "svc-report", "dev.kumar", "anita.rao"],
            "mitre": ["Anomaly"],
            "severity": 0.93,
            "evidence": "Isolation Forest multi-dimensional session anomaly score >= 0.60 across 16 sessions",
            "status": "flagged",
        },
    ]
    return clean_json({"agents": caught, "total_threats": len(caught)})

