"""Alert management endpoints: listing, filtering, detail, evidence events, action, and feedback."""
import logging
from typing import Any
from fastapi import APIRouter, HTTPException, Request
import pandas as pd

from app import runner, store, trace
from app.decision import feedback, respond
from app.decision.respond import recommend
from app.decision.scoring import counterfactuals, score_session
from app.models import ActionRequest, ActionResult, Alert, Event, FeedbackRequest
from app.simulator import get_simulator
from app.utils import to_band

log = logging.getLogger(__name__)

router = APIRouter(tags=["alerts"])


def _result(request: Request):
    res = getattr(request.app.state, "result", None)
    if res is None:
        raise HTTPException(status_code=503, detail="Pipeline has not produced results yet")
    return res


def _find_alert(res: Any, alert_id: str) -> Alert | None:
    if res.alerts:
        for a in res.alerts:
            if a.alert_id == alert_id:
                return a
    return store.load_alert(alert_id)


@router.get("/alerts", response_model=list[Alert])
def list_alerts(
    request: Request,
    min_risk: float = 0.0,
    band: str | None = None,
    pattern: str | None = None,
    identity: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[Alert]:
    alerts = _result(request).alerts or []
    out = [
        a
        for a in alerts
        if a.risk >= min_risk
        and (band is None or a.band == band)
        and (pattern is None or pattern in a.patterns)
        and (identity is None or a.identity_id == identity)
    ]
    out.sort(key=lambda a: (a.risk, a.blast_radius), reverse=True)
    return out[offset : offset + max(1, min(limit, 500))]


@router.get("/alerts/{alert_id}", response_model=Alert)
def get_alert_detail(request: Request, alert_id: str) -> Alert:
    res = _result(request)
    alert = _find_alert(res, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    return alert


@router.get("/alerts/{alert_id}/events", response_model=list[Event])
def get_alert_events(request: Request, alert_id: str) -> list[Event]:
    res = _result(request)
    alert = _find_alert(res, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")

    ev_ids = set(alert.evidence_event_ids)
    if not ev_ids or res.events is None or res.events.empty:
        return []

    matching = res.events[res.events["event_id"].isin(ev_ids)].sort_values(by="timestamp")
    out: list[Event] = []
    for _, row in matching.iterrows():
        clean_d = {k: (None if pd.isna(v) else v) for k, v in row.items()}
        out.append(Event.model_validate(clean_d))
    return out


@router.post("/alerts/{alert_id}/action", response_model=ActionResult)
def apply_alert_action(request: Request, alert_id: str, req: ActionRequest) -> ActionResult:
    if runner.is_running():
        raise HTTPException(status_code=409, detail="Pipeline is re-running; try again in a few seconds")
    res = _result(request)
    alert = _find_alert(res, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")

    sim = get_simulator()
    approved_by = req.approved_by if "approved_by" in req.model_fields_set else None
    with trace.step("response", f"Analyst action {req.action} on {alert_id}") as s:
        try:
            act_res = respond.apply_action(alert, req.action, approved_by=approved_by, sim=sim)
        except (ValueError, PermissionError) as exc:
            raise HTTPException(status_code=409, detail=str(exc))

        if act_res.status == "refused":
            raise HTTPException(status_code=409, detail=act_res.detail)

        alert.action_status = act_res.status
        store.update_alert(alert)
        s.output(
            {"alert_id": alert_id, "action": req.action, "status": act_res.status, "detail": act_res.detail},
            f"Action {req.action} on {alert_id}: {act_res.status}",
        )
        return act_res


@router.post("/alerts/{alert_id}/feedback", response_model=Alert)
def submit_feedback(request: Request, alert_id: str, req: FeedbackRequest) -> Alert:
    if runner.is_running():
        raise HTTPException(status_code=409, detail="Pipeline is re-running; try again in a few seconds")
    res = _result(request)
    alert = _find_alert(res, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")

    with trace.step("feedback", f"Analyst marked {alert_id} as {req.label}") as s:
        try:
            new_weights = feedback.apply_feedback(alert, req.label)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))

        # Rescore alert with updated weights
        s_events = pd.DataFrame()
        if res.events is not None and not res.events.empty and alert.session_id:
            s_events = res.events[res.events["session_id"] == alert.session_id]

        sess_sigs = [sig for sig in res.signals if sig.session_id == alert.session_id] if res.signals else []
        ml_s = 0.0
        for sig in sess_sigs:
            if sig.pattern == "ML":
                ml_s = float(sig.severity)

        new_risk, new_conf = score_session(
            sess_sigs,
            s_events,
            weights=new_weights,
            prediction=alert.prediction,
            ml_score=ml_s,
        )
        alert.risk = new_risk
        alert.band = to_band(new_risk)
        alert.confidence = new_conf
        alert.counterfactuals = counterfactuals(
            sess_sigs,
            s_events,
            weights=new_weights,
            prediction=alert.prediction,
            ml_score=ml_s,
        )
        alert.recommended_action = recommend(new_risk)
        store.update_alert(alert)
        s.output({"weights": new_weights}, f"Analyst marked {alert_id} as {req.label}")
        return alert
