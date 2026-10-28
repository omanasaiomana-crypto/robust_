"""Automated response recommendation, approval guard, and simulation enforcement."""
from datetime import datetime, timezone
import logging

from app import audit, store
from app.config import FRICTION_BUDGET_PER_DAY, REQUIRE_APPROVAL_FOR_REVOKE
from app.models import ActionResult, Alert
from app.simulator.base import SimulatorAdapter
from app.utils import to_band

log = logging.getLogger(__name__)

ALLOWED_ACTIONS = {"monitor", "step_up", "restrict", "revoke", "dismiss"}


def recommend(risk: float) -> str:
    """Recommend containment action based on risk band."""
    return to_band(risk)


def apply_action(
    alert: Alert,
    action: str,
    approved_by: str | None,
    sim: SimulatorAdapter,
) -> ActionResult:
    """Safely apply a containment action through the simulator adapter."""
    act = str(action).lower().strip()

    if act not in ALLOWED_ACTIONS:
        detail = f"Action '{act}' is not in allowed set: {sorted(ALLOWED_ACTIONS)}"
        audit.append("response", "refused", f"Alert {alert.alert_id}: {detail}")
        return ActionResult(alert_id=alert.alert_id, action=act, status="refused", detail=detail)

    # Dismissal
    if act == "dismiss":
        detail = f"Alert dismissed by {approved_by or 'analyst'}."
        audit.append("response", "dismiss", f"Alert {alert.alert_id}: {detail}")
        alert.action_status = "dismissed"
        store.update_alert(alert)
        return ActionResult(alert_id=alert.alert_id, action="dismiss", status="dismissed", detail=detail)

    # Monitor
    if act == "monitor":
        detail = "Session flagged for monitoring; no active enforcement required."
        audit.append("response", "monitor", f"Alert {alert.alert_id}: {detail}")
        alert.action_status = "applied"
        store.update_alert(alert)
        return ActionResult(alert_id=alert.alert_id, action="monitor", status="applied", detail=detail)

    # Revoke guard: requires explicit approval
    if act == "revoke" and REQUIRE_APPROVAL_FOR_REVOKE:
        if not approved_by or not str(approved_by).strip() or approved_by == "system":
            detail = "Revoke containment requires explicit analyst approval."
            audit.append("response", "refused", f"Alert {alert.alert_id}: {detail}")
            return ActionResult(alert_id=alert.alert_id, action="revoke", status="refused", detail=detail)

    # Step-up friction budget guard
    if act == "step_up":
        day_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        used = store.friction_used(alert.identity_id, day_str)
        if used >= FRICTION_BUDGET_PER_DAY:
            detail = (
                f"Friction budget of {FRICTION_BUDGET_PER_DAY}/day exceeded for {alert.identity_id}; "
                f"converted to notification."
            )
            audit.append("response", "notify", f"Alert {alert.alert_id}: {detail}")
            alert.action_status = "notified"
            store.update_alert(alert)
            return ActionResult(alert_id=alert.alert_id, action="step_up", status="notified", detail=detail)

        store.friction_increment(alert.identity_id, day_str)

    # Apply via simulator
    try:
        if act == "step_up":
            detail = sim.step_up(alert.identity_id, alert.session_id)
        elif act == "restrict":
            detail = sim.restrict(alert.identity_id, "default")
        elif act == "revoke":
            detail = sim.revoke(alert.identity_id, alert.session_id)
        else:
            detail = f"Action {act} applied."

        audit.append("response", act, f"Alert {alert.alert_id} ({alert.identity_id}): {detail}")
        alert.action_status = "applied"
        store.update_alert(alert)
        return ActionResult(alert_id=alert.alert_id, action=act, status="applied", detail=detail)

    except Exception as exc:
        log.exception("Simulator execution failed for %s", alert.alert_id)
        detail = f"Simulator execution error: {exc}"
        audit.append("response", "error", f"Alert {alert.alert_id}: {detail}")
        return ActionResult(alert_id=alert.alert_id, action=act, status="failed", detail=detail)


def auto_apply(alert: Alert, sim: SimulatorAdapter) -> Alert:
    """Automatically apply actions for low/medium bands; leave revoke pending."""
    rec = recommend(alert.risk)
    alert.recommended_action = rec

    if rec in ("monitor", "step_up", "restrict"):
        res = apply_action(alert, rec, approved_by="system", sim=sim)
        alert.action_status = res.status
    else:
        # Revoke must be approved by analyst
        alert.action_status = "pending"

    return alert
