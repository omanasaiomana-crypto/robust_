"""Analyst feedback learning loop updating detector weights."""
import logging

from app import audit, store
from app.config import FEEDBACK_LEARNING_RATE, WEIGHT_MAX, WEIGHT_MIN
from app.models import Alert

log = logging.getLogger(__name__)


def apply_feedback(alert: Alert, label: str) -> dict[str, float]:
    """Update detector weights based on analyst True/False Positive feedback."""
    lbl = str(label).lower().strip()
    if lbl not in ("tp", "fp"):
        raise ValueError(f"Feedback label must be 'tp' or 'fp', got '{label}'")

    target = 1.0 if lbl == "tp" else 0.0
    predicted = float(alert.risk) / 100.0
    delta = FEEDBACK_LEARNING_RATE * (target - predicted) * 10.0

    current_weights = store.get_weights()
    updated_patterns: list[str] = []

    for p in alert.patterns:
        old_w = current_weights.get(p, 20.0)
        new_w = max(WEIGHT_MIN, min(WEIGHT_MAX, old_w + delta))
        rounded_w = round(new_w, 2)
        current_weights[p] = rounded_w
        store.set_weight(p, rounded_w)
        updated_patterns.append(f"{p}:{old_w}->{rounded_w}")

    alert.feedback = lbl
    store.update_alert(alert)

    audit.append(
        "analyst",
        "feedback",
        f"Alert {alert.alert_id} labeled '{lbl}': updated weights [{', '.join(updated_patterns)}]",
    )

    return current_weights
