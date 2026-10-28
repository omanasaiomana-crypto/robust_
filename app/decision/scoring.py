"""Multi-factor risk scoring, decay, and counterfactual explanation."""
import pandas as pd

from app.config import (
    COMBO_BONUS_PER_PATTERN,
    CONFIDENCE_EVENTS_SATURATION,
    PRIVILEGE_MULTIPLIER,
    RISK_HALF_LIFE_HOURS,
    SENSITIVITY_MULTIPLIER,
    SIGNAL_WEIGHTS,
)
from app.models import Counterfactual, Prediction, Signal


def score_session(
    signals: list[Signal],
    session_events: pd.DataFrame,
    weights: dict[str, float] | None = None,
    prediction: Prediction | None = None,
    ml_score: float = 0.0,
) -> tuple[float, float]:
    """Score a session, returning (risk, confidence) rounded per spec."""
    w = dict(SIGNAL_WEIGHTS)
    if weights:
        w.update(weights)

    max_sev: dict[str, float] = {}
    for s in signals:
        max_sev[s.pattern] = max(max_sev.get(s.pattern, 0.0), float(s.severity))

    if ml_score > 0 and "ML" not in max_sev:
        max_sev["ML"] = float(ml_score)

    distinct_patterns = set(max_sev.keys())
    if not distinct_patterns:
        return 0.0, 0.0

    # 1. Base score
    base = sum(w.get(p, SIGNAL_WEIGHTS.get(p, 20.0)) * sev for p, sev in max_sev.items())

    # 2. Context multipliers
    privilege = 1
    max_sensitivity = 1
    if session_events is not None and not session_events.empty:
        if "privilege_level" in session_events:
            privilege = int(session_events["privilege_level"].max() or 1)
        if "resource_sensitivity" in session_events:
            max_sensitivity = int(session_events["resource_sensitivity"].max() or 1)

    context = PRIVILEGE_MULTIPLIER.get(privilege, 1.0) * SENSITIVITY_MULTIPLIER.get(max_sensitivity, 1.0)

    # 3. Combo bonus
    combo = 1.0 + COMBO_BONUS_PER_PATTERN * max(0, len(distinct_patterns) - 1)

    # 4. Chain multiplier
    chain = 1.0
    if prediction is not None and prediction.probability > 0:
        chain = 1.0 + float(prediction.probability)

    # Raw risk
    raw_risk = base * context * combo * chain
    risk = round(min(100.0, max(0.0, raw_risk)), 1)

    # Confidence calculation
    n_events = len(session_events) if session_events is not None else 0
    n_signals = max(1, len(signals) + (1 if ml_score > 0 and "ML" not in {s.pattern for s in signals} else 0))
    conf = min(1.0, n_events / CONFIDENCE_EVENTS_SATURATION) * (len(distinct_patterns) / n_signals)
    confidence = round(min(1.0, max(0.0, conf)), 3)

    return risk, confidence


def counterfactuals(
    signals: list[Signal],
    session_events: pd.DataFrame,
    weights: dict[str, float] | None = None,
    prediction: Prediction | None = None,
    ml_score: float = 0.0,
) -> list[Counterfactual]:
    """Recompute session risk removing each detected pattern one at a time."""
    w = dict(SIGNAL_WEIGHTS)
    if weights:
        w.update(weights)

    patterns = {s.pattern for s in signals}
    if ml_score > 0:
        patterns.add("ML")

    out: list[Counterfactual] = []
    for p in sorted(patterns):
        filtered_sigs = [s for s in signals if s.pattern != p]
        filtered_ml = 0.0 if p == "ML" else ml_score
        filtered_pred = None if p == "P3" else prediction

        risk_without, _ = score_session(
            filtered_sigs,
            session_events,
            weights=w,
            prediction=filtered_pred,
            ml_score=filtered_ml,
        )
        out.append(Counterfactual(without=p, risk=round(risk_without, 1)))

    return out


def decayed(risk: float, hours: float, confirmed: bool = False) -> float:
    """Apply half-life decay to risk score unless confirmed as true positive."""
    if confirmed:
        return round(float(risk), 1)
    decay = float(risk) * (0.5 ** (max(0.0, float(hours)) / RISK_HALF_LIFE_HOURS))
    return round(decay, 1)
