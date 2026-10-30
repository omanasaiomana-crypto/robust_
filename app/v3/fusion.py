"""Risk fusion mathematical model (PRD §14).

Implements:
1. noisy_or(signals, weights):
   P = 1 - product(1 - w_i * c_i * s_i)
2. multipliers(context_summary):
   M_privilege, M_sensitivity, M_action
3. chain_factor(stages):
   F_chain = 1 + 0.15 * (distinct_stages - 1), capped at 1.6
4. session_risk(signals, context_summary, weights):
   SessionRisk = min(100, 100 * P * M_priv * M_sens * M_act * F_chain)
5. identity_risk(previous_score, last_update_ts, now_ts, current_session_score):
   IdentityRisk(t) = max(previous * e^(-lambda * delta_t), current_session_score)
6. confidence(signals, context_completeness, identity_resolution_confidence):
   Mean signal confidence * context_completeness * identity_resolution_confidence
7. counterfactuals(signals, context_summary, weights):
   Top 3 factors by score delta when removed
"""
from __future__ import annotations

import math
from typing import Any

from app.v3 import config
from app.v3.models import (
    Counterfactual,
    Signal,
    Stage,
)

FAMILY_LABELS: dict[str, str] = {
    "D-ACC": "without access anomalies",
    "D-SES": "without session anomalies",
    "D-CRD": "without credential anomalies",
    "D-PE": "without escalation chain",
    "D-DEF": "without defense evasion",
    "D-ML": "without ML anomalies",
    "D-CMP": "without campaign signals",
}


def get_detection_id(sig: Signal | dict[str, Any]) -> str:
    """Extract detection_id string from a Signal or dict."""
    if hasattr(sig, "detection_id"):
        return str(sig.detection_id)
    return str(sig.get("detection_id", ""))


def get_signal_strength(sig: Signal | dict[str, Any]) -> float:
    """Extract strength float from a Signal or dict."""
    if hasattr(sig, "strength"):
        return float(sig.strength)
    return float(sig.get("strength", 0.0))


def get_signal_confidence(sig: Signal | dict[str, Any]) -> float:
    """Extract confidence float from a Signal or dict."""
    if hasattr(sig, "confidence"):
        return float(sig.confidence)
    return float(sig.get("confidence", 0.8))


def get_signal_stage(sig: Signal | dict[str, Any]) -> str:
    """Extract stage string from a Signal or dict."""
    if hasattr(sig, "stage"):
        val = sig.stage
        return val.value if hasattr(val, "value") else str(val)
    val = sig.get("stage", "")
    return val.value if hasattr(val, "value") else str(val)


def get_detector_weight(detection_id: str, weights: dict[str, float] | None = None) -> float:
    """Get detector weight with defaults and floor protection."""
    weights = weights or {}

    # Exact match
    if detection_id in weights:
        w = weights[detection_id]
    else:
        # Prefix match or default
        matched = False
        w = 1.0
        for prefix, weight_val in weights.items():
            if detection_id.startswith(prefix):
                w = weight_val
                matched = True
                break
        if not matched:
            w = 0.8 if detection_id.startswith("D-ML") else 1.0

    # Apply floors per PRD §14.4 & config.WEIGHT_FLOORS
    for floor_prefix, min_floor in config.WEIGHT_FLOORS.items():
        if detection_id.startswith(floor_prefix):
            w = max(min_floor, w)

    return min(1.0, max(0.0, w))


def noisy_or(
    signals: list[Signal | dict[str, Any]],
    weights: dict[str, float] | None = None,
) -> float:
    """Compute noisy-OR probability P = 1 - prod(1 - w_i * c_i * s_i)."""
    if not signals:
        return 0.0

    prod = 1.0
    for sig in signals:
        det_id = get_detection_id(sig)
        s = get_signal_strength(sig)
        c = get_signal_confidence(sig)
        w = get_detector_weight(det_id, weights)
        term = 1.0 - (w * c * s)
        prod *= max(0.0, min(1.0, term))

    p = 1.0 - prod
    return max(0.0, min(1.0, p))


def multipliers(context_summary: dict[str, Any]) -> tuple[float, float, float]:
    """Compute privilege, sensitivity, and action multipliers."""
    # 1. Privilege multiplier (level 1–5)
    priv_level = int(context_summary.get("privilege_level", 2))
    priv_idx = max(0, min(len(config.PRIVILEGE_MULT) - 1, priv_level - 1))
    m_priv = config.PRIVILEGE_MULT[priv_idx]

    # 2. Resource sensitivity multiplier (level 1–5)
    sens_level = int(context_summary.get("resource_sensitivity", 2))
    sens_idx = max(0, min(len(config.SENSITIVITY_MULT) - 1, sens_level - 1))
    m_sens = config.SENSITIVITY_MULT[sens_idx]

    # 3. Action severity multiplier
    worst_action = str(context_summary.get("worst_action", "read")).lower().strip()
    if worst_action in ("permission", "permission_change", "credential", "credential_change"):
        m_act = 1.25
    elif worst_action in ("destructive", "defense_evasion"):
        m_act = 1.4
    elif worst_action == "write":
        m_act = 1.1
    elif worst_action == "read":
        m_act = 1.0
    else:
        m_act = config.ACTION_MULT.get(worst_action, 1.0)

    return m_priv, m_sens, m_act


def chain_factor(stages: list[Stage | str] | set[Stage | str]) -> float:
    """Compute kill-chain expansion factor F_chain = 1 + 0.15 * (distinct_stages - 1), capped at 1.6."""
    stage_strs = {s.value if hasattr(s, "value") else str(s) for s in stages if s}
    k = len(stage_strs)
    if k <= 1:
        return 1.0
    return min(config.CHAIN_CAP, 1.0 + config.CHAIN_STEP * (k - 1))


def session_risk(
    signals: list[Signal | dict[str, Any]],
    context_summary: dict[str, Any],
    weights: dict[str, float] | None = None,
    override_priv_mult: float | None = None,
    override_sens_mult: float | None = None,
    override_act_mult: float | None = None,
    override_chain_factor: float | None = None,
) -> tuple[float, dict[str, float]]:
    """Compute calibrated session risk score in [0, 100] and factor dictionary."""
    p = noisy_or(signals, weights)
    base_m_priv, base_m_sens, base_m_act = multipliers(context_summary)

    m_priv = override_priv_mult if override_priv_mult is not None else base_m_priv
    m_sens = override_sens_mult if override_sens_mult is not None else base_m_sens
    m_act = override_act_mult if override_act_mult is not None else base_m_act

    # Distinct stages
    signal_stages = {get_signal_stage(s) for s in signals if get_signal_stage(s)}
    if "stages" in context_summary:
        for st in context_summary["stages"]:
            st_val = st.value if hasattr(st, "value") else str(st)
            if st_val:
                signal_stages.add(st_val)

    if override_chain_factor is not None:
        f_chain = override_chain_factor
    else:
        f_chain = chain_factor(signal_stages)

    raw_score = 100.0 * p * m_priv * m_sens * m_act * f_chain
    score = min(100.0, max(0.0, raw_score))

    factors: dict[str, float] = {
        "noisy_or_p": round(p, 4),
        "m_privilege": float(m_priv),
        "m_sensitivity": float(m_sens),
        "m_action": float(m_act),
        "f_chain": round(f_chain, 3),
        "distinct_stages": float(len(signal_stages)),
        "signal_count": float(len(signals)),
    }

    return round(score, 1), factors


def identity_risk(
    previous_score: float,
    last_update_ts: float,
    now_ts: float,
    current_session_score: float,
    half_life_hours: float = config.IDENTITY_HALF_LIFE_HOURS,
) -> float:
    """Compute decayed identity risk: max(previous * e^(-lambda * dt), current_session_score)."""
    delta_t = max(0.0, now_ts - last_update_ts)
    half_life_seconds = half_life_hours * 3600.0
    lam = math.log(2) / half_life_seconds if half_life_seconds > 0 else 0.0

    decayed = previous_score * math.exp(-lam * delta_t)
    final_score = max(decayed, current_session_score)
    return round(min(100.0, max(0.0, final_score)), 1)


def confidence(
    signals: list[Signal | dict[str, Any]],
    context_completeness: float = 1.0,
    identity_resolution_confidence: float = 1.0,
) -> float:
    """Compute overall risk confidence."""
    if not signals:
        return 0.8

    conf_values = [get_signal_confidence(s) for s in signals]
    mean_conf = sum(conf_values) / len(conf_values)
    final_conf = mean_conf * context_completeness * identity_resolution_confidence
    return round(min(1.0, max(0.0, final_conf)), 2)


def counterfactuals(
    signals: list[Signal | dict[str, Any]],
    context_summary: dict[str, Any],
    weights: dict[str, float] | None = None,
) -> list[Counterfactual]:
    """Calculate top 3 counterfactual drops when individual factors/families are removed."""
    base_score, _ = session_risk(signals, context_summary, weights)
    if base_score <= 0.0:
        return []

    candidates: list[tuple[str, float, float]] = []

    # 1. Test removal of each detection family
    for prefix, label in FAMILY_LABELS.items():
        has_family = any(get_detection_id(s).startswith(prefix) for s in signals)
        if has_family:
            subset = [s for s in signals if not get_detection_id(s).startswith(prefix)]
            score_without, _ = session_risk(subset, context_summary, weights)
            delta = max(0.0, base_score - score_without)
            candidates.append((label, score_without, delta))

    # 2. Test removal of privilege multiplier (neutral = 1.0)
    m_priv, m_sens, m_act = multipliers(context_summary)
    if m_priv != 1.0:
        score_without, _ = session_risk(signals, context_summary, weights, override_priv_mult=1.0)
        delta = max(0.0, base_score - score_without)
        candidates.append(("without privilege multiplier", score_without, delta))

    # 3. Test removal of sensitivity multiplier (neutral = 1.0)
    if m_sens != 1.0:
        score_without, _ = session_risk(signals, context_summary, weights, override_sens_mult=1.0)
        delta = max(0.0, base_score - score_without)
        candidates.append(("without sensitivity multiplier", score_without, delta))

    # 4. Test removal of action severity multiplier (neutral = 1.0)
    if m_act != 1.0:
        score_without, _ = session_risk(signals, context_summary, weights, override_act_mult=1.0)
        delta = max(0.0, base_score - score_without)
        candidates.append(("without action severity multiplier", score_without, delta))

    # 5. Test removal of multi-stage chain factor (neutral = 1.0)
    signal_stages = {get_signal_stage(s) for s in signals if get_signal_stage(s)}
    if "stages" in context_summary:
        for st in context_summary["stages"]:
            st_val = st.value if hasattr(st, "value") else str(st)
            if st_val:
                signal_stages.add(st_val)
    if len(signal_stages) > 1:
        score_without, _ = session_risk(signals, context_summary, weights, override_chain_factor=1.0)
        delta = max(0.0, base_score - score_without)
        candidates.append(("without multi-stage chain factor", score_without, delta))

    # Sort by delta descending
    candidates.sort(key=lambda c: c[2], reverse=True)

    top3 = candidates[:3]
    return [
        Counterfactual(
            removed_factor=c[0],
            score_without=round(c[1], 1),
            delta=round(c[2], 1),
        )
        for c in top3
    ]
