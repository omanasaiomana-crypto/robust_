"""Agent 12: Risk Fusion.

Fuses multi-agent signals into calibrated session and identity risk scores:
- SessionRisk = min(100, 100 * P * M_priv * M_sens * M_act * F_chain)
- IdentityRisk(t) = max(IdentityRisk_0 * e^(-lambda * dt), current_session_score)
- Pre-emptive scrutiny: Identity risk >= 60 lowers step-up threshold by 10 points
- Weight updates with floor protection (D-PE >= 0.6, D-DEF >= 0.6)
- Publishes RiskUpdate on topic `risk` when score changes by >= 1 point or band changes

Consumes: `signals`, `config.updates`
Publishes: `risk`, `deadletter`
"""
from __future__ import annotations

import json
import logging
import sqlite3
from datetime import UTC, datetime
from typing import Any, ClassVar

from app.v3 import config
from app.v3.agents.base import Agent, AgentContext
from app.v3.fusion import (
    confidence as calc_confidence,
)
from app.v3.fusion import (
    identity_risk as calc_identity_risk,
)
from app.v3.fusion import (
    session_risk as calc_session_risk,
)
from app.v3.models import (
    Band,
    Message,
    RiskScore,
    RiskUpdate,
    Signal,
    band_for,
)

log = logging.getLogger(__name__)

ACTION_SEVERITY_ORDER: dict[str, int] = {
    "read": 0,
    "write": 1,
    "permission": 2,
    "permission_change": 2,
    "credential": 2,
    "credential_change": 2,
    "destructive": 3,
    "defense_evasion": 3,
}


def _update_worst_action(current: str, candidate: str | None) -> str:
    """Return the more severe action type."""
    if not candidate:
        return current
    cand = str(candidate).lower().strip()
    curr_rank = ACTION_SEVERITY_ORDER.get(current.lower().strip(), 0)
    cand_rank = ACTION_SEVERITY_ORDER.get(cand, 0)
    return cand if cand_rank > curr_rank else current


class RiskFusion(Agent):
    """Agent 12: Calibrated risk fusion across session signals and identity history."""

    num: ClassVar[int] = 12
    agent_id: ClassVar[str] = "agent12"
    name: ClassVar[str] = "fusion"
    layer: ClassVar[str] = "decision"
    path: ClassVar[str] = "warm"
    subscribes: ClassVar[list[str]] = ["signals", "config.updates"]
    publishes: ClassVar[list[str]] = ["risk", "deadletter"]

    def process(self, msg: Message, state: dict[str, Any], ctx: AgentContext) -> list[Message]:
        if msg.topic == "config.updates":
            return self._handle_config_update(msg, state, ctx)
        if msg.topic == "signals":
            return self._handle_signal(msg, state, ctx)
        return []

    def _handle_config_update(
        self,
        msg: Message,
        state: dict[str, Any],
        ctx: AgentContext,
    ) -> list[Message]:
        """Update detector weights respecting floors."""
        weights_state: dict[str, float] = state.setdefault("weights", {})
        payload = msg.payload

        new_weights: dict[str, Any] = {}
        if isinstance(payload, dict):
            if "weights" in payload and isinstance(payload["weights"], dict):
                new_weights = payload["weights"]
            elif "changes" in payload and isinstance(payload["changes"], dict):
                changes = payload["changes"]
                new_weights = changes.get("weights", changes)
            else:
                new_weights = payload
        elif hasattr(payload, "changes") and isinstance(payload.changes, dict):
            changes = payload.changes
            new_weights = changes.get("weights", changes)
        elif hasattr(payload, "weights") and isinstance(payload.weights, dict):
            new_weights = payload.weights

        for k, v in new_weights.items():
            try:
                w = float(v)
            except (ValueError, TypeError):
                continue

            # Apply floors from config.WEIGHT_FLOORS
            for floor_prefix, floor_val in config.WEIGHT_FLOORS.items():
                if k.startswith(floor_prefix) or (floor_prefix == "D-PE" and k.startswith("PE-")):
                    w = max(floor_val, w)

            weights_state[k] = min(1.0, max(0.0, w))

        return []

    def _handle_signal(
        self,
        msg: Message,
        state: dict[str, Any],
        ctx: AgentContext,
    ) -> list[Message]:
        """Process incoming signal, recompute risk, and publish if delta >= 1.0 or band changes."""
        payload = msg.payload
        if isinstance(payload, Signal):
            sig = payload
        elif isinstance(payload, dict):
            try:
                sig = Signal.model_validate(payload)
            except Exception:
                log.exception("Invalid signal payload for agent 12: %s", payload)
                return []
        else:
            return []

        identity_id = str(sig.identity_id or "")
        session_id = str(sig.session_id or sig.details.get("session_id") or f"sess-{identity_id}")

        sessions: dict[str, dict[str, Any]] = state.setdefault("sessions", {})
        identities: dict[str, dict[str, Any]] = state.setdefault("identities", {})
        lowered_step_up: dict[str, bool] = state.setdefault("lowered_step_up", {})
        weights: dict[str, float] = state.setdefault("weights", {})

        sess_data = sessions.setdefault(
            session_id,
            {
                "identity_id": identity_id,
                "signals": [],
                "signal_ids": set(),
                "last_published_score": 0.0,
                "last_published_band": Band.monitor,
                "context_summary": {
                    "privilege_level": 2,
                    "resource_sensitivity": 2,
                    "worst_action": "read",
                    "stages": set(),
                },
            },
        )

        # Deduplicate signals
        if sig.signal_id in sess_data["signal_ids"]:
            return []
        sess_data["signal_ids"].add(sig.signal_id)
        sess_data["signals"].append(sig)

        # Update per-session context summary
        cx = sess_data["context_summary"]

        # 1. From signal details
        details = sig.details or {}
        if "privilege_level" in details:
            try:
                cx["privilege_level"] = max(cx["privilege_level"], int(details["privilege_level"]))
            except (ValueError, TypeError):
                pass
        if "resource_sensitivity" in details:
            try:
                cx["resource_sensitivity"] = max(
                    cx["resource_sensitivity"], int(details["resource_sensitivity"])
                )
            except (ValueError, TypeError):
                pass
        if "action_type" in details:
            cx["worst_action"] = _update_worst_action(cx["worst_action"], details["action_type"])
        elif "action" in details:
            cx["worst_action"] = _update_worst_action(cx["worst_action"], details["action"])

        if sig.stage:
            stage_str = sig.stage.value if hasattr(sig.stage, "value") else str(sig.stage)
            if stage_str:
                cx["stages"].add(stage_str)

        # 2. Lookup session's enriched events in store if available
        context_completeness = 1.0
        resolution_conf = 1.0
        if ctx.store:
            try:
                events = ctx.store.fetch_all(
                    "SELECT action, resource_arn, attrs, resolution_confidence FROM events_v3 WHERE session_id = ?",
                    (session_id,),
                )
                if events:
                    full_count = 0
                    conf_vals = []
                    for ev in events:
                        conf_vals.append(float(ev.get("resolution_confidence") or 1.0))
                        raw_attrs = ev.get("attrs")
                        ev_attrs: dict[str, Any] = {}
                        if isinstance(raw_attrs, str):
                            try:
                                ev_attrs = json.loads(raw_attrs)
                            except (json.JSONDecodeError, TypeError):
                                ev_attrs = {}
                        elif isinstance(raw_attrs, dict):
                            ev_attrs = raw_attrs

                        if ev_attrs.get("context_complete", True):
                            full_count += 1
                        if "privilege_level" in ev_attrs:
                            cx["privilege_level"] = max(cx["privilege_level"], int(ev_attrs["privilege_level"]))
                        if "resource_sensitivity" in ev_attrs:
                            cx["resource_sensitivity"] = max(
                                cx["resource_sensitivity"], int(ev_attrs["resource_sensitivity"])
                            )
                        if "action_type" in ev_attrs:
                            cx["worst_action"] = _update_worst_action(cx["worst_action"], ev_attrs["action_type"])
                        elif ev.get("action"):
                            cx["worst_action"] = _update_worst_action(cx["worst_action"], ev.get("action"))

                        if ev_attrs.get("stage_hint"):
                            cx["stages"].add(str(ev_attrs["stage_hint"]))

                    context_completeness = full_count / len(events)
                    resolution_conf = min(conf_vals) if conf_vals else 1.0
            except (sqlite3.Error, AttributeError, TypeError):
                log.debug("Store query failed during context enrichment for session %s", session_id)

        # 3. Compute session risk
        sess_score, factors = calc_session_risk(
            signals=sess_data["signals"],
            context_summary=cx,
            weights=weights,
        )
        sess_band = band_for(sess_score)

        # 4. Compute identity risk
        now_ts = ctx.clock.now() if hasattr(ctx, "clock") and ctx.clock else datetime.now(UTC).timestamp()
        if hasattr(now_ts, "timestamp"):
            now_ts = now_ts.timestamp()

        ident_data = identities.setdefault(
            identity_id,
            {
                "score": 0.0,
                "last_published_score": 0.0,
                "last_published_band": Band.monitor,
                "last_update_ts": now_ts,
            },
        )

        prev_id_score = float(ident_data.get("score", 0.0))
        prev_id_ts = float(ident_data.get("last_update_ts", now_ts))

        new_id_score = calc_identity_risk(
            previous_score=prev_id_score,
            last_update_ts=prev_id_ts,
            now_ts=now_ts,
            current_session_score=sess_score,
            half_life_hours=config.IDENTITY_HALF_LIFE_HOURS,
        )
        new_id_band = band_for(new_id_score)

        # Update identity score & timestamp internally
        ident_data["score"] = new_id_score
        ident_data["last_update_ts"] = now_ts

        # 5. Pre-emptive scrutiny: Identity risk >= 60 lowers next session's step-up threshold by 10
        if new_id_score >= 60.0:
            lowered_step_up[identity_id] = True

        is_lowered = lowered_step_up.get(identity_id, False)
        factors["lowered_step_up_threshold"] = 1.0 if is_lowered else 0.0

        # 6. Overall confidence
        conf = calc_confidence(
            signals=sess_data["signals"],
            context_completeness=context_completeness,
            identity_resolution_confidence=resolution_conf,
        )

        # 7. Check publish threshold (score change >= 1.0 or band changes)
        last_pub_sess_score = float(sess_data.get("last_published_score", 0.0))
        last_pub_sess_band = sess_data.get("last_published_band", Band.monitor)
        last_pub_id_score = float(ident_data.get("last_published_score", 0.0))
        last_pub_id_band = ident_data.get("last_published_band", Band.monitor)

        sess_delta = abs(sess_score - last_pub_sess_score)
        sess_band_changed = sess_band != last_pub_sess_band
        id_delta = abs(new_id_score - last_pub_id_score)
        id_band_changed = new_id_band != last_pub_id_band

        should_publish = (
            sess_delta >= 1.0
            or sess_band_changed
            or id_delta >= 1.0
            or id_band_changed
        )

        if not should_publish:
            return []

        # Update published state
        sess_data["last_published_score"] = sess_score
        sess_data["last_published_band"] = sess_band
        ident_data["last_published_score"] = new_id_score
        ident_data["last_published_band"] = new_id_band

        # 8. Build RiskScore objects and RiskUpdate
        computed_at_str = (
            datetime.fromtimestamp(now_ts, UTC).isoformat()
            if hasattr(datetime, "fromtimestamp")
            else datetime.now(UTC).isoformat()
        )

        sess_risk_obj = RiskScore(
            subject_id=session_id,
            score=sess_score,
            confidence=conf,
            band=sess_band,
            factors=factors,
            computed_at=computed_at_str,
            score_kind="session",
        )

        id_factors: dict[str, float] = {
            "decayed_from_previous": round(prev_id_score, 1),
            "current_session_score": sess_score,
            "lowered_step_up_threshold": 1.0 if is_lowered else 0.0,
        }

        id_risk_obj = RiskScore(
            subject_id=identity_id,
            score=new_id_score,
            confidence=conf,
            band=new_id_band,
            factors=id_factors,
            computed_at=computed_at_str,
            score_kind="identity",
        )

        risk_update = RiskUpdate(
            identity_id=identity_id,
            session_id=session_id,
            session_risk=sess_risk_obj,
            identity_risk=id_risk_obj,
            signal_ids=[s.signal_id for s in sess_data["signals"]],
        )

        # 9. Persist to risk_v3 store if available
        if ctx.store:
            try:
                ctx.store.execute(
                    """INSERT OR REPLACE INTO risk_v3
                       (subject_id, subject_type, score, confidence, band, factors, computed_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (session_id, "session", sess_score, conf, sess_band.value, json.dumps(factors), computed_at_str),
                )
                ctx.store.execute(
                    """INSERT OR REPLACE INTO risk_v3
                       (subject_id, subject_type, score, confidence, band, factors, computed_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (identity_id, "identity", new_id_score, conf, new_id_band.value, json.dumps(id_factors), computed_at_str),
                )
            except (sqlite3.Error, AttributeError, TypeError):
                log.debug("Store insert into risk_v3 skipped or failed for session %s", session_id)

        out_msg = ctx.new_message(
            topic="risk",
            payload=risk_update,
            partition_key=identity_id,
            producer=self.agent_id,
        )
        return [out_msg]
