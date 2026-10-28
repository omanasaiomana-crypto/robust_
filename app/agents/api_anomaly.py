"""Unusual API and region anomaly detector (P4)."""
import logging
import pandas as pd

from app.agents.base import Agent
from app.config import API_RARITY_THRESHOLD, PEER_RARITY_THRESHOLD, SENSITIVE_ACTIONS
from app.models import Signal

log = logging.getLogger(__name__)


class ApiAnomalyAgent(Agent):
    name: str = "api_anomaly"
    pattern: str = "P4"
    mitre: list[str] = ["T1526", "T1562"]

    def detect(self, events: pd.DataFrame) -> list[Signal]:
        signals: list[Signal] = []
        if events is None or events.empty:
            return signals

        # Filter API events
        api_events = events[events["category"] == "api"].sort_values(by="timestamp")
        if api_events.empty:
            return signals

        # Try to load peer anomaly if available
        peer_model = None
        try:
            from app.ml.peers import PeerModel  # type: ignore
            peer_model = PeerModel()
        except (ImportError, Exception):
            pass

        # Calculate historical counts per identity for rarity computation
        counts_per_identity: dict[str, int] = {}
        action_counts: dict[tuple[str, str], int] = {}

        for _, row in api_events.iterrows():
            uid = str(row["identity_id"])
            act = str(row["action"])
            counts_per_identity[uid] = counts_per_identity.get(uid, 0) + 1
            action_counts[(uid, act)] = action_counts.get((uid, act), 0) + 1

        # Track seen regions per identity chronologically
        seen_regions: dict[str, set[str]] = {}

        for _, row in api_events.iterrows():
            uid = str(row["identity_id"])
            act = str(row["action"])
            reg = str(row.get("region") or "")
            eid = str(row["event_id"])
            sess = str(row.get("session_id") or "")
            ts = row["timestamp"]

            if uid not in seen_regions:
                seen_regions[uid] = set()

            is_new_region = bool(reg and reg != "None" and reg not in seen_regions[uid] and len(seen_regions[uid]) > 0)
            if reg and reg != "None":
                seen_regions[uid].add(reg)

            is_sensitive = act in SENSITIVE_ACTIONS
            total_events_user = counts_per_identity.get(uid, 0)

            identity_rarity = 0.0
            if total_events_user >= 5:
                act_cnt = action_counts.get((uid, act), 0)
                identity_rarity = 1.0 - (act_cnt / total_events_user)

            peer_rarity = 1.0
            if peer_model is not None:
                try:
                    peer_rarity = peer_model.score(uid, act)
                except Exception:
                    peer_rarity = 1.0

            is_rare_action = bool(
                total_events_user >= 5
                and identity_rarity >= API_RARITY_THRESHOLD
                and peer_rarity >= PEER_RARITY_THRESHOLD
            )

            # Fire signal if sensitive action, new region, or statistically rare action
            if is_sensitive or is_new_region or is_rare_action:
                severity = 0.5
                reasons: list[str] = []

                if is_sensitive:
                    severity += 0.3
                    reasons.append(f"sensitive action {act}")
                if is_new_region:
                    severity += 0.2
                    reasons.append(f"unseen region {reg}")
                if is_rare_action:
                    reasons.append(f"rare action (identity rarity: {identity_rarity:.1%})")

                severity = min(1.0, severity)
                reason_str = f"Unusual API activity by {uid}: {', '.join(reasons)}."

                signals.append(
                    Signal(
                        pattern=self.pattern,
                        severity=round(severity, 3),
                        identity_id=uid,
                        session_id=sess,
                        agent=self.name,
                        reason=reason_str,
                        evidence_event_ids=[eid],
                        mitre=self.mitre,
                        timestamp=ts,
                    )
                )

        return signals
