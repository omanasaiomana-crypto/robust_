"""Dormant account reactivation detector (P2)."""
import pandas as pd

from app.agents.base import Agent
from app.config import DORMANT_DAYS
from app.models import Signal


class DormantAccountAgent(Agent):
    name: str = "dormant"
    pattern: str = "P2"
    mitre: list[str] = ["T1078.004"]

    def detect(self, events: pd.DataFrame) -> list[Signal]:
        signals: list[Signal] = []
        if events is None or events.empty:
            return signals

        sorted_events = events.sort_values(by="timestamp")

        for uid, group in sorted_events.groupby("identity_id", sort=False):
            if len(group) < 2:
                continue

            prev_row = None
            for _, curr_row in group.iterrows():
                if prev_row is not None:
                    prev_ts = prev_row["timestamp"]
                    curr_ts = curr_row["timestamp"]
                    gap_days = (curr_ts - prev_ts).total_seconds() / 86400.0

                    if gap_days >= DORMANT_DAYS and str(curr_row.get("outcome", "")).lower() == "success":
                        priv = int(curr_row.get("privilege_level", 1) or 1)
                        severity = 0.9 if priv >= 4 else 0.6
                        action = str(curr_row.get("action", "unknown"))

                        reason = (
                            f"Account {uid} reactivated after {gap_days:.1f} days of inactivity "
                            f"with action {action} (privilege level {priv})."
                        )

                        signals.append(
                            Signal(
                                pattern=self.pattern,
                                severity=severity,
                                identity_id=str(uid),
                                session_id=str(curr_row.get("session_id") or ""),
                                agent=self.name,
                                reason=reason,
                                evidence_event_ids=[str(curr_row["event_id"])],
                                mitre=self.mitre,
                                timestamp=curr_ts,
                            )
                        )

                prev_row = curr_row

        return signals


DormantAgent = DormantAccountAgent
