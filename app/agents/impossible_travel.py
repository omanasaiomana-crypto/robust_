"""Impossible travel detector (P1) identifying logins across geographically impossible distances."""
import pandas as pd

from app.agents.base import Agent
from app.config import IMPOSSIBLE_TRAVEL_KMH
from app.models import Signal
from app.utils import haversine_km


class ImpossibleTravelAgent(Agent):
    name: str = "impossible_travel"
    pattern: str = "P1"
    mitre: list[str] = ["T1078"]

    def detect(self, events: pd.DataFrame) -> list[Signal]:
        signals: list[Signal] = []

        # Filter: auth events with outcome success and non-null lat/lon
        mask = (
            (events["category"] == "auth")
            & (events["outcome"] == "success")
            & events["lat"].notna()
            & events["lon"].notna()
        )
        auth_events = events[mask].sort_values(by="timestamp")
        if auth_events.empty:
            return signals

        for uid, group in auth_events.groupby("identity_id", sort=False):
            if len(group) < 2:
                continue

            prev_row = None
            for _, curr_row in group.iterrows():
                if prev_row is not None:
                    prev_ts = prev_row["timestamp"]
                    curr_ts = curr_row["timestamp"]
                    hours = (curr_ts - prev_ts).total_seconds() / 3600.0

                    if hours >= 0:
                        km = haversine_km(
                            float(prev_row["lat"]),
                            float(prev_row["lon"]),
                            float(curr_row["lat"]),
                            float(curr_row["lon"]),
                        )
                        effective_hours = max(0.01, hours)
                        speed = km / effective_hours

                        asn_differs = (
                            bool(prev_row.get("asn") and curr_row.get("asn") and prev_row["asn"] != curr_row["asn"])
                            or (prev_row.get("city") != curr_row.get("city"))
                            or (prev_row.get("country") != curr_row.get("country"))
                        )

                        if speed > IMPOSSIBLE_TRAVEL_KMH and asn_differs:
                            severity = min(1.0, speed / 3000.0)
                            prev_city = prev_row.get("city") or prev_row.get("country") or "Unknown location"
                            curr_city = curr_row.get("city") or curr_row.get("country") or "Unknown location"
                            mins = hours * 60.0

                            reason = (
                                f"Login from {curr_city}, {km:,.0f} km from {prev_city}, "
                                f"{mins:.0f} min after previous login ({speed:,.0f} km/h)."
                            )
                            signals.append(
                                Signal(
                                    pattern=self.pattern,
                                    severity=round(severity, 3),
                                    identity_id=str(uid),
                                    session_id=str(curr_row.get("session_id") or ""),
                                    agent=self.name,
                                    reason=reason,
                                    evidence_event_ids=[str(prev_row["event_id"]), str(curr_row["event_id"])],
                                    mitre=self.mitre,
                                    timestamp=curr_ts,
                                )
                            )

                prev_row = curr_row

        return signals
