"""Token and session hijacking detector (P5)."""
from datetime import timedelta
from typing import Any
import pandas as pd

from app.agents.base import Agent
from app.models import Signal


class TokenAbuseAgent(Agent):
    name: str = "token_abuse"
    pattern: str = "P5"
    mitre: list[str] = ["T1550", "T1539"]

    def detect(self, events: pd.DataFrame) -> list[Signal]:
        signals: list[Signal] = []
        if events is None or events.empty:
            return signals

        sorted_events = events.sort_values(by="timestamp")
        flagged_events: set[str] = set()

        # 1. Map all Okta session termination events
        session_end_times: dict[str, tuple[Any, str]] = {}  # session_id -> (timestamp, event_id)
        for _, row in sorted_events.iterrows():
            if str(row.get("action")) == "user.session.end":
                sess = str(row.get("session_id") or "")
                if sess and sess != "None":
                    session_end_times[sess] = (row["timestamp"], str(row["event_id"]))

        # 2. Check for concurrent use of same token_id across different IPs within 5 minutes
        token_events = sorted_events[
            sorted_events["token_id"].notna()
            & (sorted_events["token_id"] != "")
            & (sorted_events["token_id"] != "None")
        ]
        five_mins = timedelta(minutes=5)

        for tid, group in token_events.groupby("token_id", sort=False):
            prev_row = None
            for _, curr_row in group.iterrows():
                if prev_row is not None:
                    prev_ip = str(prev_row.get("src_ip") or "")
                    curr_ip = str(curr_row.get("src_ip") or "")
                    if prev_ip and curr_ip and prev_ip != curr_ip:
                        time_diff = curr_row["timestamp"] - prev_row["timestamp"]
                        if timedelta(0) <= time_diff <= five_mins:
                            diff_sec = int(time_diff.total_seconds())
                            uid = str(curr_row.get("identity_id", "unknown"))
                            sess = str(curr_row.get("session_id") or "")
                            eid = str(curr_row["event_id"])
                            prev_eid = str(prev_row["event_id"])

                            reason = (
                                f"Concurrent token use: token {tid} used from {prev_ip} and {curr_ip} "
                                f"within {diff_sec} seconds."
                            )
                            signals.append(
                                Signal(
                                    pattern=self.pattern,
                                    severity=0.9,
                                    identity_id=uid,
                                    session_id=sess,
                                    agent=self.name,
                                    reason=reason,
                                    evidence_event_ids=[prev_eid, eid],
                                    mitre=self.mitre,
                                    timestamp=curr_row["timestamp"],
                                )
                            )
                            flagged_events.add(eid)
                prev_row = curr_row

        # 3. Check for activity after Okta session termination
        for _, row in sorted_events.iterrows():
            sess = str(row.get("session_id") or "")
            eid = str(row["event_id"])
            if sess in session_end_times and str(row.get("action")) != "user.session.end":
                end_ts, end_eid = session_end_times[sess]
                if row["timestamp"] > end_ts:
                    diff_min = int((row["timestamp"] - end_ts).total_seconds() / 60.0)
                    uid = str(row.get("identity_id", "unknown"))
                    act = str(row.get("action", "unknown"))
                    reason = (
                        f"Post-termination activity: action {act} executed in session {sess} "
                        f"{diff_min} minutes after session end at {end_ts.isoformat()}."
                    )
                    signals.append(
                        Signal(
                            pattern=self.pattern,
                            severity=0.9,
                            identity_id=uid,
                            session_id=sess,
                            agent=self.name,
                            reason=reason,
                            evidence_event_ids=[end_eid, eid],
                            mitre=self.mitre,
                            timestamp=row["timestamp"],
                        )
                    )
                    flagged_events.add(eid)

        # 4. Check for User-Agent changes mid-session across CloudTrail API events
        # Note: We compare among API events (excluding Okta auth browser user-agents)
        api_events = sorted_events[sorted_events["category"] == "api"]
        for sess, group in api_events.groupby("session_id", sort=False):
            if not sess or sess == "None":
                continue
            first_ua: str | None = None
            first_eid: str | None = None
            for _, row in group.iterrows():
                ua = str(row.get("user_agent") or "").strip()
                eid = str(row["event_id"])
                if ua and ua != "None":
                    if first_ua is None:
                        first_ua = ua
                        first_eid = eid
                    elif ua != first_ua and eid not in flagged_events:
                        uid = str(row.get("identity_id", "unknown"))
                        reason = (
                            f"User-Agent changed within session {sess}: "
                            f"switched from '{first_ua[:40]}...' to '{ua[:40]}...'."
                        )
                        signals.append(
                            Signal(
                                pattern=self.pattern,
                                severity=0.6,
                                identity_id=uid,
                                session_id=sess,
                                agent=self.name,
                                reason=reason,
                                evidence_event_ids=[first_eid or eid, eid],
                                mitre=self.mitre,
                                timestamp=row["timestamp"],
                            )
                        )
                        flagged_events.add(eid)
                        break

        # 5. Check for token used from different IP prefix or country than first use
        first_token_info: dict[str, tuple[str, str, str | None]] = {}  # token_id -> (first_ip, first_eid, first_country)
        for _, row in token_events.iterrows():
            tid = str(row["token_id"])
            ip = str(row.get("src_ip") or "")
            country = row.get("country")
            eid = str(row["event_id"])
            if not ip or ip == "None":
                continue

            ip_prefix = ".".join(ip.split(".")[:2])
            if tid not in first_token_info:
                first_token_info[tid] = (ip, eid, country)
            else:
                first_ip, first_eid, first_country = first_token_info[tid]
                first_prefix = ".".join(first_ip.split(".")[:2])
                # Flag if token suddenly appears from completely different network prefix or different country
                is_foreign_ip = (ip_prefix != first_prefix and (first_country and country and first_country != country))
                if is_foreign_ip and eid not in flagged_events:
                    uid = str(row.get("identity_id", "unknown"))
                    sess = str(row.get("session_id") or "")
                    reason = f"Token {tid} first observed from {first_ip} ({first_country}) now used from different network {ip} ({country})."
                    signals.append(
                        Signal(
                            pattern=self.pattern,
                            severity=0.6,
                            identity_id=uid,
                            session_id=sess,
                            agent=self.name,
                            reason=reason,
                            evidence_event_ids=[first_eid, eid],
                            mitre=self.mitre,
                            timestamp=row["timestamp"],
                        )
                    )
                    flagged_events.add(eid)

        return signals
