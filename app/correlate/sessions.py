"""Session correlation linking Okta sessions to AWS CloudTrail activity."""
from datetime import timedelta
import logging
from typing import Any
import pandas as pd

log = logging.getLogger(__name__)


def assign_sessions(df: pd.DataFrame) -> pd.DataFrame:
    """Assign unified session_id to every event in the DataFrame."""
    if df is None or df.empty:
        return df

    out = df.copy()

    # 1. Okta events: ensure session_id is prefixed with 'okta:'
    okta_sessions: dict[str, list[tuple[Any, str, str]]] = {}  # identity_id -> list of (start_ts, session_id, src_ip)

    for idx, row in out[out["source"] == "okta"].iterrows():
        raw_sess = row.get("session_id")
        uid = str(row.get("identity_id", "unknown"))
        if not raw_sess or pd.isna(raw_sess):
            sess_id = f"okta:{uid}:{idx}"
        else:
            s_str = str(raw_sess)
            sess_id = s_str if s_str.startswith("okta:") else f"okta:{s_str}"

        out.at[idx, "session_id"] = sess_id

        # Track start time of session for linking
        ip = str(row.get("src_ip", ""))
        ts = row.get("timestamp")
        if uid not in okta_sessions:
            okta_sessions[uid] = []
        okta_sessions[uid].append((ts, sess_id, ip))

    # Sort okta sessions by timestamp for binary/chronological search
    for uid in okta_sessions:
        okta_sessions[uid].sort(key=lambda x: x[0])

    # 2. Correlate CloudTrail events
    twelve_hours = timedelta(hours=12)
    unassigned_indices: list[int] = []

    for idx, row in out[out["source"] == "cloudtrail"].iterrows():
        uid = str(row.get("identity_id", "unknown"))
        ct_ts = row.get("timestamp")
        ct_ip = str(row.get("src_ip", ""))
        assigned = False

        if uid in okta_sessions:
            # Find latest Okta session with matching IP that started within previous 12h
            matching_sessions = [
                s for s in okta_sessions[uid]
                if s[2] == ct_ip and timedelta(0) <= (ct_ts - s[0]) <= twelve_hours
            ]
            if matching_sessions:
                # Latest started session
                best_session = matching_sessions[-1]
                out.at[idx, "session_id"] = best_session[1]
                assigned = True

        if not assigned:
            unassigned_indices.append(idx)

    # 3. Group remaining CloudTrail events by (identity_id, token_id) with 1-hour inactivity gap
    if unassigned_indices:
        ct_rem = out.loc[unassigned_indices].sort_values(by="timestamp")
        one_hour = timedelta(hours=1)
        # Track last_seen_time and session_counter per (identity_id, token_id)
        cluster_tracker: dict[tuple[str, str], tuple[Any, int]] = {}

        for idx, row in ct_rem.iterrows():
            uid = str(row.get("identity_id", "unknown"))
            tid = str(row.get("token_id", "default") or "default")
            key = (uid, tid)
            ts = row.get("timestamp")

            if key not in cluster_tracker:
                cluster_tracker[key] = (ts, 1)
                curr_n = 1
            else:
                last_ts, curr_n = cluster_tracker[key]
                if (ts - last_ts) > one_hour:
                    curr_n += 1
                cluster_tracker[key] = (ts, curr_n)

            out.at[idx, "session_id"] = f"aws:{uid}:{curr_n}"

    # Fallback guard: ensure no empty/None session_id anywhere
    for idx, row in out[out["session_id"].isna() | (out["session_id"] == "")].iterrows():
        uid = str(row.get("identity_id", "unknown"))
        src = str(row.get("source", "event"))
        out.at[idx, "session_id"] = f"{src}:{uid}:{idx}"

    return out
