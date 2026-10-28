"""Session feature extraction for anomaly detection and peer grouping."""
import logging
import numpy as np
import pandas as pd

log = logging.getLogger(__name__)

IAM_WRITES = {
    "AttachUserPolicy",
    "AttachRolePolicy",
    "PutUserPolicy",
    "PutRolePolicy",
    "CreateAccessKey",
    "CreateUser",
    "CreateRole",
    "AddUserToGroup",
    "UpdateAssumeRolePolicy",
    "CreateLoginProfile",
    "UpdateLoginProfile",
}

NUMERIC_COLUMNS = [
    "n_events",
    "n_distinct_actions",
    "n_iam_writes",
    "max_sensitivity",
    "privilege_level",
    "n_ips",
    "n_user_agents",
    "failure_rate",
    "hour_deviation",
    "new_region_count",
    "duration_min",
    "events_per_min",
    "peer_rarity_mean",
]


def numeric_columns() -> list[str]:
    """Return list of numeric feature column names."""
    return list(NUMERIC_COLUMNS)


def session_features(df: pd.DataFrame) -> pd.DataFrame:
    """Extract session-level features from events DataFrame, indexed by session_id."""
    if df is None or df.empty:
        empty = pd.DataFrame(columns=["identity_id"] + NUMERIC_COLUMNS)
        empty.index.name = "session_id"
        return empty

    # Try loading peer model if available
    peer_model = None
    try:
        from app.ml.peers import PeerModel  # type: ignore
        pm = PeerModel()
        if pm.fit(df):
            peer_model = pm
    except Exception:
        pass

    # Compute median login hour per identity across all events
    identity_median_hour: dict[str, float] = {}
    for uid, ugroup in df.groupby("identity_id"):
        hours = [ts.hour for ts in ugroup["timestamp"] if ts is not None]
        identity_median_hour[str(uid)] = float(np.median(hours)) if hours else 12.0

    # Region history per identity to detect new regions
    seen_regions_before: dict[str, set[str]] = {}
    for uid, ugroup in df.sort_values(by="timestamp").groupby("identity_id"):
        seen_regions_before[str(uid)] = set()

    session_rows: list[dict] = []
    session_ids: list[str] = []

    # Sort events by timestamp
    sorted_df = df.sort_values(by="timestamp")

    for sess_id, sgroup in sorted_df.groupby("session_id", sort=False):
        if not sess_id or sess_id == "None":
            continue

        n_events = len(sgroup)
        uid = str(sgroup["identity_id"].iloc[0] if "identity_id" in sgroup else "unknown")

        distinct_actions = sgroup["action"].nunique()
        n_iam = int(sgroup["action"].isin(IAM_WRITES).sum())

        max_sens = float(sgroup["resource_sensitivity"].max() if "resource_sensitivity" in sgroup else 1.0)
        priv = float(sgroup["privilege_level"].max() if "privilege_level" in sgroup else 1.0)

        n_ips = float(sgroup["src_ip"].dropna().nunique())
        n_uas = float(sgroup["user_agent"].dropna().nunique())

        failures = int((sgroup["outcome"] == "failure").sum())
        failure_rate = float(failures / n_events) if n_events > 0 else 0.0

        sess_hours = [ts.hour for ts in sgroup["timestamp"] if ts is not None]
        mean_sess_hour = float(np.mean(sess_hours)) if sess_hours else 12.0
        med_user_hour = identity_median_hour.get(uid, 12.0)
        hour_deviation = abs(mean_sess_hour - med_user_hour)

        # Region check
        sess_regions = set(sgroup["region"].dropna())
        prev_regions = seen_regions_before.get(uid, set())
        new_regs = len(sess_regions - prev_regions) if prev_regions else 0
        seen_regions_before.setdefault(uid, set()).update(sess_regions)

        # Duration
        ts_min = sgroup["timestamp"].min()
        ts_max = sgroup["timestamp"].max()
        duration_min = float((ts_max - ts_min).total_seconds() / 60.0) if ts_min is not None and ts_max is not None else 0.0
        events_per_min = float(n_events / max(duration_min, 1.0))

        # Peer rarity mean
        peer_rarities = []
        if peer_model is not None:
            for act in sgroup["action"]:
                peer_rarities.append(peer_model.peer_rarity(uid, str(act)))
        peer_rarity_mean = float(np.mean(peer_rarities)) if peer_rarities else 0.0

        row = {
            "identity_id": uid,
            "n_events": float(n_events),
            "n_distinct_actions": float(distinct_actions),
            "n_iam_writes": float(n_iam),
            "max_sensitivity": float(max_sens),
            "privilege_level": float(priv),
            "n_ips": float(n_ips),
            "n_user_agents": float(n_uas),
            "failure_rate": float(failure_rate),
            "hour_deviation": float(hour_deviation),
            "new_region_count": float(new_regs),
            "duration_min": float(duration_min),
            "events_per_min": float(events_per_min),
            "peer_rarity_mean": float(peer_rarity_mean),
        }
        session_rows.append(row)
        session_ids.append(str(sess_id))

    if not session_rows:
        empty = pd.DataFrame(columns=["identity_id"] + NUMERIC_COLUMNS)
        empty.index.name = "session_id"
        return empty

    feat_df = pd.DataFrame(session_rows, index=session_ids)
    feat_df.index.name = "session_id"
    for col in NUMERIC_COLUMNS:
        feat_df[col] = feat_df[col].fillna(0.0).astype(float)

    return feat_df
