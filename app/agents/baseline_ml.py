"""Isolation Forest baseline ML agent (ML pattern) for session anomaly detection."""
import logging
import pandas as pd

from app.agents.base import Agent
from app.ml.anomaly import AnomalyModel
from app.ml.features import numeric_columns, session_features
from app.models import Signal

log = logging.getLogger(__name__)


class BaselineMLAgent(Agent):
    name: str = "baseline_ml"
    pattern: str = "ML"
    mitre: list[str] = []

    def __init__(self) -> None:
        super().__init__()
        self.scores: dict[str, float] = {}

    def detect(self, events: pd.DataFrame) -> list[Signal]:
        signals: list[Signal] = []
        self.scores = {}

        if events is None or events.empty:
            return signals

        feat_df = session_features(events)
        if feat_df.empty:
            return signals

        num_cols = numeric_columns()
        X_all = feat_df[num_cols]

        # Determine training sessions: use sessions without attack labels if label column is present
        model = AnomalyModel()
        train_sessions = None

        if "label" in events.columns and events["label"].notna().any():
            # Identify sessions that only have benign events
            benign_sess = set()
            for sess, sgroup in events.groupby("session_id"):
                labels = set(sgroup["label"].dropna())
                if labels.issubset({"benign", "", "None"}):
                    benign_sess.add(str(sess))

            train_sessions = feat_df[feat_df.index.isin(benign_sess)]

        if train_sessions is None or len(train_sessions) < 20:
            train_sessions = feat_df

        # Fit model on training feature matrix
        fitted = model.fit(train_sessions[num_cols])
        if not fitted:
            # If fewer than MIN_ROWS, fit on whatever is available or return empty
            return signals

        raw_scores = model.score(X_all)

        # Map scores to session_id
        session_events_map = {sess: sgroup for sess, sgroup in events.groupby("session_id")}

        for sess_id, score_val in zip(feat_df.index, raw_scores):
            score = round(float(score_val), 3)
            self.scores[str(sess_id)] = score

            if score >= 0.6:
                s_events = session_events_map.get(sess_id)
                if s_events is not None and not s_events.empty:
                    s_sorted = s_events.sort_values(by="timestamp")
                    uid = str(s_sorted["identity_id"].iloc[0])
                    ts = s_sorted["timestamp"].iloc[-1]
                    ev_ids = [str(x) for x in s_sorted["event_id"].head(5)]

                    reason = f"Session behavior is unusual compared with normal activity (anomaly score {score:.2f})."

                    signals.append(
                        Signal(
                            pattern=self.pattern,
                            severity=score,
                            identity_id=uid,
                            session_id=str(sess_id),
                            agent=self.name,
                            reason=reason,
                            evidence_event_ids=ev_ids,
                            mitre=self.mitre,
                            timestamp=ts,
                        )
                    )

        return signals
