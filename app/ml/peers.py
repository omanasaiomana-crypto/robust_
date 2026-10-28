"""KMeans peer grouping based on identity privilege and action usage profiles."""
import logging
import pandas as pd
from sklearn.cluster import KMeans

log = logging.getLogger(__name__)


class PeerModel:
    def __init__(self) -> None:
        self.fitted = False
        self.identity_to_cluster: dict[str, int] = {}
        self.cluster_action_freqs: dict[int, dict[str, float]] = {}

    def fit(self, df: pd.DataFrame) -> bool:
        """Fit KMeans clusters across identities. Returns False if fewer than 3 identities."""
        if df is None or df.empty or "identity_id" not in df:
            return False

        identities = sorted(df["identity_id"].dropna().unique())
        n_identities = len(identities)
        if n_identities < 3:
            return False

        try:
            # Build profile per identity: privilege_level + action frequencies
            top_actions = list(df["action"].value_counts().head(20).index)

            profiles = []
            for uid in identities:
                ugroup = df[df["identity_id"] == uid]
                priv = float(ugroup["privilege_level"].max() if "privilege_level" in ugroup else 1.0)
                act_counts = ugroup["action"].value_counts()
                total = len(ugroup)
                row = [priv] + [float(act_counts.get(a, 0) / total) if total else 0.0 for a in top_actions]
                profiles.append(row)

            n_clusters = min(5, n_identities)
            kmeans = KMeans(n_clusters=n_clusters, n_init=10, random_state=42)
            cluster_labels = kmeans.fit_predict(profiles)

            self.identity_to_cluster = {uid: int(c) for uid, c in zip(identities, cluster_labels)}

            # Compute action frequencies per cluster
            self.cluster_action_freqs = {c: {} for c in range(n_clusters)}
            cluster_totals: dict[int, int] = {c: 0 for c in range(n_clusters)}

            for _, r in df.iterrows():
                uid = str(r["identity_id"])
                c = self.identity_to_cluster.get(uid)
                if c is not None:
                    act = str(r["action"])
                    self.cluster_action_freqs[c][act] = self.cluster_action_freqs[c].get(act, 0.0) + 1.0
                    cluster_totals[c] += 1

            for c, counts in self.cluster_action_freqs.items():
                tot = cluster_totals[c]
                if tot > 0:
                    for act in counts:
                        counts[act] /= tot

            self.fitted = True
            return True

        except Exception as exc:
            log.warning("PeerModel fitting failed: %s", exc)
            self.fitted = False
            return False

    def peer_rarity(self, identity_id: str, action: str) -> float:
        """Return 1.0 - frequency of action in identity's peer cluster (default 1.0)."""
        if not self.fitted:
            return 1.0
        c = self.identity_to_cluster.get(str(identity_id))
        if c is None:
            return 1.0
        freq = self.cluster_action_freqs.get(c, {}).get(str(action), 0.0)
        return float(1.0 - freq)

    def score(self, identity_id: str, action: str) -> float:
        """Alias for peer_rarity."""
        return self.peer_rarity(identity_id, action)
