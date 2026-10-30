"""Agent 10: Behavioral ML Detector.

Uses unsupervised machine learning to detect anomalous sessions and rare action sequences:
- D-ML-01: Session anomaly score from IsolationForest fitted per peer group (emits if >= 0.98 percentile rank -> strength 0.4..0.8).
- D-ML-02: Action sequence rarity using first-order Markov transition matrices with Laplace smoothing (emits if >= 0.99 percentile rank -> strength 0.3..0.7).

Confidence = 0.8 (0.5 if peer group has < 30 sessions).
If no model is trained: cleanly skips with a trace message and emits no signal.
Warm path, consumes sessions; publishes signals, deadletter.
"""
from __future__ import annotations

import bisect
import logging
import math
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, ClassVar

import joblib
from sklearn.ensemble import IsolationForest

from app.v3 import config
from app.v3.agents.base import Agent, AgentContext
from app.v3.models import (
    Message,
    Session,
    Signal,
    Stage,
)

log = logging.getLogger(__name__)

FEATURE_NAMES = [
    "session_duration",
    "event_count",
    "distinct_services",
    "distinct_regions",
    "write_ratio",
    "permission_change_count",
    "error_ratio",
    "sensitive_resource_count",
    "new_api_ratio",
    "hour_deviation",
    "asn_novelty",
]

ACTION_CATEGORIES = [
    "read",
    "write",
    "permission_change",
    "credential_change",
    "destructive",
    "defense_evasion",
    "other",
]


def extract_session_features(
    session_dict: dict[str, Any],
    events: list[dict[str, Any]] | None = None,
    identity_baseline: dict[str, Any] | None = None,
) -> list[float]:
    """Extract 11-dimensional feature vector for a session per PRD §12 Agent 10."""
    events = events or []
    identity_baseline = identity_baseline or {}

    # 1. Session duration
    start_str = str(session_dict.get("start", ""))
    end_str = str(session_dict.get("end", "") or "")
    duration = 0.0
    if start_str and end_str:
        try:
            ts_start = datetime.fromisoformat(start_str).timestamp()
            ts_end = datetime.fromisoformat(end_str).timestamp()
            duration = max(0.0, ts_end - ts_start)
        except (ValueError, TypeError):
            duration = 0.0

    # 2. Event count
    event_ids = session_dict.get("event_ids") or []
    event_count = float(len(events) if events else len(event_ids))
    safe_count = max(1.0, event_count)

    # 3. Distinct services
    services: set[str] = set()
    for ev in events:
        action = str(ev.get("action", ""))
        if ":" in action:
            services.add(action.split(":", 1)[0].lower())
        else:
            services.add(action[:4].lower())
    distinct_services = float(max(1, len(services))) if services else 1.0

    # 4. Distinct regions
    regions = {str(ev.get("region") or "") for ev in events if ev.get("region")}
    distinct_regions = float(max(1, len(regions)))

    # 5. Write ratio & 6. Permission change count & 7. Error ratio & 8. Sensitive resource count & 9. New API ratio
    write_count = 0
    perm_count = 0
    error_count = 0
    sensitive_count = 0
    new_api_count = 0
    known_apis: set[str] = set(identity_baseline.get("known_apis", []))

    for ev in events:
        act_type = str(ev.get("action_type", "")).lower()
        if act_type in ("write", "permission_change", "credential_change", "destructive"):
            write_count += 1
        if act_type == "permission_change":
            perm_count += 1

        outcome = str(ev.get("outcome", "")).lower()
        if outcome in ("failure", "deny", "denied", "error"):
            error_count += 1

        res_sens = int(ev.get("resource_sensitivity", 1))
        if res_sens >= 4:
            sensitive_count += 1

        action_name = str(ev.get("action", ""))
        if known_apis and action_name not in known_apis:
            new_api_count += 1

    write_ratio = write_count / safe_count
    permission_change_count = float(perm_count)
    error_ratio = error_count / safe_count
    sensitive_resource_count = float(sensitive_count)
    new_api_ratio = new_api_count / safe_count if known_apis else 0.0

    # 10. Hour deviation
    start_hour = 12.0
    if start_str:
        try:
            start_hour = float(datetime.fromisoformat(start_str).hour)
        except (ValueError, TypeError):
            pass
    mean_hour = float(identity_baseline.get("mean_hour", 12.0))
    hour_deviation = min(abs(start_hour - mean_hour), 24.0 - abs(start_hour - mean_hour))

    # 11. ASN novelty
    asns = session_dict.get("asns") or []
    known_asns: set[int] = set(identity_baseline.get("known_asns", []))
    asn_novelty = 1.0 if (known_asns and any(a not in known_asns for a in asns)) else 0.0

    return [
        duration,
        event_count,
        distinct_services,
        distinct_regions,
        write_ratio,
        permission_change_count,
        error_ratio,
        sensitive_resource_count,
        new_api_ratio,
        hour_deviation,
        asn_novelty,
    ]


def build_markov_matrix(
    sequences: list[list[str]],
    categories: list[str] | None = None,
) -> dict[str, dict[str, float]]:
    """Build first-order Markov transition probability matrix with Laplace (+1) smoothing."""
    cats = categories or ACTION_CATEGORIES

    # Initialize transition counts with +1 Laplace smoothing
    counts: dict[str, dict[str, float]] = {c1: {c2: 1.0 for c2 in cats} for c1 in cats}

    for seq in sequences:
        for i in range(len(seq) - 1):
            c1 = seq[i] if seq[i] in counts else "other"
            c2 = seq[i + 1] if seq[i + 1] in counts else "other"
            counts[c1][c2] += 1.0

    # Normalize to probabilities
    probs: dict[str, dict[str, float]] = {}
    for c1, trans in counts.items():
        total = sum(trans.values())
        probs[c1] = {c2: cnt / total for c2, cnt in trans.items()}

    return probs


def compute_sequence_nll(
    sequence: list[str],
    transition_matrix: dict[str, dict[str, float]],
) -> float:
    """Compute normalized Negative Log-Likelihood (NLL) for an action sequence."""
    if len(sequence) < 2:
        return 0.0

    total_nll = 0.0
    transitions_count = len(sequence) - 1

    for i in range(transitions_count):
        c1 = sequence[i] if sequence[i] in transition_matrix else "other"
        c2 = sequence[i + 1] if sequence[i + 1] in transition_matrix else "other"
        prob = transition_matrix.get(c1, {}).get(c2, 1e-4)
        total_nll -= math.log(max(1e-6, prob))

    return total_nll / transitions_count


def train_ml_models(
    sessions: list[dict[str, Any]],
    events_by_session: dict[str, list[dict[str, Any]]] | None = None,
    peer_groups: dict[str, str] | None = None,
    identity_baselines: dict[str, dict[str, Any]] | None = None,
    contamination: float = config.ML_CONTAMINATION,
    seed: int = config.SEED,
) -> dict[str, Any]:
    """Train IsolationForest and Markov transition models per peer group."""
    events_by_session = events_by_session or {}
    peer_groups = peer_groups or {}
    identity_baselines = identity_baselines or {}

    # Group sessions by peer group (fallback: "global")
    grouped_sessions: dict[str, list[dict[str, Any]]] = {}
    for sess in sessions:
        identity = str(sess.get("identity_id", ""))
        pg = peer_groups.get(identity, "global")
        grouped_sessions.setdefault(pg, []).append(sess)
        grouped_sessions.setdefault("global", []).append(sess)

    model_bundle: dict[str, Any] = {
        "version": 1,
        "trained_at": datetime.now().isoformat(),
        "peer_groups": {},
    }

    for pg, sess_list in grouped_sessions.items():
        if not sess_list:
            continue

        # Extract features and action sequences
        feature_matrix: list[list[float]] = []
        action_sequences: list[list[str]] = []

        for sess in sess_list:
            s_id = str(sess.get("session_id", ""))
            s_events = events_by_session.get(s_id, [])
            ident = str(sess.get("identity_id", ""))
            base = identity_baselines.get(ident, {})

            feat = extract_session_features(sess, s_events, base)
            feature_matrix.append(feat)

            seq = [str(ev.get("action_type", "other")).lower() for ev in s_events]
            if seq:
                action_sequences.append(seq)

        # 1. Fit IsolationForest
        forest = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=seed,
        )
        forest.fit(feature_matrix)

        # Anomaly scores on baseline
        raw_scores = [-s for s in forest.score_samples(feature_matrix)]
        sorted_scores = sorted(raw_scores)

        # 2. Build Markov transition matrix
        markov_probs = build_markov_matrix(action_sequences, ACTION_CATEGORIES)
        nlls = [compute_sequence_nll(seq, markov_probs) for seq in action_sequences if len(seq) >= 2]
        sorted_nlls = sorted(nlls) if nlls else [0.0]

        model_bundle["peer_groups"][pg] = {
            "session_count": len(sess_list),
            "isolation_forest": forest,
            "score_distribution": sorted_scores,
            "markov_probs": markov_probs,
            "nll_distribution": sorted_nlls,
        }

    return model_bundle


def score_session_with_bundle(
    session_dict: dict[str, Any],
    events: list[dict[str, Any]] | None,
    models: dict[str, Any],
    peer_group: str = "global",
    identity_baseline: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Score a session for behavioral anomalies using the model bundle."""
    pg_models = models.get("peer_groups", {}).get(peer_group) or models.get("peer_groups", {}).get("global")
    if not pg_models:
        return []

    sess_count = pg_models.get("session_count", 0)
    confidence = 0.8 if sess_count >= 30 else 0.5
    ev_ids = session_dict.get("event_ids") or []
    if events:
        ev_ids = [e.get("event_id") for e in events if e.get("event_id")]

    candidate_signals: list[dict[str, Any]] = []

    # 1. Score Isolation Forest Anomaly (D-ML-01)
    forest = pg_models.get("isolation_forest")
    score_dist = pg_models.get("score_distribution") or []
    if forest and score_dist:
        feat = extract_session_features(session_dict, events, identity_baseline)
        raw_score = -forest.score_samples([feat])[0]
        percentile = bisect.bisect_right(score_dist, raw_score) / len(score_dist)

        # Emit if >= 0.98 percentile -> strength 0.4..0.8 linear
        if percentile >= 0.98:
            strength = round(0.4 + ((percentile - 0.98) / 0.02) * 0.4, 2)
            candidate_signals.append(
                {
                    "detection_id": "D-ML-01",
                    "strength": min(0.8, max(0.4, strength)),
                    "confidence": confidence,
                    "evidence_event_ids": ev_ids[:10] if ev_ids else ["session"],
                    "mitre": ["T1078"],
                    "stage": Stage.initial_access,
                    "summary": f"Behavioral session anomaly (percentile {percentile * 100:.1f}%) in peer group {peer_group}",
                    "details": {
                        "percentile": round(percentile, 4),
                        "raw_score": round(raw_score, 4),
                        "peer_group": peer_group,
                        "session_count": sess_count,
                    },
                }
            )

    # 2. Score Markov Action Sequence Rarity (D-ML-02)
    markov_probs = pg_models.get("markov_probs")
    nll_dist = pg_models.get("nll_distribution") or []
    if markov_probs and nll_dist and events and len(events) >= 2:
        seq = [str(e.get("action_type", "other")).lower() for e in events]
        nll = compute_sequence_nll(seq, markov_probs)
        percentile = bisect.bisect_right(nll_dist, nll) / len(nll_dist)

        # Emit if >= 0.99 percentile -> strength 0.3..0.7 linear
        if percentile >= 0.99:
            strength = round(0.3 + ((percentile - 0.99) / 0.01) * 0.4, 2)
            candidate_signals.append(
                {
                    "detection_id": "D-ML-02",
                    "strength": min(0.7, max(0.3, strength)),
                    "confidence": confidence,
                    "evidence_event_ids": ev_ids[:10] if ev_ids else ["session"],
                    "mitre": ["T1078", "T1580"],
                    "stage": Stage.initial_access,
                    "summary": f"Rare action sequence observed (percentile {percentile * 100:.1f}%, NLL {nll:.2f})",
                    "details": {
                        "percentile": round(percentile, 4),
                        "nll": round(nll, 4),
                        "peer_group": peer_group,
                        "sequence_length": len(seq),
                    },
                }
            )

    return candidate_signals


class BehavioralML(Agent):
    """Agent 10: Behavioral ML detector (D-ML-01, D-ML-02)."""

    num: ClassVar[int] = 10
    agent_id: ClassVar[str] = "agent10"
    name: ClassVar[str] = "ml"
    layer: ClassVar[str] = "detection"
    subscribes: ClassVar[list[str]] = ["sessions"]
    publishes: ClassVar[list[str]] = ["signals", "deadletter"]
    path: ClassVar[str] = "warm"

    def __init__(self, model_path: Path | str | None = None) -> None:
        self.model_path = Path(model_path) if model_path else Path("data/models/ml_models.joblib")
        self.models: dict[str, Any] | None = self.load_models()

    def load_models(self) -> dict[str, Any] | None:
        """Load persisted models if file exists."""
        if self.model_path.is_file():
            try:
                return joblib.load(self.model_path)
            except Exception:
                log.exception("Failed to load ML models from %s", self.model_path)
                return None
        return None

    def save_models(self, bundle: dict[str, Any]) -> None:
        """Save model bundle to disk."""
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(bundle, self.model_path)
        self.models = bundle

    def train(
        self,
        sessions: list[dict[str, Any]],
        events_by_session: dict[str, list[dict[str, Any]]] | None = None,
        peer_groups: dict[str, str] | None = None,
        identity_baselines: dict[str, dict[str, Any]] | None = None,
    ) -> None:
        """Train models and persist to disk."""
        bundle = train_ml_models(
            sessions=sessions,
            events_by_session=events_by_session,
            peer_groups=peer_groups,
            identity_baselines=identity_baselines,
            contamination=config.ML_CONTAMINATION,
            seed=config.SEED,
        )
        self.save_models(bundle)

    def init_state(self) -> dict[str, Any]:
        """Initialize in-memory state."""
        return {"peer_groups": {}, "identity_baselines": {}}

    def process(
        self,
        msg: Message,
        state: dict[str, Any],
        ctx: AgentContext,
    ) -> list[Message]:
        """Score closed or updated sessions for behavioral ML anomalies."""
        if msg.topic != "sessions":
            return []

        payload = msg.payload
        if not isinstance(payload, Session):
            return []

        # If no model is trained, skip with trace message and emit no signal
        if self.models is None:
            ctx.emit_trace("skipped", "model not trained, skipping ML scoring", {"session_id": payload.session_id})
            return []

        session_dict: dict[str, Any] = {
            "session_id": payload.session_id,
            "identity_id": payload.identity_id,
            "start": payload.start,
            "end": payload.end,
            "event_ids": payload.event_ids,
            "ips": payload.ips,
            "asns": payload.asns,
            "devices": payload.devices,
            "providers": payload.providers,
            "fingerprint": payload.fingerprint,
        }

        peer_group = state.get("peer_groups", {}).get(payload.identity_id, "global")
        baseline = state.get("identity_baselines", {}).get(payload.identity_id, {})

        candidates = score_session_with_bundle(
            session_dict,
            events=None,
            models=self.models,
            peer_group=peer_group,
            identity_baseline=baseline,
        )

        messages: list[Message] = []
        for cand in candidates:
            sig = Signal(
                signal_id=f"sig-{cand['detection_id'].lower()}-{uuid.uuid4().hex[:8]}",
                detection_id=cand["detection_id"],
                agent_num=self.num,
                identity_id=payload.identity_id,
                session_id=payload.session_id,
                strength=cand["strength"],
                confidence=cand["confidence"],
                evidence_event_ids=cand["evidence_event_ids"],
                mitre=cand["mitre"],
                stage=cand["stage"],
                summary=cand["summary"],
                details=cand.get("details", {}),
            )
            messages.append(
                ctx.new_message(
                    topic="signals",
                    payload=sig,
                    partition_key=payload.identity_id,
                    producer=self.agent_id,
                )
            )

        return messages
