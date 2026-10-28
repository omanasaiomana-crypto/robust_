"""Markov chain predictor for escalation sequences."""
from collections import defaultdict

from app.models import Prediction

ESCALATION_STATES = [
    "Recon",
    "CredCreate",
    "IdentityCreate",
    "PermGrant",
    "TrustChange",
    "RoleAssume",
    "Impact",
]
ALL_STATES = ["Start"] + ESCALATION_STATES + ["End"]


class ChainModel:
    def __init__(self) -> None:
        self.transitions: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
        self._init_fallback_priors()

    def _init_fallback_priors(self) -> None:
        """Fallback prior: forward transitions along ESCALATION_ORDER get weight 3, others weight 1."""
        self.transitions = defaultdict(lambda: defaultdict(float))
        for i, s1 in enumerate(ESCALATION_STATES):
            for j, s2 in enumerate(ESCALATION_STATES):
                weight = 3.0 if j == i + 1 else (1.0 if j > i else 0.5)
                self.transitions[s1][s2] = weight
            self.transitions[s1]["End"] = 1.0

        for s in ESCALATION_STATES:
            self.transitions["Start"][s] = 2.0

    def fit(self, chains: list[list[str]]) -> None:
        """Learn transition probabilities from observed escalation chains with add-one smoothing."""
        if not chains or len(chains) < 5:
            # Keep fallback prior
            return

        counts = defaultdict(lambda: defaultdict(float))
        for chain in chains:
            if not chain:
                continue
            prev = "Start"
            for state in chain:
                counts[prev][state] += 1.0
                prev = state
            counts[prev]["End"] += 1.0

        # Apply add-one smoothing over valid destination states
        valid_destinations = [s for s in ALL_STATES if s != "Start"]
        self.transitions = defaultdict(lambda: defaultdict(float))

        for s1 in ALL_STATES:
            for s2 in valid_destinations:
                self.transitions[s1][s2] = counts[s1][s2] + 1.0

    def predict(self, state: str) -> Prediction | None:
        """Predict most likely next state and probability. Never returns 'Start'."""
        if state not in self.transitions:
            if state not in ESCALATION_STATES:
                return None
            self._init_fallback_priors()

        dest_map = self.transitions.get(state, {})
        # Filter out 'Start' and calculate probabilities
        valid_dests = {k: v for k, v in dest_map.items() if k != "Start" and v > 0}
        if not valid_dests:
            return None

        total = sum(valid_dests.values())
        if total <= 0:
            return None

        best_next, best_score = max(valid_dests.items(), key=lambda kv: kv[1])
        prob = round(float(best_score / total), 3)

        return Prediction(next_state=best_next, probability=prob)
