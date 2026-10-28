"""Privilege escalation chain detector (P3)."""
from datetime import timedelta
import pandas as pd

from app.agents.base import Agent
from app.config import (
    ESCALATION_BASE_SEVERITY,
    ESCALATION_STEP_SEVERITY,
    ESCALATION_WINDOW_HOURS,
)
from app.models import ChainStep, Signal

STATE_OF_ACTION: dict[str, str] = {
    "ListUsers": "Recon",
    "ListRoles": "Recon",
    "ListPolicies": "Recon",
    "GetAccountAuthorizationDetails": "Recon",
    "CreateAccessKey": "CredCreate",
    "CreateLoginProfile": "CredCreate",
    "UpdateLoginProfile": "CredCreate",
    "CreateUser": "IdentityCreate",
    "CreateRole": "IdentityCreate",
    "AttachUserPolicy": "PermGrant",
    "AttachRolePolicy": "PermGrant",
    "PutUserPolicy": "PermGrant",
    "PutRolePolicy": "PermGrant",
    "AddUserToGroup": "PermGrant",
    "UpdateAssumeRolePolicy": "TrustChange",
    "AssumeRole": "RoleAssume",
    "PassRole": "RoleAssume",
    "GetSecretValue": "Impact",
    "StopLogging": "Impact",
    "DeleteTrail": "Impact",
}

ESCALATION_ORDER: list[str] = [
    "Recon",
    "CredCreate",
    "IdentityCreate",
    "PermGrant",
    "TrustChange",
    "RoleAssume",
    "Impact",
]

ORDER_RANK = {state: idx for idx, state in enumerate(ESCALATION_ORDER)}


class PrivEscalationAgent(Agent):
    name: str = "priv_escalation"
    pattern: str = "P3"
    mitre: list[str] = ["T1098", "T1548"]

    def __init__(self) -> None:
        super().__init__()
        self.last_chains: dict[str, list[ChainStep]] = {}

    def detect(self, events: pd.DataFrame) -> list[Signal]:
        signals: list[Signal] = []
        self.last_chains = {}

        if events is None or events.empty:
            return signals

        # Filter API events matching escalation actions
        matched = events[events["action"].isin(STATE_OF_ACTION)].copy()
        if matched.empty:
            return signals

        matched = matched.sort_values(by="timestamp")
        window = timedelta(hours=ESCALATION_WINDOW_HOURS)

        for uid, group in matched.groupby("identity_id", sort=False):
            steps: list[tuple[ChainStep, str]] = []  # (ChainStep, session_id)
            for _, r in group.iterrows():
                act = str(r["action"])
                st = STATE_OF_ACTION[act]
                eid = str(r["event_id"])
                ts = r["timestamp"]
                sess = str(r.get("session_id") or "")
                step = ChainStep(event_id=eid, action=act, state=st, timestamp=ts)
                steps.append((step, sess))

            # Find chains within sliding window of ESCALATION_WINDOW_HOURS
            n = len(steps)
            i = 0
            while i < n:
                chain = [steps[i]]
                j = i + 1
                while j < n and (steps[j][0].timestamp - steps[i][0].timestamp) <= window:
                    # Append step to chain
                    chain.append(steps[j])
                    j += 1

                chain_steps = [s[0] for s in chain]
                distinct_states = {s.state for s in chain_steps}
                non_recon_states = distinct_states - {"Recon"}

                # Emit when >= 2 distinct escalation states (Recon alone does not count)
                if len(distinct_states) >= 2 and len(non_recon_states) >= 1:
                    sess_id = chain[-1][1] or chain[0][1]
                    self.last_chains[sess_id] = chain_steps

                    # Calculate severity: base + step per distinct state
                    severity = min(1.0, ESCALATION_BASE_SEVERITY + ESCALATION_STEP_SEVERITY * len(distinct_states))

                    # Duration in minutes
                    dur_min = max(1.0, (chain_steps[-1].timestamp - chain_steps[0].timestamp).total_seconds() / 60.0)
                    state_seq = " -> ".join(f"{s.state} ({s.action})" for s in chain_steps)
                    reason = (
                        f"Privilege escalation chain detected for {uid}: {state_seq} "
                        f"across {len(chain_steps)} steps in {dur_min:.0f} minutes."
                    )

                    signals.append(
                        Signal(
                            pattern=self.pattern,
                            severity=round(severity, 3),
                            identity_id=str(uid),
                            session_id=sess_id,
                            agent=self.name,
                            reason=reason,
                            evidence_event_ids=[s.event_id for s in chain_steps],
                            mitre=self.mitre,
                            timestamp=chain_steps[-1].timestamp,
                        )
                    )
                    # Advance i past this chain
                    i = j
                else:
                    i += 1

        return signals
