"""In-memory mock simulator adapter recording calls."""
from app.simulator.base import SimulatorAdapter


class MockSimulator(SimulatorAdapter):
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def step_up(self, identity_id: str, session_id: str | None = None) -> str:
        self.calls.append({"action": "step_up", "identity_id": identity_id, "session_id": session_id})
        return "simulated:step_up:ok"

    def restrict(self, identity_id: str, scope: str = "default") -> str:
        self.calls.append({"action": "restrict", "identity_id": identity_id, "scope": scope})
        return "simulated:restrict:ok"

    def revoke(self, identity_id: str, session_id: str | None = None) -> str:
        self.calls.append({"action": "revoke", "identity_id": identity_id, "session_id": session_id})
        return "simulated:revoke:ok"
