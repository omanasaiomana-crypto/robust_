"""Adapter for supplied hackathon environment enforcement (configured at runtime)."""
from app.simulator.base import SimulatorAdapter


class SuppliedSimulator(SimulatorAdapter):
    def step_up(self, identity_id: str, session_id: str | None = None) -> str:
        raise NotImplementedError("Configure the supplied simulator in app/simulator/supplied.py")

    def restrict(self, identity_id: str, scope: str = "default") -> str:
        raise NotImplementedError("Configure the supplied simulator in app/simulator/supplied.py")

    def revoke(self, identity_id: str, session_id: str | None = None) -> str:
        raise NotImplementedError("Configure the supplied simulator in app/simulator/supplied.py")
