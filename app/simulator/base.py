"""Base interface for security enforcement simulator adapters."""

class SimulatorAdapter:
    def step_up(self, identity_id: str, session_id: str | None = None) -> str:
        raise NotImplementedError

    def restrict(self, identity_id: str, scope: str = "default") -> str:
        raise NotImplementedError

    def revoke(self, identity_id: str, session_id: str | None = None) -> str:
        raise NotImplementedError
