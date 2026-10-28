"""Base class for all IdentityShield detection agents."""
import logging
import pandas as pd
from app.models import Signal


class Agent:
    name: str = "base"
    permissions: frozenset[str] = frozenset({"read:events"})

    def __init__(self) -> None:
        self.log = logging.getLogger(f"agent.{self.name}")

    def run(self, events: pd.DataFrame) -> list[Signal]:
        """Return signals. Must never raise; return [] on any error."""
        if events is None or events.empty:
            return []
        try:
            return self.detect(events)
        except Exception:  # noqa: BLE001 - isolation is intentional
            self.log.exception("Agent %s failed; returning no signals", self.name)
            return []

    def detect(self, events: pd.DataFrame) -> list[Signal]:
        raise NotImplementedError
