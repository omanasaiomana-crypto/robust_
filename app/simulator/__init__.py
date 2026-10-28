"""Simulator package entry point."""
from app.config import SIMULATOR_MODE
from app.simulator.base import SimulatorAdapter
from app.simulator.mock import MockSimulator
from app.simulator.supplied import SuppliedSimulator

_mock_sim_instance: MockSimulator | None = None


def get_simulator() -> SimulatorAdapter:
    """Return configured simulator adapter instance."""
    global _mock_sim_instance
    if SIMULATOR_MODE == "supplied":
        return SuppliedSimulator()
    if _mock_sim_instance is None:
        _mock_sim_instance = MockSimulator()
    return _mock_sim_instance
