"""IdentityShield v3 agents package.

Provides register_all(supervisor, bus) to automatically discover and register
all available agent modules with the Supervisor and Bus.
"""
import importlib
import inspect
import logging
from typing import Any

from app.v3.agents.base import Agent

log = logging.getLogger(__name__)

# Registered module names for all 15 agents
AGENT_MODULES: list[tuple[int, str]] = [
    (1, "a01_collector"),
    (2, "a02_normalizer"),
    (3, "a03_context"),
    (4, "a04_correlation"),
    (5, "a05_access"),
    (6, "a06_session"),
    (7, "a07_credentials"),
    (8, "a08_privesc"),
    (9, "a09_evasion"),
    (10, "a10_ml"),
    (11, "a11_campaign"),
    (12, "a12_fusion"),
    (13, "a13_investigation"),
    (14, "a14_response"),
    (15, "a15_feedback"),
]


def register_all(supervisor: Any, bus: Any = None) -> list[Agent]:
    """Import and register all existing agent modules with Supervisor and Bus.

    Missing agent modules are cleanly skipped. Returns list of registered Agent instances.
    """
    registered: list[Agent] = []

    for num, mod_name in AGENT_MODULES:
        try:
            mod = importlib.import_module(f"app.v3.agents.{mod_name}")
        except ModuleNotFoundError:
            continue
        except Exception:
            log.exception("Error importing agent module %s", mod_name)
            continue

        # Find Agent subclass in module
        agent_cls: type[Agent] | None = None
        for _, obj in inspect.getmembers(mod, inspect.isclass):
            if issubclass(obj, Agent) and obj is not Agent and getattr(obj, "num", None) == num:
                agent_cls = obj
                break

        if agent_cls is None:
            # Fallback: check any Agent subclass
            for _, obj in inspect.getmembers(mod, inspect.isclass):
                if issubclass(obj, Agent) and obj is not Agent:
                    agent_cls = obj
                    break

        if agent_cls is not None:
            try:
                agent = agent_cls()
                if supervisor is not None:
                    supervisor.register_agent(agent)
                if bus is not None:
                    bus.subscribe(agent)
                registered.append(agent)
                log.info("Registered Agent %d (%s) with Supervisor and Bus", num, agent.name)
            except Exception:
                log.exception("Failed to instantiate or register agent %s", mod_name)

    return registered
