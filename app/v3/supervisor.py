"""Supervisor and Agent Registry for IdentityShield v3.

Follows context.md Section 10:
- Registry of 15 agent slots
- Capability manifests enforcement
- Agent health tracking, rolling percentiles (p50/p95), degraded state
- Pace control for live simulation
"""
import math
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.v3.agents.base import Agent

AGENT_METADATA = [
    (1, "a01", "Collector", "data"),
    (2, "a02", "Normalizer & Identity Resolver", "data"),
    (3, "a03", "Context & Threat Intel", "data"),
    (4, "a04", "Correlation & Graph", "data"),
    (5, "a05", "Access Anomaly", "detection"),
    (6, "a06", "Session & Token Integrity", "detection"),
    (7, "a07", "Credential Lifecycle", "detection"),
    (8, "a08", "Privilege Escalation", "detection"),
    (9, "a09", "Defense Evasion & Impact", "detection"),
    (10, "a10", "Behavioral ML", "detection"),
    (11, "a11", "Campaign", "detection"),
    (12, "a12", "Risk Fusion", "decision"),
    (13, "a13", "Investigation & Explanation", "decision"),
    (14, "a14", "Response", "decision"),
    (15, "a15", "Feedback & Tuning", "learning"),
]


class CapabilityError(PermissionError):
    """Raised when an agent attempts an action outside its capability manifest."""


@dataclass(frozen=True)
class CapabilityManifest:
    allowed_publish_topics: frozenset[str]
    allowed_tables: frozenset[str]
    allowed_simulator: bool
    allowed_network: str


CAPABILITY_MANIFESTS: dict[int, CapabilityManifest] = {
    1: CapabilityManifest(
        allowed_publish_topics=frozenset(["events", "deadletter"]),
        allowed_tables=frozenset(["events_v3"]),
        allowed_simulator=False,
        allowed_network="no",
    ),
    2: CapabilityManifest(
        allowed_publish_topics=frozenset(["events.normalized", "deadletter"]),
        allowed_tables=frozenset(["identities_v3", "identity_aliases_v3"]),
        allowed_simulator=False,
        allowed_network="no",
    ),
    3: CapabilityManifest(
        allowed_publish_topics=frozenset(["events.enriched", "deadletter"]),
        allowed_tables=frozenset(["enrich_cache_v3"]),
        allowed_simulator=False,
        allowed_network="optional enrichers only",
    ),
    4: CapabilityManifest(
        allowed_publish_topics=frozenset(["sessions", "graph.updates", "deadletter"]),
        allowed_tables=frozenset(["sessions_v3"]),
        allowed_simulator=False,
        allowed_network="no",
    ),
    5: CapabilityManifest(
        allowed_publish_topics=frozenset(["signals", "deadletter"]),
        allowed_tables=frozenset(["signals_v3", "agent_state_v3"]),
        allowed_simulator=False,
        allowed_network="no",
    ),
    6: CapabilityManifest(
        allowed_publish_topics=frozenset(["signals", "deadletter"]),
        allowed_tables=frozenset(["signals_v3", "agent_state_v3"]),
        allowed_simulator=False,
        allowed_network="no",
    ),
    7: CapabilityManifest(
        allowed_publish_topics=frozenset(["signals", "deadletter"]),
        allowed_tables=frozenset(["signals_v3", "agent_state_v3"]),
        allowed_simulator=False,
        allowed_network="no",
    ),
    8: CapabilityManifest(
        allowed_publish_topics=frozenset(["signals", "deadletter"]),
        allowed_tables=frozenset(["signals_v3", "agent_state_v3"]),
        allowed_simulator=False,
        allowed_network="no",
    ),
    9: CapabilityManifest(
        allowed_publish_topics=frozenset(["signals", "deadletter"]),
        allowed_tables=frozenset(["signals_v3", "agent_state_v3"]),
        allowed_simulator=False,
        allowed_network="no",
    ),
    10: CapabilityManifest(
        allowed_publish_topics=frozenset(["signals", "deadletter"]),
        allowed_tables=frozenset(["signals_v3", "agent_state_v3"]),
        allowed_simulator=False,
        allowed_network="no",
    ),
    11: CapabilityManifest(
        allowed_publish_topics=frozenset(["signals", "deadletter"]),
        allowed_tables=frozenset(["signals_v3", "agent_state_v3"]),
        allowed_simulator=False,
        allowed_network="no",
    ),
    12: CapabilityManifest(
        allowed_publish_topics=frozenset(["risk", "deadletter"]),
        allowed_tables=frozenset(["risk_v3"]),
        allowed_simulator=False,
        allowed_network="no",
    ),
    13: CapabilityManifest(
        allowed_publish_topics=frozenset(["cases", "deadletter"]),
        allowed_tables=frozenset(["cases_v3"]),
        allowed_simulator=False,
        allowed_network="optional LLM only",
    ),
    14: CapabilityManifest(
        allowed_publish_topics=frozenset(["actions", "deadletter"]),
        allowed_tables=frozenset(["actions_v3", "notifications"]),
        allowed_simulator=True,
        allowed_network="email only",
    ),
    15: CapabilityManifest(
        allowed_publish_topics=frozenset(["config.updates", "deadletter"]),
        allowed_tables=frozenset(["config_versions_v3"]),
        allowed_simulator=False,
        allowed_network="no",
    ),
}


@dataclass
class AgentHealth:
    num: int
    agent_id: str
    name: str
    layer: str
    status: str = "not_built"  # idle | running | degraded | not_built | error
    processed: int = 0
    errors: int = 0
    blocked: int = 0
    last_message_at: str | None = None
    queue_lag: int = 0
    durations: deque = field(default_factory=lambda: deque(maxlen=500))
    recent_errors: deque = field(default_factory=deque)

    def record_success(self, duration_ms: float) -> None:
        self.processed += 1
        self.durations.append(duration_ms)
        self.last_message_at = datetime.now(UTC).isoformat()
        if self.status in ("running", "error"):
            self.status = "idle"

    def record_error(self) -> None:
        now = time.monotonic()
        self.errors += 1
        self.recent_errors.append(now)
        # Prune errors older than 60s
        while self.recent_errors and (now - self.recent_errors[0] > 60.0):
            self.recent_errors.popleft()
        if len(self.recent_errors) >= 3:
            self.status = "degraded"
        else:
            self.status = "error"

    def record_blocked(self) -> None:
        self.blocked += 1

    @property
    def p50_ms(self) -> float:
        if not self.durations:
            return 0.0
        sorted_d = sorted(self.durations)
        k = (len(sorted_d) - 1) * 0.50
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            return round(float(sorted_d[int(k)]), 2)
        d0 = sorted_d[int(f)] * (c - k)
        d1 = sorted_d[int(c)] * (k - f)
        return round(float(d0 + d1), 2)

    @property
    def p95_ms(self) -> float:
        if not self.durations:
            return 0.0
        sorted_d = sorted(self.durations)
        k = (len(sorted_d) - 1) * 0.95
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            return round(float(sorted_d[int(k)]), 2)
        d0 = sorted_d[int(f)] * (c - k)
        d1 = sorted_d[int(c)] * (k - f)
        return round(float(d0 + d1), 2)

    def to_dict(self) -> dict[str, Any]:
        return {
            "num": self.num,
            "agent_id": self.agent_id,
            "name": self.name,
            "layer": self.layer,
            "status": self.status,
            "processed": self.processed,
            "errors": self.errors,
            "blocked": self.blocked,
            "last_message_at": self.last_message_at,
            "p50_ms": self.p50_ms,
            "p95_ms": self.p95_ms,
            "queue_lag": self.queue_lag,
        }


class Supervisor:
    """Oversees agent capabilities, registry, health metrics, and simulation pace."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._agents: dict[str, Agent] = {}
        self._health: dict[str, AgentHealth] = {}
        self._pace: float = 0.0

        for num, aid, name, layer in AGENT_METADATA:
            self._health[aid] = AgentHealth(num=num, agent_id=aid, name=name, layer=layer)

    def register_agent(self, agent: Agent) -> None:
        """Register an agent into its assigned slot."""
        with self._lock:
            self._agents[agent.agent_id] = agent
            h = self._health.get(agent.agent_id)
            if h:
                h.status = "idle"
            else:
                self._health[agent.agent_id] = AgentHealth(
                    num=agent.num, agent_id=agent.agent_id, name=agent.name, layer=agent.layer, status="idle"
                )

    def get_agent(self, agent_id: str) -> Agent | None:
        with self._lock:
            return self._agents.get(agent_id)

    def get_registered_agents(self) -> list[Agent]:
        with self._lock:
            return list(self._agents.values())

    def check_publish(self, agent: Agent, topic: str) -> None:
        """Verify that agent is permitted to publish to the target topic.

        Raises CapabilityError if unauthorized.
        """
        manifest = CAPABILITY_MANIFESTS.get(agent.num)
        if not manifest or topic not in manifest.allowed_publish_topics:
            h = self._health.get(agent.agent_id)
            if h:
                h.record_blocked()
            raise CapabilityError(
                f"Agent {agent.agent_id} (num {agent.num}) capability manifest forbids publishing to topic '{topic}'"
            )

    def get_health(self, agent_id: str | None = None) -> Any:
        with self._lock:
            if agent_id:
                h = self._health.get(agent_id)
                return h.to_dict() if h else None
            return [h.to_dict() for h in self._health.values()]

    def record_step_result(self, agent_id: str, duration_ms: float, error: bool = False) -> None:
        with self._lock:
            h = self._health.get(agent_id)
            if not h:
                return
            if error:
                h.record_error()
            else:
                h.record_success(duration_ms)

    def set_pace(self, seconds: float) -> float:
        """Set pace in seconds (0.0 to 3.0) for live view simulation."""
        with self._lock:
            try:
                self._pace = max(0.0, min(float(seconds or 0.0), 3.0))
            except (ValueError, TypeError):
                self._pace = 0.0
            return self._pace

    def get_pace(self) -> float:
        with self._lock:
            return self._pace
