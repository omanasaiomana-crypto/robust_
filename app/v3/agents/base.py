"""Base Agent class and AgentContext for IdentityShield v3."""
import uuid
from abc import ABC, abstractmethod
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from app.v3.config import Settings, get_settings
from app.v3.models import Message, Payload


class Clock:
    """Default UTC clock provider."""

    def now(self) -> datetime:
        return datetime.now(UTC)

    def __call__(self) -> datetime:
        return self.now()


class AgentContext:
    """Context provided to an agent during processing and ticks.

    Contains injected clock, configuration settings, storage adapter,
    tracing, and factory for creating new bus messages.
    """

    def __init__(
        self,
        clock: Any = None,
        settings: Settings | None = None,
        store: Any = None,
        run_id: str = "live",
        trace_fn: Callable[[str, str, Any], None] | None = None,
    ) -> None:
        self.clock = clock or Clock()
        self.settings = settings or get_settings()
        self.store = store
        self.run_id = run_id
        self._trace_fn = trace_fn

    def emit_trace(self, state: str, message: str, data: Any = None) -> None:
        """Emit a trace telemetry event for this agent."""
        if self._trace_fn:
            self._trace_fn(state, message, data)

    def new_message(
        self,
        topic: str,
        payload: Payload,
        partition_key: str = "",
        producer: str = "platform",
    ) -> Message:
        """Create a new validated Message matching v3 contract."""
        now_dt = self.clock() if callable(self.clock) else self.clock.now()
        iso = now_dt.isoformat() if hasattr(now_dt, "isoformat") else str(now_dt)
        return Message(
            topic=topic,
            msg_id=f"msg-{uuid.uuid4().hex[:12]}",
            producer=producer,
            run_id=self.run_id,
            created_at=iso,
            schema_version="3.0",
            partition_key=partition_key,
            payload=payload,
        )


class Agent(ABC):
    """Abstract base class for all 15 IdentityShield v3 agents.

    Pure given its state and inputs; produces output messages through the bus.
    """

    num: int
    agent_id: str
    name: str
    layer: str
    subscribes: list[str]
    publishes: list[str]
    path: str = "hot"

    def init_state(self) -> dict[str, Any]:
        """Initialize clean in-memory state for this agent."""
        return {}

    @abstractmethod
    def process(
        self,
        msg: Message,
        state: dict[str, Any],
        ctx: AgentContext,
    ) -> list[Message]:
        """Process one incoming message and return resulting messages."""
        raise NotImplementedError

    def on_tick(
        self,
        state: dict[str, Any],
        ctx: AgentContext,
    ) -> list[Message]:
        """Handle periodic or end-of-drain tick (default returns empty list)."""
        return []
