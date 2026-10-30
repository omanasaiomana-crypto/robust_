"""Unit tests for app/v3/bus.py topic event bus."""
import asyncio
from typing import Any, ClassVar

from app.v3.agents.base import Agent, AgentContext
from app.v3.bus import Bus
from app.v3.models import Event, EventClass, Message, RawLog, Source


class MockCollector(Agent):
    num = 1
    agent_id = "a01"
    name = "Collector"
    layer = "data"
    subscribes: ClassVar[list[str]] = ["raw.okta"]
    publishes: ClassVar[list[str]] = ["events"]
    path = "hot"

    def process(self, msg: Message, state: dict[str, Any], ctx: AgentContext) -> list[Message]:
        # Emits an event on topic "events"
        ev = Event(
            event_id="ev-from-raw",
            time="2026-10-30T12:00:00Z",
            source=Source.okta,
            event_class=EventClass.authentication,
            action="user.session.start",
            identity_id="alice",
            raw_principal="alice",
            src_ip="1.2.3.4",
            user_agent="agent",
            outcome="success",
            read_only=True,
            resolution_confidence=1.0,
        )
        return [ctx.new_message(topic="events", payload=ev, producer=self.agent_id)]


class MockNormalizer(Agent):
    num = 2
    agent_id = "a02"
    name = "Normalizer"
    layer = "data"
    subscribes: ClassVar[list[str]] = ["events"]
    publishes: ClassVar[list[str]] = ["events.normalized"]
    path = "hot"

    def process(self, msg: Message, state: dict[str, Any], ctx: AgentContext) -> list[Message]:
        state.setdefault("seen", []).append(msg.msg_id)
        return []


class MockWarmAgent(Agent):
    num = 12
    agent_id = "a12"
    name = "Risk Fusion"
    layer = "decision"
    subscribes: ClassVar[list[str]] = ["signals"]
    publishes: ClassVar[list[str]] = ["risk"]
    path = "warm"

    def process(self, msg: Message, state: dict[str, Any], ctx: AgentContext) -> list[Message]:
        return []

    def on_tick(self, state: dict[str, Any], ctx: AgentContext) -> list[Message]:
        ticks = state.get("ticks", 0) + 1
        state["ticks"] = ticks
        return []


class FailingAgent(Agent):
    num = 1
    agent_id = "a01"
    name = "FailingCollector"
    layer = "data"
    subscribes: ClassVar[list[str]] = ["raw.okta"]
    publishes: ClassVar[list[str]] = ["events"]
    path = "hot"

    def process(self, msg: Message, state: dict[str, Any], ctx: AgentContext) -> list[Message]:
        raise RuntimeError("Synthetic processing crash")


# ---------------------------------------------------------------------------
# Test FIFO & Pipeline Drain Ordering
# ---------------------------------------------------------------------------


def test_bus_drain_pipeline_ordering() -> None:
    bus = Bus()
    a1 = MockCollector()
    a2 = MockNormalizer()
    bus.subscribe(a1)
    bus.subscribe(a2)

    raw1 = bus.ctx.new_message(topic="raw.okta", payload=RawLog(source=Source.okta, raw_text="log1"))
    bus.publish(raw1)

    result = bus.run_until_idle()
    assert result["steps"] >= 2
    assert result["delivered"] >= 2

    # Verify Normalizer received event produced by Collector
    state2 = bus._agent_states["a02"]
    assert len(state2.get("seen", [])) == 1


# ---------------------------------------------------------------------------
# Test Deadletter on Agent Exception
# ---------------------------------------------------------------------------


def test_bus_deadletter_on_exception() -> None:
    bus = Bus()
    fail_agent = FailingAgent()
    bus.subscribe(fail_agent)

    raw_msg = bus.ctx.new_message(topic="raw.okta", payload=RawLog(source=Source.okta, raw_text="fail"))
    bus.publish(raw_msg)

    result = bus.run_until_idle()
    assert result["errors"] == 1

    # Verify message in deadletter queue
    dl_queue = bus._queues["deadletter"]
    assert len(dl_queue) == 1
    dl_msg = dl_queue[0]
    assert dl_msg.payload.kind == "deadletter"
    assert dl_msg.payload.failed_topic == "raw.okta"
    assert "Synthetic processing crash" in dl_msg.payload.error


# ---------------------------------------------------------------------------
# Test Bounded Queue Overflow & Drops
# ---------------------------------------------------------------------------


def test_bus_bounded_queue_drops() -> None:
    bus = Bus(queue_max=5)
    for i in range(10):
        msg = bus.ctx.new_message(topic="raw.okta", payload=RawLog(source=Source.okta, raw_text=f"msg-{i}"))
        bus.publish(msg)

    stats = bus.stats()
    assert stats["queue_depths"]["raw.okta"] == 5
    assert stats["dropped"] == 5
    assert stats["published"] == 10


# ---------------------------------------------------------------------------
# Test Backpressure Flag at 80% Capacity
# ---------------------------------------------------------------------------


def test_bus_backpressure_flag() -> None:
    bus = Bus(queue_max=10)
    assert not bus.backpressure

    # Push 8 items (80%) -> still no backpressure
    for i in range(8):
        msg = bus.ctx.new_message(topic="raw.okta", payload=RawLog(source=Source.okta, raw_text=f"m-{i}"))
        bus.publish(msg)
    assert not bus.backpressure

    # 9th item (>80%) -> backpressure active
    msg = bus.ctx.new_message(topic="raw.okta", payload=RawLog(source=Source.okta, raw_text="m-9"))
    bus.publish(msg)
    assert bus.backpressure


# ---------------------------------------------------------------------------
# Test Warm Agent on_tick
# ---------------------------------------------------------------------------


def test_bus_warm_agent_on_tick() -> None:
    bus = Bus()
    warm_ag = MockWarmAgent()
    bus.subscribe(warm_ag)

    bus.run_until_idle()
    state = bus._agent_states["a12"]
    assert state.get("ticks") == 1


# ---------------------------------------------------------------------------
# Test Live Mode Start / Stop
# ---------------------------------------------------------------------------


def test_bus_live_mode_lifecycle() -> None:
    async def _run():
        bus = Bus()
        a1 = MockCollector()
        bus.subscribe(a1)

        await bus.start()
        assert bus._live_running

        msg = bus.ctx.new_message(topic="raw.okta", payload=RawLog(source=Source.okta, raw_text="live"))
        bus.publish(msg)

        # Allow worker to process
        await asyncio.sleep(0.08)
        await bus.stop()
        assert not bus._live_running

    asyncio.run(_run())
