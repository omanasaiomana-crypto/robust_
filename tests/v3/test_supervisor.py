"""Unit tests for app/v3/supervisor.py supervisor, registry, capabilities, and health."""
from typing import Any, ClassVar

import pytest

from app.v3.agents.base import Agent, AgentContext
from app.v3.bus import Bus
from app.v3.models import Message, RawLog, Source
from app.v3.supervisor import CapabilityError, Supervisor


class LegitimateAgent1(Agent):
    num = 1
    agent_id = "a01"
    name = "Collector"
    layer = "data"
    subscribes: ClassVar[list[str]] = ["raw.okta"]
    publishes: ClassVar[list[str]] = ["events", "deadletter"]
    path = "hot"

    def process(self, msg: Message, state: dict[str, Any], ctx: AgentContext) -> list[Message]:
        return []


class RogueAgent1(Agent):
    num = 1
    agent_id = "a01"
    name = "RogueCollector"
    layer = "data"
    subscribes: ClassVar[list[str]] = ["raw.okta"]
    # Agent 1 is NOT allowed to publish to "signals"
    publishes: ClassVar[list[str]] = ["signals"]
    path = "hot"

    def process(self, msg: Message, state: dict[str, Any], ctx: AgentContext) -> list[Message]:
        return [ctx.new_message(topic="signals", payload=RawLog(source=Source.okta, raw_text="unauthorized"), producer=self.agent_id)]


# ---------------------------------------------------------------------------
# Test 15 Agent Registry Slots
# ---------------------------------------------------------------------------


def test_registry_fifteen_slots() -> None:
    sup = Supervisor()
    health_list = sup.get_health()
    assert len(health_list) == 15

    # Check unbuilt agent status
    a01_health = sup.get_health("a01")
    assert a01_health["status"] == "not_built"

    # Register an agent and check status transition to idle
    ag = LegitimateAgent1()
    sup.register_agent(ag)
    a01_updated = sup.get_health("a01")
    assert a01_updated["status"] == "idle"


# ---------------------------------------------------------------------------
# Test Capability Manifest Enforcement
# ---------------------------------------------------------------------------


def test_capability_manifest_check_publish() -> None:
    sup = Supervisor()
    ag = LegitimateAgent1()
    sup.register_agent(ag)

    # Allowed topic for agent 1
    sup.check_publish(ag, "events")

    # Forbidden topic for agent 1 (only allowed "events", "deadletter")
    with pytest.raises(CapabilityError):
        sup.check_publish(ag, "signals")

    h = sup.get_health("a01")
    assert h["blocked"] == 1


def test_bus_converts_capability_violation_into_blocked_event() -> None:
    sup = Supervisor()
    bus = Bus(supervisor=sup)
    rogue = RogueAgent1()
    bus.subscribe(rogue)

    raw_msg = bus.ctx.new_message(topic="raw.okta", payload=RawLog(source=Source.okta, raw_text="trigger"))
    bus.publish(raw_msg)

    # Drain will trigger rogue.process(), which tries to publish to "signals"
    bus.run_until_idle()

    # Unauthorized message was blocked and not delivered to "signals"
    assert len(bus._queues["signals"]) == 0

    # Agent blocked counter incremented
    h = sup.get_health("a01")
    assert h["blocked"] >= 1


# ---------------------------------------------------------------------------
# Test Health Percentiles
# ---------------------------------------------------------------------------


def test_health_rolling_percentiles() -> None:
    sup = Supervisor()
    ag = LegitimateAgent1()
    sup.register_agent(ag)

    # Record 100 durations from 1ms to 100ms
    for i in range(1, 101):
        sup.record_step_result("a01", duration_ms=float(i), error=False)

    h = sup.get_health("a01")
    assert h["processed"] == 100
    # p50 around 50.5 ms
    assert 49.0 <= h["p50_ms"] <= 52.0
    # p95 around 95.0 ms
    assert 94.0 <= h["p95_ms"] <= 96.5


# ---------------------------------------------------------------------------
# Test Agent Restart/Degraded Policy (3 errors in 60s)
# ---------------------------------------------------------------------------


def test_agent_degraded_after_three_errors() -> None:
    sup = Supervisor()
    ag = LegitimateAgent1()
    sup.register_agent(ag)

    sup.record_step_result("a01", 10.0, error=True)
    assert sup.get_health("a01")["status"] == "error"

    sup.record_step_result("a01", 10.0, error=True)
    assert sup.get_health("a01")["status"] == "error"

    # 3rd error within 60s triggers degraded status
    sup.record_step_result("a01", 10.0, error=True)
    assert sup.get_health("a01")["status"] == "degraded"


# ---------------------------------------------------------------------------
# Test Pace Control
# ---------------------------------------------------------------------------


def test_pace_control_bounds() -> None:
    sup = Supervisor()
    assert sup.get_pace() == 0.0

    sup.set_pace(1.5)
    assert sup.get_pace() == 1.5

    # Clamped at 3.0 max
    sup.set_pace(5.0)
    assert sup.get_pace() == 3.0

    # Clamped at 0.0 min
    sup.set_pace(-1.0)
    assert sup.get_pace() == 0.0
