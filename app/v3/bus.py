"""Topic Event Bus for IdentityShield v3.

Follows context.md Section 9 and P02 specifications:
- Bounded deques per topic (config.QUEUE_MAX)
- Pipeline topic ordering for deterministic drain mode
- FIFO per topic with per-partition ordering
- Capability checks, deadletter on agent exception
- Backpressure flag when any queue > 80% full
- Async live mode with pace-controlled pauses and warm-agent ticking
"""
import asyncio
import logging
import threading
import time
from collections import deque
from typing import Any

from app.v3 import audit, config, trace
from app.v3.agents.base import Agent, AgentContext
from app.v3.models import DeadletterPayload, Message
from app.v3.supervisor import CapabilityError, Supervisor

log = logging.getLogger(__name__)

TOPICS: list[str] = [
    "raw.okta",
    "raw.cloudtrail",
    "events",
    "events.normalized",
    "events.enriched",
    "sessions",
    "graph.updates",
    "signals",
    "risk",
    "cases",
    "actions",
    "approvals",
    "labels",
    "config.updates",
    "trace",
    "deadletter",
]

VALID_TOPICS: frozenset[str] = frozenset(TOPICS)


class Bus:
    """Thread-safe and async-compatible topic event bus."""

    def __init__(
        self,
        supervisor: Supervisor | None = None,
        queue_max: int | None = None,
        ctx: AgentContext | None = None,
    ) -> None:
        self.supervisor = supervisor or Supervisor()
        self.queue_max = queue_max or config.QUEUE_MAX
        self.ctx = ctx or AgentContext(settings=config.get_settings())
        self._lock = threading.RLock()

        self._queues: dict[str, deque[Message]] = {t: deque(maxlen=self.queue_max) for t in TOPICS}
        self._subscribers: dict[str, list[Agent]] = {t: [] for t in TOPICS}
        self._agent_states: dict[str, dict[str, Any]] = {}

        # Metrics
        self._published = 0
        self._delivered = 0
        self._dropped = 0
        self.backpressure = False

        # Live mode task tracking
        self._live_running = False
        self._live_tasks: list[asyncio.Task] = []

    @property
    def queue_depth(self) -> int:
        with self._lock:
            return sum(len(q) for q in self._queues.values())

    @property
    def topics(self) -> list[str]:
        return list(TOPICS)

    def subscribe(self, agent: Agent) -> None:
        """Register agent for its subscribed topics and initialize its state."""
        with self._lock:
            self.supervisor.register_agent(agent)
            self._agent_states[agent.agent_id] = agent.init_state()
            for topic in agent.subscribes:
                if topic in self._subscribers and agent not in self._subscribers[topic]:
                    self._subscribers[topic].append(agent)

    def publish(self, message: Message, agent: Agent | None = None) -> bool:
        """Publish message to topic after capability check.

        Returns True if message was enqueued, False if blocked or rejected.
        """
        if message.topic not in VALID_TOPICS:
            raise ValueError(f"Unknown topic: {message.topic}. Valid topics: {TOPICS}")

        with self._lock:
            # Check capability manifest if produced by an agent
            prod_agent = agent or self.supervisor.get_agent(message.producer)
            if prod_agent is not None:
                try:
                    self.supervisor.check_publish(prod_agent, message.topic)
                except CapabilityError as exc:
                    log.warning("Capability violation: %s", exc)
                    audit.append(
                        prod_agent.agent_id,
                        "capability_blocked",
                        {"topic": message.topic, "msg_id": message.msg_id, "error": str(exc)},
                    )
                    trace.emit(
                        prod_agent.agent_id,
                        "blocked",
                        f"Capability violation: blocked publishing to '{message.topic}'",
                    )
                    return False

            q = self._queues[message.topic]
            if len(q) >= self.queue_max:
                self._dropped += 1
                log.warning("Queue overflow on topic '%s'. Dropping oldest message.", message.topic)

            q.append(message)
            self._published += 1

            # Update backpressure if any queue exceeds 80% threshold
            high_watermark = int(self.queue_max * 0.80)
            self.backpressure = any(len(queue) > high_watermark for queue in self._queues.values())

            # Update queue lag in supervisor health
            for aid, ag in self.supervisor._agents.items():
                h = self.supervisor._health.get(aid)
                if h:
                    h.queue_lag = sum(len(self._queues[t]) for t in ag.subscribes if t in self._queues)

            return True

    def stats(self) -> dict[str, Any]:
        """Return bus statistics and queue depths."""
        with self._lock:
            depths = {t: len(q) for t, q in self._queues.items()}
            return {
                "published": self._published,
                "delivered": self._delivered,
                "dropped": self._dropped,
                "backpressure": self.backpressure,
                "queue_depths": depths,
                "total_queued": sum(depths.values()),
            }

    def _deliver_message_to_agent(self, agent: Agent, msg: Message) -> list[Message]:
        """Deliver one message to an agent safely; catches exceptions and deadletters."""
        t0 = time.perf_counter()
        state = self._agent_states.setdefault(agent.agent_id, agent.init_state())
        try:
            out_msgs = agent.process(msg, state, self.ctx)
            dur_ms = (time.perf_counter() - t0) * 1000.0
            self.supervisor.record_step_result(agent.agent_id, dur_ms, error=False)
            return out_msgs or []
        except Exception as exc:
            dur_ms = (time.perf_counter() - t0) * 1000.0
            log.exception("Exception in agent %s processing message %s", agent.agent_id, msg.msg_id)
            self.supervisor.record_step_result(agent.agent_id, dur_ms, error=True)

            # Publish deadletter message
            dl_payload = DeadletterPayload(
                failed_topic=msg.topic,
                failed_msg_id=msg.msg_id,
                error=f"{type(exc).__name__}: {exc}",
                producer=agent.agent_id,
                raw=msg.payload.model_dump() if hasattr(msg.payload, "model_dump") else str(msg.payload),
            )
            dl_msg = self.ctx.new_message(
                topic="deadletter",
                payload=dl_payload,
                partition_key=msg.partition_key,
                producer=agent.agent_id,
            )
            self._queues["deadletter"].append(dl_msg)
            return []

    def run_until_idle(self, max_steps: int = 10000) -> dict[str, int]:
        """Synchronously drain all queues in deterministic pipeline order.

        Once queues are empty, calls on_tick for warm agents, repeating until completely idle.
        """
        steps = 0
        delivered = 0
        published_start = self._published

        while steps < max_steps:
            progress = False

            # Process queues topic-by-topic in defined pipeline order
            for topic in TOPICS:
                if topic == "deadletter":
                    # Keep deadletter messages stored for inspection without delivery loops
                    continue

                q = self._queues[topic]
                if not q:
                    continue

                # Process all messages currently in this topic queue
                batch: list[Message] = []
                with self._lock:
                    while q:
                        batch.append(q.popleft())

                for msg in batch:
                    steps += 1
                    subscribers = list(self._subscribers.get(topic, []))
                    for ag in subscribers:
                        delivered += 1
                        self._delivered += 1
                        out = self._deliver_message_to_agent(ag, msg)
                        for out_msg in out:
                            self.publish(out_msg, agent=ag)
                    progress = True

            # If all queues are now empty, trigger on_tick for warm agents
            if not progress:
                warm_agents = [ag for ag in self.supervisor.get_registered_agents() if ag.path == "warm"]
                tick_produced = False
                for ag in warm_agents:
                    state = self._agent_states.setdefault(ag.agent_id, ag.init_state())
                    try:
                        tick_msgs = ag.on_tick(state, self.ctx)
                        for m in tick_msgs or []:
                            self.publish(m, agent=ag)
                            tick_produced = True
                    except Exception:
                        log.exception("Exception during on_tick for agent %s", ag.agent_id)
                        self.supervisor.record_step_result(ag.agent_id, 0.0, error=True)

                if not tick_produced:
                    # System is completely idle
                    break

        return {
            "steps": steps,
            "delivered": delivered,
            "published": self._published - published_start,
            "dropped": self._dropped,
            "errors": sum(h.errors for h in self.supervisor._health.values()),
        }

    # -----------------------------------------------------------------------
    # Async Live Mode
    # -----------------------------------------------------------------------

    async def _dispatcher_worker(self) -> None:
        """Central async bus dispatcher delivering messages to all topic subscribers in pipeline order."""
        while self._live_running:
            processed_any = False
            for topic in TOPICS:
                if topic == "deadletter":
                    continue

                batch: list[Message] = []
                with self._lock:
                    q = self._queues[topic]
                    if not q:
                        continue
                    while q:
                        batch.append(q.popleft())

                if not batch:
                    continue

                for msg in batch:
                    subscribers = list(self._subscribers.get(topic, []))
                    for ag in subscribers:
                        self._delivered += 1
                        out = self._deliver_message_to_agent(ag, msg)
                        for out_msg in out:
                            self.publish(out_msg, agent=ag)
                    processed_any = True

            if not processed_any:
                await asyncio.sleep(0.01)

    async def _warm_ticker(self) -> None:
        """Background ticker for warm agents."""
        while self._live_running:
            await asyncio.sleep(config.WARM_TICK_SECONDS)
            if not self._live_running:
                break
            warm_agents = [ag for ag in self.supervisor.get_registered_agents() if ag.path == "warm"]
            for ag in warm_agents:
                state = self._agent_states.setdefault(ag.agent_id, ag.init_state())
                try:
                    msgs = ag.on_tick(state, self.ctx)
                    for m in msgs or []:
                        self.publish(m, agent=ag)
                except Exception:
                    log.exception("Warm ticker error for %s", ag.agent_id)

    async def start(self) -> None:
        """Start async live mode workers."""
        if self._live_running:
            return
        self._live_running = True
        self._live_tasks = []
        self._live_tasks.append(asyncio.create_task(self._dispatcher_worker(), name="bus_dispatcher"))
        self._live_tasks.append(asyncio.create_task(self._warm_ticker(), name="bus_warm_ticker"))

    async def stop(self) -> None:
        """Stop async live mode workers."""
        self._live_running = False
        for task in self._live_tasks:
            task.cancel()
        if self._live_tasks:
            await asyncio.gather(*self._live_tasks, return_exceptions=True)
        self._live_tasks.clear()
