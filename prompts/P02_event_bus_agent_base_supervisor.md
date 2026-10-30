# P02: Event bus, agent base, Supervisor (MUST)

> **Before pasting:** open a NEW Antigravity chat and paste T1 from `00_TEMPLATES.md` first. Then paste only the text block below. Run the CHECK yourself.

```text
Read context.md Sections 5, 6, 7, 9, 10. Phase P2: platform core.
DO:
1. app/v3/agents/base.py: abstract class Agent with: num (1-15), agent_id ("a01".."a15"), name, layer,
   subscribes (list of topics), publishes (list of topics), path ("hot"/"warm"/"nightly"),
   init_state() -> dict, process(msg: Message, state: dict, ctx: AgentContext) -> list[Message],
   on_tick(state, ctx) -> list[Message] (default empty). AgentContext provides: clock, settings, store (later),
   run_id, emit_trace(state, message, data=None), new_message(topic, payload, partition_key).
2. app/v3/bus.py:
   - class Bus with bounded deques per topic (config.QUEUE_MAX), publish(message) validating topic name,
     subscribe(agent), stats() (depth per topic, published, delivered, dropped).
   - Drain mode: run_until_idle(max_steps) delivers messages to subscribed agents in deterministic order
     (FIFO per topic, topics processed in pipeline order of context.md Section 9), then calls on_tick for warm
     agents once queues are empty, repeats until no new messages. Returns counts.
   - Live mode: async start()/stop() running one asyncio task per agent consuming its subscribed topics,
     with per-partition ordering preserved; warm agents get on_tick every config.WARM_TICK_SECONDS (add constant 30).
   - Any exception inside an agent: catch, increment error counter, publish a deadletter message with
     agent_id, topic, msg_id, error class and message (no stack trace in payload; stack goes to log), continue.
   - Backpressure flag when any queue > 80 % full.
3. app/v3/supervisor.py:
   - Registry of 15 agent slots (agents registered later phases; missing agents show status "not_built").
   - Capability manifests exactly as context.md Section 10; check_publish(agent, topic) raises CapabilityError,
     which the bus converts into a blocked + audited event and a counter on the agent.
   - Health per agent: status (idle/running/degraded/not_built/error), processed, errors, blocked, last_message_at,
     p50/p95 processing ms (rolling window of 500), queue lag.
   - Pace control: set_pace(seconds 0..3) used by the Live view; in paced mode the bus sleeps pace*0.35 before and
     pace*0.45 after each agent step (live mode only).
   - Restart policy: an agent raising 3 times in 60 s → status degraded (still processing, flagged).
4. app/v3/trace.py: adapter that converts v3 agent trace calls into the existing app/trace.py events (reuse its
   emit/step/progress/finding functions found in P0). If app/trace.py is missing, implement an in-memory ring
   buffer of 5,000 events with the same schema.
5. app/v3/store.py: SQLite helper (WAL, one connection per thread, parameterized), create_tables() for all tables
   in context.md Section 11 with indexes, insert_many(table, rows) batched, simple query helpers. JSON fields as TEXT.
6. app/v3/audit.py: adapter to the existing hash-chained audit append and verify functions (from P0); if absent,
   implement a v3 table with prev_hash/hash SHA-256 chaining and verify().
7. Tests tests/v3/test_bus.py, test_supervisor.py, test_store.py: drain ordering, bounded queue drops counted,
   deadletter on exception, capability violation blocked and audited, health percentiles, store round trip,
   audit chain verify true then false after tampering a row.
FILES: app/v3/agents/base.py, app/v3/bus.py, app/v3/supervisor.py, app/v3/trace.py, app/v3/store.py,
app/v3/audit.py, app/v3/config.py (add WARM_TICK_SECONDS only), tests/v3/test_bus.py, tests/v3/test_supervisor.py,
tests/v3/test_store.py
```

**CHECK**
```bash
pytest -q tests/v3
ruff check app/v3 tests/v3
```

---
**After the CHECK passes:** paste template T5 (in `00_TEMPLATES.md`), then commit: `git add -A && git commit -m "v3 P02: Event bus, agent base, Supervisor"`. Next file: `P03_secure_ingest_service_on_port_8001.md`.
