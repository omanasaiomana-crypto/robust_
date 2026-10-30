"""Agent 4: Correlation & Graph for IdentityShield v3.

Follows context.md Section 5, 8, 10, 12, 13 and PRD §8, §12:
- Subscribes: events.enriched
- Publishes: sessions, graph.updates, deadletter
- Correlates multi-provider sessions (Okta external_session_id + derived AWS events)
- Publishes sessions on open, update (cadence throttled), and close (idle timeout 15 min or final tick)
- Maintains a NetworkX MultiDiGraph (identity, session, ip, asn, device, access_key, role, resource)
- Calculates blast_radius(identity_id) for sensitivity >= 4 resources within 3 hops
- Prunes graph by retention days and max nodes
- Exposes get_graph() for API consumption
"""
import logging
from datetime import UTC, datetime
from typing import Any, ClassVar

import networkx as nx

from app.v3.agents.base import Agent, AgentContext
from app.v3.config import (
    GRAPH_MAX_NODES,
    SESSION_IDLE_MINUTES,
)
from app.v3.models import (
    DeadletterPayload,
    EnrichedEvent,
    GraphDelta,
    GraphEdge,
    GraphNode,
    Message,
    Session,
    Source,
)

log = logging.getLogger(__name__)

SESSION_IDLE_SECONDS = SESSION_IDLE_MINUTES * 60.0


def _parse_iso(s: str) -> float:
    """Safely parse ISO string to unix timestamp."""
    try:
        clean = s.strip()
        if clean.endswith("Z"):
            clean = clean[:-1] + "+00:00"
        dt = datetime.fromisoformat(clean)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt.timestamp()
    except (ValueError, TypeError):
        return 0.0


class CorrelationGraph(Agent):
    """Agent 4: Correlation and Graph.

    Stitches Okta and AWS events into unified sessions and maintains the identity graph.
    """

    num = 4
    agent_id = "a04"
    name = "Correlation & Graph"
    layer = "data"
    subscribes: ClassVar[list[str]] = ["events.enriched"]
    publishes: ClassVar[list[str]] = ["sessions", "graph.updates", "deadletter"]
    path = "hot"

    def __init__(self) -> None:
        self.graph = nx.MultiDiGraph()

    def init_state(self) -> dict[str, Any]:
        return {
            "sessions": {},  # session_id -> dict of session fields
            "identity_sessions": {},  # identity_id -> active session_id
            "key_sessions": {},  # access_key_id -> session_id
            "session_event_counts": {},  # session_id -> count since last publish
            "session_last_published": {},  # session_id -> timestamp
            "last_event_time": 0.0,
        }

    def get_graph(self) -> nx.MultiDiGraph:
        """Return a copy of the active identity graph."""
        return self.graph.copy()

    def blast_radius(self, identity_id: str) -> int:
        """Count distinct sensitivity >= 4 resources reachable within 3 hops."""
        ident_node = f"identity:{identity_id}"
        if ident_node not in self.graph:
            return 0

        # Subgraph considering role, key, session, resource edges
        allowed_kinds = {"assumed", "created_key", "used_key", "touched", "in_session"}

        visited_nodes: set[str] = {ident_node}
        current_frontier: set[str] = {ident_node}
        sensitive_resources: set[str] = set()

        for _ in range(3):
            next_frontier: set[str] = set()
            for u in current_frontier:
                for _, v, edge_data in self.graph.out_edges(u, data=True):
                    if edge_data.get("kind") in allowed_kinds and v not in visited_nodes:
                        visited_nodes.add(v)
                        next_frontier.add(v)
                        # Check if sensitive resource
                        node_data = self.graph.nodes.get(v, {})
                        if node_data.get("kind") == "resource" and node_data.get("attrs", {}).get("sensitivity", 1) >= 4:
                            sensitive_resources.add(v)
            current_frontier = next_frontier
            if not current_frontier:
                break

        return len(sensitive_resources)

    def _prune_graph(self) -> None:
        """Prune graph when exceeding GRAPH_MAX_NODES."""
        if self.graph.number_of_nodes() <= GRAPH_MAX_NODES:
            return

        excess = self.graph.number_of_nodes() - GRAPH_MAX_NODES
        # Remove low-degree nodes first
        degrees = sorted(self.graph.degree, key=lambda x: x[1])
        to_remove = [node for node, deg in degrees[:excess] if not node.startswith("identity:")]
        self.graph.remove_nodes_from(to_remove)

    def process(
        self,
        msg: Message,
        state: dict[str, Any],
        ctx: AgentContext,
    ) -> list[Message]:
        if not isinstance(msg.payload, EnrichedEvent):
            dl = DeadletterPayload(
                failed_topic=msg.topic,
                failed_msg_id=msg.msg_id,
                error=f"Expected EnrichedEvent payload, got {type(msg.payload).__name__}",
                producer=self.agent_id,
                raw=getattr(msg.payload, "__dict__", str(msg.payload)),
            )
            return [ctx.new_message(topic="deadletter", payload=dl, producer=self.agent_id)]

        enriched: EnrichedEvent = msg.payload
        ev = enriched.event
        c = enriched.context

        now_dt = ctx.clock() if callable(ctx.clock) else ctx.clock.now()
        now_ts = now_dt.timestamp() if hasattr(now_dt, "timestamp") else _parse_iso(str(now_dt))
        ev_ts = _parse_iso(ev.time)
        state["last_event_time"] = max(state.get("last_event_time", 0.0), ev_ts)

        out_messages: list[Message] = []

        # -------------------------------------------------------------
        # 1. Session Stitching & Correlation
        # -------------------------------------------------------------
        sessions: dict[str, dict[str, Any]] = state["sessions"]
        ident_sessions: dict[str, str] = state["identity_sessions"]
        key_sessions: dict[str, str] = state["key_sessions"]

        target_session_id = None
        key_id = ev.attrs.get("access_key_id")
        created_key_id = ev.attrs.get("created_access_key")
        temp_key_id = ev.attrs.get("temp_access_key")
        okta_sess_id = ev.attrs.get("okta_session_id") or ev.attrs.get("external_session_id") or ev.session_id

        # Case A: Okta event with explicit session ID
        if ev.source == Source.okta and okta_sess_id:
            target_session_id = f"sess:{okta_sess_id}"
            ident_sessions[ev.identity_id] = target_session_id
        # Case B: AWS event with access key already bound to a session
        elif key_id and key_id in key_sessions:
            target_session_id = key_sessions[key_id]
        # Case C: Active identity session within window (e.g. SAML federated login joining Okta session)
        elif ev.identity_id in ident_sessions:
            cand_sess = ident_sessions[ev.identity_id]
            s_data = sessions.get(cand_sess)
            if s_data and s_data["state"] == "open":
                last_time = s_data["last_event_ts"]
                if (ev_ts - last_time) <= SESSION_IDLE_SECONDS:
                    target_session_id = cand_sess
                else:
                    s_data["state"] = "closed"

        # Case D: Fallback standalone AWS session
        if not target_session_id:
            s_key = key_id or "default"
            target_session_id = f"sess:{ev.identity_id}:{s_key}:{int(ev_ts // SESSION_IDLE_SECONDS)}"
            ident_sessions[ev.identity_id] = target_session_id

        # Update key-to-session mappings
        if key_id:
            key_sessions[key_id] = target_session_id
        if temp_key_id:
            key_sessions[temp_key_id] = target_session_id
        if created_key_id:
            key_sessions[created_key_id] = target_session_id

        is_new = target_session_id not in sessions
        if is_new:
            # Create new session
            sess_dict = {
                "session_id": target_session_id,
                "identity_id": ev.identity_id,
                "start": ev.time,
                "end": ev.time,
                "start_ts": ev_ts,
                "last_event_ts": ev_ts,
                "event_ids": [ev.event_id],
                "ips": [ev.src_ip] if ev.src_ip else [],
                "asns": [c.asn] if c.asn is not None else [],
                "devices": [ev.user_agent] if ev.user_agent else [],
                "providers": [ev.source.value],
                "state": "open",
                "fingerprint": {
                    "initial_ip": ev.src_ip,
                    "initial_asn": c.asn,
                    "initial_user_agent": ev.user_agent,
                },
            }
            sessions[target_session_id] = sess_dict
            state["session_event_counts"][target_session_id] = 1
            state["session_last_published"][target_session_id] = now_ts

            # Publish session OPEN
            open_sess = Session(
                session_id=sess_dict["session_id"],
                identity_id=sess_dict["identity_id"],
                start=sess_dict["start"],
                end=sess_dict["end"],
                event_ids=list(sess_dict["event_ids"]),
                ips=list(sess_dict["ips"]),
                asns=list(sess_dict["asns"]),
                devices=list(sess_dict["devices"]),
                providers=list(sess_dict["providers"]),
                state="open",
                fingerprint=sess_dict["fingerprint"],
            )
            out_messages.append(
                ctx.new_message(topic="sessions", payload=open_sess, partition_key=ev.identity_id, producer=self.agent_id)
            )
        else:
            # Update existing session
            sess_dict = sessions[target_session_id]
            sess_dict["end"] = ev.time
            sess_dict["last_event_ts"] = ev_ts
            sess_dict["event_ids"].append(ev.event_id)
            if ev.src_ip and ev.src_ip not in sess_dict["ips"]:
                sess_dict["ips"].append(ev.src_ip)
            if c.asn is not None and c.asn not in sess_dict["asns"]:
                sess_dict["asns"].append(c.asn)
            if ev.user_agent and ev.user_agent not in sess_dict["devices"]:
                sess_dict["devices"].append(ev.user_agent)
            if ev.source.value not in sess_dict["providers"]:
                sess_dict["providers"].append(ev.source.value)

            state["session_event_counts"][target_session_id] = state["session_event_counts"].get(target_session_id, 0) + 1

            # Check update cadence: every 5 events or 10s
            count = state["session_event_counts"][target_session_id]
            last_pub = state["session_last_published"].get(target_session_id, 0.0)
            if count >= 5 or (now_ts - last_pub) >= 10.0:
                state["session_event_counts"][target_session_id] = 0
                state["session_last_published"][target_session_id] = now_ts
                updated_sess = Session(
                    session_id=sess_dict["session_id"],
                    identity_id=sess_dict["identity_id"],
                    start=sess_dict["start"],
                    end=sess_dict["end"],
                    event_ids=list(sess_dict["event_ids"]),
                    ips=list(sess_dict["ips"]),
                    asns=list(sess_dict["asns"]),
                    devices=list(sess_dict["devices"]),
                    providers=list(sess_dict["providers"]),
                    state=sess_dict["state"],
                    fingerprint=sess_dict["fingerprint"],
                )
                out_messages.append(
                    ctx.new_message(topic="sessions", payload=updated_sess, partition_key=ev.identity_id, producer=self.agent_id)
                )

        # -------------------------------------------------------------
        # 2. Graph Maintenance & GraphDelta
        # -------------------------------------------------------------
        delta_nodes: list[GraphNode] = []
        delta_edges: list[GraphEdge] = []

        # Identity Node
        ident_id = f"identity:{ev.identity_id}"
        if ident_id not in self.graph:
            delta_nodes.append(GraphNode(id=ident_id, kind="identity", label=ev.identity_id, attrs={"privilege": c.privilege_level}))
            self.graph.add_node(ident_id, kind="identity", label=ev.identity_id, attrs={"privilege": c.privilege_level})

        # Session Node
        s_node = target_session_id
        if s_node not in self.graph:
            delta_nodes.append(GraphNode(id=s_node, kind="session", label=s_node, attrs={"identity": ev.identity_id}))
            self.graph.add_node(s_node, kind="session", label=s_node, attrs={"identity": ev.identity_id})

        # Identity -> Session Edge
        delta_edges.append(GraphEdge(source=ident_id, target=s_node, kind="in_session", event_id=ev.event_id, time=ev.time))
        self.graph.add_edge(ident_id, s_node, kind="in_session", event_id=ev.event_id, time=ev.time)

        # IP Node & Edge
        if ev.src_ip:
            ip_node = f"ip:{ev.src_ip}"
            if ip_node not in self.graph:
                delta_nodes.append(GraphNode(id=ip_node, kind="ip", label=ev.src_ip, attrs={"country": c.country, "city": c.city}))
                self.graph.add_node(ip_node, kind="ip", label=ev.src_ip, attrs={"country": c.country, "city": c.city})
            delta_edges.append(GraphEdge(source=s_node, target=ip_node, kind="logged_in_from", event_id=ev.event_id, time=ev.time))
            self.graph.add_edge(s_node, ip_node, kind="logged_in_from", event_id=ev.event_id, time=ev.time)

            # ASN Node & Edge
            if c.asn is not None:
                asn_node = f"asn:{c.asn}"
                if asn_node not in self.graph:
                    delta_nodes.append(GraphNode(id=asn_node, kind="asn", label=f"AS{c.asn}", attrs={"org": c.as_org}))
                    self.graph.add_node(asn_node, kind="asn", label=f"AS{c.asn}", attrs={"org": c.as_org})
                delta_edges.append(GraphEdge(source=ip_node, target=asn_node, kind="routed_via", event_id=ev.event_id, time=ev.time))
                self.graph.add_edge(ip_node, asn_node, kind="routed_via", event_id=ev.event_id, time=ev.time)

        # Role Node & Edge
        role_arn = ev.attrs.get("role_arn")
        if role_arn:
            role_node = f"role:{role_arn}"
            if role_node not in self.graph:
                delta_nodes.append(GraphNode(id=role_node, kind="role", label=role_arn.split("/")[-1], attrs={"arn": role_arn}))
                self.graph.add_node(role_node, kind="role", label=role_arn.split("/")[-1], attrs={"arn": role_arn})
            delta_edges.append(GraphEdge(source=ident_id, target=role_node, kind="assumed", event_id=ev.event_id, time=ev.time))
            self.graph.add_edge(ident_id, role_node, kind="assumed", event_id=ev.event_id, time=ev.time)

        # Access Key Node & Edge
        if key_id:
            key_node = f"access_key:{key_id}"
            if key_node not in self.graph:
                delta_nodes.append(GraphNode(id=key_node, kind="access_key", label=key_id, attrs={}))
                self.graph.add_node(key_node, kind="access_key", label=key_id, attrs={})
            delta_edges.append(GraphEdge(source=s_node, target=key_node, kind="used_key", event_id=ev.event_id, time=ev.time))
            self.graph.add_edge(s_node, key_node, kind="used_key", event_id=ev.event_id, time=ev.time)

        # Resource Node & Edge
        if ev.resource_arn:
            res_node = f"resource:{ev.resource_arn}"
            if res_node not in self.graph:
                delta_nodes.append(
                    GraphNode(id=res_node, kind="resource", label=ev.resource_arn, attrs={"sensitivity": c.resource_sensitivity})
                )
                self.graph.add_node(
                    res_node, kind="resource", label=ev.resource_arn, attrs={"sensitivity": c.resource_sensitivity}
                )
            delta_edges.append(GraphEdge(source=s_node, target=res_node, kind="touched", event_id=ev.event_id, time=ev.time))
            self.graph.add_edge(s_node, res_node, kind="touched", event_id=ev.event_id, time=ev.time)
            if role_arn:
                self.graph.add_edge(f"role:{role_arn}", res_node, kind="touched", event_id=ev.event_id, time=ev.time)
            if key_id:
                self.graph.add_edge(f"access_key:{key_id}", res_node, kind="touched", event_id=ev.event_id, time=ev.time)

        self._prune_graph()

        if delta_nodes or delta_edges:
            delta = GraphDelta(nodes=delta_nodes, edges=delta_edges)
            out_messages.append(
                ctx.new_message(topic="graph.updates", payload=delta, partition_key=ev.identity_id, producer=self.agent_id)
            )

        return out_messages

    def on_tick(
        self,
        state: dict[str, Any],
        ctx: AgentContext,
    ) -> list[Message]:
        """Close idle sessions or flush remaining sessions on final tick."""
        sessions: dict[str, dict[str, Any]] = state.get("sessions", {})
        now_dt = ctx.clock() if callable(ctx.clock) else ctx.clock.now()
        now_ts = now_dt.timestamp() if hasattr(now_dt, "timestamp") else _parse_iso(str(now_dt))
        last_ev_ts = state.get("last_event_time", now_ts)

        out_messages: list[Message] = []

        for sess_id, s in list(sessions.items()):
            if s["state"] == "open":
                # Close if idle beyond threshold or drain tick
                idle_gap = max(now_ts, last_ev_ts) - s["last_event_ts"]
                if idle_gap >= SESSION_IDLE_SECONDS or ctx.run_id != "live":
                    s["state"] = "closed"
                    closed_sess = Session(
                        session_id=s["session_id"],
                        identity_id=s["identity_id"],
                        start=s["start"],
                        end=s["end"],
                        event_ids=list(s["event_ids"]),
                        ips=list(s["ips"]),
                        asns=list(s["asns"]),
                        devices=list(s["devices"]),
                        providers=list(s["providers"]),
                        state="closed",
                        fingerprint=s["fingerprint"],
                    )
                    out_messages.append(
                        ctx.new_message(
                            topic="sessions", payload=closed_sess, partition_key=s["identity_id"], producer=self.agent_id
                        )
                    )

        return out_messages
