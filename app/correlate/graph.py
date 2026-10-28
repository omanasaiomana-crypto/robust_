"""NetworkX identity graph modeling relationships between users, sessions, roles, keys, and resources."""
import logging
import networkx as nx
import pandas as pd

from app.models import GraphEdge, GraphNode, IdentityGraph

log = logging.getLogger(__name__)


def build_graph(events: pd.DataFrame) -> nx.MultiDiGraph:
    """Build a multi-directed graph capturing identity relationships and activity."""
    g = nx.MultiDiGraph()
    if events is None or events.empty:
        return g

    for _, row in events.iterrows():
        uid = str(row.get("identity_id", "unknown"))
        sess = str(row.get("session_id", ""))
        action = str(row.get("action", ""))
        ip = str(row.get("src_ip", ""))
        token = str(row.get("token_id", ""))
        res = str(row.get("resource", ""))
        sens = int(row.get("resource_sensitivity", 1) or 1)
        eid = str(row.get("event_id", ""))
        label = str(row.get("label", "benign"))
        suspicious = label not in ("benign", "", "None")

        user_node = f"user:{uid}"
        if not g.has_node(user_node):
            g.add_node(user_node, id=user_node, label=uid, kind="user", risk=0.0)

        # Session node and user -> session edge
        if sess and sess != "None":
            sess_node = f"session:{sess}"
            if not g.has_node(sess_node):
                g.add_node(sess_node, id=sess_node, label=sess, kind="session", risk=0.0)
            
            # Connect user to session
            if not g.has_edge(user_node, sess_node):
                g.add_edge(user_node, sess_node, label="login", event_id=eid, suspicious=suspicious)

            # Session -> IP edge
            if ip and ip != "None":
                ip_node = f"ip:{ip}"
                if not g.has_node(ip_node):
                    g.add_node(ip_node, id=ip_node, label=ip, kind="ip", risk=0.0)
                if not g.has_edge(sess_node, ip_node):
                    g.add_edge(sess_node, ip_node, label="from_ip", event_id=eid, suspicious=suspicious)

            # Role assumption: session -> role
            if action in ("AssumeRole", "AssumeRoleWithSAML"):
                role_name = res.split("/")[-1] if "/" in res else (res or "AssumedRole")
                role_node = f"role:{role_name}"
                if not g.has_node(role_node):
                    g.add_node(role_node, id=role_node, label=role_name, kind="role", risk=0.0)
                g.add_edge(sess_node, role_node, label="assumed", event_id=eid, suspicious=suspicious)
                # Link user directly to role for reachability
                if not g.has_edge(user_node, role_node):
                    g.add_edge(user_node, role_node, label="assumed", event_id=eid, suspicious=suspicious)

            # Resource access: session -> resource
            if res and res != "None" and action not in ("AssumeRole", "AssumeRoleWithSAML", "AttachUserPolicy", "AttachRolePolicy"):
                res_label = res.split("/")[-1] if "/" in res else res
                res_node = f"res:{res}"
                if not g.has_node(res_node):
                    g.add_node(res_node, id=res_node, label=res_label, kind="resource", sensitivity=sens, risk=0.0)
                else:
                    curr_sens = g.nodes[res_node].get("sensitivity", 1)
                    if sens > curr_sens:
                        g.nodes[res_node]["sensitivity"] = sens
                g.add_edge(sess_node, res_node, label="accessed", event_id=eid, suspicious=suspicious)

        # Key creation
        if action == "CreateAccessKey" or (token and token != "None" and action == "CreateAccessKey"):
            key_name = token if (token and token != "None") else f"AKIA_{uid.upper()}"
            key_node = f"key:{key_name}"
            if not g.has_node(key_node):
                g.add_node(key_node, id=key_node, label=key_name, kind="key", risk=0.0)
            g.add_edge(user_node, key_node, label="created_key", event_id=eid, suspicious=suspicious)

        # Policy attachment: user/role -> policy
        if "Policy" in action:
            pol_name = res.split("/")[-1] if "/" in res else (res or "Policy")
            pol_node = f"policy:{pol_name}"
            if not g.has_node(pol_node):
                g.add_node(pol_node, id=pol_node, label=pol_name, kind="policy", risk=0.0)
            g.add_edge(user_node, pol_node, label="attached", event_id=eid, suspicious=suspicious)

    return g


def escalation_paths(g: nx.MultiDiGraph, identity_id: str) -> list[list[str]]:
    """Return paths from identity to any admin role or policy (cutoff=6)."""
    start_node = f"user:{identity_id}"
    if not g.has_node(start_node):
        return []

    paths: list[list[str]] = []
    # Identify target nodes that are admin roles or policies
    targets = [
        n for n in g.nodes()
        if g.nodes[n].get("kind") in ("role", "policy")
        and any(k in n.lower() for k in ("admin", "administrator", "root"))
    ]

    for t in targets:
        if nx.has_path(g, start_node, t):
            try:
                for p in nx.all_simple_paths(g, start_node, t, cutoff=6):
                    paths.append(p)
                    if len(paths) >= 20:  # Cap at 20 paths for responsiveness
                        return paths
            except Exception as exc:
                log.debug("Path search error for %s -> %s: %s", start_node, t, exc)

    return paths


def blast_radius(g: nx.MultiDiGraph, identity_id: str) -> int:
    """Count reachable resource nodes with sensitivity >= 4."""
    start_node = f"user:{identity_id}"
    if not g.has_node(start_node):
        return 0

    try:
        reachable = nx.descendants(g, start_node)
        count = 0
        for n in reachable:
            if g.nodes[n].get("kind") == "resource" and g.nodes[n].get("sensitivity", 1) >= 4:
                count += 1
        return count
    except Exception as exc:
        log.warning("Failed calculating blast_radius for %s: %s", identity_id, exc)
        return 0


def identity_subgraph(g: nx.MultiDiGraph, identity_id: str, suspicious_ids: set[str] | None = None) -> IdentityGraph:
    """Return subgraph centered on identity with at most 150 nodes."""
    sus_ids = suspicious_ids or set()
    start_node = f"user:{identity_id}"

    if not g.has_node(start_node):
        return IdentityGraph(identity_id=identity_id, nodes=[], edges=[], escalation_paths=[])

    # Neighborhood discovery up to radius 3
    try:
        undirected = g.to_undirected()
        lengths = nx.single_source_shortest_path_length(undirected, start_node, cutoff=3)
        # Prioritize start_node and endpoints of suspicious evidence edges
        sus_endpoints: set[str] = set()
        if sus_ids:
            for u, v, d in g.edges(data=True):
                if d.get("event_id") in sus_ids:
                    sus_endpoints.add(u)
                    sus_endpoints.add(v)

        priority_nodes = [start_node] + [n for n in sorted(sus_endpoints) if n != start_node and g.has_node(n)]
        sorted_nodes = sorted(lengths.keys(), key=lambda n: lengths[n])
        remaining = [n for n in sorted_nodes if n not in sus_endpoints and n != start_node]
        selected_nodes = (priority_nodes + remaining)[:150]
        sub = g.subgraph(selected_nodes)
    except Exception as exc:
        log.warning("Subgraph extraction fallback for %s: %s", identity_id, exc)
        sub = g.subgraph([start_node])

    nodes: list[GraphNode] = []
    for n in sub.nodes():
        nodes.append(
            GraphNode(
                id=n,
                label=str(g.nodes[n].get("label", n)),
                kind=str(g.nodes[n].get("kind", "unknown")),
                risk=float(g.nodes[n].get("risk", 0.0)),
            )
        )

    edges: list[GraphEdge] = []
    seen_edges: set[tuple[str, str, str]] = set()
    for u, v, data in sub.edges(data=True):
        lbl = str(data.get("label", ""))
        edge_key = (u, v, lbl)
        if edge_key in seen_edges:
            continue
        seen_edges.add(edge_key)

        eid = data.get("event_id")
        is_sus = bool(eid in sus_ids or data.get("suspicious", False))
        edges.append(
            GraphEdge(
                source=u,
                target=v,
                label=lbl,
                event_id=eid,
                suspicious=is_sus,
            )
        )

    paths = escalation_paths(g, identity_id)
    return IdentityGraph(identity_id=identity_id, nodes=nodes, edges=edges, escalation_paths=paths)
