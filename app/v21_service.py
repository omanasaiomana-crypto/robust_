"""Plain functions behind the v2.1 API (no FastAPI imports, so they are unit-testable).

Every function is defensive: it never raises on missing pipeline pieces; it returns empty structures instead.
"""
import inspect
import logging
from typing import Any

from app import analytics, config, inputs, runner, trace

log = logging.getLogger(__name__)


def _dump(obj: Any) -> Any:
    if obj is None:
        return None
    if hasattr(obj, "model_dump"):
        return obj.model_dump(mode="json")
    return obj


# ---------------------------------------------------------------- agents / scan

def agents_payload() -> dict:
    return {"agents": trace.agents_status(), "run": trace.run_status()}


def scan_trace(after: int = 0, limit: int = 500, run_id: str | None = None) -> dict:
    st = trace.run_status()
    rid = run_id or st["run_id"]
    if not rid:
        return {"run_id": None, "state": "idle", "last_seq": st["last_seq"], "events": []}
    state = st["state"] if rid == st["run_id"] else "done"
    return {"run_id": rid, "state": state, "last_seq": st["last_seq"],
            "events": trace.events(max(0, int(after)), max(1, min(int(limit), 2000)), rid)}


def pipeline_supports_input_mode() -> bool:
    try:
        from app import pipeline
        return "input_mode" in inspect.signature(pipeline.run_pipeline).parameters
    except Exception:  # noqa: BLE001
        return False


def start_scan(app, use_sample: bool | None = None, input_mode: str | None = None) -> tuple[str, Any]:
    """Returns (outcome, payload). outcome: started | busy | invalid."""
    if input_mode in ("", "dataset"):
        input_mode = None
    if input_mode not in (None, "only", "merge"):
        return "invalid", "input_mode must be 'only' or 'merge'"
    if input_mode and not pipeline_supports_input_mode():
        return "invalid", "Scanning input data needs the pipeline update from the v2.1 integration prompt (input_mode)."
    if input_mode == "only" and not inputs.has_input():
        return "invalid", "No input data. Add data on the Input page first."
    started, st = runner.start(app, use_sample=use_sample, input_mode=input_mode)
    return ("started" if started else "busy"), st


# ---------------------------------------------------------------- analytics

def analytics_detectors(res) -> dict:
    return analytics.detector_comparison(getattr(res, "events", None), getattr(res, "signals", []) or [],
                                         getattr(res, "alerts", []) or [])


def analytics_time(res, days: int) -> dict:
    return analytics.attack_time_heatmap(getattr(res, "events", None), getattr(res, "alerts", []) or [],
                                         days=max(1, min(int(days), 60)))


def analytics_identities(res, top: int) -> dict:
    return analytics.identity_pattern_heatmap(getattr(res, "signals", []) or [], getattr(res, "alerts", []) or [],
                                              top=max(1, min(int(top), 30)))


# ---------------------------------------------------------------- graph

def find_alert(res, alert_id: str):
    for a in getattr(res, "alerts", []) or []:
        if a.alert_id == alert_id:
            return a
    return None


def _identity_row(res, identity_id: str) -> dict | None:
    try:
        from app import pipeline
        rows = pipeline.get_identity_rows(res)
        return next((r for r in rows if r.get("identity_id") == identity_id), None)
    except Exception:  # noqa: BLE001
        return None


def _subgraph(res, identity_id: str, suspicious: set[str]) -> dict:
    empty = {"identity_id": identity_id, "nodes": [], "edges": [], "escalation_paths": []}
    try:
        from app.correlate import graph as G
        g = getattr(res, "graph", None)
        if g is None:
            return empty
        out = _dump(G.identity_subgraph(g, identity_id, suspicious))
        return out if isinstance(out, dict) else empty
    except Exception:  # noqa: BLE001
        log.exception("identity_subgraph failed for %s", identity_id)
        return empty


def identity_attack(res, identity_id: str) -> dict | None:
    """Graph + top alert for one identity. None if the identity is unknown."""
    alerts = [a for a in getattr(res, "alerts", []) or [] if a.identity_id == identity_id]
    top = max(alerts, key=lambda a: a.risk, default=None)
    graph = _subgraph(res, identity_id, set(top.evidence_event_ids) if top else set())
    if not alerts and not graph["nodes"]:
        return None
    try:
        from app.correlate import graph as G
        blast = int(G.blast_radius(res.graph, identity_id))
    except Exception:  # noqa: BLE001
        blast = int(top.blast_radius) if top else 0
    return {"identity_id": identity_id, "identity": _identity_row(res, identity_id), "graph": graph,
            "alert": _dump(top), "blast_radius": blast}


def global_graph(res, top: int = 8, max_nodes: int = 300) -> dict:
    top = max(1, min(int(top), 15))
    best: dict[str, Any] = {}
    for a in getattr(res, "alerts", []) or []:
        if a.identity_id not in best or a.risk > best[a.identity_id].risk:
            best[a.identity_id] = a
    ids = [i for i, _ in sorted(best.items(), key=lambda kv: kv[1].risk, reverse=True)[:top]]
    evidence = {e for i in ids for e in best[i].evidence_event_ids}
    nodes: dict[str, dict] = {}
    edges: dict[tuple, dict] = {}
    truncated = False
    for i in ids:
        g = _subgraph(res, i, set(best[i].evidence_event_ids))
        for n in g["nodes"]:
            if n["id"] not in nodes:
                if len(nodes) >= max_nodes:
                    truncated = True
                    continue
                nodes[n["id"]] = n
        for e in g["edges"]:
            key = (e.get("source"), e.get("target"), e.get("label"), e.get("event_id"))
            if key[0] in nodes and key[1] in nodes and key not in edges:
                edges[key] = {**e, "suspicious": bool(e.get("suspicious")) or e.get("event_id") in evidence}
    return {"identities": ids, "nodes": list(nodes.values()), "edges": list(edges.values()), "truncated": truncated}
