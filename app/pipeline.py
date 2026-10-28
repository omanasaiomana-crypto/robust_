"""Pipeline orchestrator: runs ingestion, correlation, ML, 6 agents, scoring, response, and evaluation."""
from dataclasses import dataclass, field
from datetime import datetime, timezone
import logging
from pathlib import Path
import time

import networkx as nx
import pandas as pd

from app import audit, sample_data, store
from app.agents.api_anomaly import ApiAnomalyAgent
from app.agents.baseline_ml import BaselineMLAgent
from app.agents.dormant import DormantAgent
from app.agents.impossible_travel import ImpossibleTravelAgent
from app.agents.priv_escalation import PrivEscalationAgent, STATE_OF_ACTION
from app.agents.token_abuse import TokenAbuseAgent
from app.config import (
    BAND_RESTRICT,
    LABELS_DIR,
    MAX_EVIDENCE_EVENTS,
    METADATA_DIR,
    ML_ANOMALY_THRESHOLD,
    RAW_CLOUDTRAIL,
    RAW_OKTA,
    SAMPLE_DIR,
    USE_SAMPLE_IF_NO_DATA,
)
from app.correlate.graph import blast_radius, build_graph
from app.correlate.sessions import assign_sessions
from app.decision.explain import build_reasons, evidence_ids, mitre_tags
from app.decision.respond import auto_apply, recommend
from app.decision.scoring import counterfactuals, score_session
from app.evaluation import compute_metrics
from app.ingest.enrich import enrich
from app.ingest.loaders import load_cloudtrail, load_labels, load_metadata, load_okta
from app.ingest.normalize import normalize_all
from app.ml.chain_model import ChainModel
from app.models import Alert, Metrics, Prediction, Signal
from app.simulator import get_simulator
from app.utils import to_band

log = logging.getLogger(__name__)


@dataclass
class PipelineResult:
    events: pd.DataFrame
    graph: nx.MultiDiGraph
    alerts: list[Alert]
    metrics: Metrics
    status: str  # "ok" | "degraded" | "failed"
    detail: str
    data_mode: str  # "official" | "sample"
    signals: list[Signal] = field(default_factory=list)
    step_errors: list[str] = field(default_factory=list)
    timings_ms: dict[str, float] = field(default_factory=dict)


def detect_and_score(
    events_df: pd.DataFrame,
    graph: nx.MultiDiGraph | None = None,
    weights: dict[str, float] | None = None,
) -> tuple[list[Alert], list[Signal]]:
    """Execute detection agents, ML modeling, and alert risk scoring on events_df."""
    if events_df is None or events_df.empty:
        return [], []

    w = weights if weights is not None else store.get_weights()
    g = graph if graph is not None else build_graph(events_df)

    # 1. Train ML chain model
    chain_model = ChainModel()
    try:
        chains: list[list[str]] = []
        for _, sgroup in events_df.groupby("session_id"):
            matched = sgroup[sgroup["action"].isin(STATE_OF_ACTION)].sort_values(by="timestamp")
            if not matched.empty:
                states = [STATE_OF_ACTION[act] for act in matched["action"]]
                if len(states) >= 2:
                    chains.append(states)
        chain_model.fit(chains)
    except Exception as exc:
        log.exception("ML chain model fitting failed: %s", exc)

    # 2. Run 6 detection agents
    p1_agent = ImpossibleTravelAgent()
    p2_agent = DormantAgent()
    p3_agent = PrivEscalationAgent()
    p4_agent = ApiAnomalyAgent()
    p5_agent = TokenAbuseAgent()
    ml_agent = BaselineMLAgent()

    agents = [p1_agent, p2_agent, p3_agent, p4_agent, p5_agent, ml_agent]
    all_signals: list[Signal] = []

    for ag in agents:
        try:
            sigs = ag.detect(events_df)
            all_signals.extend(sigs)
        except Exception as exc:
            log.exception("Agent %s failed during detection: %s", ag.name, exc)

    # 3. Group signals by session and create alerts
    candidate_alerts: list[Alert] = []
    ml_scores = ml_agent.scores if ml_agent else {}
    last_chains = p3_agent.last_chains if p3_agent else {}

    signals_by_sess: dict[str, list[Signal]] = {}
    for s in all_signals:
        if s.session_id:
            signals_by_sess.setdefault(s.session_id, []).append(s)

    candidate_sessions: set[str] = set()
    for sess_id, sigs in signals_by_sess.items():
        if any(s.pattern != "ML" for s in sigs) or ml_scores.get(sess_id, 0.0) >= ML_ANOMALY_THRESHOLD:
            candidate_sessions.add(sess_id)

    for sess_id, score in ml_scores.items():
        if score >= ML_ANOMALY_THRESHOLD:
            candidate_sessions.add(sess_id)

    for sess_id in candidate_sessions:
        sess_sigs = signals_by_sess.get(sess_id, [])
        s_events = events_df[events_df["session_id"] == sess_id].sort_values(by="timestamp")

        if not s_events.empty:
            uid = str(s_events["identity_id"].iloc[0])
            first_seen = s_events["timestamp"].iloc[0]
            last_seen = s_events["timestamp"].iloc[-1]
        elif sess_sigs:
            uid = sess_sigs[0].identity_id
            first_seen = sess_sigs[0].timestamp
            last_seen = sess_sigs[-1].timestamp
        else:
            uid = "unknown"
            first_seen = datetime.now(timezone.utc)
            last_seen = datetime.now(timezone.utc)

        chain = last_chains.get(sess_id, [])
        prediction: Prediction | None = None
        if chain:
            prediction = chain_model.predict(chain[-1].state)

        b_rad = blast_radius(g, uid) if g is not None else 0
        ml_s = ml_scores.get(sess_id, 0.0)

        risk, confidence = score_session(
            sess_sigs,
            s_events,
            weights=w,
            prediction=prediction,
            ml_score=ml_s,
        )
        band = to_band(risk)
        patterns = sorted(list({s.pattern for s in sess_sigs}))
        if ml_s >= ML_ANOMALY_THRESHOLD and "ML" not in patterns:
            patterns.append("ML")
            patterns.sort()

        reasons = build_reasons(sess_sigs)
        if not reasons and ml_s >= ML_ANOMALY_THRESHOLD:
            reasons = [f"Session behavior is unusual compared with normal activity (anomaly score {ml_s:.2f})."]

        mitre = mitre_tags(sess_sigs)
        ev_ids = evidence_ids(sess_sigs, s_events)
        if not ev_ids and not s_events.empty:
            ev_ids = [str(x) for x in s_events["event_id"].head(MAX_EVIDENCE_EVENTS)]

        cfs = counterfactuals(
            sess_sigs,
            s_events,
            weights=w,
            prediction=prediction,
            ml_score=ml_s,
        )
        rec_action = recommend(risk)

        candidate_alerts.append(
            Alert(
                alert_id="",
                level="session",
                identity_id=uid,
                session_id=sess_id,
                risk=risk,
                confidence=confidence,
                blast_radius=b_rad,
                band=band,
                patterns=patterns,
                mitre=mitre,
                reasons=reasons,
                evidence_event_ids=ev_ids,
                chain=chain,
                prediction=prediction,
                counterfactuals=cfs,
                recommended_action=rec_action,
                action_status="pending",
                feedback=None,
                first_seen=first_seen,
                last_seen=last_seen,
            )
        )

    candidate_alerts.sort(key=lambda a: (a.risk, a.blast_radius), reverse=True)
    for i, a in enumerate(candidate_alerts, start=1):
        a.alert_id = f"AL-{i:04d}"

    return candidate_alerts, all_signals


def run_pipeline(use_sample: bool | None = None) -> PipelineResult:
    """Run end-to-end detection pipeline following context.md Section 7."""
    t_start = time.perf_counter()
    step_errors: list[str] = []
    timings_ms: dict[str, float] = {}

    # 1. Data selection
    if use_sample is True:
        data_mode = "sample"
    elif use_sample is False:
        data_mode = "official"
    else:
        # None: inspect if data/raw has input files
        has_raw = False
        if RAW_CLOUDTRAIL.exists() and any(p.is_file() for p in RAW_CLOUDTRAIL.iterdir() if not p.name.startswith(".")):
            has_raw = True
        elif RAW_OKTA.exists() and any(p.is_file() for p in RAW_OKTA.iterdir() if not p.name.startswith(".")):
            has_raw = True

        if has_raw:
            data_mode = "official"
        elif USE_SAMPLE_IF_NO_DATA:
            data_mode = "sample"
        else:
            data_mode = "official"

    if data_mode == "sample":
        ct_folder = SAMPLE_DIR
        okta_folder = SAMPLE_DIR
        if not (SAMPLE_DIR / "cloudtrail.json").exists() or not (SAMPLE_DIR / "okta.json").exists():
            log.info("Sample data missing; generating sample dataset in %s", SAMPLE_DIR)
            try:
                sample_data.generate(SAMPLE_DIR)
            except Exception as exc:
                log.exception("Sample data generation failed")
                step_errors.append(f"sample_generation: {exc}")
    else:
        ct_folder = RAW_CLOUDTRAIL
        okta_folder = RAW_OKTA

    # Step 1: Start audit entry
    try:
        audit.append("pipeline", "start", f"Pipeline started (mode={data_mode})")
    except Exception as exc:
        log.exception("Audit start error")
        step_errors.append(f"audit_start: {exc}")

    # Step 2: Load data
    step_t0 = time.perf_counter()
    raw_ct: list[dict] = []
    raw_okta: list[dict] = []
    skipped = 0
    metadata: dict[str, dict] = {}
    labels: dict[str, str] = {}

    try:
        raw_ct, sk_ct = load_cloudtrail(ct_folder)
        raw_okta, sk_okta = load_okta(okta_folder)
        skipped += (sk_ct + sk_okta)
        metadata = load_metadata(METADATA_DIR)
        labels = load_labels(LABELS_DIR)
    except Exception as exc:
        log.exception("Failed loading log data")
        step_errors.append(f"load_data: {exc}")
        return PipelineResult(
            events=pd.DataFrame(),
            graph=nx.MultiDiGraph(),
            alerts=[],
            metrics=Metrics(skipped_records=skipped),
            status="failed",
            detail=f"Loading failed: {exc}",
            data_mode=data_mode,
            signals=[],
            step_errors=step_errors,
            timings_ms=timings_ms,
        )
    timings_ms["load_data"] = round((time.perf_counter() - step_t0) * 1000.0, 2)

    # Step 3: Normalize + Enrich
    step_t0 = time.perf_counter()
    events_df = pd.DataFrame()
    try:
        events_df, sk_norm = normalize_all(raw_ct, raw_okta)
        skipped += sk_norm
        if labels and not events_df.empty:
            for idx, row in events_df.iterrows():
                eid = str(row["event_id"])
                if eid in labels and (not row.get("label") or row.get("label") in ("benign", "None", "")):
                    events_df.at[idx, "label"] = labels[eid]
        events_df = enrich(events_df, metadata=metadata)
    except Exception as exc:
        log.exception("Normalization and enrichment failed")
        step_errors.append(f"normalize_enrich: {exc}")
        return PipelineResult(
            events=pd.DataFrame(),
            graph=nx.MultiDiGraph(),
            alerts=[],
            metrics=Metrics(skipped_records=skipped),
            status="failed",
            detail=f"Normalize/enrich failed: {exc}",
            data_mode=data_mode,
            signals=[],
            step_errors=step_errors,
            timings_ms=timings_ms,
        )
    timings_ms["normalize_enrich"] = round((time.perf_counter() - step_t0) * 1000.0, 2)

    if events_df.empty:
        log.warning("Pipeline found 0 normalized events")
        return PipelineResult(
            events=events_df,
            graph=nx.MultiDiGraph(),
            alerts=[],
            metrics=Metrics(total_events=0, total_alerts=0, skipped_records=skipped),
            status="failed",
            detail="No events loaded or normalized",
            data_mode=data_mode,
            signals=[],
            step_errors=step_errors,
            timings_ms=timings_ms,
        )

    # Step 4: Assign sessions
    step_t0 = time.perf_counter()
    try:
        events_df = assign_sessions(events_df)
    except Exception as exc:
        log.exception("Session correlation failed")
        step_errors.append(f"assign_sessions: {exc}")
    timings_ms["assign_sessions"] = round((time.perf_counter() - step_t0) * 1000.0, 2)

    # Step 5: Build identity graph
    step_t0 = time.perf_counter()
    graph = nx.MultiDiGraph()
    try:
        graph = build_graph(events_df)
    except Exception as exc:
        log.exception("Graph construction failed")
        step_errors.append(f"build_graph: {exc}")
    timings_ms["build_graph"] = round((time.perf_counter() - step_t0) * 1000.0, 2)

    # Steps 6-8: ML modeling, 6 detection agents, risk scoring
    step_t0 = time.perf_counter()
    all_signals: list[Signal] = []
    candidate_alerts: list[Alert] = []
    try:
        candidate_alerts, all_signals = detect_and_score(
            events_df,
            graph=graph,
            weights=store.get_weights(),
        )
    except Exception as exc:
        log.exception("Detection and scoring failed")
        step_errors.append(f"detect_and_score: {exc}")
    detection_sec = time.perf_counter() - step_t0
    timings_ms["detection_and_scoring"] = round(detection_sec * 1000.0, 2)

    # Step 9: Save alerts, Write audit entries, Auto-apply containment
    step_t0 = time.perf_counter()
    try:
        store.reset_run_tables()
        store.save_alerts(candidate_alerts)

        # Audit alerts with risk >= BAND_RESTRICT (70)
        for a in candidate_alerts:
            if a.risk >= float(BAND_RESTRICT):
                audit.append(
                    "decision",
                    "alert_created",
                    f"Alert {a.alert_id} ({a.identity_id}): risk {a.risk:.1f} ({a.band}), patterns={a.patterns}",
                )

        # Auto-apply actions via simulator adapter
        sim = get_simulator()
        for a in candidate_alerts:
            auto_apply(a, sim)

        # Save again with updated action_status
        store.save_alerts(candidate_alerts)

        audit.append("pipeline", "end", f"Pipeline finished: {len(candidate_alerts)} alerts produced")
    except Exception as exc:
        log.exception("Alert persistence and auto-apply failed")
        step_errors.append(f"persistence_auto_apply: {exc}")
    timings_ms["persistence_auto_apply"] = round((time.perf_counter() - step_t0) * 1000.0, 2)

    # Step 10: Compute evaluation metrics
    step_t0 = time.perf_counter()
    metrics = Metrics()
    try:
        metrics = compute_metrics(
            events_df,
            candidate_alerts,
            all_signals,
            skipped=skipped,
            elapsed_detection_sec=detection_sec,
        )
    except Exception as exc:
        log.exception("Metrics computation failed")
        step_errors.append(f"compute_metrics: {exc}")
    timings_ms["compute_metrics"] = round((time.perf_counter() - step_t0) * 1000.0, 2)

    total_ms = round((time.perf_counter() - t_start) * 1000.0, 2)
    timings_ms["total_ms"] = total_ms

    status = "degraded" if step_errors else "ok"
    detail = f"{len(step_errors)} step error(s): {', '.join(step_errors)}" if step_errors else ""

    return PipelineResult(
        events=events_df,
        graph=graph,
        alerts=candidate_alerts,
        metrics=metrics,
        status=status,
        detail=detail,
        data_mode=data_mode,
        signals=all_signals,
        step_errors=step_errors,
        timings_ms=timings_ms,
    )


def get_identity_rows(result: PipelineResult) -> list[dict]:
    """Return aggregated identity summary rows for the /api/identities endpoint."""
    if result is None or result.events is None or result.events.empty:
        return []

    events_df = result.events
    alerts = result.alerts or []
    graph = result.graph

    # Map alerts by identity_id
    alerts_by_id: dict[str, list[Alert]] = {}
    for a in alerts:
        alerts_by_id.setdefault(a.identity_id, []).append(a)

    rows: list[dict] = []
    unique_ids = events_df["identity_id"].unique()

    for uid in sorted(unique_ids):
        uid_str = str(uid)
        id_alerts = alerts_by_id.get(uid_str, [])
        max_risk = max((a.risk for a in id_alerts), default=0.0)
        alerts_count = len(id_alerts)

        sub = events_df[events_df["identity_id"] == uid]
        priv_lvl = int(sub["privilege_level"].max() if "privilege_level" in sub else 1) or 1
        b_rad = blast_radius(graph, uid_str) if graph is not None else 0

        rows.append(
            {
                "identity_id": uid_str,
                "risk": round(float(max_risk), 1),
                "alerts": alerts_count,
                "privilege_level": priv_lvl,
                "blast_radius": b_rad,
            }
        )

    # Sort by risk descending, then blast_radius desc, then identity_id
    rows.sort(key=lambda r: (r["risk"], r["blast_radius"]), reverse=True)
    return rows
