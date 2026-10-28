"""Pipeline orchestrator: runs ingestion, correlation, ML, 6 agents, scoring, response, and evaluation."""
from dataclasses import dataclass, field
from datetime import datetime, timezone
import logging
from pathlib import Path
import time

import networkx as nx
import pandas as pd

from app import audit, sample_data, store, trace
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
    ML_MIN_TRAIN_SESSIONS,
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
from app.utils import clean_json, to_band

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

    # 2. Run 5 rule detection agents
    p1_agent = ImpossibleTravelAgent()
    p2_agent = DormantAgent()
    p3_agent = PrivEscalationAgent()
    p4_agent = ApiAnomalyAgent()
    p5_agent = TokenAbuseAgent()
    ml_agent = BaselineMLAgent()

    rule_agents = [p1_agent, p2_agent, p3_agent, p4_agent, p5_agent]
    all_signals: list[Signal] = []

    for ag in rule_agents:
        try:
            with trace.step(ag.name, f"Running {ag.name.replace('_', ' ').title()}") as s:
                sigs = ag.detect(events_df)
                all_signals.extend(sigs)
                examples = [
                    {
                        "identity_id": sig.identity_id,
                        "session_id": sig.session_id,
                        "severity": float(sig.severity),
                        "reason": sig.reason,
                        "evidence_count": len(sig.evidence_event_ids or []),
                    }
                    for sig in sigs[:3]
                ]
                msg = f"{len(sigs)} signal{'s' if len(sigs) != 1 else ''}"
                if sigs:
                    msg += f" · {sigs[0].identity_id} {sigs[0].reason[:35]}"
                s.output({"signals": len(sigs), "examples": examples}, msg)
        except Exception as exc:
            log.exception("Agent %s failed during detection: %s", ag.name, exc)

    # 10. Baseline ML Agent
    n_sessions = int(events_df["session_id"].nunique()) if "session_id" in events_df else 0
    try:
        if n_sessions < ML_MIN_TRAIN_SESSIONS:
            trace.skip("baseline_ml", f"Not enough sessions to train (n={n_sessions})")
            sigs = ml_agent.detect(events_df)
            all_signals.extend(sigs)
        else:
            with trace.step("baseline_ml", f"Isolation Forest over {n_sessions} session feature vectors") as s:
                sigs = ml_agent.detect(events_df)
                all_signals.extend(sigs)
                top_scores = [
                    {"session_id": sid, "score": float(sc)}
                    for sid, sc in sorted(ml_agent.scores.items(), key=lambda x: x[1], reverse=True)[:3]
                ]
                from app.ml.features import numeric_columns
                s.output({
                    "signals": len(sigs),
                    "trained_on": n_sessions,
                    "features": numeric_columns(),
                    "top_scores": top_scores,
                }, f"{len(sigs)} sessions above anomaly threshold {ML_ANOMALY_THRESHOLD:.2f}")
    except Exception as exc:
        log.exception("Baseline ML agent failed: %s", exc)

    # 11. Risk Scoring Agent
    candidate_alerts: list[Alert] = []
    try:
        with trace.step("risk_scoring", "Combining signals × privilege × sensitivity") as s:
            ml_scores = ml_agent.scores if ml_agent else {}
            last_chains = p3_agent.last_chains if p3_agent else {}

            signals_by_sess: dict[str, list[Signal]] = {}
            for sig in all_signals:
                if sig.session_id:
                    signals_by_sess.setdefault(sig.session_id, []).append(sig)

            candidate_sessions: set[str] = set()
            for sess_id, sigs in signals_by_sess.items():
                if any(sig.pattern != "ML" for sig in sigs) or ml_scores.get(sess_id, 0.0) >= ML_ANOMALY_THRESHOLD:
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
                patterns = sorted(list({sig.pattern for sig in sess_sigs}))
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

            bands_count = {"revoke": 0, "restrict": 0, "step_up": 0, "monitor": 0}
            for a in candidate_alerts:
                bands_count[a.band] = bands_count.get(a.band, 0) + 1

            top_alert = candidate_alerts[0] if candidate_alerts else None
            top_info = {"alert_id": top_alert.alert_id, "risk": round(top_alert.risk, 1)} if top_alert else None
            top_msg = f" · top risk {int(top_alert.risk)} ({top_alert.identity_id})" if top_alert else ""

            s.output({
                "sessions_scored": len(candidate_sessions),
                "alerts": len(candidate_alerts),
                "bands": bands_count,
                "top": top_info,
            }, f"{len(candidate_alerts)} alerts{top_msg}")
    except Exception as exc:
        log.exception("Risk scoring failed: %s", exc)

    # 12. Explanation Agent
    try:
        with trace.step("explanation", "Writing reasons, counterfactuals and MITRE tags") as s:
            all_mitre = sorted(list({m for a in candidate_alerts for m in (a.mitre or [])}))
            top_cfs = candidate_alerts[0].counterfactuals if candidate_alerts else []
            s.output({
                "alerts_explained": len(candidate_alerts),
                "mitre": all_mitre,
                "counterfactuals": [clean_json(cf) for cf in top_cfs],
            }, f"{len(candidate_alerts)} alerts explained with evidence")
    except Exception as exc:
        log.exception("Explanation failed: %s", exc)

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
        with trace.step("ingestion", "Loading CloudTrail and Okta files") as s:
            raw_ct, sk_ct = load_cloudtrail(ct_folder)
            raw_okta, sk_okta = load_okta(okta_folder)
            skipped += (sk_ct + sk_okta)
            metadata = load_metadata(METADATA_DIR)
            labels = load_labels(LABELS_DIR)

            ct_path = Path(ct_folder)
            okta_path = Path(okta_folder)
            ct_files = [p.name for p in ct_path.glob("*.json*") if not p.name.startswith(".")] if ct_path.exists() else []
            okta_files = [p.name for p in okta_path.glob("*.json*") if not p.name.startswith(".")] if okta_path.exists() else []
            tot_recs = len(raw_ct) + len(raw_okta)
            tot_files = len(ct_files) + len(okta_files)
            s.output({
                "files": {"cloudtrail": ct_files, "okta": okta_files},
                "records": {"cloudtrail": len(raw_ct), "okta": len(raw_okta)},
                "skipped": int(skipped),
            }, f"Loaded {tot_recs:,} records from {tot_files} files")
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
        with trace.step("normalization", "Mapping both formats to the unified event schema") as s:
            events_df, sk_norm = normalize_all(raw_ct, raw_okta)
            skipped += sk_norm
            if labels and not events_df.empty:
                for idx, row in events_df.iterrows():
                    eid = str(row["event_id"])
                    if eid in labels and (not row.get("label") or row.get("label") in ("benign", "None", "")):
                        events_df.at[idx, "label"] = labels[eid]
            ct_cnt = int((events_df["source"] == "cloudtrail").sum()) if "source" in events_df else 0
            okta_cnt = int((events_df["source"] == "okta").sum()) if "source" in events_df else 0
            n_ids = int(events_df["identity_id"].nunique()) if "identity_id" in events_df else 0
            sample_ev = events_df.iloc[0].to_dict() if not events_df.empty else None
            s.output({
                "events": len(events_df),
                "skipped": int(skipped),
                "sources": {"cloudtrail": ct_cnt, "okta": okta_cnt},
                "identities": n_ids,
                "sample_event": clean_json(sample_ev),
            }, f"{len(events_df):,} events normalized for {n_ids} identities")
    except Exception as exc:
        log.exception("Normalization failed")
        step_errors.append(f"normalization: {exc}")
        return PipelineResult(
            events=pd.DataFrame(),
            graph=nx.MultiDiGraph(),
            alerts=[],
            metrics=Metrics(skipped_records=skipped),
            status="failed",
            detail=f"Normalize failed: {exc}",
            data_mode=data_mode,
            signals=[],
            step_errors=step_errors,
            timings_ms=timings_ms,
        )

    try:
        with trace.step("enrichment", "Adding geo, privilege level and resource sensitivity") as s:
            events_df = enrich(events_df, metadata=metadata)
            geo_filled = int(events_df["country"].notna().sum()) if "country" in events_df else 0
            priv_ids = int(events_df[events_df["privilege_level"] >= 3]["identity_id"].nunique()) if "privilege_level" in events_df else 0
            sens_events = int((events_df["sensitivity"] >= 4).sum()) if "sensitivity" in events_df else 0
            s.output({
                "geo_filled": geo_filled,
                "privileged_identities": priv_ids,
                "sensitive_events": sens_events,
            }, f"Enriched {len(events_df):,} events · {sens_events} touch sensitive resources")
    except Exception as exc:
        log.exception("Enrichment failed")
        step_errors.append(f"enrichment: {exc}")
        return PipelineResult(
            events=pd.DataFrame(),
            graph=nx.MultiDiGraph(),
            alerts=[],
            metrics=Metrics(skipped_records=skipped),
            status="failed",
            detail=f"Enrich failed: {exc}",
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

    # Step 4: Assign sessions + graph
    step_t0 = time.perf_counter()
    graph = nx.MultiDiGraph()
    try:
        with trace.step("correlation", "Linking Okta sessions to AWS activity") as s:
            events_df = assign_sessions(events_df)
            graph = build_graph(events_df)
            n_sessions = int(events_df["session_id"].nunique()) if "session_id" in events_df else 0
            okta_linked = int(events_df[events_df["session_id"].str.startswith("okta:")]["session_id"].nunique()) if "session_id" in events_df else 0
            aws_only = n_sessions - okta_linked
            n_nodes = graph.number_of_nodes()
            n_edges = graph.number_of_edges()
            s.output({
                "sessions": n_sessions,
                "okta_linked": okta_linked,
                "aws_only": aws_only,
                "graph": {"nodes": n_nodes, "edges": n_edges},
            }, f"{n_sessions} sessions · graph {n_nodes:,} nodes / {n_edges:,} edges")
    except Exception as exc:
        log.exception("Session correlation failed")
        step_errors.append(f"assign_sessions: {exc}")
    timings_ms["assign_sessions"] = round((time.perf_counter() - step_t0) * 1000.0, 2)
    timings_ms["build_graph"] = 0.0

    # Steps 5-12: ML modeling, detection agents, risk scoring, explanation
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

    # Step 13: Auto-apply containment (Response agent)
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
        applied = []
        pending_approval = []
        with trace.step("response", "Choosing actions (simulator only)") as s:
            for a in candidate_alerts:
                auto_apply(a, sim)
                if a.action_status in ("applied", "notified"):
                    applied.append({"alert_id": a.alert_id, "action": a.recommended_action, "result": a.action_status})
                else:
                    pending_approval.append({"alert_id": a.alert_id, "action": a.recommended_action})

            s.output({
                "applied": applied,
                "pending_approval": pending_approval,
            }, f"{len(applied)} actions applied · {len(pending_approval)} awaiting analyst approval")

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
